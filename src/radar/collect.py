"""Collect station: one source → raw items + updated source state. Failures are recorded, never swallowed:
a failed source keeps its old cursor and its error is visible in sources.json."""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from radar import fetch, parsers, timeutil
from radar.limits import Limits
from radar.model import RawItem
from radar.registry import BY_ID, SOURCES, Source

log = logging.getLogger(__name__)

MAX_POC_FETCHES = 10  # DeFiHackLabs .sol headers fetched per run (only for entries not seen before)
MAX_CSAF_FETCHES = 10  # CSAF advisory documents fetched per run (new entries / updates only; the rest wait a run)
CSAF_RECENT_DAYS = 14  # a ROLIE feed holds every advisory since 2016 (OT: 3,995): only recent entries are reports

# Incremental collection (2026-11-10, research/17 §0.1/§5.1). Live 24 h on 28 sources: Process received 101,584 raw
# entries of which 835 (0.82 %) were new or changed — a list feed returns its last N entries every run, and 18 of 28
# sources never answer 304 (DefiLlama alone: 64,368 entries/day). The collector now remembers, per source, what it
# handed over (guid hash → content hash) in a SEEN record of its own and passes on only new or edited entries.
# An edited entry (DeFiLlama revising an amount, a media outlet fixing a headline) is still passed on: the content hash
# changed. CSAF (rolie) keeps its own unseen-advisory rule; X is a windowed search and is deduped the same way.
NOT_INCREMENTAL = frozenset({"rolie"})


def _gh(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def _content(r: RawItem) -> str:
    return _gh(f"{r.title}\x1f{r.text}\x1f{json.dumps(r.extra, sort_keys=True, default=str)}")[:8]


def incremental(raws: list[RawItem], seen: dict[str, str], now: datetime, brand_new: bool) -> tuple[list[RawItem], dict[str, str]]:
    """(entries to hand over, the SEEN record to store after they are safely written). A brand-new source (never
    succeeded) hands over only its last FIRST_RUN_DAYS — it must not flood Process with its archive; an existing
    source with no SEEN record yet hands over everything once (Process dedupes by item id), so nothing is lost on the
    switch. SEEN keeps the current response plus up to SEEN_CAP older entries: an entry that drops out of a feed and
    comes back after that is handed over again, harmlessly."""
    fresh, cur = [], {}
    for r in raws:
        g, c = _gh(r.guid or r.url), _content(r)
        cur[g] = c
        if seen.get(g) == c:
            continue
        if brand_new and r.published_at and now - r.published_at > timedelta(days=Limits.FIRST_RUN_DAYS):
            continue
        fresh.append(r)
    # the current response plus up to SEEN_CAP older entries — not "up to SEEN_CAP in total": a feed whose CDN serves
    # two versions with different guids (alas2023, live 2026-11-10: 1,135 entries each) pushed the other version out
    # of a total-capped SEEN, and every other run handed over all 1,135 again
    older = [(g, c) for g, c in seen.items() if g not in cur][:Limits.SEEN_CAP]
    return fresh, {**cur, **dict(older)}


# Follow-up fetches whose URL comes from feed content (a ROLIE entry's href, a CVE delta's githubLink, a README's .sol
# path) go only to the hosts each parser's documents live on, over https, redirects included (fetch.http_get
# allow_hosts). Why (docs/research/action/05 §3.7): the feed decides the URL, so an edited or spoofed entry could point
# the collector anywhere — 169.254.169.254, the Lambda runtime API on 127.0.0.1:9001, an ftp: redirect.
FOLLOWUP_HOSTS: dict[str, frozenset[str]] = {
    "rolie": frozenset({"raw.githubusercontent.com"}),          # cisagov/CSAF advisories (registry cisa_csaf_*)
    "cvelist_delta": frozenset({"raw.githubusercontent.com"}),  # CVEProject/cvelistV5 records
    "defihacklabs": frozenset({"raw.githubusercontent.com"}),   # SunWeb3Sec/DeFiHackLabs PoC files
}

HEAVY_PARSERS = frozenset({"twitterapi", "rolie", "defihacklabs", "cvelist_delta"})   # several requests per run
EMPTY_OK = frozenset({"twitterapi", "cvelist_delta"})   # an empty window is normal, not a broken page
# Direct feed fetches that failed are retried once through firecrawl (live 2026-11-11, 3 days: anquanke 26 timeouts,
# doonsec 10 TLS handshake timeouts, netsec 6 "Blocked", sans_isc 3 block pages parsed to 0 entries — every one of them
# fetched fine through firecrawl). XML / HTML parsers only: rawHtml corrupts JSON (fetch.firecrawl_raw).
FIRECRAWL_FALLBACK_PARSERS = frozenset({"feed", "feed_cst", "telegram"})
FALLBACK_HTTP = frozenset({403, 451, 503, *range(520, 531)})     # refusals / CDN blocks, not 404 / 410 / 429


def _fallback_ok(source: Source, e: fetch.FetchError, st: dict[str, Any], now: datetime) -> bool:
    """Is this direct failure worth one firecrawl retry? A 429 is respected (asking again elsewhere is evasion), a 404
    is a dead URL. Bounded per source per day; the count lives in the source state."""
    if source.via != "direct" or source.parser not in FIRECRAWL_FALLBACK_PARSERS:
        return False
    if not (e.code in ("network_error", "parse_empty")
            or (e.code == "http_error" and (e.status in FALLBACK_HTTP or "block" in e.reason.lower()))):
        return False
    day = now.date().isoformat()
    used = st.get("fc_fallbacks", 0) if st.get("fc_fallback_day") == day else 0
    return used < Limits.FEED_FIRECRAWL_FALLBACKS_PER_DAY


def _parsed(source: Source, resp: fetch.Response) -> list[RawItem]:
    raws: list[RawItem] = [] if resp.status == 304 else parsers.PARSERS[source.parser](resp.body, source.source_id)
    if resp.status == 200 and not raws and source.parser not in EMPTY_OK:
        # a feed/DB that parses to nothing is broken (block page, format change), not "no news"
        raise fetch.FetchError("parse_empty", f"0 entries parsed from {len(resp.body)} bytes", 200, source.url)
    return raws


def _fetch_parse(source: Source, st: dict[str, Any], now: datetime) -> tuple[fetch.Response, list[RawItem]]:
    try:
        resp = _body(source, st, now)
        raws = _parsed(source, resp)
    except fetch.FetchError as e:
        if not _fallback_ok(source, e, st, now):
            raise
        day = now.date().isoformat()
        st["fc_fallbacks"] = (st.get("fc_fallbacks", 0) if st.get("fc_fallback_day") == day else 0) + 1
        st["fc_fallback_day"] = day
        try:
            resp = fetch.Response(200, fetch.firecrawl_raw(source.url))
            raws = _parsed(source, resp)
        except (fetch.FetchError, ValueError, KeyError) as e2:
            raise fetch.FetchError(e.code, f"{e}; firecrawl fallback also failed: {str(e2)[:160]}", e.status,
                                   source.url) from e2
        st["degraded"] = f"direct {e.code}/{e.status}; served by firecrawl"     # visible on #/sources (not "ok")
        return resp, raws
    if source.parser in FIRECRAWL_FALLBACK_PARSERS:
        st.pop("degraded", None)            # direct works again
    return resp, raws
CVE_GAP_MIN = 10            # delta.json covers one ~7-min window: a longer gap between two fetchTimes lost windows


def _cve_records(source: Source, raws: list[RawItem], st: dict[str, Any], now: datetime,
                 seen: dict[str, str] | None) -> list[RawItem]:
    """Complete each new CVE from its record (≤ MAX_CVE_RECORDS per run, newest first). A window we missed
    (fetchTime gap > CVE_GAP_MIN) is backfilled from deltaLog.json — logged, never silent. A record that cannot be
    read is dropped from SEEN, so the next run tries it again instead of losing the CVE."""
    ft = next((r.extra.get("fetch_time") for r in raws), None)
    prev = st.get("cve_fetch_time")
    if ft and prev and (timeutil.parse(ft) - timeutil.parse(prev)) > timedelta(minutes=CVE_GAP_MIN):
        try:
            log_raws = parsers.cvelist_delta(fetch.http_get(source.url.replace("delta.json", "deltaLog.json")).body,
                                             source.source_id)
            have = {r.guid for r in raws}
            back = [r for r in log_raws if r.guid not in have and (r.extra.get("fetch_time") or "") > prev
                    and (seen is None or _gh(r.guid) not in seen)]
            raws = raws + back
            log.warning(json.dumps({"source": source.source_id, "degraded": "cvelist_gap_backfilled", "from": prev,
                                    "to": ft, "backfilled": len(back)}))
        except (fetch.FetchError, ValueError) as e:
            log.warning(json.dumps({"source": source.source_id, "degraded": "cvelist_gap_unfilled", "from": prev,
                                    "to": ft, "error": str(e)[:200]}))
    if ft:
        st["cve_fetch_time"] = ft
    # CVEs an earlier run could not complete come first. They live in the source state because the list cannot bring
    # them back: an unchanged delta.json answers 304 (nothing parsed) and the next window no longer lists them — dropping
    # them from SEEN, the old "retry", lost the CVE (audit 01 #2).
    waiting = {p["guid"]: p for p in st.pop("cve_pending", [])}
    have = {r.guid for r in raws}
    raws = [RawItem.from_dict(p["raw"]) for g, p in waiting.items() if g not in have] + raws
    pending: list[dict[str, Any]] = []

    def put_off(r: RawItem, missed: bool) -> None:
        misses = waiting.get(r.guid, {}).get("misses", 0) + (1 if missed else 0)
        if misses >= Limits.CVE_PENDING_RETRIES:
            log.warning(json.dumps({"source": source.source_id, "degraded": "cve_record_gave_up", "cve": r.guid, "misses": misses}))
            return
        pending.append({"guid": r.guid, "misses": misses, "raw": r.to_dict()})
    out = []
    for r in sorted(raws, key=lambda r: r.published_at or now, reverse=True)[:Limits.MAX_CVE_RECORDS]:
        try:
            d = parsers.cve_record(fetch.http_get(r.extra["record_url"], allow_hosts=FOLLOWUP_HOSTS["cvelist_delta"]).body)
        except (fetch.FetchError, ValueError, KeyError) as e:
            put_off(r, missed=True)
            log.warning(json.dumps({"source": source.source_id, "degraded": "cve_record_unavailable", "cve": r.guid,
                                    "error": str(e)[:200]}))
            continue
        r.title = f"{r.guid} {d['title']}".strip()
        r.text = d["text"] or r.title
        r.extra.update(cvss=d["cvss"], severity=d["severity"], entity=d["vendor"], product=d["product"],
                       cna_published=d["published"], assigner=d["assigner"])
        out.append(r)
    for r in sorted(raws, key=lambda r: r.published_at or now, reverse=True)[Limits.MAX_CVE_RECORDS:]:
        put_off(r, missed=False)                          # over the cap: waits a run, not lost
    if pending:
        st["cve_pending"] = pending[-Limits.CVE_PENDING_MAX:]
        if len(pending) > Limits.CVE_PENDING_MAX:
            log.warning(json.dumps({"source": source.source_id, "degraded": "cve_pending_overflow",
                                    "dropped": len(pending) - Limits.CVE_PENDING_MAX, "limit": Limits.CVE_PENDING_MAX}))
    return out


def _host(s: Source) -> str:
    return s.url.split("/")[2] if "://" in s.url else s.url


def batches(source_ids: list[str]) -> list[list[str]]:
    """Pack due sources into Collect invocations (research/17 §4, design B): one invocation per heavy or firecrawl source;
    light ones grouped by host (a host's sources run serially inside the batch — the per-host rate limit) and host groups
    packed up to COLLECT_BATCH. 167 sources ⇒ ~15 invocations instead of 167, i.e. ~15 Map state transitions."""
    heavy, groups = [], {}
    for sid in source_ids:
        s = BY_ID[sid]
        if s.parser in HEAVY_PARSERS or s.via != "direct":
            heavy.append([sid])
        else:
            groups.setdefault(_host(s), []).append(sid)
    out, cur = [], []
    for g in sorted(groups.values(), key=len, reverse=True):
        if cur and len(cur) + len(g) > Limits.COLLECT_BATCH:
            out.append(cur)
            cur = []
        cur += g
    return heavy + out + ([cur] if cur else [])


def due(states: dict[str, dict[str, Any]], now: datetime) -> list[str]:
    out = []
    for s in SOURCES:
        if not s.enabled:
            continue
        last = timeutil.parse(states.get(s.source_id, {}).get("last_run"))
        # half a cycle of slack: `last_run` is when the source was collected, up to minutes into its cycle. With one
        # minute, a 15-minute source collected 90 s in was "not due" 15 minutes later and ran every 20 (audit 01 #12)
        if last is None or now - last >= timedelta(minutes=s.cadence_min) - timedelta(minutes=Limits.CYCLE_MINUTES / 2):
            out.append(s.source_id)
    return out


def _x_fallback(source: Source, state: dict[str, Any], now: datetime, why: fetch.FetchError) -> fetch.Response:
    """the X data source out of key / credit / quota ⇒ firecrawl profile snapshots, marked degraded (≤5 posts per handle,
    so a busy account can lose posts between runs). Capped per day: the firecrawl keys are a one-off pool shared with
    the blocked-site sources (docs/research/13 §4)."""
    day = now.date().isoformat()
    used = state.get("x_fc_credits", 0) if state.get("x_fc_day") == day else 0
    handles = source.handles[:Limits.X_FIRECRAWL_MAX_HANDLES]
    planned = len(handles) * Limits.FIRECRAWL_CREDITS_X_PROFILE
    if used + planned > Limits.X_FIRECRAWL_CREDITS_PER_DAY:
        raise fetch.FetchError("x_firecrawl_cap", f"{why.code}/{why.status} and the fallback is paused: {used} firecrawl "
                               f"credits used today, +{planned} would pass the {Limits.X_FIRECRAWL_CREDITS_PER_DAY} cap",
                               why.status, why.url)
    body = fetch.firecrawl_x_profiles(handles)
    meta = json.loads(body)
    state.update(x_fc_day=day, x_fc_credits=used + int(meta.get("credits") or 0),
                 degraded=f"twitterapi {why.code}/{why.status}; served by firecrawl profile snapshots (≤5 posts/handle)")
    if meta.get("failed_handles"):
        state["failed_handles"] = meta["failed_handles"]
    else:
        state.pop("failed_handles", None)
    return fetch.Response(200, body)


def _body(source: Source, state: dict[str, Any], now: datetime) -> fetch.Response:
    if source.parser == "twitterapi":
        try:
            body = fetch.twitterapi_search(source.handles, source.cadence_min)
        except fetch.FetchError as e:
            if not fetch.twitterapi_unavailable(e):
                raise
            return _x_fallback(source, state, now, e)
        state.pop("degraded", None)
        state.pop("failed_handles", None)
        return fetch.Response(200, body)
    if source.via == "firecrawl":
        return fetch.Response(200, fetch.firecrawl_raw(source.url))
    return fetch.http_get(source.url, etag=state.get("etag"), last_modified=state.get("last_modified"))


def _csaf_reports(source: Source, raws: list[RawItem], now: datetime, known_item: Callable[[str, str], bool],
                  st: dict[str, Any]) -> list[RawItem]:
    """Recent, not yet seen ROLIE entries, each completed from its CSAF document (CVEs — the clustering key —, vendor,
    summary). Entries over the per-run cap wait for the next run (they are still unseen then); an entry whose document
    cannot be read is dropped this run, logged, and retried next run."""
    cutoff = now - timedelta(days=CSAF_RECENT_DAYS)
    seen = lambda r: known_item(source.source_id, r.guid or "")
    todo = sorted((r for r in raws if r.published_at and r.published_at >= cutoff and not seen(r)),
                  key=lambda r: r.published_at, reverse=True)
    out = []
    for r in todo[:MAX_CSAF_FETCHES]:
        try:
            d = parsers.csaf_doc(fetch.http_get(r.extra["csaf_url"], allow_hosts=FOLLOWUP_HOSTS["rolie"]).body)
        except (fetch.FetchError, ValueError, KeyError) as e:
            log.warning(json.dumps({"source": source.source_id, "degraded": "csaf_doc_unavailable", "advisory": r.extra.get("advisory_id"),
                                    "error": str(e)[:200]}))
            st["deferred"] = st.get("deferred", 0) + 1      # CSAF document unreadable
            continue  # retried next run: the entry is still unseen
        r.text = d["text"]
        r.extra.update(cves=d["cves"], cvss=d["cvss"], entity=(d["vendors"] or [None])[0])
        out.append(r)
    if len(todo) > MAX_CSAF_FETCHES:
        st["deferred"] = st.get("deferred", 0) + len(todo) - MAX_CSAF_FETCHES
    return out


def _poc_headers(source: Source, raws: list[RawItem], known_item: Callable[[str, str], bool],
                 seen: dict[str, str] | None, st: dict[str, Any]) -> list[RawItem]:
    """Attack tx / attacker from each new entry's PoC header (≤ MAX_POC_FETCHES per run) → the entries to hand over.
    A .sol that cannot be read (deleted upstream, a GitHub raw 5xx) degrades only its own entry — it no longer fails
    the source (that lost the whole batch). The entry is held back (not handed over, dropped from SEEN, its misses
    counted in st["poc_misses"]) so the next run, which still does not know the item, fetches the PoC again. Handing
    it over without attack_tx was no retry: once stored, known_item skips the fetch and ingest's content hash ignores
    attack_tx — the tx key never arrived. A .sol still unreadable on its POC_RETRIES-th run is given up on (logged):
    the entry goes over without it rather than never."""
    misses: dict[str, int] = dict(st.get("poc_misses") or {})
    out, fetched = [], 0
    for r in raws:
        g = _gh(r.guid or r.url)
        if fetched >= MAX_POC_FETCHES or not r.extra.get("sol_url") or known_item(source.source_id, r.guid or ""):
            out.append(r)
            continue
        fetched += 1
        try:
            poc = parsers.defihacklabs_poc(fetch.http_get(r.extra["sol_url"], allow_hosts=FOLLOWUP_HOSTS["defihacklabs"]).body)
        except (fetch.FetchError, ValueError, KeyError) as e:
            misses[g] = misses.get(g, 0) + 1
            gave_up = misses[g] >= Limits.POC_RETRIES
            log.warning(json.dumps({"source": source.source_id, "degraded": "poc_gave_up" if gave_up else "poc_unavailable",
                                    "entry": r.guid, "misses": misses[g], "error": str(e)[:200]}))
            if gave_up:
                misses.pop(g)
                out.append(r)
            else:
                st["deferred"] = st.get("deferred", 0) + 1      # PoC held back
                if seen is not None:
                    seen.pop(g, None)      # held back: its PoC is fetched again next run
            continue
        misses.pop(g, None)
        r.extra.update(attack_tx=poc["attack_tx"], attacker_urls=poc["attacker_urls"])
        out.append(r)
    # only entries still waiting stay counted (one that left the README or was given up on is forgotten)
    waiting = {g: n for g, n in misses.items() if g in {_gh(r.guid or r.url) for r in raws}}
    if waiting:
        st["poc_misses"] = waiting
    else:
        st.pop("poc_misses", None)
    return out


def collect(source: Source, state: dict[str, Any], now: datetime,
            known_item: Callable[[str, str], bool] = lambda sid, guid: False,
            seen: dict[str, str] | None = None) -> tuple[list[RawItem], dict[str, Any]]:
    """`seen` (the source's SEEN record) switches on incremental collection; without it every parsed entry is handed
    over (tests, replays). It is updated in place only when the run succeeds — a failed run leaves it as it was."""
    st = dict(state)
    st["last_run"] = timeutil.iso(now)
    st.pop("deferred", None)          # counted afresh by this run
    try:
        resp, raws = _fetch_parse(source, st, now)
        nxt: dict[str, str] | None = None
        if seen is not None and source.parser not in NOT_INCREMENTAL:
            raws, nxt = incremental(raws, seen, now, brand_new=not state.get("last_success"))
            st["handed_over"] = len(raws)
        if source.parser == "rolie":
            raws = _csaf_reports(source, raws, now, known_item, st)
        if source.parser == "cvelist_delta":
            raws = _cve_records(source, raws, st, now, nxt)
        if source.parser == "defihacklabs":
            raws = _poc_headers(source, raws, known_item, nxt, st)
            if nxt is not None:
                st["handed_over"] = len(raws)
        if seen is not None and nxt is not None:
            # SEEN is handed back only by a run that succeeded (the caller stores it after the raw batch is written).
            # Live bug (docs/research/action/07 B3): SEEN was updated right after incremental(), so a later failure —
            # one .sol 404 — emptied the batch while the advanced SEEN was stored: those entries never came back.
            seen.clear()
            seen.update(nxt)
        st.update(etag=resp.etag or st.get("etag"), last_modified=resp.last_modified or st.get("last_modified"),
                  last_success=timeutil.iso(now), consecutive_failures=0, last_status=resp.status)
        if st.get("deferred"):
            # this run put entries off (over a per-run cap, a follow-up document unreadable). The list must be read
            # again next run — with its validators kept, an unchanged list answers 304 and the entries wait until it
            # changes, days on a quiet feed (audit 01 #1: 25 new CSAF advisories, 10 handed over)
            st.pop("etag", None)
            st.pop("last_modified", None)
    except (fetch.FetchError, ValueError, KeyError) as e:
        # keep going for other sources, but make the failure loud and distinguishable from "no news"
        st.update(last_error=str(e)[:300], last_error_at=timeutil.iso(now),
                  consecutive_failures=st.get("consecutive_failures", 0) + 1)
        raws = []
    day_ago = timeutil.iso(now - timedelta(days=1))
    st["runs"] = [r for r in st.get("runs", []) if r[0] >= day_ago] + [[timeutil.iso(now), len(raws)]]
    return raws, count_day(st, now, len(raws))


def count_day(state: dict[str, Any], now: datetime, n: int) -> dict[str, Any]:
    """Items handed over per UTC day, SOURCE_DAYS_KEPT days: the baseline `silent` is judged against (`runs` keeps
    24 hours — too short to tell a source that went quiet from one that is always quiet)."""
    days = dict(state.get("days") or {})
    day = now.strftime("%Y-%m-%d")
    days[day] = days.get(day, 0) + n
    return {**state, "days": dict(sorted(days.items())[-Limits.SOURCE_DAYS_KEPT:])}


def crashed(state: dict[str, Any], now: datetime, exc: BaseException) -> dict[str, Any]:
    """The state after a run that raised outside collect()'s own error handling (a socket error mid-read, a parser
    bug). Unrecorded, the source kept status ok with an old last_success and was retried every cycle unseen."""
    return {**state, "last_run": timeutil.iso(now), "last_error": f"crashed: {type(exc).__name__}: {exc}"[:300],
            "last_error_at": timeutil.iso(now), "consecutive_failures": state.get("consecutive_failures", 0) + 1}
