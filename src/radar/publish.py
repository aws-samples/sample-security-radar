"""Store → site-data documents (schemas/site-data.schema.json). Pure: returns {relative_path: document};
the publish handler writes them to S3."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from radar import (
    announcements,
    anomaly,
    attack_path,
    attacktx,
    awsfix,
    cluster_judge,
    coverage,
    cvemeta,
    decisions,
    duplabels,
    insights,
    latency,
    onchain,
    ops,
    respond,
    retitle,
    retitle_judge,
    rulepack,
    stages,
    stationtime,
    timeutil,
    triage,
)
from radar.limits import Limits
from radar.model import SEVERITY_ORDER, SITE_SCHEMA_VERSION, Event, Item
from radar.registry import BY_ID, SOURCES
from radar.store import Store
from radar.targets import NAMES as TARGET_NAMES


def _analysis_status(ev: Event) -> str:
    if ev.severity not in ("P0", "P1"):
        return "not_applicable" if not ev.analysis else ev.analysis["status"]
    return ev.analysis["status"] if ev.analysis else "pending"


def _public_analysis(ev: Event) -> dict[str, Any] | None:
    if not ev.analysis:
        return None
    a = {k: v for k, v in ev.analysis.items() if k not in ("input_hash", "facts")}  # cache keys are internal
    return a


def _summary(ev: Event, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    fix = (extra or {}).get("title_override")    # radar.retitle: an operator's sourced root-cause correction
    return {**(extra or {}),
        "event_id": ev.event_id, "domain": ev.domain, "title": fix["title"] if fix else ev.title, "level": ev.level,
        "level_reason": ev.level_reason, "severity": ev.severity, "exploitation": ev.exploitation,
        "first_seen": ev.first_seen, "last_updated": ev.last_updated,
        "first_report_source": ev.first_report_source, "independent_sources": ev.independent_sources,
        "item_count": len(ev.item_ids), "cves": ev.cves, "entities": ev.entities, "chains": ev.chains,
        # GitHub advisory ids (keys.ghsas): the identifier of a flaw whose CVE is still pending (Ruby2Shell 11-19)
        "ghsas": sorted({k[5:] for k in ev.keys if k.startswith("ghsa:")}),
        "amount_usd_latest": ev.amount_usd_latest, "amount_disputed": ev.amount_disputed,
        "amount_frozen_latest": ev.amount_frozen_latest, "attribution": ev.attribution,
        # attack transactions whose receipt the radar read on chain (radar.chain: verified = confirmed) — the push
        # station updates a P0 thread when this rises (R4.3)
        "tx_confirmed": sum(1 for t in ev.tx or [] if t.get("verified") == "confirmed"),
        **_summary_field(ev),
        "analysis_status": _analysis_status(ev),
    }


def _summary_field(ev: Event) -> dict[str, Any]:
    """The event summary: the first grounded BLUF sentence that does not contradict the code's fields (CVEs,
    exploitation, amount), else the code's own summary — and why a sentence was passed over (#/ops, the notice)."""
    from radar import analyst
    facts = {"cves": ev.cves, "exploitation": ev.exploitation, "amount_usd_latest": ev.amount_usd_latest,
             "amount_disputed": ev.amount_disputed}
    rejected = []
    for x in (ev.analysis or {}).get("bluf", []):
        if not x.get("grounded"):
            continue
        why = analyst.contradiction(x["text"], facts)
        if why is None:
            return {"summary": x["text"], "summary_source": "brief", **({"summary_rejected": rejected} if rejected else {})}
        rejected.append(why)
    return {"summary": ev.summary, "summary_source": "code", **({"summary_rejected": rejected} if rejected else {})}


def _cve_disclosed(ev: Event, meta: dict[str, Any]) -> dict[str, Any] | None:
    """Card-sized disclosure (cvemeta.disclosure decides): list cards and the wall drawer show 「CVE 公开 10-15」 so an event
    first reported 10-29 does not read as a 10-29 vulnerability (live 2026-11-03, CVE-2026-98432)."""
    d = cvemeta.disclosure(ev.cves, meta, ev.first_seen, ev.title) if ev.cves else None
    return {"at": d["at"], "cve": d["cve"], "resurfaced": d["resurfaced"]} if d else None


def decision_ledgers(store: Store) -> dict[str, Any]:
    """The station ledgers radar.decisions.evaluate reads (respond / mitigate / notify)."""
    return {k: store.get_source_state(v) for k, v in decisions.LEDGERS.items()}


def _response(ev: Event, store: Store, now: datetime) -> dict[str, Any] | None:
    return respond.to_response(store.get_response(ev.event_id), TARGET_NAMES, timeutil.iso(now))


def _attack_txs(ev: Event, store: Store) -> dict[str, Any] | None:
    """M4.1 E3 attack-tx breakdown; the shared token ledger is read only for events that have a decoded tx."""
    if ev.domain != "web3":
        return None
    case = store.get_source_state(attacktx.case_key(ev.event_id))
    return attacktx.doc(case, store.get_source_state(attacktx.TOKEN_KEY)) if case.get("txs") else None


def _phase(it: Item, src: Any) -> str:
    """Attack stage of one report (stages.of_title). A web3 hack-database record is the record of the theft itself — the
    asset transfer — when its title names no stage (live 2026-10-30: 105 of 141 web3 events had no phase at all, so no
    attack flow) or only the technique ("Binance — Hot Wallet Key Compromised": DeFiLlama's category, not a report of
    the key access; read as key_access the database-only incident listed 资产转出 as having no evidence)."""
    p = stages.of_title(it.title)
    db = src is not None and src.always_eventful and src.domain == "web3"
    return "asset_transfer" if db and (p == "other" or stages.before_transfer(p)) else p


def _item_ref(it: Item, group: int, at: str) -> dict[str, Any]:
    from radar.pipeline import (  # local import: pipeline imports publish-free modules only
        collected_at,
        day_precision,
    )
    src = BY_ID.get(it.source_id)
    name = src.name if src else it.source_id
    if it.source_id.startswith("x_") and it.extra.get("x_status"):
        name = f"X @{it.url.split('/')[3]}" if it.url.count("/") >= 4 else name
    return {
        "item_id": it.item_id, "source_id": it.source_id, "source_name": name, "tier": it.tier, "url": it.url,
        "title": it.title, "published_at": it.published_at, "evidence_at": at, "excerpt": it.text[: Limits.EXCERPT_MAX_CHARS],
        # when the radar captured it; equal to published_at ⇔ the source gave no date (normalize falls back to capture)
        "collected_at": collected_at(it), "published_is_collected": it.published_at == it.fetched_at,
        "date_only": day_precision(it),     # the source gave a day, not a time (DeFiLlama, KEV dateAdded)
        "independent_group": group, "phase": _phase(it, src),
        "signals": {"exploited": it.signals["exploited"], "kev": it.signals["kev"], "poc": it.signals["poc"],
                    "amount_usd": it.signals["amount_usd"]},
    }


def _cve_details(cves: list[str], items: list[Item], epss: dict[str, dict[str, float]],
                 meta: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    kev = {c: it for it in items if it.signals["kev"] for c in it.extra.get("cves") or []}
    meta = meta or {}
    return [{"cve": c, "kev": c in kev, "kev_date_added": kev[c].extra.get("kev_date_added") if c in kev else None,
             "ransomware": kev[c].extra.get("ransomware") if c in kev else None,
             "cwes": list(kev[c].extra.get("cwes") or []) if c in kev else [],   # M3: weakness class → WAF cwe tier
             "epss": epss.get(c, {}).get("epss"), "epss_percentile": epss.get(c, {}).get("percentile"),
             # CVE record (cvemeta): null = not looked up yet / lookup failed / CVE not in the CVE List
             "published_at": (meta.get(c) or {}).get("published"), "assigner": (meta.get(c) or {}).get("assigner"),
             "cvss": (meta.get(c) or {}).get("cvss"), "cvss_severity": (meta.get(c) or {}).get("severity"),
             "cvss_source": (meta.get(c) or {}).get("cvss_source"),
             # PUBLISHED / NOT_FOUND (not in the CVE List: reserved, or a mistyped id in a report) / null = not looked up
             "cve_record": (meta.get(c) or {}).get("state")}
            for c in cves]


def event_doc(ev: Event, store: Store, now: datetime, epss: dict[str, dict[str, float]] | None = None,
              titles: dict[str, str] | None = None, cve_meta: dict[str, Any] | None = None,
              ledgers: dict[str, Any] | None = None, dup_pairs: dict[str, Any] | None = None,
              aws_led: dict[str, Any] | None = None) -> dict[str, Any]:
    from radar.pipeline import (  # local import: pipeline imports publish-free modules only
        evidence_at,
        first_report,
        independent_groups,
        sighting,
    )
    items = sorted(store.get_items(ev.item_ids), key=lambda i: (i.published_at, i.source_id, i.item_id))
    meta = cve_meta if cve_meta is not None else (cvemeta.load(store) if ev.cves else {})
    groups = independent_groups(items)
    vel = insights.velocity(ev, items, now)
    resp = _response(ev, store, now)
    # 「响应决策」: every action of the radar.decisions table, for EVERY event — one with no response state (a P2, an
    # incident the station never takes) still gets its E_* / notify / WAF rows; read the ledgers once per publish
    dec = decisions.evaluate(
        {"event_id": ev.event_id, "domain": ev.domain, "severity": ev.severity, "exploitation": ev.exploitation,
         "last_updated": ev.last_updated, "title": ev.title, "level_reason": ev.level_reason},
        store.get_response(ev.event_id), ledgers if ledgers is not None else decision_ledgers(store), now, resp)
    chain = _chain(ev, store)
    return {
        "kind": "event", "generated_at": timeutil.iso(now),
        "event": _summary(ev, {"triage": triage.public(store.get_source_state(triage.KEY).get(ev.event_id)),
                               "title_override": retitle.public(store.get_source_state(retitle.KEY).get(ev.event_id), ev.title),
                               "velocity_6h": vel, "lifecycle": insights.lifecycle(ev, vel, now),
                               "impact": respond.impact(resp), "cve_disclosed": _cve_disclosed(ev, meta)}),
        "analysis": _public_analysis(ev),
        "response": resp,
        "decisions": dec,
        "mitigation": _mitigation(store, ev.event_id),   # M3: WAF / DNS plans + their live state (mitigate station)
        # P2: the event's WAF rule pack + its five renderings (row written by the mitigate station; one read per page)
        "rule_pack": rulepack.public(store.get_source_state(rulepack.key(ev.event_id))),
        # C4: model-judged "same incident" pairs (advisory, never merged); titles only for events still published
        "possible_duplicates": cluster_judge.possible_duplicates(
            ev.event_id, dup_pairs if dup_pairs is not None else cluster_judge.load(store, "__cluster_judge__"),
            titles or {ev.event_id: ev.title},
            store.get_source_state(duplabels.KEY)),
        # stage 0 for a CVE event: when the vulnerability was published (else a 10-29 first report reads as a 10-29 bug)
        "progress": ([{"stage": "disclosed", "at": disc["at"]}] if (disc := cvemeta.disclosure(ev.cves, meta, ev.first_seen, ev.title))
                     else []) + insights.progress(ev, items, now),
        "pipeline_steps": insights.pipeline_steps(ev, items, resp),
        # evidence_at: where an item sits on a timeline (a date-only entry never before the first report) — the UI
        # draws with it and never re-decides that ambiguity
        "items": [_item_ref(it, g, evidence_at(it, first_report(items))) for it, g in zip(items, groups)],
        "timeline": ev.timeline, "amount_history": ev.amount_history,
        "cve_details": _cve_details(ev.cves, items, epss or {}, meta),
        # AWS's own fix status (radar.awsfix; Neo 2026-11-18: highlight it when AWS has fixed it) — vulnerability events
        "aws_fix": (fix := awsfix.for_event(ev.cves, aws_led if aws_led is not None else awsfix.load(store))
                    if ev.domain == "vuln" and ev.cves else None),
        # R9.5: how it is attacked and where each defence stops it (radar.attack_path; vulnerability P0 / P1)
        "attack_path": attack_path.public(store.get_source_state(attack_path.key(ev.event_id)) if ev.domain == "vuln" else None,
                                          rule_pack=bool(store.get_source_state(rulepack.key(ev.event_id))),
                                          aws_fix_line=(fix or {}).get("line")),
        # when the world knew (CVE record published) vs when the radar knew (first_seen) — see cvemeta.disclosure
        "disclosure": cvemeta.disclosure(ev.cves, meta, ev.first_seen, ev.title),
        # first report published (by its source) vs the radar's first capture — pipeline.sighting decides
        "sighting": sighting(items),
        "tx": [{"chain": t["chain"], "hash": t["hash"], "explorer_url": t.get("explorer_url"),
                "verified": t.get("verified", "unchecked"),
                **({"block": t["block"]} if t.get("block") is not None else {}),
                **({"checked_at": t["checked_at"]} if t.get("checked_at") else {})} for t in ev.tx],
        # M4 D6: minute-level on-chain reconstruction (web3 only — one ledger read per web3 event doc)
        "onchain": chain["onchain"],
        "attack_txs": chain["attack_txs"],
        # P1b: what those chain rows confirm per attack stage (stages.chain_evidence decides; the UI only draws it)
        "chain_stages": chain["stages"],
    }


def _chain(ev: Event, store: Store) -> dict[str, Any]:
    """The event's on-chain sections and the stage evidence they carry (one onchain case read, web3 only)."""
    case = store.get_source_state(onchain.case_key(ev.event_id)) if ev.domain == "web3" else None
    oc, atx = onchain.doc(case), _attack_txs(ev, store)
    return {"onchain": oc, "attack_txs": atx, "stages": stages.chain_evidence(oc, onchain.victim_set(case), atx)}


def select_listing(window: list[Event], day: str) -> list[Event]:
    """The PUBLISH_MAX_EVENTS events the live pages list, in their order: severity, then newest inside it — so what
    changed today leads each severity. Severity always wins across levels: a P0 or P1 is never cut to make room for
    a P2 updated today (live 2026-11-15, the first version of R3.1 did exactly that: 343 P2s updated in a day pushed
    4 of 6 P0s and 353 of 508 P1s off the page). What the cap leaves out is said on the page (window_counts) and is
    in search. `day` is unused: the order alone puts today first within a severity (kept so callers do not change)."""
    order = sorted(window, key=lambda e: e.last_updated, reverse=True)   # newest first …
    order.sort(key=lambda e: -SEVERITY_ORDER[e.severity])               # … within severity (stable sort), P0 on top
    return order[: Limits.PUBLISH_MAX_EVENTS]


def window_counts(window: list[Event], listed: int) -> dict[str, Any]:
    """How many events the window holds and how many the page lists — said on the page, so a cut list is never read as
    the whole (audit 03 6.2). The rest is in search (data/search)."""
    sev, dom = Counter(e.severity for e in window), Counter(e.domain for e in window)
    return {"days": Limits.PUBLISH_WINDOW_DAYS, "total": len(window), "listed": listed, "cap": Limits.PUBLISH_MAX_EVENTS,
            "by_severity": {k: sev.get(k, 0) for k in ("P0", "P1", "P2")},
            "by_domain": {k: dom.get(k, 0) for k in ("vuln", "web3", "incident")}}


def events_doc(store: Store, now: datetime) -> tuple[dict[str, Any], list[Event]]:
    tri = store.get_source_state(triage.KEY)
    since = timeutil.iso(now - timedelta(days=Limits.PUBLISH_WINDOW_DAYS))
    window = store.events_updated_since(since)
    day = timeutil.iso(now - timedelta(days=1))
    evs = select_listing(window, day)
    fixes = store.get_source_state(retitle.KEY)
    meta = cvemeta.load(store)
    store.get_items([i for e in evs for i in e.item_ids])          # warm the run's caches: one batched read each,
    if hasattr(store, "get_responses"):                            # not 500 + 500 serial ones (live 2026-11-11)
        store.get_responses([e.event_id for e in evs])
    rows = []
    for e in evs:
        vel = insights.velocity(e, store.get_items(e.item_ids), now)
        rows.append(_summary(e, {"triage": triage.public(tri.get(e.event_id)),
                                 "title_override": retitle.public(fixes.get(e.event_id), e.title),
                                 "velocity_6h": vel, "lifecycle": insights.lifecycle(e, vel, now),
                                 "impact": respond.impact(_response(e, store, now)),
                                 "cve_disclosed": _cve_disclosed(e, meta),
                                 **({"followup": insights.followup(store, e.event_id)} if e.domain == "web3" else {})}))
    board = insights.now_board(evs, store, now)
    states = store.get_source_states([s.source_id for s in SOURCES])
    ok = sum(1 for s in SOURCES if s.enabled and (states.get(s.source_id) or {}).get("consecutive_failures", 0) == 0
             and (states.get(s.source_id) or {}).get("last_run"))
    total = sum(1 for s in SOURCES if s.enabled)
    # counts are of the window, before the listing is cut (audit 03 6.2: the funnel's 「24 小时内有更新」 and P0 counted
    # only the 500 listed events, so they changed with the cap, not with the world)
    touched = [e for e in window if e.last_updated >= day]
    fun = insights.funnel(store.get_source_state("__funnel__").get("runs", []), events_touched=len(touched),
                          corroborated=sum(1 for e in touched if e.level in ("V2", "V3", "V4")),
                          p0=sum(1 for e in window if e.severity == "P0"), now=now)
    return {"kind": "events", "generated_at": timeutil.iso(now), "events": rows, "now": board,
            "window": window_counts(window, len(evs)),
            "headline": insights.headline(board, {e.event_id: e for e in evs}, ok, total, now), "funnel": fun,
            **_digest(store)}, evs


DIGEST_FIELDS = ("day", "generated_at", "model", "status", "reason", "header", "summary", "highlights", "watch", "event_ids")


def _digest(store: Store) -> dict[str, Any]:
    """C7: the latest daily digest as written by the analyze station (bookkeeping fields stay in the store)."""
    d = store.get_source_state("__digest__")
    return {"digest": {k: d.get(k) for k in DIGEST_FIELDS}} if d.get("day") else {}


def _status(st: dict[str, Any], enabled: bool) -> str:
    if not enabled:
        return "disabled"
    if not st.get("last_run"):
        return "never_run"
    fails = st.get("consecutive_failures", 0)
    if fails >= Limits.SOURCE_FAILING_AFTER:
        return "failing"
    return "degraded" if fails or st.get("degraded") else "ok"   # degraded: served by a fallback channel


def stalled_sources(states: dict[str, dict[str, Any]], now: datetime) -> list[dict[str, Any]]:
    """Enabled sources that are not being collected (overdue) or stopped producing (silent). `_status` cannot see
    either: both look ok. Silent needs SOURCE_SILENT_BASELINE_DAYS of per-day counts before the quiet days, so nothing
    is reported for a source until it has that history."""
    import statistics
    out = []
    for s in SOURCES:
        st = states.get(s.source_id) or {}
        last = timeutil.parse(st.get("last_run"))
        if not s.enabled or last is None:
            continue
        idle = round((now - last).total_seconds() / 60)
        # the interval the source actually runs at (R2.5: backed off while failing — source_unhealthy reports that);
        # a server-requested hold (Retry-After) is not "overdue" either
        from radar.collect import cadence
        hold = timeutil.parse(st.get("retry_after_until"))
        if hold is not None and now < hold:
            continue
        limit = max(Limits.SOURCE_OVERDUE_CADENCES * cadence(s, st), Limits.SOURCE_OVERDUE_MIN_MINUTES)
        if idle > limit:
            out.append({"source_id": s.source_id, "name": s.name, "kind": "overdue", "minutes": idle, "limit_min": limit})
            continue
        days = st.get("days") or {}
        day = lambda d: (now - timedelta(days=d)).strftime("%Y-%m-%d")
        quiet = range(Limits.SOURCE_SILENT_DAYS)
        base = [days[day(d)] for d in range(Limits.SOURCE_SILENT_DAYS, Limits.SOURCE_SILENT_DAYS + Limits.SOURCE_SILENT_BASELINE_DAYS)
                if day(d) in days]
        if len(base) == Limits.SOURCE_SILENT_BASELINE_DAYS and statistics.median(base) >= 1 \
                and not any(days.get(day(d)) for d in quiet):
            out.append({"source_id": s.source_id, "name": s.name, "kind": "silent", "days": Limits.SOURCE_SILENT_DAYS,
                        "usual_per_day": round(statistics.median(base))})
    return out


def sources_doc(store: Store, now: datetime) -> dict[str, Any]:
    day_ago = timeutil.iso(now - timedelta(days=1))
    rows = []
    states = store.get_source_states([s.source_id for s in SOURCES])    # one batch read, not 167 GetItems
    for s in SOURCES:
        st = states.get(s.source_id) or {}
        rows.append({
            "source_id": s.source_id, "name": s.name, "tier": s.tier, "domain": s.domain or "incident",
            "cadence_min": s.cadence_min, "enabled": s.enabled, "status": _status(st, s.enabled),
            "last_success": st.get("last_success"), "last_error": st.get("last_error"),
            "last_error_at": st.get("last_error_at"), "degraded": st.get("degraded"),
            "items_24h": sum(n for ts, n in st.get("runs", []) if ts >= day_ago),
        })
    return {"kind": "sources", "generated_at": timeutil.iso(now), "sources": rows}


def continuum_doc(store: Store, now: datetime, evs: list[Event]) -> dict[str, Any]:
    """Overview of the AWS Continuum / Security Agent integration, from the respond ledger + responses."""
    led = store.get_source_state("__continuum__")
    recent, patch_paths, issue_ids = [], set(), set()
    for e in evs:
        r = _response(e, store, now)
        if r and r["status"] != "not_eligible":
            patch_paths |= {p["path"] for p in r["patches"]}
            issue_ids |= {i["issue_id"] for i in r["issues"]}
            imp = respond.impact(r) or {"status": "queued", "affected": 0, "checked": 0}  # r is truthy: never None
            # impact = the same authority as the event page / listing chip; status alone ('done') made the UI
            # render a target nobody checked as 未命中 0/N (live Node2Shell × security-radar, 2026-11-11)
            recent.append({"event_id": e.event_id, "title": e.title, "severity": e.severity, "status": r["status"],
                           "impact": imp["status"], "affected": imp["affected"], "checked": imp["checked"],
                           "updated_at": r["updated_at"]})
    c = led.get("counters") or {}
    day = timeutil.iso(now - timedelta(days=1))
    return {"kind": "continuum", "generated_at": timeutil.iso(now), "resources": led.get("resources") or [],
            "targets": led.get("targets") or [], "coverage": coverage.rows(led), "recent": recent[:50],
            "ledger": {"code_reviews_total": int(c.get("code_reviews_started", 0)),
                       "code_reviews_24h": sum(1 for t in led.get("reviews", []) if t >= day),
                       "scans_total": int(c.get("scans_requested", 0)),
                       "findings_submitted": int(c.get("findings_submitted", 0)),
                       # counted from the responses themselves (ledger counters only prove liveness and
                       # double-count when a finished review is re-read)
                       "issues": len(issue_ids), "patches": len(patch_paths),
                       # R4: per-day spend from Cost Explorer (null until the first read; error kept visible)
                       "cost": ({**led["cost"], "error": (led.get("cost_error") or {}).get("error")}
                                if led.get("cost") else None)}}


def _splits(store: Store, now: datetime, evs: list[Event] | None = None) -> list[dict[str, str]]:
    from radar.pipeline import split_candidates  # local import: pipeline imports publish-free modules only
    return split_candidates(store, now, evs)


ENRICH_KEY = "__enrich__"             # last publish run's EPSS / CVE-record health (single writer: publish)
PENDING_KEY = "__publish_pending__"   # event pages a deadline-limited publish run left for the next one (single writer)


def _amount_checks(evs: list[Event]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(outliers, shared): web3 events holding a loss figure the pipeline set aside as an outlier, and groups of
    published events carrying the same specific loss figure (amt: key) — one theft shown as several, its loss counted
    several times on the wall's ranking (live 2026-11-04: 「欧盟实体」 ×4 + SlowMist's Crédit Mutuel Arkéa)."""
    outliers = [{"event_id": e.event_id, "title": e.title, "values": sorted({p["value"] for p in e.amount_history
                                                                             if p.get("kind") == "outlier"})}
                for e in evs if e.domain == "web3" and any(p.get("kind") == "outlier" for p in e.amount_history)]
    by_amt: dict[str, list[Event]] = {}
    for e in evs:
        if e.domain == "web3":
            for k in e.keys:
                if k.startswith("amt:"):
                    by_amt.setdefault(k, []).append(e)
    shared = [{"amount": float(k[4:]), "events": [{"event_id": e.event_id, "title": e.title} for e in group]}
              for k, group in sorted(by_amt.items()) if len(group) >= 2]
    return outliers, shared


def _first_via_kev(store: Store, ev: Event) -> bool:
    """The event's first report is a KEV listing (its date marks known exploitation, not disclosure)."""
    from radar.pipeline import first_report  # local import: pipeline imports publish-free modules only
    items = store.get_items(ev.item_ids[:50])
    return bool(items) and first_report(sorted(items, key=lambda i: i.published_at)).source_id == "cisa_kev"


def _late_detections(store: Store, now: datetime, evs: list[Event]) -> list[dict[str, Any]]:
    """Recent vulnerability events whose critical CVE the radar saw LATE_DETECTION_HOURS+ after the CVE record was
    published (cvemeta ledger; CVEs not looked up yet simply do not qualify)."""
    meta = cvemeta.load(store)
    out = []
    for ev in evs:
        if ev.domain != "vuln" or not ev.cves or now - (timeutil.parse(ev.first_seen) or now) > timedelta(
                days=Limits.LATE_DETECTION_RECENT_DAYS):
            continue
        d = cvemeta.disclosure(ev.cves, meta, ev.first_seen, ev.title)
        top = max((meta[c]["cvss"] for c in ev.cves if (meta.get(c) or {}).get("cvss") is not None), default=None)
        # a resurfaced CVE (KEV listing, a years-old bug back in the news) is not a radar miss: the event is the new
        # exploitation / report, not the disclosure (live 2026-11-02: CVE-2025-39682 via KEV, 377 days after publication)
        if d and d["lag_hours"] is not None and d["lag_hours"] >= Limits.LATE_DETECTION_HOURS and top is not None \
                and top >= Limits.LATE_DETECTION_MIN_CVSS and not d["resurfaced"] and not _first_via_kev(store, ev):
            out.append({"event_id": ev.event_id, "title": ev.title, "cve": d["cve"], "cvss": top,
                        "assigner": d["assigner"], "published": d["at"], "first_seen": ev.first_seen,
                        "first_source": ev.first_report_source, "lag_days": round(d["lag_hours"] / 24)})
    return out


def ops_doc(store: Store, now: datetime, srcs: dict[str, Any], evs: list[Event]) -> dict[str, Any]:
    """D/M3: what needs a human, from state the stations already keep (radar.ops RULES)."""
    tri = store.get_source_state(triage.KEY)
    items = ops.attention({"sources": srcs["sources"], "ledger": store.get_source_state("__continuum__"),
                           "events": [{"event_id": e.event_id, "tx": e.tx, "severity": e.severity, "title": e.title,
                                       "triage": tri.get(e.event_id)} for e in evs],
                           "digest": store.get_source_state("__digest__"), "dup_labels": store.get_source_state(duplabels.KEY),
                           "splits": _splits(store, now, evs), "late": _late_detections(store, now, evs),
                           "title_proposals": store.get_source_state(retitle_judge.KEY),
                           # the judge's verdict ledger (handlers.DUP_KEY): #/ops lists its would-merge pairs (shadow mode)
                           "cluster_judge": cluster_judge.load(store, "__cluster_judge__"),
                           # handlers.JUDGE_TRUTH_KEY (restated: handlers imports the AWS SDK)
                           "judge_truth": store.get_source_state("__judge_truth__"),
                           "ghsa_alias": store.get_source_state("__ghsa_alias__"),          # radar.ghsa_alias.KEY
                           "slow_stations": stationtime.slow(stationtime.facts(store)),
                           "enrich": store.get_source_state(ENRICH_KEY), "pending": store.get_source_state(PENDING_KEY),
                           **dict(zip(("amount_outliers", "amount_shared"), _amount_checks(evs))),
                           "mitigate": store.get_source_state("__mitigate__"),
                           "notify": store.get_source_state("__notify_status__"),   # radar.notify_station.STATUS_KEY
                           "anomalies": anomaly.recent(store, now),
                           # handlers.RAW_BAD_KEY (the handlers module imports the AWS SDK; the key is restated here)
                           "raw_bad": sorted(({"key": k, **v} for k, v in store.get_source_state("__raw_bad__").items()
                                              if (v.get("at") or "") >= timeutil.iso(now - timedelta(days=1))),
                                             key=lambda r: r["at"], reverse=True),
                           # radar.dynamo.ROW_SIZES_KEY (restated: publish does not import the DynamoDB store)
                           "row_sizes": sorted(({"key": k, **v} for k, v in store.get_source_state("__row_sizes__").items()
                                                if (v.get("at") or "") >= timeutil.iso(now - timedelta(days=1))),
                                               key=lambda r: -r["bytes"]),
                           "spend": store.counts(timeutil.iso(now)[:10]),            # R5.6 paid calls today
                           "latency": latency.summary(store, now),
                           "push_latency": latency.summary(store, now, latency.PUSH_KEY, latency.PUSH_HOURS),
                           "stalled_sources": stalled_sources(
                               store.get_source_states([s.source_id for s in SOURCES]), now),
                           "silent_stations": stationtime.silent(stationtime.facts(store), now)})
    return {"kind": "ops", "generated_at": timeutil.iso(now), "attention": items,
            "counts": {lv: sum(1 for i in items if i["level"] == lv) for lv in ops.LEVELS}}


def mitigate_doc(store: Store, now: datetime) -> dict[str, Any]:
    """M3: radar-owned web ACLs, per-target Inspector dependency baseline, and what the station could not check."""
    from radar.mitigate import MITIGATION_NOTE
    from radar.targets import NAMES
    led = store.get_source_state("__mitigate__")
    insp = led.get("inspector") or {}
    return {"kind": "mitigate", "generated_at": timeutil.iso(now), "note": MITIGATION_NOTE, "run_at": led.get("run_at"),
            "web_acls": led.get("web_acls") or [], "errors": led.get("errors") or [], "applied": led.get("applied") or [],
            "dns": led.get("dns"),
            "inspector": [{"target_id": t, "state": (insp.get(t) or {}).get("state", "never"),
                           "components": (insp.get(t) or {}).get("components", 0),
                           "scanned_on": (insp.get(t) or {}).get("scanned_on"),
                           "findings": (insp.get(t) or {}).get("findings") or []} for t in NAMES]}


def _mitigation(store: Store, event_id: str) -> dict[str, Any] | None:
    return (store.get_source_state("__mitigate__").get("events") or {}).get(event_id)


def build(store: Store, now: datetime, changed: set[str] | None = None,
          epss: dict[str, dict[str, float]] | None = None,
          enrich: Callable[[list[str]], Any] | None = None,
          aws_fix: Callable[[list[str]], set[str]] | None = None,
          time_left: Callable[[], float] | None = None, deferred: list[str] | None = None,
          timings: dict[str, float] | None = None) -> dict[str, dict[str, Any]]:
    """changed=None ⇒ every listed event gets a detail doc (first publish / full rebuild).
    enrich(cves) ⇒ EPSS for every published CVE, or (EPSS, touched): pages carrying a touched CVE (record or EPSS changed
    this run, radar.enrich) are rebuilt even when their event did not change.
    Live 2026-11-02: the caller used to collect those CVEs from `changed`, so a full rebuild (changed=None) asked for
    none and blanked EPSS on every event page.
    time_left() ⇒ seconds this invocation still has: detail docs are built most-severe / most-recent first and the
    rest is appended to `deferred` once fewer than Limits.PUBLISH_RESERVE_S remain (the caller carries them to the next
    run) — a slow page delays other pages by one cycle instead of failing the whole cycle (live 2026-11-02: 300 s)."""
    import time
    tm = timings if timings is not None else {}
    t0 = [time.monotonic()]

    def mark(phase: str) -> None:       # seconds per phase, read by the station's timeout watchdog and its last log
        t = time.monotonic()
        tm[phase] = round(tm.get(phase, 0.0) + t - t0[0], 1)
        t0[0] = t
    listing, evs = events_doc(store, now)
    mark("listing")
    touched: set[str] = set()
    if enrich is not None:      # before ops.json: late_detection reads the CVE records this refresh just filled
        # every published CVE (not only the changed pages'): a score that arrives later must reach its page
        got = enrich(sorted({c for ev in evs for c in ev.cves}))
        epss, touched = got if isinstance(got, tuple) else (got, set())
    if aws_fix is not None:     # Amazon Linux Security Center, for P0 / P1 vulnerability CVEs only (radar.awsfix)
        hot = sorted((ev for ev in evs if ev.domain == "vuln" and ev.severity in ("P0", "P1")),
                     key=lambda ev: (-SEVERITY_ORDER[ev.severity], ev.first_seen))
        touched |= aws_fix(list(dict.fromkeys(c for ev in hot for c in ev.cves)))     # P0 CVEs first
    mark("enrich")
    if touched:     # the listing was built before this refresh: rebuild it so cards carry the new CVE dates
        listing, evs = events_doc(store, now)
        mark("listing")
    detail = [ev for ev in evs if changed is None or ev.event_id in changed or set(ev.cves) & touched]
    srcs = sources_doc(store, now)
    # status.json: the site-wide freshness beacon (R3.3) — a few bytes every page polls instead of the 400 KB listing
    docs: dict[str, dict[str, Any]] = {"status.json": {"kind": "status", "generated_at": timeutil.iso(now)},
                                       "events.json": listing, "sources.json": srcs,
                                       "continuum.json": continuum_doc(store, now, evs), "ops.json": ops_doc(store, now, srcs, evs),
                                       "mitigate.json": mitigate_doc(store, now),
                                       "announcements.json": announcements.board_doc(
                                           store.get_source_state(announcements.BOARD_KEY), BY_ID, timeutil.iso(now))}
    mark("side_docs")
    titles = {e.event_id: e.title for e in evs}
    meta = cvemeta.load(store)
    aws_led = awsfix.load(store)
    ledgers = decision_ledgers(store)
    detail.sort(key=lambda e: (-SEVERITY_ORDER[e.severity], -(timeutil.parse(e.last_updated) or now).timestamp()))
    dup_pairs = cluster_judge.load(store, "__cluster_judge__")      # once per build, not 17 reads per page
    for k, ev in enumerate(detail):
        if time_left is not None and time_left() < Limits.PUBLISH_RESERVE_S:
            if deferred is not None:
                deferred.extend(e.event_id for e in detail[k:])
            break
        docs[f"events/{ev.event_id}.json"] = event_doc(ev, store, now, epss, titles, meta, ledgers, dup_pairs=dup_pairs,
                                                       aws_led=aws_led)
        tm["pages_done"] = k + 1
    mark("pages")
    return {path: {**doc, "schema_version": SITE_SCHEMA_VERSION} for path, doc in docs.items()}   # every root document
