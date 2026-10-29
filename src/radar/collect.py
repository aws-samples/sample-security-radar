"""Collect station: one source → raw items + updated source state. Failures are recorded, never swallowed:
a failed source keeps its old cursor and its error is visible in sources.json."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from radar import fetch, parsers, timeutil
from radar.model import RawItem
from radar.registry import SOURCES, Source

MAX_POC_FETCHES = 10  # DeFiHackLabs .sol headers fetched per run (only for entries not seen before)


def due(states: dict[str, dict[str, Any]], now: datetime) -> list[str]:
    out = []
    for s in SOURCES:
        if not s.enabled:
            continue
        last = timeutil.parse(states.get(s.source_id, {}).get("last_run"))
        if last is None or now - last >= timedelta(minutes=s.cadence_min) - timedelta(minutes=1):
            out.append(s.source_id)
    return out


def _body(source: Source, state: dict[str, Any]) -> fetch.Response:
    if source.parser == "twitterapi":
        return fetch.Response(200, fetch.twitterapi_search(source.handles, source.cadence_min))
    if source.via == "firecrawl":
        return fetch.Response(200, fetch.firecrawl_raw(source.url))
    return fetch.http_get(source.url, etag=state.get("etag"), last_modified=state.get("last_modified"))


def collect(source: Source, state: dict[str, Any], now: datetime,
            known_item: Callable[[str, str], bool] = lambda sid, guid: False) -> tuple[list[RawItem], dict[str, Any]]:
    st = dict(state)
    st["last_run"] = timeutil.iso(now)
    try:
        resp = _body(source, st)
        raws: list[RawItem] = [] if resp.status == 304 else parsers.PARSERS[source.parser](resp.body, source.source_id)
        if resp.status == 200 and not raws and source.parser != "twitterapi":
            # a feed/DB that parses to nothing is broken (block page, format change), not "no news"
            raise fetch.FetchError("parse_empty", f"0 entries parsed from {len(resp.body)} bytes", 200, source.url)
        if source.parser == "defihacklabs":
            fetched = 0
            for r in raws:
                if fetched >= MAX_POC_FETCHES or not r.extra.get("sol_url") or known_item(source.source_id, r.guid or ""):
                    continue
                poc = parsers.defihacklabs_poc(fetch.http_get(r.extra["sol_url"]).body)
                r.extra.update(attack_tx=poc["attack_tx"], attacker_urls=poc["attacker_urls"])
                fetched += 1
        st.update(etag=resp.etag or st.get("etag"), last_modified=resp.last_modified or st.get("last_modified"),
                  last_success=timeutil.iso(now), consecutive_failures=0, last_status=resp.status)
    except (fetch.FetchError, ValueError, KeyError) as e:
        # keep going for other sources, but make the failure loud and distinguishable from "no news"
        st.update(last_error=str(e)[:300], last_error_at=timeutil.iso(now),
                  consecutive_failures=st.get("consecutive_failures", 0) + 1)
        raws = []
    day_ago = timeutil.iso(now - timedelta(days=1))
    st["runs"] = [r for r in st.get("runs", []) if r[0] >= day_ago] + [[timeutil.iso(now), len(raws)]]
    return raws, st
