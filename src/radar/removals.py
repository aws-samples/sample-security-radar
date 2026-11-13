"""Events that stopped existing (merged into another, or removed by a recluster repair) leave the published site too.

Live 2026-11-11: the recluster repairs removed events, but their search rows (data/search/<month>.json is upserted, never
pruned) and their detail pages (data/events/<id>.json) stayed — a search for Binance still showed the hairball's title
and CVEs, and an old link still opened the pre-repair page.

Two ledgers, one writer each:
- REMOVED_KEY  (writers: the process station's merges; scripts/recluster_web3.py, which runs only while the schedule is
  paused) — {event_id: {"m": first_seen month, "to": successor event or None, "at": iso}}.
- PRUNED_KEY   (writer: the publish station) — the ids whose search row and detail page it already removed.
Both are capped (Limits.REMOVED_EVENTS_MAX), so neither row grows toward the 400 KB item limit.
"""
from __future__ import annotations

from typing import Any

from radar.limits import Limits

REMOVED_KEY = "__removed_events__"
PRUNED_KEY = "__removed_pruned__"


def record(store: Any, removed: list[tuple[str, str, str | None]], at: str) -> None:
    """removed: (event_id, first_seen month 'YYYY-MM', successor event_id or None)."""
    if not removed:
        return
    led = store.get_source_state(REMOVED_KEY)
    for eid, month, to in removed:
        led[eid] = {"m": month, "to": to, "at": at}
    keep = sorted(led.items(), key=lambda kv: kv[1].get("at") or "")[-Limits.REMOVED_EVENTS_MAX:]
    store.put_source_state(REMOVED_KEY, dict(keep))


def pending(store: Any) -> dict[str, dict[str, Any]]:
    """Removed events whose site traces the publish station has not pruned yet."""
    done = store.get_source_state(PRUNED_KEY)
    return {eid: r for eid, r in store.get_source_state(REMOVED_KEY).items() if eid not in done}


def mark_pruned(store: Any, ids: list[str], at: str) -> None:
    if not ids:
        return
    removed = store.get_source_state(REMOVED_KEY)
    done = {eid: v for eid, v in store.get_source_state(PRUNED_KEY).items() if eid in removed}   # forget what aged out
    done.update({eid: at for eid in ids})
    store.put_source_state(PRUNED_KEY, done)
