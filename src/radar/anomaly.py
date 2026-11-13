"""An event that changes shape within one cycle is reported, whatever caused it (roadmap R0.1).

Live 2026-11-12 03:58Z: one newsletter's links merged the Binance theft (540 reports) into a vulnerability event — the
site's top event was a 703-item "P0 vuln" for eleven hours and nothing said so. Clustering rules fix causes one at a
time; this compares each touched event with what it was at the start of the cycle and with the events it absorbed.

Pure: `scan` takes snapshots and returns rows; the process station records them (`record`), #/ops shows the fresh ones
(`recent`, rule event_anomaly), and the owner gets them through the ops push. No rule here changes an event.
"""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from radar import timeutil
from radar.limits import Limits
from radar.model import Event

KEY = "__event_anomalies__"


def snap(ev: Event) -> dict[str, Any]:
    """What `scan` compares — small, so a cycle keeps one per touched event."""
    return {"event_id": ev.event_id, "domain": ev.domain, "items": len(ev.item_ids), "cves": len(ev.cves),
            "loss": ev.amount_usd_latest, "title": ev.title}


def _row(kind: str, level: str, ev: Event, at: str, actual: str, limit: str, message: str, **more: Any) -> dict[str, Any]:
    return {"kind": kind, "level": level, "event_id": ev.event_id, "title": ev.title[:120], "at": at,
            "actual": actual, "limit": limit, "message": message, **more}


def scan(before: dict[str, dict[str, Any]], absorbed: dict[str, list[dict[str, Any]]],
         get_event: Callable[[str], Event | None], at: str) -> list[dict[str, Any]]:
    """before: snapshot of each touched event as the cycle found it (absent = created this cycle);
    absorbed: snapshots of the events merged into it this cycle. One row per (event, kind)."""
    out: list[dict[str, Any]] = []
    for eid in sorted(set(before) | set(absorbed)):
        ev = get_event(eid)
        if ev is None:           # absorbed in turn later in the cycle: its survivor carries the report
            continue
        for a in absorbed.get(eid, []):
            if a["domain"] != ev.domain:
                out.append(_row("absorbed_other_domain", "error", ev, at, f"{a['domain']} → {ev.domain}", "same domain",
                                f"absorbed a {a['domain']} event ({a['items']} reports): {a['title'][:80]}",
                                absorbed=a["event_id"]))
            if a["items"] >= Limits.ANOMALY_ABSORBED_ITEMS:
                out.append(_row("absorbed_large_event", "error", ev, at, f"{a['items']} reports",
                                f"< {Limits.ANOMALY_ABSORBED_ITEMS}",
                                f"absorbed an established event: {a['title'][:80]}", absorbed=a["event_id"]))
        b = before.get(eid)
        if b is None:
            continue
        n, m = b["items"], len(ev.item_ids)
        jumped = m - n >= Limits.ANOMALY_ITEMS_ADDED or (n >= Limits.ANOMALY_GROWTH_MIN_ITEMS and m >= 2 * n)
        # an absorbed large event already explains the growth: one row for one cause
        if jumped and not any(r["event_id"] == eid and r["kind"] == "absorbed_large_event" for r in out):
            out.append(_row("items_jump", "warn", ev, at, f"{n} → {m}", f"+{Limits.ANOMALY_ITEMS_ADDED}",
                            "reports grew sharply in one cycle"))
        if len(ev.cves) - b["cves"] >= Limits.ANOMALY_CVES_ADDED:
            out.append(_row("cves_jump", "warn", ev, at, f"{b['cves']} → {len(ev.cves)}", f"+{Limits.ANOMALY_CVES_ADDED}",
                            "CVEs grew sharply in one cycle"))
        x, y = b["loss"], ev.amount_usd_latest
        if x and y and max(x, y) / min(x, y) >= Limits.ANOMALY_LOSS_RATIO:
            out.append(_row("loss_changed", "error", ev, at, f"${x:,.0f} → ${y:,.0f}", f"×{Limits.ANOMALY_LOSS_RATIO}",
                            "headline loss changed by an order of magnitude in one cycle"))
    return out


def record(store: Any, found: list[dict[str, Any]], now: datetime) -> None:
    """Append this cycle's rows; keep the newest ANOMALY_MAX and nothing older than the show window."""
    if not found:
        return
    floor = timeutil.iso(now - timedelta(hours=Limits.ANOMALY_SHOW_HOURS))
    rows = [r for r in (store.get_source_state(KEY).get("rows") or []) if r.get("at", "") >= floor] + found
    store.put_source_state(KEY, {"rows": sorted(rows, key=lambda r: r["at"])[-Limits.ANOMALY_MAX:]})


def recent(store: Any, now: datetime) -> list[dict[str, Any]]:
    floor = timeutil.iso(now - timedelta(hours=Limits.ANOMALY_SHOW_HOURS))
    return [r for r in (store.get_source_state(KEY).get("rows") or []) if r.get("at", "") >= floor]
