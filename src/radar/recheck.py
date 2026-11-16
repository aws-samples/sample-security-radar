"""What would the CURRENT rules make of the events already stored? (roadmap R8.1)

A rule change is tested on fixtures, and three times in one week the fixtures were green while the stored events
would have changed in ways nobody intended (17 events lost or gained "exploited"; a real claim beyond the stored
text; a headline CVE in a report without cve: keys) — each found only by recomputing the live events by hand.
`diff` is that recompute as a function: read-only, every derived field, one row per changed event.

It is the comparison pipeline.refresh makes, without the write. Age-driven changes (V4 finalization) are applied by
the hourly refresh, so what is left here is what the code change does.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from radar import pipeline, timeutil
from radar.model import Event
from radar.store import Store

# the fields a reader acts on, in the order a report lists them
FIELDS = ("severity", "level", "exploitation", "amount_usd_latest", "title", "cves", "entities", "attribution")


def diff(store: Store, now: datetime, since_days: int, domain: str | None = None) -> dict[str, Any]:
    since = timeutil.iso(now - timedelta(days=since_days))
    changed: list[dict[str, Any]] = []
    seen = skipped = 0
    for ev in store.events_updated_since(since):
        if domain and ev.domain != domain:
            continue
        items = store.get_items(ev.item_ids)
        if not items:
            skipped += 1                       # an event whose reports are gone cannot be recomputed: said, not counted
            continue
        seen += 1
        before = Event.from_dict(ev.to_dict())
        after = pipeline.recompute(Event.from_dict(ev.to_dict()), items, now)
        fields = {f: [getattr(before, f), getattr(after, f)] for f in FIELDS if getattr(before, f) != getattr(after, f)}
        if fields:
            changed.append({"event_id": ev.event_id, "domain": ev.domain, "items": len(items), "title": before.title,
                            "fields": fields})
    rank = {"P0": 0, "P1": 1, "P2": 2}
    changed.sort(key=lambda c: (min(rank.get(s, 3) for s in c["fields"].get("severity", [c["title"]]) if s in rank)
                                if "severity" in c["fields"] else 3, -c["items"], c["event_id"]))
    return {"events": seen, "unchanged": seen - len(changed), "changed": changed, "not_recomputable": skipped,
            "since_days": since_days, "at": timeutil.iso(now)}


def summary(report: dict[str, Any], limit: int = 40) -> str:
    lines = [f"{report['events']} events recomputed · {report['unchanged']} unchanged · {len(report['changed'])} changed"
             + (f" · {report['not_recomputable']} without reports (skipped)" if report["not_recomputable"] else "")]
    for c in report["changed"][:limit]:
        what = " · ".join(f"{f}: {_short(a)} → {_short(b)}" for f, (a, b) in c["fields"].items())
        lines.append(f"  {c['event_id']} [{c['domain']}, {c['items']} reports] {c['title'][:60]}\n      {what}")
    if len(report["changed"]) > limit:
        lines.append(f"  … {len(report['changed']) - limit} more (all of them are in the JSON report)")
    return "\n".join(lines)


def _short(v: Any) -> str:
    s = str(v)
    return s if len(s) <= 48 else s[:45] + "…"
