"""Move one report from an event to another — the repair that did not exist (roadmap R1.2, audit 02 Q5).

Merging two events and re-clustering a whole domain were the only repairs; a single report in the wrong event (a
Mercado follow-up on the Binance page) could only be fixed by changing a rule and replaying everything. This module
moves it, with three guarantees:

- both events are recomputed from the reports they now hold;
- an event's keys are exactly the keys its reports contribute (pipeline.indexed_keys) — the keys the moved report
  lent its old event leave with it, index rows included, so the next report of that story no longer finds the old event;
- the report is pinned (item.extra["event_pin"]): a later revision of it, or a replay, attaches it to the pinned event
  (pipeline.attach), not to wherever the rules would send it.

Run between cycles (scripts/move_item.py refuses while one is running) and follow with a full publish.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from radar import keys, pipeline, removals, respond, timeutil
from radar.model import Event, Item
from radar.store import Store

PIN = "event_pin"


class MoveError(ValueError):
    def __init__(self, error: str, message: str, actual: Any, limit: Any) -> None:
        super().__init__(f"{error}: {message} (actual {actual!r}, expected {limit!r})")
        self.detail = {"error": error, "message": message, "actual": actual, "limit": limit}


def event_keys(items: list[Item]) -> list[str]:
    return sorted({k for i in items for k in pipeline.indexed_keys(i)})


def _rewrite(store: Store, ev: Event, was: Event | None, item_ids: list[str], now: datetime, moved: str) -> Event:
    """The event as its reports now make it; index rows follow the keys (stale ones dropped, new ones added)."""
    at = timeutil.iso(now)
    items = store.get_items(item_ids)
    new = pipeline.recompute(Event.from_dict(ev.to_dict()), items, now)
    new.keys = event_keys(items)
    new.timeline = sorted([*(was.timeline if was else []), *pipeline._timeline_diff(was, new, at, moved),
                           {"at": at, "kind": "repaired", "from": None, "to": new.level, "item_id": moved}],
                          key=lambda t: t["at"])
    store.put_event(new)
    store.remove_keys(new.event_id, sorted(set(was.keys if was else []) - set(new.keys)))
    store.add_keys(new.event_id, new.keys)
    return new


def move_item(store: Store, item_id: str, src_id: str, dst_id: str | None, now: datetime) -> dict[str, Any]:
    """dst_id None = the report opens an event of its own. Returns {"from", "to", "removed"} (removed: the source
    event held nothing else and is gone; its respond state and its site pages follow the report)."""
    item, src = store.get_item(item_id), store.get_event(src_id)
    if item is None or src is None or item_id not in src.item_ids:
        raise MoveError("item_not_in_event", "the report is not held by the source event", item_id, src_id)
    if dst_id == src_id:
        raise MoveError("same_event", "source and destination are the same event", dst_id, "another event, or none")
    dst = store.get_event(dst_id) if dst_id else None
    if dst_id and dst is None:
        raise MoveError("destination_missing", "the destination event does not exist", dst_id, "an existing event id")
    if dst is None:
        seed = next((k for k in item.keys if k.startswith(pipeline._STRONG[:4])), item.item_id)
        dst_id, salt = keys.event_id(f"{seed}#moved"), item.item_id
        while store.get_event(dst_id) is not None:
            dst_id, salt = keys.event_id(f"{seed}#moved#{salt}"), salt + "#"
        dst = Event(event_id=dst_id, domain=item.domain, title=item.title, first_seen=item.published_at,
                    last_updated=item.published_at, item_ids=[], keys=[])
    at = timeutil.iso(now)
    item.extra = {**item.extra, PIN: dst.event_id}
    store.put_item(item)
    rest = [i for i in src.item_ids if i != item_id]
    if rest:
        _rewrite(store, src, src, rest, now, item_id)
    else:
        if (gone := store.get_response(src_id)) is not None:
            store.put_response(dst.event_id, respond.merge_states(dst.event_id, store.get_response(dst.event_id), src_id, gone))
            store.delete_response(src_id)
        store.delete_event(src_id)
        store.remove_keys(src_id, src.keys)
        removals.record(store, [(src_id, src.first_seen[:7], dst.event_id)], at)
    _rewrite(store, dst, store.get_event(dst.event_id), [*dst.item_ids, item_id], now, item_id)
    return {"from": src_id, "to": dst.event_id, "removed": not rest}


class _Without:
    """The store as it would answer if one report had not lent its event any key: the event is found only through
    keys its OTHER reports contribute. Without this every report finds its own event through its own index rows."""

    def __init__(self, store: Store, event_id: str, solo: set[str]) -> None:
        self._store, self._eid, self._solo = store, event_id, solo

    def event_ids_for_key(self, key: str) -> list[str]:
        return [e for e in self._store.event_ids_for_key(key) if not (e == self._eid and key in self._solo)]

    def __getattr__(self, name: str) -> Any:
        return getattr(self._store, name)


def misplaced_candidates(store: Store, evs: list[Event], limit: int = 200) -> list[dict[str, Any]]:
    """Reports the CURRENT rules would not put where they sit: asked where it belongs when its event is known only
    through its other reports (find_events), the answer is another event ("elsewhere") or none ("rejected": nothing
    the other reports say attaches it). Pinned reports are a human's decision and are skipped. One index read per key
    per report — a repair tool's query, not a per-cycle check. `limit` caps the list, and the result says so (never a
    silent truncation)."""
    out: list[dict[str, Any]] = []
    for ev in sorted(evs, key=lambda e: (-len(e.item_ids), e.event_id)):
        if len(ev.item_ids) < 2:
            continue
        items = store.get_items(ev.item_ids)
        holders: dict[str, int] = {}
        for it in items:
            for k in set(pipeline.indexed_keys(it)):
                holders[k] = holders.get(k, 0) + 1
        for it in items:
            if it.extra.get(PIN):
                continue
            solo = {k for k in pipeline.indexed_keys(it) if holders[k] == 1}
            best, _ = pipeline.find_events(it, _Without(store, ev.event_id, solo))  # type: ignore[arg-type]
            if best == ev.event_id or (best is None and not it.eventful):
                continue
            if len(out) >= limit:
                out.append({"truncated": True, "limit": limit})
                return out
            out.append({"item_id": it.item_id, "title": it.title, "event_id": ev.event_id, "event_title": ev.title,
                        "kind": "elsewhere" if best else "rejected", "to": best})
    return out
