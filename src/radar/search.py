"""Static search index: every event ever published stays findable (docs/research/19 P2, B7).

Why: the site publishes the 60-day window, top 500 — with 214 sources that is a few percent of the events, and an
event older than 60 days had no entry point at all. Publish now also writes data/search/<yyyy-mm>.json (one compact
row per event, by the month of first_seen) and data/search/index.json; the UI loads months lazily and searches in the
browser. Zero standing cost (site bucket objects), no search cluster.

A month shard is merged, never rebuilt from the window alone: the window holds only recently updated events, and a
month's older events must survive (upsert by event id). Pure functions; the station does the S3 reads and writes.
"""
from __future__ import annotations

from collections.abc import Collection
from typing import Any

from radar.limits import Limits
from radar.model import SITE_SCHEMA_VERSION, Event

KIND_SHARD, KIND_INDEX = "search-shard", "search-index"


def record(ev: Event, published: bool = False, title: str | None = None) -> dict[str, Any]:
    """published ⇒ "p": true — Publish wrote this event's detail doc (events/<id>.json), so the UI may link to it.
    Absent, not false, otherwise: most rows have no page and the shards are downloaded whole.
    title: the title the site shows (an operator's radar.retitle fix), so a search finds what the page says."""
    row = {"id": ev.event_id, "t": (title or ev.title)[:200], "d": ev.domain, "s": ev.severity, "l": ev.level,
           "f": ev.first_seen[:10], "u": ev.last_updated[:10], "c": ev.cves[:10], "e": ev.entities[:6],
           "a": ev.amount_usd_latest}
    if published:
        row["p"] = True
    return row


def source_url(url: str | None) -> str | None:
    """A row's "r": http(s) only and ≤ 300 characters (the schema's rule) — anything else is no link, not a broken one."""
    u = (url or "").strip()
    return u if u.lower().startswith(("https://", "http://")) and len(u) <= 300 else None


def first_item_id(ev: Event) -> str | None:
    """The item that created the event (its timeline's `created` entry), else its first item id."""
    return next((t.get("item_id") for t in ev.timeline or [] if t.get("kind") == "created" and t.get("item_id")),
                (ev.item_ids or [None])[0])


def month(ev: Event) -> str:
    return ev.first_seen[:7]


def shards(events: list[Event], published: Collection[str] = (),
           titles: dict[str, str] | None = None) -> dict[str, list[dict[str, Any]]]:
    """published = ids whose detail doc this run wrote (handlers.publish_site: the events/<id>.json keys);
    titles = display titles by id (radar.retitle), where they differ from ev.title."""
    out: dict[str, list[dict[str, Any]]] = {}
    for ev in events:
        out.setdefault(month(ev), []).append(record(ev, ev.event_id in published, (titles or {}).get(ev.event_id)))
    return out


def merge(existing: list[dict[str, Any]], fresh: list[dict[str, Any]],
          drop: Collection[str] = ()) -> list[dict[str, Any]]:
    """Upsert by id — a month's events not in this window are kept as they were — minus `drop`: events that no longer
    exist (merged, or removed by a repair; radar.removals), whose detail page publish deletes too.
    The "p" mark is sticky: an event's detail doc stays while the event exists, and an incremental publish rewrites only
    the changed events' pages — an unchanged event whose page an earlier run wrote still has it. "r" (source URL) is
    sticky too, so publish reads an item only for a row that never had one (handlers._publish_search); a row with a
    page does not carry it over (the page links its sources)."""
    by_id = {r["id"]: r for r in existing if r["id"] not in drop}
    for r in fresh:
        was = by_id.get(r["id"]) or {}
        row = {**r, "p": True} if was.get("p") else dict(r)
        if not row.get("p") and "r" not in row and was.get("r"):
            row["r"] = was["r"]
        by_id[r["id"]] = row
    return sorted(by_id.values(), key=lambda r: (r["f"], r["id"]), reverse=True)


def shard_doc(m: str, rows: list[dict[str, Any]], now_iso: str) -> dict[str, Any]:
    return {"kind": KIND_SHARD, "schema_version": SITE_SCHEMA_VERSION, "generated_at": now_iso, "month": m, "events": rows}


def index_doc(counts: dict[str, int], now_iso: str) -> dict[str, Any]:
    """detail_cap: how many of the window's events get a detail doc — the UI's 「未进入发布的前 N 条」 reads it from
    here, so the cap has one source (Limits.PUBLISH_MAX_EVENTS) and no copy in the UI."""
    months = sorted(counts, reverse=True)
    return {"kind": KIND_INDEX, "schema_version": SITE_SCHEMA_VERSION, "generated_at": now_iso, "months": [{"month": m, "events": counts[m]} for m in months],
            "total": sum(counts.values()), "detail_cap": Limits.PUBLISH_MAX_EVENTS}
