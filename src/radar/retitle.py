"""Root-cause title correction, set by an operator with their own AWS IAM credentials (scripts/retitle.py) — no web
write surface, like radar.triage.

Why it exists: an event is named by the first structured record captured, and a later record never renames it — that
guard stops a hypothesis ("may involve …") from rewriting the title (live 2026-10-30). Its price is that a title stays
wrong once the cause becomes clear (live 2026-11-02: "Binance CEX — Key Leaked via Infrastructure" while Binance stated
there is no evidence of any wallet private key leak). The correction must cite a source; the page shows it as a
correction and keeps the original. Concurrency as triage: the CLI writes KEY only, the process station SEEN_KEY only.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from radar import timeutil

KEY = "__retitle__"
SEEN_KEY = "__retitle_seen__"
TITLE_MAX = 160
NOTE_MAX = 280
_EVENT_ID = re.compile(r"ev_[0-9a-f]{16}")
_SOURCE = re.compile(r"https://[^\s<>\"']{4,500}")


class RetitleError(ValueError):
    def __init__(self, error: str, message: str, actual: Any, limit: Any) -> None:
        super().__init__(message)
        self.detail = {"error": error, "message": message, "actual": actual, "limit": limit}


def set_title(store: Any, event_id: str, title: str, source: str, note: str, by: str, now: datetime) -> dict[str, Any]:
    if not _EVENT_ID.fullmatch(event_id or ""):
        raise RetitleError("bad_event_id", "event id must be ev_ + 16 hex", event_id, "ev_[0-9a-f]{16}")
    ev = store.get_event(event_id)
    if ev is None:
        raise RetitleError("unknown_event", "no such event in the table", event_id, "an existing event id")
    title = (title or "").strip()
    if not title or len(title) > TITLE_MAX:
        raise RetitleError("bad_title", "title must be 1–160 characters", len(title), TITLE_MAX)
    if not _SOURCE.fullmatch(source or ""):
        raise RetitleError("bad_source", "a correction must cite an https source URL", source, "https://…")
    if len(note or "") > NOTE_MAX:
        raise RetitleError("note_too_long", "note exceeds the limit", len(note), NOTE_MAX)
    idx = store.get_source_state(KEY)
    prev = idx.get(event_id)
    entry = {"title": title, "source": source, "note": (note or "").strip(), "by": by[:40], "at": timeutil.iso(now),
             **({"previous": {k: prev[k] for k in ("title", "at") if k in prev}} if prev else {})}
    store.put_source_state(KEY, {**idx, event_id: entry})
    return entry


def changed(store: Any) -> list[str]:
    """Events whose correction changed since the station last looked (then marks them seen) ⇒ republished."""
    idx, seen = store.get_source_state(KEY), store.get_source_state(SEEN_KEY)
    ids = sorted(eid for eid, e in idx.items() if isinstance(e, dict) and e.get("at") != seen.get(eid))
    if ids:
        store.put_source_state(SEEN_KEY, {**seen, **{eid: idx[eid]["at"] for eid in ids}})
    return ids


def public(entry: dict[str, Any] | None, original: str) -> dict[str, Any] | None:
    if not entry:
        return None
    return {"title": entry["title"], "original": original, "source": entry["source"], "note": entry.get("note", ""),
            "by": entry.get("by", ""), "at": entry["at"]}
