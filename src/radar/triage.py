"""D (half): disposition of an event — 研判中 / 跟进中 / 已关闭 / 误报 — set by an operator, shown read-only on the site.

No public write surface (Neo 2026-10-31: decide by best practice; builder-security: a new write endpoint behind the
shared Basic Auth would be invented auth). The operator writes with `scripts/triage.py` using their own AWS IAM
credentials straight to the table; the site only reads. Concurrency: the CLI writes only KEY, the process station
writes only SEEN_KEY, so neither overwrites the other; the station republishes the events whose entry changed.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from radar import timeutil

KEY = "__triage__"
SEEN_KEY = "__triage_seen__"
STATUSES = {"triage": "研判中", "tracking": "跟进中", "closed": "已关闭", "false_positive": "误报"}
NOTE_MAX = 280
_EVENT_ID = re.compile(r"ev_[0-9a-f]{16}")


class TriageError(ValueError):
    def __init__(self, error: str, message: str, actual: Any, limit: Any) -> None:
        super().__init__(message)
        self.detail = {"error": error, "message": message, "actual": actual, "limit": limit}


def set_status(store: Any, event_id: str, status: str, note: str, by: str, now: datetime) -> dict[str, Any]:
    """Validate and record one disposition (the previous one is kept as `previous`)."""
    if not _EVENT_ID.fullmatch(event_id or ""):
        raise TriageError("bad_event_id", "event id must be ev_ + 16 hex", event_id, "ev_[0-9a-f]{16}")
    if store.get_event(event_id) is None:
        raise TriageError("unknown_event", "no such event in the table", event_id, "an existing event id")
    if status not in STATUSES:
        raise TriageError("bad_status", "unknown status", status, sorted(STATUSES))
    if len(note or "") > NOTE_MAX:
        raise TriageError("note_too_long", "note exceeds the limit", len(note), NOTE_MAX)
    idx = store.get_source_state(KEY)
    prev = idx.get(event_id)
    entry = {"status": status, "label": STATUSES[status], "note": (note or "").strip(), "by": by[:40],
             "at": timeutil.iso(now), **({"previous": {k: prev[k] for k in ("status", "at") if k in prev}} if prev else {})}
    store.put_source_state(KEY, {**idx, event_id: entry})
    return entry


def changed(store: Any) -> list[str]:
    """Events whose disposition changed since the station last looked (then marks them seen)."""
    idx, seen = store.get_source_state(KEY), store.get_source_state(SEEN_KEY)
    ids = sorted(eid for eid, e in idx.items() if isinstance(e, dict) and e.get("at") != seen.get(eid))
    if ids:
        store.put_source_state(SEEN_KEY, {**seen, **{eid: idx[eid]["at"] for eid in ids}})
    return ids


def public(entry: dict[str, Any] | None) -> dict[str, Any] | None:
    """The published shape (the operator name is kept: an internal tool, behind the site's auth)."""
    if not entry:
        return None
    return {k: entry[k] for k in ("status", "label", "note", "by", "at") if k in entry}
