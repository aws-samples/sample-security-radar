"""Point-in-time restore planning for a versioned bucket (roadmap R5.5) — pure, so the decision is tested without S3.

Given every version of every key under a prefix (ListObjectVersions: versions + delete markers) and a moment, the plan
says, per key, what to do so the bucket reads as it did at that moment:
  restore   the version current at `at` is not the current one now ⇒ copy that version on top (a new current version;
            nothing is deleted, so the restore itself is undoable the same way)
  delete    the key did not exist at `at` (created later, or deleted before it) but exists now ⇒ a delete marker
  keep      already as it was
A key with no version at or before `at` and no current object is skipped. Times compare as aware datetimes."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class Step:
    key: str
    action: str                  # restore | delete | keep
    version_id: str | None = None


def _current(rows: list[dict[str, Any]], at: datetime | None) -> dict[str, Any] | None:
    """The row in effect at `at` (None ⇒ now): the newest version or delete marker not after it."""
    live = [r for r in rows if at is None or r["LastModified"] <= at]
    return max(live, key=lambda r: r["LastModified"], default=None)


def plan(versions: list[dict[str, Any]], markers: list[dict[str, Any]], at: datetime) -> list[Step]:
    """`versions` / `markers` as ListObjectVersions returns them (Key, VersionId, LastModified)."""
    by_key: dict[str, list[dict[str, Any]]] = {}
    for r in versions:
        by_key.setdefault(r["Key"], []).append({**r, "marker": False})
    for r in markers:
        by_key.setdefault(r["Key"], []).append({**r, "marker": True})
    out = []
    for key in sorted(by_key):
        rows = by_key[key]
        then, now = _current(rows, at), _current(rows, None)
        then_obj = None if then is None or then["marker"] else then
        now_obj = None if now is None or now["marker"] else now
        if then_obj is None and now_obj is None:
            continue
        if then_obj is None:
            out.append(Step(key, "delete"))
        elif now_obj is not None and now_obj["VersionId"] == then_obj["VersionId"]:
            out.append(Step(key, "keep", then_obj["VersionId"]))
        else:
            out.append(Step(key, "restore", then_obj["VersionId"]))
    return out
