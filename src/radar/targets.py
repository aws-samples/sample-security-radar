"""Code bases the respond station checks ("your environment"). Each is uploaded as a zip to
s3://<continuum bucket>/code/<target_id>.zip (and the Security Agent bucket) by scripts/sync-continuum-targets.sh.
Continuum quota: ≤10 repositories per environment.

The rows are DATA (roadmap R4.7): src/radar/targets.json, validated here at import — adding a target is one row there
(+ its code under integrations/continuum/targets/<dir>/), no code change. Demo targets are small, realistic,
DELIBERATELY vulnerable code bases, each mirroring a real incident the radar tracked on 2026-10-23; security-radar is
this repo (git archive HEAD).

channel — which Continuum environment validates the target, exactly one (cost, 2026-10-28: the same code in two
environments was validated and scanned twice; the radar's own 404 KB repo was 99 % of what every S3-environment scan read):
  s3      the S3 environment (code/<id>.zip in the Continuum bucket) — patches as artifacts
  github  the GitHub environment on the demo-fleet repo — patches as native pull requests
  gitlab  the GitLab environment on gitlab.com — patches as native merge requests
  none    not sent to Continuum (Security Agent still reviews it)
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

FILE = Path(__file__).with_name("targets.json")
CHANNELS = ("s3", "github", "gitlab", "none")
_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,40}")


class TargetsError(ValueError):
    """A targets.json row the radar cannot use: code, message, actual, limit (degradation-and-guards §5)."""

    def __init__(self, error: str, message: str, actual: Any, limit: Any) -> None:
        self.detail = {"error": error, "message": message, "actual": actual, "limit": limit}
        super().__init__(json.dumps(self.detail, ensure_ascii=False))


def load(text: str) -> tuple[tuple[str, str, str], ...]:
    """targets.json → ((id, dir, summary), …); every row checked, the first bad one raises."""
    rows = json.loads(text).get("targets")
    if not isinstance(rows, list) or not rows:
        raise TargetsError("no_targets", "targets.json needs a non-empty \"targets\" list", type(rows).__name__, "list")
    seen: set[str] = set()
    for r in rows:
        tid = r.get("id") if isinstance(r, dict) else None
        if not isinstance(tid, str) or not _ID.fullmatch(tid):
            raise TargetsError("bad_id", "a target id is lowercase letters, digits and '-'", tid, _ID.pattern)
        if tid in seen:
            raise TargetsError("duplicate_id", "target ids are unique", tid, "unique")
        if r.get("channel") not in CHANNELS:
            raise TargetsError("bad_channel", f"target {tid}: channel must be one of {CHANNELS}", r.get("channel"), CHANNELS)
        if not isinstance(r.get("dir"), str) or not _ID.fullmatch(r["dir"]):
            raise TargetsError("bad_dir", f"target {tid}: dir is a directory name under integrations/continuum/targets",
                               r.get("dir"), _ID.pattern)
        seen.add(tid)
    return tuple((r["id"], r["dir"], str(r.get("summary") or "")) for r in rows)


_ROWS = json.loads(FILE.read_text("utf-8"))["targets"]
TARGETS: tuple[tuple[str, str, str], ...] = load(FILE.read_text("utf-8"))
NAMES = {t[0]: t[1] for t in TARGETS}
CHANNEL: dict[str, str] = {r["id"]: r["channel"] for r in _ROWS}


def on(channel: str) -> tuple[str, ...]:
    return tuple(t for t in NAMES if CHANNEL[t] == channel)
