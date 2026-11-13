"""Shared inputs of the R11 characterization (tests/fixtures/respond_shape): live event docs and the shipped demo
targets, addressed by short keys so golden.json can name them instead of embedding them."""
from __future__ import annotations

import copy
import json
from functools import cache
from pathlib import Path
from typing import Any

from radar import respond

ROOT = Path(__file__).resolve().parents[1]
FX = ROOT / "tests" / "fixtures" / "events"
DEMO = ROOT / "integrations/continuum/targets"
NOW = "2026-10-23T18:00:00Z"
NAMES: dict[str, str] = {}


def doc(key: str) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any] | None]:
    """php2shell | node2shell, optionally _cooled / _p1, optionally @<event_id> (the survivor of a merge)."""
    key, _, eid = key.partition("@")
    name, _, variant = key.partition("_")
    d = json.loads((FX / f"{name}.json").read_text())
    ev = {**d["event"], **({"event_id": eid} if eid else {})}
    if variant == "cooled":
        ev = {**ev, "severity": "P1", "exploitation": "reported"}
    elif variant == "p1":
        ev = {**ev, "severity": "P1"}
    return ev, d["items"], (None if variant == "cooled" else d.get("analysis"))


def _dir(tid: str, root: Path) -> dict[str, str]:
    return {f"{tid}/{p.relative_to(root)}": p.read_text() for p in sorted(root.rglob("*")) if p.is_file()}


@cache
def _base(kind: str) -> tuple[respond.Target, ...]:
    radar_files = {"security-radar/.gitlab-ci.yml": "lint:\n  image: python:3.12-bookworm\nui:\n  image: node:24-bookworm\n",
                   **{f"security-radar/{p}": (ROOT / p).read_text() for p in ("infra/stack.py", "pyproject.toml")}}
    out = [respond.Target("demo-shop", "demo-shop", "demo", _dir("demo-shop", DEMO / "demo-shop")),
           respond.Target("security-radar", "security-radar", "self", radar_files)]
    if kind == "fleet":
        out += [respond.Target(t, t, t, _dir(t, DEMO / t)) for t in ("node-gateway", "wp-storefront", "alps-vault")]
    return tuple(out)


def targets_of(key: str) -> list[respond.Target]:
    """targets | fleet, optionally _fixed (every 8.3.30 pin of demo-shop bumped) or _shift (a line inserted at the top
    of demo-shop's Dockerfile)."""
    kind, _, variant = key.partition("_")
    out = []
    for t in _base(kind):
        files = dict(t.files)
        if t.target_id == "demo-shop" and variant == "fixed":
            files = {k: v.replace("8.3.30", "8.3.36") for k, v in files.items()}
        elif t.target_id == "demo-shop" and variant == "shift":
            files = {k: ("# edited\n" + v if k.endswith("Dockerfile") else v) for k, v in files.items()}
        out.append(respond.Target(t.target_id, t.name, t.description, files))
    return out


def budget(b: dict[str, Any]) -> respond.Budget:
    b = copy.deepcopy(b)
    for k in ("github_targets", "gitlab_targets", "s3_targets"):
        if b.get(k) is not None:
            b[k] = tuple(b[k])
    return respond.Budget(**b)


def op_dict(op: respond.Op) -> dict[str, Any]:
    return {"kind": op.kind, "target_id": op.target_id, "payload": copy.deepcopy(op.payload)}


def op_of(d: dict[str, Any]) -> respond.Op:
    return respond.Op(d["kind"], d["target_id"], copy.deepcopy(d["payload"]))
