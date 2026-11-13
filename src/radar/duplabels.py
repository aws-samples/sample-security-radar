"""Item 6 · C4 overrides: an operator's same / different label on a pair of events, written with their own AWS IAM
credentials by `scripts/dup_label.py` (no public write surface — same reasoning as radar.triage).

Effects: the label beats the model's verdict on the event page (cluster_judge.possible_duplicates); a confirmed
duplicate queues in #/ops until someone repairs it (scripts/recluster_web3.py --event …); and `report` measures the
judge's precision against the labels — the gate before any automatic merge (docs/research/12 §11: ≥ 30 shadow merges,
0 wrong). Merging itself stays a separate, explicit repair step.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from radar import timeutil

KEY = "__dup_labels__"
LABELS = {"same": "同一事件", "different": "不同事件"}
NOTE_MAX = 280
_EVENT_ID = re.compile(r"ev_[0-9a-f]{16}")


class LabelError(ValueError):
    def __init__(self, error: str, message: str, actual: Any, limit: Any) -> None:
        super().__init__(message)
        self.detail = {"error": error, "message": message, "actual": actual, "limit": limit}


def pair(a: str, b: str) -> str:
    """One entry per pair, whatever order the operator typed them in."""
    x, y = sorted((a, b))
    return f"{x}|{y}"


def set_label(store: Any, a: str, b: str, label: str, note: str, by: str, now: datetime) -> dict[str, Any]:
    for eid in (a, b):
        if not _EVENT_ID.fullmatch(eid or ""):
            raise LabelError("bad_event_id", "event id must be ev_ + 16 hex", eid, "ev_[0-9a-f]{16}")
    if a == b:
        raise LabelError("same_event", "a pair needs two different events", a, "two event ids")
    for eid in (a, b):
        if store.get_event(eid) is None:
            raise LabelError("unknown_event", "no such event in the table", eid, "an existing event id")
    if label not in LABELS:
        raise LabelError("bad_label", "unknown label", label, sorted(LABELS))
    if len(note or "") > NOTE_MAX:
        raise LabelError("note_too_long", "note exceeds the limit", len(note), NOTE_MAX)
    idx = store.get_source_state(KEY)
    k = pair(a, b)
    prev = idx.get(k)
    entry = {"label": label, "note": (note or "").strip(), "by": by[:40], "at": timeutil.iso(now),
             **({"previous": {f: prev[f] for f in ("label", "at") if f in prev}} if prev else {})}
    store.put_source_state(KEY, {**idx, k: entry})
    return entry


def label_of(labels: dict[str, Any], a: str, b: str) -> dict[str, Any] | None:
    return labels.get(pair(a, b))


def report(labels: dict[str, Any], judged: dict[str, Any]) -> dict[str, Any]:
    """The judge's 'same' verdicts against human labels: precision over labelled pairs only (an unlabelled verdict is
    counted apart, never assumed right)."""
    same = [r for r in judged.values() if r.get("verdict") == "same" and pair(r["a"], r["b"]) in labels]
    ok = sum(1 for r in same if labels[pair(r["a"], r["b"])]["label"] == "same")
    unlabelled = sum(1 for r in judged.values() if pair(r["a"], r["b"]) not in labels)
    return {"labelled": len(labels), "judged_same": len(same), "judged_same_correct": ok,
            "precision": round(ok / len(same), 3) if same else None, "unlabelled_judged": unlabelled}
