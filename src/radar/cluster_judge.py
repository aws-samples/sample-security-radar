"""C4 · cluster_judge (M2-PLAN §3, T-class): "are these two events the same incident?" for the pairs the clustering
rules cannot decide — advisory only, never an automatic merge.

Veto measurement (live, 14 days to 2026-10-29): 40 candidate pairs (same domain, first seen ≤ 72 h apart, no shared
key, title similarity ≥ 0.55 or a shared entity); of the 15 most similar, 4 were the same incident (all P2 press
copies: Quest Diagnostics, Hive affiliate sentence, Tailscale SSH, the AI-assistant file trick) and 11 were not (three
Plex CVEs, Swell vs CoinDCX, templated "— Smart Contract Vulnerability" titles). A wrong merge is expensive (10-27:
Node2Shell + Adobe folded into PHP2Shell, a PR attached to the wrong event) and precision is unmeasured ⇒ the judge only
annotates `possible_duplicates`; merging stays with the rules (and a human).

  code  candidate pairs, contradiction guards (disjoint CVE sets / disjoint tx hashes ⇒ different, no call), pair key,
        cache (a pair is judged once unless either title changes), per-cycle cap, storage
  LLM   one Haiku call per remaining pair → {"verdict": same|different|unsure, "why": "<≤ 1 sentence>"}
"""
from __future__ import annotations

import hashlib
import itertools
import json
import re
from datetime import timedelta
from difflib import SequenceMatcher
from typing import Any

from radar import llm, timeutil
from radar.model import Event

PROMPT_VERSION = "cluster-judge-v1"
MAX_PAIRS_PER_CYCLE = 5
WINDOW_H = 72
TITLE_SIMILARITY = 0.55
MAX_TOKENS = 400
VERDICTS = ("same", "different", "unsure")


def pair_key(a: Event, b: Event) -> str:
    x, y = sorted([(a.event_id, a.title), (b.event_id, b.title)])
    return hashlib.sha256(f"{PROMPT_VERSION}\x1f{x}\x1f{y}".encode()).hexdigest()[:20]


def candidates(evs: list[Event]) -> list[tuple[Event, Event]]:
    out = []
    for a, b in itertools.combinations(evs, 2):
        if a.domain != b.domain or set(a.keys) & set(b.keys):
            continue
        ta, tb = timeutil.parse(a.first_seen), timeutil.parse(b.first_seen)
        if not ta or not tb or abs(ta - tb) > timedelta(hours=WINDOW_H):
            continue
        shared_entity = bool({e.lower() for e in a.entities} & {e.lower() for e in b.entities})
        if shared_entity or SequenceMatcher(None, a.title.lower(), b.title.lower()).ratio() >= TITLE_SIMILARITY:
            out.append((a, b))
    # most severe first: a P0/P1 duplicate matters more than a P2 press copy
    out.sort(key=lambda p: -max({"P0": 2, "P1": 1}.get(p[0].severity, 0), {"P0": 2, "P1": 1}.get(p[1].severity, 0)))
    return out


def contradiction(a: Event, b: Event) -> str | None:
    """Code decides 'different' when the facts already disagree — no call, no chance of a wrong 'same'."""
    if a.cves and b.cves and not set(a.cves) & set(b.cves):
        return "different CVE ids"
    ta, tb = {t["hash"] for t in a.tx}, {t["hash"] for t in b.tx}
    if ta and tb and not ta & tb:
        return "different attack transactions"
    return None


def render_prompt(a: Event, b: Event) -> str:
    def side(e: Event) -> dict[str, Any]:
        return {"title": e.title, "domain": e.domain, "first_seen": e.first_seen, "entities": e.entities[:6],
                "cves": e.cves[:6], "chains": e.chains[:4], "amount_usd": e.amount_usd_latest}
    return ("Two security news events were not merged by the rules. Are they the SAME real-world incident?\n"
            "Answer 'same' only if they describe one incident (same victim / product and same occurrence), 'different' if "
            "they are separate incidents (e.g. different CVEs, different victims, a templated title), else 'unsure'.\n"
            'Output JSON only: {"verdict": "same|different|unsure", "why": "<one short sentence>"}\n\n'
            f"A: {json.dumps(side(a), ensure_ascii=False)}\nB: {json.dumps(side(b), ensure_ascii=False)}")


def judge(a: Event, b: Event, call: Any = None, model: str = llm.MODEL_FAST) -> dict[str, Any]:
    why = contradiction(a, b)
    if why:
        return {"verdict": "different", "why": why, "by": "code"}
    res = (call or llm.converse)(render_prompt(a, b), model, MAX_TOKENS)
    if res.status != "ok":
        return {"verdict": "unsure", "why": f"model {res.status}", "by": "error"}
    m = re.search(r"\{.*\}", res.text or "", re.DOTALL)
    try:
        d = json.loads(m.group(0)) if m else {}
    except json.JSONDecodeError:
        d = {}
    verdict = d.get("verdict") if d.get("verdict") in VERDICTS else "unsure"   # anything else is not a 'same'
    return {"verdict": verdict, "why": str(d.get("why") or "")[:200], "by": res.model or model}


def run(evs: list[Event], state: dict[str, Any], now_iso: str, call: Any = None) -> tuple[dict[str, Any], int]:
    """Judge new candidate pairs (≤ MAX_PAIRS_PER_CYCLE model calls). state = {pair_key: verdict row}; returns
    (state, model calls made). Rows of pairs no longer candidates are dropped (the window moved on)."""
    pairs = candidates(evs)
    live = {pair_key(a, b): (a, b) for a, b in pairs}
    state = {k: v for k, v in state.items() if k in live}
    calls = 0
    for k, (a, b) in live.items():
        if k in state:
            continue
        guarded = contradiction(a, b) is not None
        if not guarded and calls >= MAX_PAIRS_PER_CYCLE:
            continue
        row = judge(a, b, call)
        calls += 0 if row["by"] == "code" else 1
        state[k] = {**row, "a": a.event_id, "b": b.event_id, "at": now_iso}
    return state, calls


def possible_duplicates(event_id: str, state: dict[str, Any], titles: dict[str, str]) -> list[dict[str, str]]:
    """What the event page shows: the other side of every 'same' verdict that is still on the board."""
    out = []
    for row in state.values():
        if row.get("verdict") != "same" or event_id not in (row.get("a"), row.get("b")):
            continue
        other = row["b"] if row["a"] == event_id else row["a"]
        if other in titles:
            out.append({"event_id": other, "title": titles[other], "why": row.get("why", "")})
    return sorted(out, key=lambda d: d["event_id"])
