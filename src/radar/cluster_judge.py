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
    """Same-domain pairs first seen within WINDOW_H of each other that share no key but share an entity or a similar
    title. A sweep over events sorted by first_seen (only neighbours inside the window are compared) with times, key
    and entity sets computed once — the all-pairs loop with per-pair parsing took 5.5 min of every Analyze run once the
    CVE List filled the window (live 2026-11-11, ~1,500 events: ~1.1 M pairs). SequenceMatcher runs only when its
    cheap upper bounds can reach TITLE_SIMILARITY. Same result as the all-pairs loop (test)."""
    prep = []
    for i, e in enumerate(evs):
        t = timeutil.parse(e.first_seen)
        if t:
            prep.append((t, i, e, set(e.keys), {x.lower() for x in e.entities}, e.title.lower(), set(e.cves),
                         {x["hash"] for x in e.tx}))
    prep.sort(key=lambda r: (r[0], r[1]))
    win = timedelta(hours=WINDOW_H)
    out = []
    for j, (tb, ib, b, kb, eb, lb, cb, xb) in enumerate(prep):
        k = j - 1
        while k >= 0 and tb - prep[k][0] <= win:
            _, ia, a, ka, ea, la, ca, xa = prep[k]
            k -= 1
            if a.domain != b.domain or ka & kb:
                continue
            if (ca and cb and not ca & cb) or (xa and xb and not xa & xb):
                continue    # contradiction(): code already says different — not a pair to judge (107,811 → few)
            if ea & eb:
                out.append((a, b) if ia < ib else (b, a))
                continue
            sm = SequenceMatcher(None, la, lb)
            if sm.real_quick_ratio() >= TITLE_SIMILARITY and sm.quick_ratio() >= TITLE_SIMILARITY \
                    and sm.ratio() >= TITLE_SIMILARITY:
                out.append((a, b) if ia < ib else (b, a))
    order = {id(e): i for i, e in enumerate(evs)}
    out.sort(key=lambda p: (order[id(p[0])], order[id(p[1])]))           # the all-pairs loop's order …
    # … then most severe first (stable): a P0/P1 duplicate matters more than a P2 press copy
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


SHARDS = 16


def _shard(key: str, pair: str) -> str:
    return f"{key}#{int(hashlib.sha1(pair.encode(), usedforsecurity=False).hexdigest(), 16) % SHARDS}"


def load(store: Any, key: str) -> dict[str, Any]:
    """Every remembered verdict: the legacy single record (read-merged until the first save) plus the shards."""
    out = dict((store.get_source_state(key) or {}).get("pairs") or {})
    for part in store.get_source_states([f"{key}#{i}" for i in range(SHARDS)]).values():
        out.update((part or {}).get("pairs") or {})
    return out


def save(store: Any, key: str, pairs: dict[str, Any]) -> None:
    """Live 2026-11-11: one record held 1,658 pairs in 399,029 bytes and the next write failed with 413, every cycle.
    Only model verdicts are kept — a code verdict (contradiction()) is recomputed for free on every run — and they are
    sharded so no record nears DynamoDB's 400 KB. A shard is rewritten only when it changed (pairs leave as the window moves on)."""
    kept = {k: v for k, v in pairs.items() if v.get("by") != "code"}
    for i in range(SHARDS):
        sh = f"{key}#{i}"
        new = {"pairs": {k: v for k, v in kept.items() if _shard(key, k) == sh}}
        if store.get_source_state(sh) != new:   # R2.6: only a shard that changed is written (read is cached per run)
            store.put_source_state(sh, new)
    if store.get_source_state(key):
        store.put_source_state(key, {})


def possible_duplicates(event_id: str, state: dict[str, Any], titles: dict[str, str],
                        labels: dict[str, Any] | None = None) -> list[dict[str, str]]:
    """What the event page shows: the other side of every 'same' verdict that is still on the board. An operator's
    label (radar.duplabels, item 6) beats the model: 'different' hides the hint, 'same' shows it whatever the verdict."""
    labels = labels or {}
    why: dict[str, str] = {}
    for row in state.values():
        if row.get("verdict") == "same" and event_id in (row.get("a"), row.get("b")):
            why[row["b"] if row["a"] == event_id else row["a"]] = row.get("why", "")
    for k, lab in labels.items():
        a, b = k.split("|")
        if event_id in (a, b):
            other = b if a == event_id else a
            if lab.get("label") == "same":
                why[other] = f"人工确认：{lab.get('note') or LABEL_SAME_DEFAULT}"
            else:
                why.pop(other, None)
    return sorted(({"event_id": o, "title": titles[o], "why": w} for o, w in why.items() if o in titles),
                  key=lambda d: d["event_id"])


LABEL_SAME_DEFAULT = "同一事件"
