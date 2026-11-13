"""Root-cause title proposals — SHADOW mode: the model proposes, code verifies, an operator adopts with
scripts/retitle.py. Nothing here changes a published title.

Why (live 2026-11-02): "Binance CEX — Key Leaked via Infrastructure" stayed the title while Binance itself said no wallet
key leaked; an operator corrected it by hand (radar.retitle). This finds such cases for review instead of waiting for
someone to notice. Shadow first because a wrong automatic rename is worse than a stale one, and precision is unmeasured.

  code  candidates (web3 / incident, P0–P1, ≥ 3 reports, no operator title yet), cache per (event, title, report-count
        bucket), per-cycle cap, and the verification gates below — every gate failure is recorded with its reason
  LLM   one Sonnet call per candidate → {"keep": bool, "title", "quote", "item_id", "terms": [..]}

Gates (all must pass for a "propose" row):
  1. quote is verbatim in the cited report (title + text, whitespace-normalised)
  2. quote carries no hedge (allegedly / may / suspected / 据称 / 疑似 / 可能 …) — a hypothesis is not a cause
  3. the new title keeps the victim prefix ("Binance CEX — …") and is ≤ 160 characters
  4. every term occurs in the quote (terms are the cause in 1–3 words; they cannot be invented)
  5. support: the cited report is T1, or ≥ 2 independent T1/T2 reports mention a term
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timedelta
from typing import Any

from radar import llm, retitle, timeutil
from radar.model import Event, Item

KEY = "__retitle_shadow__"
PROMPT_VERSION = "retitle-shadow-v1"
MAX_CALLS_PER_CYCLE = 2
RECENT_DAYS = 7
MIN_ITEMS = 3
MAX_EVIDENCE = 14
TEXT_CHARS = 700
MAX_TOKENS = 600
HEDGE = re.compile(r"\b(alleged(ly)?|may|might|possibl[ey]|suspect(ed)?|reportedly|likely|could|rumou?r(ed)?|unconfirmed|"
                   r"believed)\b|据称|疑似|可能|或许|传闻|未经证实|据传|猜测", re.IGNORECASE)


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip().lower()


def candidates(evs: list[Event], overrides: dict[str, Any], now: datetime) -> list[Event]:
    cut = now - timedelta(days=RECENT_DAYS)
    out = [e for e in evs if e.domain in ("web3", "incident") and e.severity in ("P0", "P1")
           and len(e.item_ids) >= MIN_ITEMS and e.event_id not in overrides
           and (timeutil.parse(e.last_updated) or cut) >= cut]
    return sorted(out, key=lambda e: (e.severity, -len(e.item_ids)))


def cache_key(ev: Event) -> str:
    """Re-asked when the title changes or the report count doubles (3, 4–7, 8–15, …) — new evidence, new answer."""
    bucket = int(math.log2(max(1, len(ev.item_ids))))
    return hashlib.sha256(f"{PROMPT_VERSION}\x1f{ev.event_id}\x1f{ev.title}\x1f{bucket}".encode()).hexdigest()[:20]


def evidence(items: list[Item]) -> list[Item]:
    """T1 first, then T2, newest first; T3 only if nothing better (it is never enough on its own, gate 5)."""
    rank = {"T1": 0, "T2": 1, "T3": 2}
    newest = sorted(items, key=lambda i: i.published_at, reverse=True)
    return sorted(newest, key=lambda i: rank.get(i.tier, 3))[:MAX_EVIDENCE]   # stable: newest first within a tier


def render_prompt(ev: Event, ev_items: list[Item]) -> str:
    rows = [{"item_id": i.item_id, "tier": i.tier, "source": i.org, "title": i.title, "text": (i.text or "")[:TEXT_CHARS]}
            for i in ev_items]
    return ("You review the title of a security incident. Titles look like '<Victim> — <what happened / root cause>'.\n"
            "Decide whether the reports below state the root cause more precisely than, or differently from, the title.\n"
            "If the title is fine, output {\"keep\": true}. Otherwise propose a title that keeps the victim prefix exactly, "
            "states only what a report states as FACT (no hypotheses), in English, ≤ 120 characters, and cite it:\n"
            '{"keep": false, "title": "<new title>", "item_id": "<the report you quote>", '
            '"quote": "<verbatim sentence from that report, ≤ 240 chars>", "terms": ["<1–3 cause words from the quote>"]}\n'
            "Output JSON only.\n\n"
            f"Current title: {ev.title}\nReports:\n{json.dumps(rows, ensure_ascii=False)}")


def verify(ev: Event, ans: dict[str, Any], items: list[Item], groups: list[int]) -> tuple[str, str]:
    """('propose', '') or ('rejected', reason) — the code half of the harness; the model's word is never enough."""
    by_id = {i.item_id: (i, g) for i, g in zip(items, groups)}
    title, quote, iid = str(ans.get("title") or "").strip(), str(ans.get("quote") or "").strip(), ans.get("item_id")
    terms = [str(t).strip() for t in (ans.get("terms") or []) if str(t).strip()][:3]
    if iid not in by_id:
        return "rejected", "cited report is not in the event"
    cited, _ = by_id[iid]
    if not quote or _norm(quote) not in _norm(f"{cited.title}\n{cited.text}"):
        return "rejected", "quote not found verbatim in the cited report"
    if HEDGE.search(quote):
        return "rejected", "quote is hedged (a hypothesis, not a stated cause)"
    victim = ev.title.split(" — ")[0].strip()
    if not title or len(title) > retitle.TITLE_MAX or not title.startswith(f"{victim} — ") or title == ev.title:
        return "rejected", f"title must keep the victim prefix '{victim} — ', differ, ≤ {retitle.TITLE_MAX} chars"
    if not terms or any(_norm(t) not in _norm(quote) for t in terms):
        return "rejected", "cause terms missing or not in the quote"
    if cited.tier != "T1":
        mention = {g for i, g in zip(items, groups) if i.tier in ("T1", "T2")
                   and any(_norm(t) in _norm(f"{i.title}\n{i.text}") for t in terms)}
        if len(mention) < 2:
            return "rejected", f"support: cited report is {cited.tier} and only {len(mention)} independent T1/T2 report(s) mention the cause"
    return "propose", ""


def judge(ev: Event, items: list[Item], call: Any = None, model: str = llm.MODEL_BRIEF) -> dict[str, Any]:
    from radar.pipeline import independent_groups  # local import: pipeline imports publish-free modules only
    ev_items = evidence(items)
    res = (call or llm.converse)(render_prompt(ev, ev_items), model, MAX_TOKENS)
    if res.status != "ok":
        return {"verdict": "error", "reason": f"model {res.status}", "by": res.model or model}
    m = re.search(r"\{.*\}", res.text or "", re.DOTALL)
    try:
        ans = json.loads(m.group(0)) if m else None
    except json.JSONDecodeError:
        ans = None
    if not isinstance(ans, dict):
        return {"verdict": "rejected", "reason": "no JSON object in the answer", "by": res.model or model}
    if ans.get("keep") is True:
        return {"verdict": "keep", "reason": "", "by": res.model or model}
    verdict, reason = verify(ev, ans, items, independent_groups(items))
    cited = next((i for i in items if i.item_id == ans.get("item_id")), None)
    return {"verdict": verdict, "reason": reason, "by": res.model or model,
            "title": str(ans.get("title") or "")[:retitle.TITLE_MAX], "quote": str(ans.get("quote") or "")[:300],
            "item_id": ans.get("item_id"), "source": cited.url if cited else None}


def run(evs: list[Event], get_items: Any, state: dict[str, Any], overrides: dict[str, Any], now: datetime,
        call: Any = None) -> tuple[dict[str, Any], int]:
    """Judge new candidates (≤ MAX_CALLS_PER_CYCLE calls). state = {event_id: row}; rows of events that are no longer
    candidates are dropped (an operator adopted a title, the event aged out). Returns (state, model calls)."""
    cands = candidates(evs, overrides, now)
    live = {e.event_id for e in cands}
    state = {k: v for k, v in state.items() if k in live}
    calls = 0
    for ev in cands:
        prev = state.get(ev.event_id) or {}
        if prev.get("key") == cache_key(ev) and prev.get("verdict") != "error":   # a failed call is retried
            continue
        if calls >= MAX_CALLS_PER_CYCLE:
            break
        row = judge(ev, get_items(ev.item_ids), call)
        calls += 1
        state[ev.event_id] = {**row, "key": cache_key(ev), "current": ev.title, "at": timeutil.iso(now)}
    return state, calls
