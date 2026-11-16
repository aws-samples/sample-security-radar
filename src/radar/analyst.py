"""Analyst station (J-class, M2-PLAN §3): event evidence → analysis card. The LLM writes sentences with
citations; code checks every sentence (citation exists, every number appears in the cited text) and marks
it grounded or not. Ungrounded sentences are kept and flagged — never silently dropped, never shown as fact.
Severity, level, amounts and ranking are never asked of the LLM."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from typing import Any

from radar import llm

PROMPT_VERSION = "brief-v1"
SECTIONS = ("bluf", "what", "impact", "exploitation", "actions", "unknowns")
PROMPT_MAX_BYTES = 60_000
ITEM_TEXT_MAX = 1_200
MAX_TOKENS = 8_000            # reasoning + JSON; 2_000 truncated in the 2026-10-23 probe

_MONTHS = {m: str(i) for i, m in enumerate(
    ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"], 1)}
_MONTHS.update({m[:3]: v for m, v in list(_MONTHS.items())})
_NUM = re.compile(r"\d+(?:[.,]\d+)*")

Call = Callable[[str, str, int], llm.LlmResult]


def trim_evidence(evidence: list[dict[str, Any]], structured: set[str] | frozenset[str] = frozenset()) -> list[dict[str, Any]]:
    """The evidence a brief is written from, within PROMPT_MAX_BYTES. All of it when it fits (unchanged: the
    input_hash of every event that fits stays the same). When it does not (R1.8, audit 02 Q6 #2): the list was cut
    oldest-first, so a 391-report event was briefed from its first 44 reports for ever — and the hash, taken after the
    cut, never changed again. Now: structured records (`structured` item ids), the first report, then the newest of
    each tier in turn (T1, T2, T3, …) until the budget; returned in time order."""
    cut = [dict(e, text=(e.get("text") or "")[:ITEM_TEXT_MAX]) for e in evidence]
    room = PROMPT_MAX_BYTES - 4_000                                   # leave room for instructions
    size = lambda e: len(json.dumps(e, ensure_ascii=False).encode())
    if sum(map(size, cut)) <= room:
        return cut
    order = list(range(len(cut)))                                    # input is time-ordered (handlers._evidence)
    picks = [i for i in order if cut[i]["item_id"] in structured] + order[:1]
    by_tier: dict[str, list[int]] = {}
    for i in reversed(order):                                        # newest first within a tier
        by_tier.setdefault(str(cut[i].get("tier") or "T9"), []).append(i)
    queues = [by_tier[t] for t in sorted(by_tier)]
    while any(queues):
        for q in queues:
            if q:
                picks.append(q.pop(0))
    chosen, used = set(), 0
    for i in dict.fromkeys(picks):
        if used + size(cut[i]) <= room:
            chosen.add(i)
            used += size(cut[i])
    return [cut[i] for i in order if i in chosen]


def render_prompt(evidence: list[dict[str, Any]]) -> str:
    schema = ('{"bluf":[S],"what":[S],"impact":[S],"exploitation":[S],"actions":[S],"unknowns":[S]} '
              'where S = {"text": "<one sentence in Chinese>", "cite": ["<item_id>", ...]}')
    return ("You are a senior security analyst writing an event brief for an on-call team.\n"
            "Rules:\n- Use ONLY the evidence items below. Every sentence must cite ≥1 item_id that supports it.\n"
            "- Never state numbers, versions, dates, amounts or addresses that do not appear in the cited items.\n"
            "- Do NOT assign severity, priority, confidence or verification level — code does that.\n"
            "- bluf: exactly one sentence (≤60 Chinese characters) answering: what happened and why it matters now.\n"
            "- exploitation: say explicitly when sources disagree (e.g. one says not observed, another reports attempts).\n"
            "- actions: concrete steps a defender or protocol team can take, only if supported by evidence.\n"
            "- unknowns: what is not yet known or unconfirmed.\n"
            f"Output JSON only, shape: {schema}\n\nEVIDENCE:\n" + json.dumps(evidence, ensure_ascii=False))


def input_hash(evidence: list[dict[str, Any]], model: str = llm.MODEL_BRIEF) -> str:
    blob = json.dumps(evidence, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(f"{PROMPT_VERSION}\x1f{model}\x1f{blob}".encode()).hexdigest()


def _normalise(text: str) -> str:
    """Source text as numbers can be matched in it: thousands separators removed, month names also
    present as their number ('October 17' ⇒ '… 10 17'), so a localised date in the brief is groundable."""
    t = text.lower()
    t = re.sub(r"(?<=\d),(?=\d{3}\b)", "", t)
    for name, num in _MONTHS.items():
        t = re.sub(rf"\b{name}\b", f"{name} {num}", t)
    return t


def _check(sentence: dict[str, Any], by_id: dict[str, str]) -> dict[str, Any]:
    text = str(sentence.get("text") or "").strip()
    cites = [str(c) for c in (sentence.get("cite") or [])]
    issues: list[str] = []
    if not cites:
        issues.append("no_citation")
    elif any(c not in by_id for c in cites):
        issues.append("unknown_citation")
    else:
        src = _normalise(" ".join(by_id[c] for c in cites))
        for n in _NUM.findall(text):
            plain = n.replace(",", "")
            # whole numbers only (R1.8, audit 02 Q6 #1): "6" was grounded by "2026" and "1.5" by "11.5"
            if (len(plain) >= 2 or "." in plain) and not re.search(rf"(?<![\d.]){re.escape(plain)}(?![\d]|\.\d)", src):
                issues.append("ungrounded_number")
                break
    return {"text": text, "cite": cites, "grounded": not issues, "issues": issues}


def validate(raw: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    by_id = {e["item_id"]: f"{e.get('title', '')} {e.get('text', '')}" for e in evidence}
    out: dict[str, Any] = {k: [_check(s, by_id) for s in (raw.get(k) or []) if isinstance(s, dict)] for k in SECTIONS}
    all_s = [s for k in SECTIONS for s in out[k]]
    out["status"] = "ok" if all_s and all(s["grounded"] for s in all_s) else "partial"
    return out


def _parse(text: str) -> dict[str, Any] | None:
    m = re.search(r"\{.*\}", text or "", re.DOTALL)
    if not m:
        return None
    try:
        d = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    return d if isinstance(d, dict) else None


def analyze(evidence: list[dict[str, Any]], now_iso: str, call: Call | None = None,
            model: str = llm.MODEL_BRIEF) -> dict[str, Any]:
    evidence = trim_evidence(evidence)
    res = (call or llm.converse)(render_prompt(evidence), model, MAX_TOKENS)  # resolved at call time
    base = {"generated_at": now_iso, "model": res.model or model, "input_hash": input_hash(evidence, model)}
    empty = {k: [] for k in SECTIONS}
    if res.status != "ok":
        return {**base, **empty, "status": "failed", "reason": res.status}
    raw = _parse(res.text)
    if raw is None:
        return {**base, **empty, "status": "failed", "reason": "bad_json"}
    return {**base, **validate(raw, evidence), "reason": None}
