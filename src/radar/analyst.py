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


def facts_of(ev: Any) -> dict[str, Any]:
    """The facts the CODE decided about an event — what a brief may become wrong about. Stored with the brief
    (analysis["facts"], internal) so the station can tell whether any of them moved."""
    amt = ev.amount_usd_latest
    return {"severity": ev.severity, "exploitation": ev.exploitation or "none", "cves": sorted(ev.cves or []),
            "amount": None if not amt else float(f"{float(amt):.2g}")}     # 2 significant digits: $12.3M ≈ $12.4M


IMMEDIATE_FACTS = ("severity", "exploitation")     # a brief contradicting these is wrong now: rewrite at once


def needs_rewrite(analysis: dict[str, Any] | None, evidence: list[dict[str, Any]], facts: dict[str, Any],
                  now_iso: str = "", cooldown_h: float = 6) -> str | None:
    """Why this brief must be (re)generated, or None to keep it — one definition for the station and its tests.

    Live 11-19: 1,422 generations in 7 days (~203/day) because every new report changed the evidence hash. Replayed
    over 7 days of real reports: rewriting on code-decided facts only = ~10 a day. New reports repeating the story,
    new figures and re-fetches keep the brief (its citations still resolve; the page's code-made sections carry the
    rest). CVE / amount changes wait `cooldown_h` after the last brief (a multi-CVE advisory gains its CVEs one by one)."""
    if not analysis:
        return "new"
    if analysis.get("status") == "failed":
        return "failed"
    ids = {e["item_id"] for e in evidence}
    if any(c not in ids for k in SECTIONS for s in (analysis.get(k) or []) for c in (s.get("cite") or [])):
        return "cited_report_gone"          # a citation that no longer resolves would show as ungrounded
    old = analysis.get("facts")
    if old is None:
        return None if analysis.get("input_hash") == input_hash(evidence) else "legacy"   # stamped while current
    for k in IMMEDIATE_FACTS:
        if old.get(k) != facts.get(k):
            return f"facts_{k}"
    for k in ("cves", "amount"):
        if old.get(k) != facts.get(k):
            gen = str(analysis.get("generated_at") or "")
            if gen and now_iso and _hours(gen, now_iso) < cooldown_h:
                return None
            return f"facts_{k}"
    return None


def _hours(a: str, b: str) -> float:
    from radar import timeutil
    ta, tb = timeutil.parse(a), timeutil.parse(b)
    return (tb - ta).total_seconds() / 3600 if ta and tb else float("inf")


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

# --- what a brief sentence may not say against the code's own fields (harness audit 11-19, R1 / P1: the grounded BLUF
# becomes the event summary → the Slack P0 📝 line, feeds, webhooks, the site; grounding checks citations and numbers
# only, and 61 % of passing sentences have no number at all) ---
_CLAIM_EXPLOITED = re.compile(r"在野利用|已被利用|遭到利用|被积极利用|正被利用|actively exploited|exploited in the wild|"
                              r"under active exploitation|being exploited|has been exploited|were exploited", re.IGNORECASE)
_DENY_EXPLOITED = re.compile(r"(?:尚无|没有|未见|未发现|暂无|无)[^，。,.;；]{0,8}(?:在野利用|被利用|利用)|"
                             r"no (?:known |public |evidence of |reports? of )?[a-z -]{0,20}exploit|"
                             r"not (?:yet |been |known to be )*(?:actively )?exploited", re.IGNORECASE)
_USD = re.compile(r"\$\s?(\d+(?:\.\d+)?)\s?(k|m|b|million|billion|thousand)?\b", re.IGNORECASE)
_SCALE = {"k": 1e3, "thousand": 1e3, "m": 1e6, "million": 1e6, "b": 1e9, "billion": 1e9}


def contradiction(text: str, ev: dict[str, Any]) -> str | None:
    """Why this sentence contradicts the event's code-decided fields, or None. `ev` = the published view fields
    (cves, exploitation, amount_usd_latest, amount_disputed)."""
    from radar import keys
    named, own = set(keys.cves(text)), set(ev.get("cves") or [])
    # only against CVEs the code holds: an event with none (the code missed it — live: Chrome CVE-2026-125350) has
    # nothing to contradict, and the brief naming its CVE is the better text (30-day replay 11-19: 7 of 8 such)
    if named and own and not named <= own:
        return "cve_not_in_event"
    denied = bool(_DENY_EXPLOITED.search(text))
    claimed = bool(_CLAIM_EXPLOITED.search(_DENY_EXPLOITED.sub(" ", text)))
    code = ev.get("exploitation") or "none"
    if claimed and code not in ("reported", "confirmed"):
        return "exploited_claim_not_in_code"
    if denied and code == "confirmed":
        return "denies_confirmed_exploitation"
    amount = ev.get("amount_usd_latest")
    if amount and not ev.get("amount_disputed"):
        for n, unit in _USD.findall(text):
            v = float(n) * _SCALE.get(unit.lower(), 1) if unit else float(n)
            if v >= 1000 and abs(v - float(amount)) > 0.15 * float(amount):
                return "amount_not_event"
    return None
