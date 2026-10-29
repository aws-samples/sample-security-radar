"""C7 · daily digest (M2-PLAN A8): every day after 08:00 HKT, the last 24 h as one page.

Harness split (M2-PLAN §3, `daily_digest` = J):
  code  the index (which events, their level / severity changes, counts), every number in the header, the day key,
        when to run, retries, validation, storage
  LLM   only the prose: a summary, highlights and what still needs confirming — each sentence must cite event ids
        from the index, and every number in it must appear in the cited entries (the analyst's rule, reused)
Ungrounded sentences are kept and flagged, never shown as fact. Cost: one Sonnet call a day (~10 k tokens).
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from radar import analyst, llm, timeutil
from radar.model import LEVEL_ORDER, SEVERITY_ORDER, Event

PROMPT_VERSION = "digest-v1"
SECTIONS = ("summary", "highlights", "watch")
HKT = timezone(timedelta(hours=8))
RUN_AFTER_HKT_HOUR = 8
MAX_ATTEMPTS = 3            # per day; a failed day shows "failed" with the reason, not an empty card
MAX_EVENTS = 40             # index size cap (P0 first); keeps the prompt ~10 k tokens
MAX_TOKENS = 6_000


def day_key(now: datetime) -> str:
    """The digest's date = the HKT calendar day it is published on (one definition: degradation-and-guards §6)."""
    return now.astimezone(HKT).date().isoformat()


def due(state: dict[str, Any], now: datetime) -> bool:
    if now.astimezone(HKT).hour < RUN_AFTER_HKT_HOUR:
        return False
    day = state.get("day")
    if day != day_key(now):
        return True
    return state.get("status") != "ok" and int(state.get("attempts", 0)) < MAX_ATTEMPTS


def index(evs: list[Event], now: datetime) -> list[dict[str, Any]]:
    """Events updated in the last 24 h that matter (P0/P1, or a level/severity change), P0 first. Code-only."""
    since = timeutil.iso(now - timedelta(hours=24))
    rows = []
    for e in evs:
        if e.last_updated < since:
            continue
        changes = [t for t in e.timeline if (t.get("at") or "") >= since and t.get("kind") in ("level_change", "severity_change", "created")]
        if e.severity == "P2" and not changes:
            continue
        bluf = " ".join(s["text"] for s in ((e.analysis or {}).get("bluf") or []) if s.get("grounded"))
        rows.append({"event_id": e.event_id, "title": e.title, "domain": e.domain, "severity": e.severity, "level": e.level,
                     "exploitation": e.exploitation, "first_seen": e.first_seen, "independent_sources": e.independent_sources,
                     "amount_usd": e.amount_usd_latest, "cves": e.cves[:6], "chains": e.chains[:4],
                     "changes": [f"{t['kind']}: {t.get('from')} → {t.get('to')}" for t in changes][:4], "bluf": bluf})
    rows.sort(key=lambda r: (-SEVERITY_ORDER[r["severity"]], -LEVEL_ORDER.get(r["level"], 0), r["event_id"]))
    return rows[:MAX_EVENTS]


def header(rows: list[dict[str, Any]]) -> dict[str, int]:
    """Every number the digest shows outside the prose — code, never the LLM."""
    return {"events": len(rows), "p0": sum(r["severity"] == "P0" for r in rows), "p1": sum(r["severity"] == "P1" for r in rows),
            "new": sum(any(c.startswith("created") for c in r["changes"]) for r in rows),
            "escalated": sum(any(c.startswith(("level_change", "severity_change")) for c in r["changes"]) for r in rows),
            "web3": sum(r["domain"] == "web3" for r in rows)}


def render_prompt(rows: list[dict[str, Any]], day: str) -> str:
    schema = ('{"summary":[S],"highlights":[S],"watch":[S]} where S = {"text": "<one sentence in Chinese>", '
              '"cite": ["<event_id>", ...]}')
    return ("You are writing the daily security digest for an on-call team, for the 24 hours ending " + day + " 08:00 HKT.\n"
            "Rules:\n- Use ONLY the index below. Every sentence must cite ≥1 event_id from it.\n"
            "- Never state numbers, versions, dates, amounts or addresses that are not in the cited entries.\n"
            "- Do NOT assign severity, priority or verification level, and do not count events — code does that.\n"
            "- summary: at most 3 sentences: what changed and what matters most today.\n"
            "- highlights: one sentence per event worth acting on, most urgent first (at most 8).\n"
            "- watch: what is still unconfirmed or needs a human to check (single-source, disputed, amounts moving).\n"
            f"Output JSON only, shape: {schema}\n\nINDEX:\n" + json.dumps(rows, ensure_ascii=False))


def _evidence(rows: list[dict[str, Any]]) -> dict[str, str]:
    return {r["event_id"]: " ".join(str(v) for k, v in r.items() if k != "event_id" and v not in (None, "", [])) for r in rows}


def input_hash(rows: list[dict[str, Any]], model: str = llm.MODEL_BRIEF) -> str:
    blob = json.dumps(rows, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(f"{PROMPT_VERSION}\x1f{model}\x1f{blob}".encode()).hexdigest()


def generate(evs: list[Event], now: datetime, call: analyst.Call | None = None, model: str = llm.MODEL_BRIEF) -> dict[str, Any]:
    rows, day = index(evs, now), day_key(now)
    base = {"day": day, "generated_at": timeutil.iso(now), "model": model, "header": header(rows),
            "input_hash": input_hash(rows, model), "event_ids": [r["event_id"] for r in rows]}
    empty = {k: [] for k in SECTIONS}
    if not rows:   # a quiet day is a result, not a failure — and costs no LLM call
        return {**base, **empty, "status": "ok", "reason": "no P0/P1 activity or level change in the last 24 h"}
    res = (call or llm.converse)(render_prompt(rows, day), model, MAX_TOKENS)
    base["model"] = res.model or model
    if res.status != "ok":
        return {**base, **empty, "status": "failed", "reason": res.status}
    raw = analyst._parse(res.text)   # same JSON extraction as the analyst
    if raw is None:
        return {**base, **empty, "status": "failed", "reason": "bad_json"}
    by_id = _evidence(rows)
    out = {k: [analyst._check(s, by_id) for s in (raw.get(k) or []) if isinstance(s, dict)] for k in SECTIONS}
    sentences = [s for k in SECTIONS for s in out[k]]
    status = "ok" if sentences and all(s["grounded"] for s in sentences) else "partial"
    return {**base, **out, "status": status, "reason": None}
