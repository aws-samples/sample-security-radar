"""Publish-time enrichment of published CVEs: CVE records (cvemeta) + FIRST EPSS, and which pages they changed.

Why (live 2026-11-03 audit of all 411 pages): enrichment arrived late but pages did not follow. EPSS scores a new CVE
the day after publication and CNAs / CISA-ADP add CVSS days later (CVE-2026-98432: 9 days), yet an event page was
rebuilt only when the event itself changed — 4 CVEs published 11-02 would have shown EPSS 「—」 indefinitely. Now:

  * every published CVE is enriched each run (CVE records within their call / time budget; EPSS from a daily ledger),
  * `touched` = CVEs whose record or EPSS changed this run ⇒ publish rebuilds the pages that carry them.

EPSS ledger `__epss__` {"day": UTC date, "missing_at": iso} + shards `__epss__#<n>` {cve: [epss, percentile]}: FIRST is asked for all CVEs
once per UTC day (it updates daily) and for CVEs it does not know yet at most every EPSS_MISSING_RECHECK_HOURS. A FIRST
failure keeps yesterday's values (a stale score beats a blank page) and is reported in stats (⇒ #/ops enrich_degraded).
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from radar import cvemeta, timeutil
from radar.limits import Limits

EPSS_KEY = "__epss__"         # header {"day", "missing_at"}; scores live in shards EPSS_KEY#<n>
# Sharded like cvemeta (docs/research/action/07 B7): the scores were one DynamoDB item that only ever grew — at ~40 B a
# CVE it passes the 400 KB item limit near 10k CVEs, and the failed put fails Publish every cycle. 64 shards ≈ 600k CVEs.
EPSS_SHARDS = 64
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
BATCH = 100


def _record(e: dict[str, Any] | None) -> tuple[Any, ...]:
    e = e or {}
    return (e.get("state"), e.get("published"), e.get("assigner"), e.get("cvss"), e.get("severity"), e.get("cvss_source"))


def _shard(cve: str) -> str:
    return f"{EPSS_KEY}#{int(hashlib.sha1(cve.encode(), usedforsecurity=False).hexdigest(), 16) % EPSS_SHARDS}"


def _load(store: Any, led: dict[str, Any]) -> dict[str, list[float]]:
    """Every score: the legacy `v` of the header record (until its first sharded save) plus one batch read of the shards."""
    out: dict[str, list[float]] = dict(led.get("v") or {})
    for part in store.get_source_states([f"{EPSS_KEY}#{i}" for i in range(EPSS_SHARDS)]).values():
        out.update(part or {})
    return out


def _epss(store: Any, cves: list[str], now: datetime, get: Callable[[str], str], stats: dict[str, Any]
          ) -> tuple[dict[str, dict[str, float]], set[str]]:
    led = store.get_source_state(EPSS_KEY)
    old = _load(store, led)
    day = now.strftime("%Y-%m-%d")
    missing = [c for c in cves if c not in old]
    missing_at = timeutil.parse(led.get("missing_at") or "")
    recheck = missing and (missing_at is None or now - missing_at >= timedelta(hours=Limits.EPSS_MISSING_RECHECK_HOURS))
    ask = cves if led.get("day") != day else (missing if recheck else [])
    new = dict(old)
    failed = False
    for i in range(0, len(ask), BATCH):
        try:
            for row in json.loads(get(EPSS_URL + ",".join(ask[i:i + BATCH]))).get("data", []):
                new[row["cve"]] = [float(row["epss"]), float(row["percentile"])]
        except Exception as e:   # noqa: BLE001 — a failed batch keeps the previous values, counted for #/ops
            failed = True
            stats["epss_failed"] = stats.get("epss_failed", 0) + 1
            stats["epss_error"] = str(e)[:200]
    if ask:
        # shards holding a changed score first (each rewritten whole), then the header — which drops a legacy `v` only
        # once its scores are safely in shards (all of them count as changed on that first save)
        changed = {c for c, v in new.items() if old.get(c) != v} | set(led.get("v") or {})
        shards: dict[str, dict[str, list[float]]] = {}
        for c, v in new.items():           # one pass, one hash per CVE (was 64 × N: every shard rehashed every CVE)
            shards.setdefault(_shard(c), {})[c] = v
        for sh in sorted({_shard(c) for c in changed}):
            store.put_source_state(sh, shards[sh])
        store.put_source_state(EPSS_KEY, {"day": day if (led.get("day") == day or not failed) else led.get("day"),
                                          "missing_at": timeutil.iso(now) if missing else led.get("missing_at")})
    touched = {c for c in cves if new.get(c) != old.get(c)}
    wanted = set(cves)                     # built once: `in set(cves)` inside the comprehension was O(N²)
    return {c: {"epss": v[0], "percentile": v[1]} for c, v in new.items() if c in wanted}, touched


def run(store: Any, cves: list[str], now: datetime, get: Callable[[str], str], budget_s: float
        ) -> tuple[dict[str, dict[str, float]], set[str], dict[str, Any]]:
    """(EPSS per CVE, CVEs whose published data changed this run, stats for #/ops)."""
    stats: dict[str, Any] = {"at": timeutil.iso(now), "cves": len(cves)}
    if not cves:
        return {}, set(), stats
    before = {c: _record(e) for c, e in cvemeta.load(store).items()}
    cvemeta.refresh(store, cves, now, get, budget_s=budget_s, stats=stats)
    after = cvemeta.load(store)
    touched = {c for c in cves if c in after and _record(after[c]) != before.get(c)}
    epss, moved = _epss(store, cves, now, get, stats)
    touched |= moved
    stats["touched"] = len(touched)
    return epss, touched, stats
