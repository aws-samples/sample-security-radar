"""CVE record metadata from CVE Services (cveawg.mitre.org — the CVE Program's own record API, no key):
when the CNA published the CVE, who the CNA is, and the CVSS score in the record (CNA's own, else an ADP's).

Why (live 2026-11-02): CVE-2026-98432 was published by the Linux CNA on 10-15 and scored 9.8 on 10-24; the radar first
saw it in The Hacker News on 10-29, and the event page said only 「首见 10-29」 — read as "disclosed 10-29". The page
now states both: when the world knew (disclosure) and when the radar knew (first_seen), and the lag between them.

Cache: {cve: entry} sharded over SHARDS records `__cve_meta__#<n>` (load / save). One record held 391 CVEs in
78.6 KB and was never trimmed — at ~2,000 CVEs it would pass DynamoDB's 400 KB item limit and fail Publish every
cycle (docs/research/19 B1; with the full CVE List feed, in about two weeks). The legacy single record is merged on
load and emptied on the first save. `published` never changes once set; a record without a score is
re-read after CVE_META_RESCORE_HOURS (CNAs and CISA-ADP add scores days later — this CVE: 9 days). Lookups per run
are capped; a failed lookup is logged as degraded and leaves no entry (retried next run), never fatal."""
from __future__ import annotations

import hashlib
import json
import logging
import time
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from radar import timeutil
from radar.limits import Limits

KEY = "__cve_meta__"          # legacy single record (read-merged, emptied on the first save); shards are KEY#<n>
SHARDS = 64                   # × ~400 KB / ~200 B per entry ≈ 120k CVEs (the CVE List publishes ~40k a year)


def _shard(cve: str) -> str:
    return f"{KEY}#{int(hashlib.sha1(cve.encode(), usedforsecurity=False).hexdigest(), 16) % SHARDS}"


def load(store: Any) -> dict[str, dict[str, Any]]:
    """Every entry: one batch read of the shards, plus the legacy record while it still holds anything."""
    out: dict[str, dict[str, Any]] = dict(store.get_source_state(KEY) or {})
    for part in store.get_source_states([f"{KEY}#{i}" for i in range(SHARDS)]).values():
        out.update(part or {})
    return out


def save(store: Any, led: dict[str, dict[str, Any]], changed: set[str]) -> None:
    """Write the shards that hold a changed CVE (each shard rewritten whole from `led`); a non-empty legacy record is
    migrated — all its CVEs count as changed — and emptied after its entries are safely in shards."""
    legacy = store.get_source_state(KEY) or {}
    changed = set(changed) | set(legacy)
    for sh in sorted({_shard(c) for c in changed}):
        store.put_source_state(sh, {c: e for c, e in led.items() if _shard(c) == sh})
    if legacy:
        store.put_source_state(KEY, {})
URL = "https://cveawg.mitre.org/api/cve/"
log = logging.getLogger(__name__)


def _score(metrics: list[dict[str, Any]] | None) -> tuple[float, str] | None:
    """Newest CVSS version first (4.0 → 3.1 → 3.0 → 2.0)."""
    for m in metrics or []:
        for v in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            if isinstance(m.get(v), dict) and m[v].get("baseScore") is not None:
                return float(m[v]["baseScore"]), str(m[v].get("baseSeverity") or "").upper()
    return None


def parse(record: dict[str, Any]) -> dict[str, Any]:
    md = record.get("cveMetadata") or {}
    c = record.get("containers") or {}
    cvss, sev, src = None, None, None
    if (s := _score((c.get("cna") or {}).get("metrics"))):
        cvss, sev, src = s[0], s[1], "cna"
    else:
        for adp in c.get("adp") or []:
            if (s := _score(adp.get("metrics"))):
                cvss, sev, src = s[0], s[1], f"adp:{(adp.get('providerMetadata') or {}).get('shortName', '?')}"
                break
    return {"state": md.get("state"), "published": md.get("datePublished"), "assigner": md.get("assignerShortName"),
            "cvss": cvss, "severity": sev or None, "cvss_source": src}


def _due(entry: dict[str, Any] | None, now: datetime) -> bool:
    if not entry:
        return True
    if entry.get("published") and entry.get("cvss") is not None:
        return False
    t = timeutil.parse(entry.get("checked_at") or "")
    return t is None or now - t >= timedelta(hours=Limits.CVE_META_RESCORE_HOURS)


def refresh(store: Any, cves: list[str], now: datetime, get: Callable[[str], str],
            limit: int = Limits.CVE_META_CALLS_PER_RUN, budget_s: float = Limits.CVE_META_BUDGET_S,
            clock: Callable[[], float] = time.monotonic, stats: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    """Fill the ledger for `cves` (at most `limit` lookups within `budget_s`, never-seen CVEs first) and return the
    entries for them. The rest waits for the next run (logged as backlog)."""
    led = load(store)
    changed: set[str] = set()
    due = sorted((c for c in set(cves) if _due(led.get(c), now)), key=lambda c: (c in led, c))
    done, tried, start = 0, 0, clock()
    for c in due[:limit]:
        if clock() - start > budget_s:
            break
        tried += 1
        try:
            entry = parse(json.loads(get(URL + c)))
        except Exception as e:   # noqa: BLE001 — any failure is one CVE without metadata this run, logged
            if getattr(e, "status", None) == 404:
                # not in the CVE List (yet): remember it, re-read daily (_due) instead of on every publish
                led[c] = {"state": "NOT_FOUND", "published": None, "assigner": None, "cvss": None, "severity": None,
                          "cvss_source": None, "checked_at": timeutil.iso(now)}
                changed.add(c)
                done += 1
                continue
            if stats is not None:
                stats["cve_meta_failed"] = stats.get("cve_meta_failed", 0) + 1
                stats["cve_meta_error"] = str(e)[:200]
            log.warning(json.dumps({"station": "publish", "degraded": "cve_meta_unavailable", "cve": c,
                                    "error": str(e)[:200]}))
            continue
        led[c] = {**entry, "checked_at": timeutil.iso(now)}
        changed.add(c)
        done += 1
    if done:
        save(store, led, changed)
    if stats is not None:
        stats["cve_meta_backlog"] = len(due) - tried
    if len(due) > tried:
        log.info(json.dumps({"station": "publish", "cve_meta_backlog": len(due) - tried}))
    return {c: led[c] for c in cves if c in led}


def disclosure(cves: list[str], meta: dict[str, dict[str, Any]], first_seen: str,
               title: str = "") -> dict[str, Any] | None:
    """Earliest CVE publication among the event's CVEs and the radar's lag behind it (hours, ≥ 0) — among the CVEs its
    title names when it names any: the headline CVE is the one the event is about (live 2026-11-19: the vCenter zero-day
    CVE-2026-123890, published that day, was shown as 「旧漏洞，公开 112 天后」 through a second, older CVE a report had
    mentioned). None when no CVE has a known publication date. The one place this is decided — the UI only renders it."""
    low = title.lower()
    cves = [c for c in cves if c.lower() in low] or cves
    dated = [(timeutil.parse(meta[c]["published"]), c) for c in cves if (meta.get(c) or {}).get("published")]
    dated = [(t, c) for t, c in dated if t]
    if not dated:
        return None
    at, cve = min(dated)
    seen = timeutil.parse(first_seen)
    lag = max(0.0, (seen - at).total_seconds() / 3600) if seen else None
    return {"at": timeutil.iso(at), "cve": cve, "assigner": meta[cve].get("assigner"),
            "lag_hours": round(lag, 1) if lag is not None else None,
            # an old CVE back on the radar (KEV listing, new exploitation, a retrospective) — worded apart on the page
            "resurfaced": lag is not None and lag >= Limits.RESURFACED_DAYS * 24}
