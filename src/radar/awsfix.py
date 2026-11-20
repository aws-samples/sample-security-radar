"""AWS's own fix status for a CVE — the Amazon Linux Security Center's per-CVE page
(explore.alas.aws.amazon.com/<CVE>.html, public, no key): per platform and package, Fixed / Pending Fix / Not Affected /
No Fix Planned, with the ALAS advisory that fixed it.

Why (Neo 2026-11-18): the team is AWS; when a P0 lands, colleagues and customers first ask "is AWS's own build affected,
and is it fixed?" (Java4Shell: Corretto 17/21/25/27 fixed in AL2023 within hours, Corretto 8/11 not affected, ARM64 not
affected). The answer was on that page; the radar did not read it.

Read for the CVEs of P0 / P1 vulnerability events only (the publish station passes them), at most
Limits.AWS_FIX_CALLS_PER_RUN per run within a time budget. A page that still has a Pending Fix / Under Investigation row
is re-read every AWS_FIX_RECHECK_HOURS; a CVE Amazon Linux does not track (404) is re-read daily; all-final pages are
not re-read. A failed read leaves no entry and is counted for #/ops (degraded, never fatal).
Cache: {cve: entry} sharded over SHARDS records `__aws_fix__#<n>`.
"""
from __future__ import annotations

import hashlib
import html as htmllib
import json
import logging
import re
import time
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from radar import timeutil
from radar.limits import Limits

KEY = "__aws_fix__"
SHARDS = 16
URL = "https://explore.alas.aws.amazon.com/{cve}.html"
HOST = "explore.alas.aws.amazon.com"
log = logging.getLogger(__name__)

# the page's words → ours. An unknown word is kept as "other" with its text (shown, never guessed)
STATUS = {"fixed": "fixed", "pending fix": "pending", "under investigation": "pending", "not affected": "not_affected",
          "no fix planned": "no_fix"}
OPEN = ("pending",)            # a page with one of these is re-read

_TABLE = re.compile(r'<table id="affected-packages-table">(.*?)</table>', re.DOTALL)
_ROW = re.compile(r"<tr>(.*?)</tr>", re.DOTALL)
_CELL = re.compile(r"<td[^>]*>(.*?)</td>", re.DOTALL)
_TAG = re.compile(r"<[^>]+>")
_ALAS = re.compile(r"\bALAS[0-9A-Z]*-\d{4}-\d+\b")
_DESC = re.compile(r'<div class="description-content" id="description-content">(.*?)</div>', re.DOTALL)
# the description, not the table, says which CPU architecture is spared (Java4Shell: "ARM64 systems are not affected")
_ARM_SPARED = re.compile(r"(?i)\b(?:ARM64|aarch64|Graviton)\b[^.]{0,60}?\b(?:is|are) not affected\b")
_CORRETTO = re.compile(r"^java-(?:1\.(\d+)\.0|(\d+))-amazon-corretto$")


def _shard(cve: str) -> str:
    return f"{KEY}#{int(hashlib.sha1(cve.encode(), usedforsecurity=False).hexdigest(), 16) % SHARDS}"


def load(store: Any) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for part in store.get_source_states([f"{KEY}#{i}" for i in range(SHARDS)]).values():
        out.update(part or {})
    return out


def _text(cell: str) -> str:
    return " ".join(htmllib.unescape(_TAG.sub(" ", re.sub(r"<!--.*?-->", "", cell, flags=re.DOTALL))).split())


def parse(page: str) -> list[dict[str, Any]]:
    """The affected-packages table → rows {platform, package, status, status_text, advisory, released}.
    No table ⇒ [] (the caller decides what an empty page means)."""
    m = _TABLE.search(page)
    if not m:
        return []
    rows = []
    for r in _ROW.findall(m.group(1)):
        cells = [_text(c) for c in _CELL.findall(r)]
        if len(cells) != 5:          # the header row has <th>, not <td>
            continue
        platform, package, released, advisory, status_text = cells
        adv = _ALAS.search(advisory)
        rows.append({"platform": platform, "package": package, "released": released or None,
                     "advisory": adv.group(0) if adv else None, "status_text": status_text,
                     "status": STATUS.get(status_text.lower(), "other")})
    return rows


def arm_spared(page: str) -> bool:
    """Does the page's description say ARM64 (Graviton) is not affected? Neo 2026-11-18: 「Graviton 不受影响，这你没有说」."""
    m = _DESC.search(page)
    return bool(m and _ARM_SPARED.search(_text(m.group(1))))


def label(package: str) -> str:
    """java-1.8.0-amazon-corretto → Corretto 8, java-17-amazon-corretto → Corretto 17; anything else as it is."""
    m = _CORRETTO.match(package)
    return f"Corretto {m.group(1) or m.group(2)}" if m else package


def _join(labels: list[str]) -> str:
    """Corretto 17, Corretto 21 → Corretto 17/21 (numeric order); mixed packages joined with 、"""
    cor = sorted({int(x.split()[1]) for x in labels if x.startswith("Corretto ")})
    other = sorted({x for x in labels if not x.startswith("Corretto ")})
    parts = (["Corretto " + "/".join(str(n) for n in cor)] if cor else []) + other
    return "、".join(parts)


def summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Per status, the packages (labels) and — for fixed — the advisories. A package fixed on one platform and pending on
    another is listed in both, with the platforms (AL2 Corretto 17: Pending Fix while AL2023 is Fixed)."""
    by: dict[str, dict[str, set[str]]] = {}
    advisories: list[str] = []
    for r in rows:
        by.setdefault(r["status"], {}).setdefault(label(r["package"]), set()).add(r["platform"])
        if r["status"] == "fixed" and r["advisory"] and r["advisory"] not in advisories:
            advisories.append(r["advisory"])
    return {s: [{"package": p, "platforms": sorted(pl)} for p, pl in sorted(v.items())] for s, v in by.items()} | \
        {"advisories": advisories}


def _aws_built(label_: str) -> bool:
    """AWS's own builds (Corretto, amazon-*): what a notice names under 不受影响 — distro OpenJDK builds stay on the page."""
    return label_.startswith("Corretto ") or "amazon" in label_


def line(entry: dict[str, Any] | None) -> str | None:
    """One line for a P0 notice (Neo 2026-11-18: highlight it when AWS has fixed it). None when there is nothing to say."""
    if not entry or entry.get("state") != "FOUND":
        return None
    s = entry.get("summary") or {}
    # Neo 2026-11-18 「再简练一点」: fixed / pending / spared — "no fix planned" and the advisories stay on the event page
    parts = []
    if s.get("fixed"):
        parts.append(f"已修复：{_join([x['package'] for x in s['fixed']])}")
    if s.get("pending"):
        parts.append(f"待修复：{_join([x['package'] for x in s['pending']])}")
    # not affected: AWS's own builds only (Corretto, amazon-*) — 「java-1.7.0-openjdk 不受影响」 is noise in a notice
    spared = [x["package"] for x in s.get("not_affected") or [] if _aws_built(x["package"])]
    spared_txt = "、".join(p for p in (_join(spared) if spared else "", "Graviton" if s.get("arm64_not_affected") else "") if p)
    if spared_txt:
        parts.append(f"不受影响：{spared_txt}")
    return "🟧 AWS " + " ｜ ".join(parts) if parts else None


def for_event(cves: list[str], led: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    """The event's AWS status: the first of its CVEs Amazon Linux tracks (an event names one vulnerability; a second CVE
    is usually the same bug's earlier id)."""
    for c in cves:
        e = led.get(c)
        if e and e.get("state") == "FOUND":
            return {"cve": c, "url": URL.format(cve=c), "checked_at": e.get("checked_at"), "summary": e.get("summary"),
                    "line": line(e)}
    return None


def _due(entry: dict[str, Any] | None, now: datetime) -> bool:
    if not entry:
        return True
    t = timeutil.parse(entry.get("checked_at") or "")
    if t is None:
        return True
    first = timeutil.parse(entry.get("first_checked_at") or "") or t
    if now - first >= timedelta(days=Limits.AWS_FIX_FOLLOW_DAYS):
        return False
    if entry.get("state") == "FOUND" and "arm64_not_affected" not in (entry.get("summary") or {}):
        return True     # read before the description was parsed (2026-11-18): once more, so the Graviton note appears
    if entry.get("state") in ("NOT_FOUND", "NO_TABLE"):    # AWS may publish the page after our P0 went out
        return now - t >= timedelta(hours=Limits.AWS_FIX_RECHECK_HOURS)
    if any(entry.get("summary", {}).get(s) for s in OPEN):
        return now - t >= timedelta(hours=Limits.AWS_FIX_RECHECK_HOURS)
    return False


def refresh(store: Any, cves: list[str], now: datetime, get: Callable[[str], str],
            limit: int = Limits.AWS_FIX_CALLS_PER_RUN, budget_s: float = Limits.AWS_FIX_BUDGET_S,
            clock: Callable[[], float] = time.monotonic, stats: dict[str, Any] | None = None) -> set[str]:
    """Read the due pages (never-seen CVEs first); returns the CVEs whose entry changed (their pages are rebuilt)."""
    led = load(store)
    # never-read CVEs first, and within each group the caller's order — publish passes P0 CVEs before P1 (live
    # 2026-11-18: the first full publish queued ~750 P0 / P1 CVEs alphabetically and Java4Shell's waited behind P1s)
    due = sorted((c for c in dict.fromkeys(cves) if _due(led.get(c), now)), key=lambda c: c in led)
    changed: set[str] = set()
    start, tried = clock(), 0
    for c in due[:limit]:
        if clock() - start > budget_s:
            break
        tried += 1
        prev = led.get(c) or {}
        base = {"checked_at": timeutil.iso(now), "first_checked_at": prev.get("first_checked_at") or timeutil.iso(now)}
        try:
            page = get(URL.format(cve=c))
            rows = parse(page)
        except Exception as e:   # noqa: BLE001 — one CVE without AWS status this run, counted
            if getattr(e, "status", None) == 404:
                entry = {"state": "NOT_FOUND", **base}
            else:
                if stats is not None:
                    stats["aws_fix_failed"] = stats.get("aws_fix_failed", 0) + 1
                    stats["aws_fix_error"] = str(e)[:200]
                log.warning(json.dumps({"station": "publish", "degraded": "aws_fix_unavailable", "cve": c,
                                        "error": str(e)[:200]}))
                continue
        else:
            # a 200 without the table is not "not affected": it is a page we cannot read — say so, re-read daily
            entry = {"state": "FOUND", "summary": summary(rows) | {"arm64_not_affected": arm_spared(page)}, **base} \
                if rows else {"state": "NO_TABLE", **base}
        if {k: v for k, v in entry.items() if "checked" not in k} != {k: v for k, v in prev.items() if "checked" not in k}:
            changed.add(c)
        led[c] = entry
    for sh in sorted({_shard(c) for c in due[:tried]}):
        store.put_source_state(sh, {c: e for c, e in led.items() if _shard(c) == sh})
    if stats is not None:
        stats["aws_fix_backlog"] = len(due) - tried
    return changed
