"""Station run-time ledger: how long each single-writer station ran, against its Lambda timeout.

Why (live 2026-11-02): publish runs crept 89 s → 256 s over two days (an O(n³) progress replay on the growing Binance
event) and nobody saw it until the 300 s timeout failed a cycle. The durations were in CloudWatch the whole time; nothing
read them. Each station now appends its run here and #/ops `station_slow` warns at SLOW_SHARE of the timeout — while
there is still headroom.

One ledger per station (`__timing__#<station>`): every station is its own single writer. Collect (a Map of parallel
invocations) is not recorded — concurrent writers would race on one item.
A run that raised is recorded with ok=False; one killed by its timeout never records itself. Both show on #/ops as
station_silent (`silent`): the cycle catches four stations' failures and still succeeds, so nothing else reports them.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from radar import timeutil

PREFIX = "__timing__#"
STATIONS = ("process", "analyze", "respond", "mitigate", "publish", "notify")
KEEP = 12            # last two hours of 10-minute cycles
SLOW_SHARE = 0.6     # warn when the slowest recent run used this share of the timeout
RECENT = 6           # … among the last RECENT runs
FAILING_RUNS = 3     # this many failed runs in a row ⇒ station_silent (failing)
SILENT_MINUTES = 30  # no run recorded for this long ⇒ station_silent (silent); cycles run every 5, gaps reach 17.5


def record(store: Any, station: str, elapsed_s: float, timeout_s: float | None, now: datetime, ok: bool = True) -> None:
    """ok=False: the station raised. The cycle catches that for four stations and still succeeds, so this row is the
    only place the failure shows (absent = ok, as rows written before the flag)."""
    led = store.get_source_state(PREFIX + station)
    run = {"at": timeutil.iso(now), "s": round(elapsed_s, 1), **({} if ok else {"ok": False})}
    runs = [*(led.get("runs") or []), run][-KEEP:]
    store.put_source_state(PREFIX + station, {"runs": runs, "timeout_s": timeout_s or led.get("timeout_s")})


def facts(store: Any) -> dict[str, dict[str, Any]]:
    return {s: store.get_source_state(PREFIX + s) for s in STATIONS}


def slow(ledgers: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Stations whose slowest recent run used ≥ SLOW_SHARE of the timeout (actual + limit, error rule 5)."""
    out = []
    for st, led in sorted(ledgers.items()):
        runs, limit = (led or {}).get("runs") or [], (led or {}).get("timeout_s")
        if not runs or not limit:
            continue
        worst = max(runs[-RECENT:], key=lambda r: r["s"])
        if worst["s"] >= SLOW_SHARE * limit:
            out.append({"station": st, "worst_s": worst["s"], "at": worst["at"], "timeout_s": limit,
                        "share": round(worst["s"] / limit, 2), "median_s": sorted(r["s"] for r in runs)[len(runs) // 2]})
    return out


def silent(ledgers: dict[str, dict[str, Any]], now: datetime) -> list[dict[str, Any]]:
    """Stations that do nothing while the cycle succeeds: the last FAILING_RUNS runs all raised (kind failing), or no
    run was recorded for SILENT_MINUTES (kind silent — killed by its timeout, never invoked, or the cycle is down).
    A station with no ledger yet (a fresh deployment) is not reported."""
    out = []
    for st, led in sorted(ledgers.items()):
        runs = (led or {}).get("runs") or []
        if not runs:
            continue
        last = timeutil.parse(runs[-1]["at"])
        idle = (now - last).total_seconds() / 60 if last else None
        tail = runs[-FAILING_RUNS:]
        if idle is not None and idle > SILENT_MINUTES:
            out.append({"station": st, "kind": "silent", "at": runs[-1]["at"], "minutes": round(idle), "limit_min": SILENT_MINUTES})
        elif len(tail) == FAILING_RUNS and not any(r.get("ok", True) for r in tail):
            out.append({"station": st, "kind": "failing", "at": tail[0]["at"], "runs": FAILING_RUNS})
    return out
