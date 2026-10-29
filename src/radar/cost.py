"""What the AWS side of the radar costs, per day (roadmap R4) — from Cost Explorer, folded into the respond ledger.

Pure: the Respond handler fetches (continuum_aws.fetch_costs) and stores the result of summarize(); publish copies it
into continuum.json. Until 10-26 these numbers only lived in docs (CONTINUUM-INTEGRATION.md §6), read by hand."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from radar import timeutil
from radar.limits import Limits

SERVICES = {"AWS Continuum": "continuum", "AWS Security Agent": "security_agent"}  # Cost Explorer SERVICE values


def due(led: dict[str, Any], now: datetime) -> bool:
    """Every COST_REFRESH_H since the last attempt — a failed read backs off too (each request costs $0.01)."""
    tries = [timeutil.parse((led.get("cost") or {}).get("fetched_at")), timeutil.parse((led.get("cost_error") or {}).get("at"))]
    last = max((t for t in tries if t), default=None)
    return last is None or now - last >= timedelta(hours=Limits.COST_REFRESH_H)


def over_cap(led: dict[str, Any]) -> dict[str, Any] | None:
    """R10 spend guard. Cost Explorer lags ~24 h, so 'today' is not enough: the two most recent days with data count.
    Returns the offending day (for the ledger / push) or None. No cost data yet ⇒ None (nothing to judge on)."""
    days = (led.get("cost") or {}).get("days") or []   # calendar days in the window, zero-spend days included
    for d in days[-2:][::-1]:
        if d["continuum_usd"] > Limits.CONTINUUM_DAILY_USD_CAP:
            return {"date": d["date"], "continuum_usd": d["continuum_usd"], "cap": Limits.CONTINUUM_DAILY_USD_CAP}
    return None


def window(now: datetime) -> tuple[str, str]:
    """[start, end) dates for get_cost_and_usage; end is exclusive, so today is included."""
    end = (now + timedelta(days=1)).date()
    return (end - timedelta(days=Limits.COST_WINDOW_DAYS)).isoformat(), end.isoformat()


def summarize(results_by_time: list[dict[str, Any]], now: datetime) -> dict[str, Any]:
    """ResultsByTime grouped by SERVICE, USAGE_TYPE → per-day USD per service + Continuum inference units."""
    days = []
    for r in results_by_time:
        row: dict[str, Any] = {"date": r["TimePeriod"]["Start"], "continuum_usd": 0.0, "security_agent_usd": 0.0,
                               "continuum_inference_units": 0.0}
        for g in r.get("Groups") or []:
            svc = SERVICES.get(g["Keys"][0])
            if svc is None:
                continue
            usd = float(g["Metrics"]["UnblendedCost"]["Amount"])
            row[f"{svc}_usd"] += usd
            if svc == "continuum" and g["Keys"][1].endswith("ContinuumInference"):
                row["continuum_inference_units"] += float(g["Metrics"]["UsageQuantity"]["Amount"])
        days.append({k: (round(v, 2) if isinstance(v, float) else v) for k, v in row.items()})
    return {"fetched_at": timeutil.iso(now), "days": days,
            "total_usd": round(sum(d["continuum_usd"] + d["security_agent_usd"] for d in days), 2)}
