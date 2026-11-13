"""Published → held: how long a report takes to reach the radar, measured every cycle (roadmap R0.5).

A hand measurement on 2026-11-12 gave a median of 48 minutes (Telegram 5, X 35, RSS 51). The speed work (R2) is judged
by this number, so it is recorded by the process station and stated on #/ops — not re-derived by a script when asked.

A sample is one newly held report: minutes from its `published_at` to the cycle that ingested it, with its source
tier. Reports older than LATENCY_MAX_HOURS when first seen are backfills (a new source's history, a database's old
entries) and are left out: they say nothing about speed. A source's own timestamp is trusted as given.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from radar import timeutil
from radar.limits import Limits

KEY = "__latency__"
# the second half of the chain: first report published → the first P0 push of an event to a subscription (notify
# station). P0s are few a day, so this ledger keeps a week.
PUSH_KEY, PUSH_HOURS = "__latency_push__", 168


def minutes(published_at: str, held_at: datetime) -> int | None:
    """Minutes from publication to being held, or None for a backfill / a timestamp in the future."""
    at = timeutil.parse(published_at)
    if at is None:
        return None
    lag = (held_at - at).total_seconds() / 60
    return round(lag) if 0 <= lag <= Limits.LATENCY_MAX_HOURS * 60 else None


def _recent(store: Any, now: datetime, key: str, hours: int) -> list[list[Any]]:
    floor = timeutil.iso(now - timedelta(hours=hours))
    return [r for r in (store.get_source_state(key).get("rows") or []) if r[0] >= floor]


def record(store: Any, samples: list[list[Any]], now: datetime, key: str = KEY, hours: int = 24) -> None:
    """samples: [group, minutes]. Keeps `hours`, at most LATENCY_SAMPLES_MAX rows (newest)."""
    if not samples:
        return
    at = timeutil.iso(now)
    rows = _recent(store, now, key, hours) + [[at, t, m] for t, m in samples]
    store.put_source_state(key, {"rows": rows[-Limits.LATENCY_SAMPLES_MAX:]})


def _q(v: list[int], p: float) -> int:
    return sorted(v)[min(len(v) - 1, int(len(v) * p))]


def summary(store: Any, now: datetime, key: str = KEY, hours: int = 24) -> dict[str, Any] | None:
    """Median and 90th percentile over the last `hours`, overall and per group. None = nothing measured (not zero)."""
    rows = _recent(store, now, key, hours)
    if not rows:
        return None
    tiers: dict[str, list[int]] = {}
    for _, t, m in rows:
        tiers.setdefault(t, []).append(m)
    allv = [m for _, _, m in rows]
    return {"n": len(allv), "p50": _q(allv, 0.5), "p90": _q(allv, 0.9),
            "tiers": {t: {"n": len(v), "p50": _q(v, 0.5), "p90": _q(v, 0.9)} for t, v in sorted(tiers.items())}}
