"""The only place that parses or formats time (degradation-and-guards §6). Everything is aware UTC.

Date-only inputs ("2026-10-18") mean 00:00:00Z of that day — defined here once, never guessed by callers."""

from __future__ import annotations

import email.utils
import re
from datetime import UTC, date, datetime

_TWITTER_FMT = "%a %b %d %H:%M:%S %z %Y"  # "Fri Oct 23 03:39:57 +0000 2026" (the X data source createdAt)
_X_EPOCH_MS = 1288834974657               # snowflake epoch for X status ids


def parse(value: str | float | None) -> datetime | None:
    """Parse any timestamp shape our sources emit. Returns None (not 'now') when unparseable, so callers
    must decide explicitly what a missing time means."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        secs = value / 1000 if value > 10_000_000_000 else value
        return datetime.fromtimestamp(secs, UTC)
    s = value.strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        d = date.fromisoformat(s)
        return datetime(d.year, d.month, d.day, tzinfo=UTC)
    if re.fullmatch(r"\d{8}", s):  # DeFiHackLabs "20261018"
        return datetime(int(s[:4]), int(s[4:6]), int(s[6:]), tzinfo=UTC)
    try:
        dt = datetime.fromisoformat(s)
        return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
    except ValueError:
        pass
    try:
        return datetime.strptime(s, _TWITTER_FMT).astimezone(UTC)
    except ValueError:
        pass
    try:
        dt = email.utils.parsedate_to_datetime(s)  # RFC 822 (RSS pubDate)
        return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
    except (TypeError, ValueError):
        return None


def x_status_time(status_id: int | str) -> datetime:
    """X status ids are snowflakes: (id >> 22) + epoch = creation time in ms."""
    return datetime.fromtimestamp(((int(status_id) >> 22) + _X_EPOCH_MS) / 1000, UTC)


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def now() -> datetime:
    return datetime.now(UTC)
