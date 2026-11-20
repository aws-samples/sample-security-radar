"""The only place that parses or formats time (degradation-and-guards §6). Everything is aware UTC.

Date-only inputs ("2026-10-18") mean 00:00:00Z of that day — defined here once, never guessed by callers."""

from __future__ import annotations

import email.utils
import re
from datetime import UTC, date, datetime, timedelta, timezone

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


UTC8 = timezone(timedelta(hours=8))   # the team's clock (Hong Kong / Singapore); messages show it, storage stays UTC


def utc8(value: str | float | None) -> str | None:
    """"2026-11-16 11:05（UTC+8）" for a stored UTC time; None when it does not parse (the caller says "unknown")."""
    dt = parse(value)
    return dt.astimezone(UTC8).strftime("%Y-%m-%d %H:%M（UTC+8）") if dt else None


def day_only(value: str | None) -> bool:
    """A stored time of exactly 00:00:00Z: the source gave a day, not a time (KEV dateAdded, an RSS date without a time).
    The single definition — pipeline.day_precision and the push notice both read it."""
    return bool(value) and str(value).endswith("T00:00:00Z")



# A feed that prints the entry's age into its text ("Published : Nov. 19, 2026, 3:17 a.m. | 1 hour, 52 minutes ago") makes
# every fetch a revision: a new content hash, a re-cluster, the event's last_updated moved, quotes that no longer read back
# (live 2026-11-19, cvefeed: 60 of 257 such items revised in 24 h; the rule-pack deploy check failed on one). Only the
# `| N unit ago` stamp: an age in prose ("patched 3 days ago") is the article's words. Used where text is normalized
# (pipeline.normalize) and where a quote is read back (rulepack.verify_quote), so both see the same text.
# every quantifier is bounded (the input is third-party text): a stamp has at most a few units ("1 year, 2 months, 3
# days ago"). semgrep regex_dos flags any quantified group; measured linear: 20,000 near-stamps with no "ago" in 4 ms,
# and item text is capped at Limits.ITEM_TEXT_MAX (tests/test_relative_age_20261119.py times a hostile input).
_RELATIVE_AGE = re.compile(r"\|\s{0,3}(?:\d{1,4}\s{1,3}(?:years?|months?|weeks?|days?|hours?|minutes?|seconds?),?\s{0,3}){1,4}ago\b")  # nosemgrep


def strip_relative_age(text: str) -> str:
    return _RELATIVE_AGE.sub("|", text)
