"""R2.5: a failing source is asked less often, a server's Retry-After is honoured, and the firecrawl fallback quota is
spread over the day instead of spent in the first hours."""
from datetime import UTC, datetime, timedelta

import pytest

from radar import collect, fetch, timeutil
from radar.limits import Limits
from radar.registry import SOURCES

NOW = datetime(2026, 11, 15, 12, tzinfo=UTC)
SRC = next(s for s in SOURCES if s.enabled and s.cadence_min == 15)


@pytest.mark.parametrize(("failures", "minutes"), [(0, 15), (2, 15), (3, 30), (4, 60), (5, 120), (9, 360), (40, 360)])
def test_the_interval_doubles_from_the_third_failure_and_is_capped(failures, minutes):
    assert collect.cadence(SRC, {"consecutive_failures": failures}) == minutes


def _due(st):
    return SRC.source_id in collect.due({SRC.source_id: st}, NOW)


def test_due_follows_the_backed_off_interval():
    ran = timeutil.iso(NOW - timedelta(minutes=20))
    assert _due({"last_run": ran, "consecutive_failures": 0})
    assert not _due({"last_run": ran, "consecutive_failures": 4})            # 60-minute interval now


def test_retry_after_holds_the_source_until_then():
    ran = timeutil.iso(NOW - timedelta(hours=1))
    assert not _due({"last_run": ran, "retry_after_until": timeutil.iso(NOW + timedelta(minutes=5))})
    assert _due({"last_run": ran, "retry_after_until": timeutil.iso(NOW - timedelta(minutes=1))})


def test_retry_after_parses_seconds_and_dates():
    assert fetch.retry_after("120", 0) == 120
    assert fetch.retry_after("Sun, 15 Nov 2026 12:10:00 GMT", NOW.timestamp()) == 600
    assert fetch.retry_after("soon", 0) is None and fetch.retry_after(None, 0) is None


def test_a_429_with_retry_after_is_stored_capped_and_a_success_clears_it(monkeypatch):
    err = fetch.FetchError("http_error", "Too Many Requests", 429, SRC.url)
    err.retry_after_s = 10 * 3600                                           # longer than the cap
    monkeypatch.setattr(collect, "_body", lambda *a, **k: (_ for _ in ()).throw(err))
    _, st = collect.collect(SRC, {}, NOW)
    assert st["retry_after_until"] == timeutil.iso(NOW + timedelta(seconds=Limits.RETRY_AFTER_MAX_S))
    monkeypatch.setattr(collect, "_body", lambda *a, **k: fetch.Response(304, "", None, None))
    _, st = collect.collect(SRC, st, NOW + timedelta(hours=7))
    assert "retry_after_until" not in st and st["consecutive_failures"] == 0


def test_the_fallback_quota_is_spaced_over_the_day():
    src = next(s for s in SOURCES if s.via == "direct" and s.parser in collect.FIRECRAWL_FALLBACK_PARSERS)
    e = fetch.FetchError("network_error", "timed out", None, src.url)
    gap = timedelta(minutes=24 * 60 / Limits.FEED_FIRECRAWL_FALLBACKS_PER_DAY)
    st = {"fc_fallbacks": 1, "fc_fallback_day": NOW.date().isoformat(), "fc_fallback_at": timeutil.iso(NOW - gap / 4)}
    assert not collect._fallback_ok(src, e, st, NOW)
    assert collect._fallback_ok(src, e, {**st, "fc_fallback_at": timeutil.iso(NOW - gap)}, NOW)


def test_a_backed_off_or_held_source_is_not_reported_as_overdue():
    from radar import publish
    st = {"last_run": timeutil.iso(NOW - timedelta(minutes=100)), "consecutive_failures": 5}     # 120-minute interval
    assert not [r for r in publish.stalled_sources({SRC.source_id: st}, NOW) if r["source_id"] == SRC.source_id]
    held = {"last_run": timeutil.iso(NOW - timedelta(hours=5)), "retry_after_until": timeutil.iso(NOW + timedelta(hours=1))}
    assert not [r for r in publish.stalled_sources({SRC.source_id: held}, NOW) if r["source_id"] == SRC.source_id]
    ok = {"last_run": timeutil.iso(NOW - timedelta(hours=5))}
    assert [r for r in publish.stalled_sources({SRC.source_id: ok}, NOW) if r["source_id"] == SRC.source_id]
