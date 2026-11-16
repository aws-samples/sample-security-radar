"""R2.5: one source's requests share one wall-time budget. Live 2026-11-13: ex_bit2me's direct read timed out (25 s) and
its firecrawl fallback then got its own 60 s — one source held its batch thread 86 s. Socket timeouts bound a call,
not a source. No network: the socket seam (fetch._open) and the clock are replaced."""
from datetime import UTC, datetime

import pytest

from radar import collect, fetch, parsers
from radar.limits import Limits
from radar.model import RawItem
from radar.registry import BY_ID

NOW = datetime(2026, 11, 13, 10, 0, tzinfo=UTC)
CVE = RawItem(source_id="cve_list", url="https://www.cve.org/CVERecord?id=CVE-2026-1", title="CVE-2026-1", text="",
              published_at=NOW, guid="CVE-2026-1", extra={"cves": ["CVE-2026-1"], "fetch_time": "2026-11-13T10:00:00Z",
              "record_url": "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/1.json"})


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def wire(monkeypatch):
    """fetch._open replaced: records the timeout each call got; `spend` seconds pass per call, then `fail` raises."""
    clock, calls = Clock(), []
    monkeypatch.setattr(fetch.time, "monotonic", clock)

    def open_(req, timeout, redirect):
        calls.append(timeout)
        clock.t += timeout                      # the call uses all of its time and times out
        raise TimeoutError("The read operation timed out")
    monkeypatch.setattr(fetch, "_open", open_)
    return clock, calls


def test_a_direct_timeout_and_its_fallback_share_one_budget(wire, monkeypatch):
    _, calls = wire
    monkeypatch.setattr(fetch, "secrets", lambda: {"FIRECRAWL_API_KEYS": ["k1"]})
    with fetch.source_budget(Limits.SOURCE_BUDGET_S):
        with pytest.raises(fetch.FetchError):
            fetch.http_get("https://www.example.com/feed")
        with pytest.raises((fetch.FetchError, TimeoutError)):
            fetch.firecrawl_raw("https://www.example.com/feed")
    assert calls == [Limits.HTTP_TIMEOUT_S, Limits.SOURCE_BUDGET_S - Limits.HTTP_TIMEOUT_S]   # not 25 + 60
    assert sum(calls) <= Limits.SOURCE_BUDGET_S


def test_a_spent_budget_refuses_the_next_call_without_opening_it(wire):
    clock, calls = wire
    with fetch.source_budget(10), pytest.raises(fetch.FetchError) as e:
        clock.t += 10 - Limits.SOURCE_BUDGET_MIN_CALL_S + 0.5
        fetch.http_get("https://www.example.com/feed")
    assert e.value.code == "source_budget" and calls == [] and fetch.budget_spent(e.value)


def test_outside_a_budget_every_call_keeps_its_own_timeout_and_the_budget_ends_with_its_block(wire):
    _, calls = wire
    with fetch.source_budget(5), pytest.raises(fetch.FetchError):
        fetch.http_get("https://www.example.com/a")
    with pytest.raises(fetch.FetchError):
        fetch.http_get("https://www.example.com/b")              # scripts, tests, and the next source: no leftover deadline
    assert calls == [5, Limits.HTTP_TIMEOUT_S]
    assert not fetch.budget_spent(fetch.FetchError("network_error", "x"))


def test_a_cve_record_put_off_for_lack_of_time_is_not_counted_as_a_miss(monkeypatch):
    src, st = BY_ID["cve_list"], {}

    def get(url, **k):
        raise fetch.FetchError("source_budget", "the source's budget is spent", None, url)
    monkeypatch.setattr(fetch, "http_get", get)
    monkeypatch.setattr(parsers, "cve_record", lambda body: {})
    for _ in range(Limits.CVE_PENDING_RETRIES + 1):             # more runs than a real miss is allowed
        collect._cve_records(src, [CVE] if not st.get("cve_pending") else [], st, NOW, {})
    assert [(p["guid"], p["misses"]) for p in st["cve_pending"]] == [("CVE-2026-1", 0)]   # waits; never given up
