"""Collect station criteria: scheduling, failure recording (降级留痕), conditional GET, PoC enrichment."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from radar import collect, fetch, timeutil
from radar.registry import BY_ID

NOW = datetime(2026, 10, 23, 4, 0, tzinfo=UTC)
SNAP = Path(__file__).parent / "fixtures" / "snapshots" / "2026-10-23"


def test_due_respects_cadence_and_never_run():
    states = {"cisa_advisories": {"last_run": "2026-10-23T03:45:00Z"}, "bleepingcomputer": {"last_run": "2026-10-23T03:45:00Z"}}
    d = collect.due(states, NOW)
    assert "cisa_advisories" not in d   # 30-min cadence, ran 15 min ago
    assert "bleepingcomputer" in d      # 15-min cadence
    assert "defillama_hacks" in d       # never ran


def test_failure_is_recorded_and_distinguishable_from_no_news(monkeypatch):
    def boom(*a, **k):
        raise fetch.FetchError("http_error", "Not Allowed", 405, "https://www.freebuf.com/feed")
    monkeypatch.setattr(fetch, "http_get", boom)
    raws, st = collect.collect(BY_ID["bleepingcomputer"], {"consecutive_failures": 2}, NOW)
    assert raws == [] and st["consecutive_failures"] == 3
    assert "405" in st["last_error"] and st["last_error_at"] == "2026-10-23T04:00:00Z"
    assert "last_success" not in st


def test_not_modified_keeps_cursor_and_counts_as_success(monkeypatch):
    monkeypatch.setattr(fetch, "http_get", lambda url, etag=None, last_modified=None, **k: fetch.Response(304, "", etag, last_modified))
    raws, st = collect.collect(BY_ID["bleepingcomputer"], {"etag": '"abc"', "consecutive_failures": 1}, NOW)
    assert raws == [] and st["etag"] == '"abc"' and st["consecutive_failures"] == 0
    assert st["last_success"] == "2026-10-23T04:00:00Z"


def test_defihacklabs_enriches_only_unseen_entries(monkeypatch):
    readme = (SNAP / "defihacklabs.md").read_text()
    sol = (SNAP / "AlpsCon_exp.sol").read_text()
    calls = []
    def fake(url, etag=None, last_modified=None, **k):
        calls.append(url)
        return fetch.Response(200, readme if url.endswith("README.md") else sol)
    monkeypatch.setattr(fetch, "http_get", fake)
    known = lambda sid, guid: "AlpsCon" not in guid
    raws, _ = collect.collect(BY_ID["defihacklabs"], {}, NOW, known_item=known)
    alps = next(r for r in raws if r.extra["entity"] == "AlpsCon")
    assert alps.extra["attack_tx"][0]["hash"].startswith("0x824b83f9")
    assert sum(u.endswith(".sol") for u in calls) == 1


def test_runs_window_drops_entries_older_than_a_day(monkeypatch):
    # hermetic: never spend the (tiny) the X data source quota from tests
    monkeypatch.setattr(fetch, "twitterapi_search", lambda *a, **k: '{"tweets": []}')
    old = (NOW - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    _, st = collect.collect(BY_ID["x_security"], {"runs": [[old, 9]]}, NOW)
    assert all(r[0] > old for r in st["runs"])


def test_empty_parse_of_a_200_is_a_failure_not_silence(monkeypatch):
    """Regression (live 2026-10-23): FreeBuf served a WAF page; 0 items was reported as ok."""
    monkeypatch.setattr(fetch, "http_get", lambda *a, **k: fetch.Response(200, "<html>blocked</html>"))
    monkeypatch.setattr(fetch, "firecrawl_raw", lambda url: "<html>blocked too</html>")   # the fallback is blocked too
    raws, st = collect.collect(BY_ID["bleepingcomputer"], {}, NOW)
    assert raws == [] and st["consecutive_failures"] == 1 and "parse_empty" in st["last_error"]
    assert "firecrawl fallback also failed" in st["last_error"]


def test_firecrawl_upstream_error_page_is_an_error(monkeypatch):
    import io
    import json as _json
    monkeypatch.setattr(fetch, "secrets", lambda: {"FIRECRAWL_API_KEYS": ["k"]})
    body = _json.dumps({"data": {"rawHtml": "<html>405</html>", "metadata": {"statusCode": 405}}}).encode()
    class R(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr(fetch.urllib.request, "urlopen", lambda *a, **k: R(body))
    import pytest
    with pytest.raises(fetch.FetchError) as e:
        fetch.firecrawl_raw("https://www.freebuf.com/feed")
    assert e.value.code == "upstream_blocked" and e.value.status == 405


def test_twitterapi_429_backs_off_then_succeeds(monkeypatch):
    calls = []
    def flaky(url, headers=None, **k):
        calls.append(url)
        if len(calls) == 1:
            raise fetch.FetchError("http_error", "Too Many Requests", 429, url)
        return fetch.Response(200, '{"tweets": [], "has_next_page": false}')
    monkeypatch.setattr(fetch, "http_get", flaky)
    monkeypatch.setattr(fetch, "secrets", lambda: {"X_API_KEY": "k"})
    monkeypatch.setenv("X_SEARCH_URL", "https://x-data.example/search")
    monkeypatch.setattr(fetch.time, "sleep", lambda s: None)
    assert fetch.twitterapi_search(("a",), 60) == '{"tweets": []}'
    assert len(calls) == 2


def test_urlopen_refuses_every_scheme_but_http_and_https():
    import urllib.error

    import pytest

    from radar import fetch
    for bad in ("file:///etc/passwd", "ftp://x/y", "gopher://x", "jar:file:/x!/y", "/relative"):
        with pytest.raises(urllib.error.URLError, match="http/https only"):
            fetch.urlopen(bad, timeout=1)


# ---- firecrawl fallback for direct feeds (live 2026-11-11: anquanke 26 timeouts / 3 days, netsec "Blocked", …)

RSS = ("<?xml version='1.0'?><rss><channel><item><title>Fresh advisory CVE-2026-1234</title>"
       "<link>https://e.example/a</link><pubDate>Tue, 10 Nov 2026 10:00:00 GMT</pubDate></item></channel></rss>")


def _boom(code, status=None, msg="x"):
    def f(*a, **k):
        raise fetch.FetchError(code, msg, status, "https://feed.example")
    return f


def test_a_timed_out_feed_is_served_by_firecrawl_and_marked_degraded(monkeypatch):
    monkeypatch.setattr(fetch, "http_get", _boom("network_error", None, "[Errno 110] Connection timed out"))
    monkeypatch.setattr(fetch, "firecrawl_raw", lambda url: RSS)
    raws, st = collect.collect(BY_ID["bleepingcomputer"], {}, NOW)
    assert len(raws) == 1 and st["consecutive_failures"] == 0
    assert st["degraded"].startswith("direct network_error") and st["fc_fallbacks"] == 1


def test_a_rate_limited_or_missing_feed_is_not_retried_elsewhere(monkeypatch):
    called = []
    monkeypatch.setattr(fetch, "firecrawl_raw", lambda url: called.append(url) or RSS)
    for code, status in (("http_error", 429), ("http_error", 404)):
        monkeypatch.setattr(fetch, "http_get", _boom(code, status))
        raws, st = collect.collect(BY_ID["bleepingcomputer"], {}, NOW)
        assert raws == [] and st["consecutive_failures"] == 1
    assert called == []


def test_a_blocked_feed_is_retried_but_a_json_api_never_is(monkeypatch):
    called = []
    monkeypatch.setattr(fetch, "firecrawl_raw", lambda url: called.append(url) or RSS)
    monkeypatch.setattr(fetch, "http_get", _boom("http_error", 403, "Blocked"))
    raws, _ = collect.collect(BY_ID["bleepingcomputer"], {}, NOW)
    assert len(raws) == 1 and len(called) == 1
    zd = next(s for s in collect.SOURCES if s.parser == "zendesk")     # JSON: rawHtml would corrupt it
    raws, st = collect.collect(zd, {}, NOW)
    assert raws == [] and len(called) == 1 and "403" in st["last_error"]


def test_fallbacks_stop_at_the_daily_cap_and_a_direct_success_clears_degraded(monkeypatch):
    from radar.limits import Limits
    monkeypatch.setattr(fetch, "firecrawl_raw", lambda url: RSS)
    monkeypatch.setattr(fetch, "http_get", _boom("network_error"))
    full = {"fc_fallback_day": NOW.date().isoformat(), "fc_fallbacks": Limits.FEED_FIRECRAWL_FALLBACKS_PER_DAY}
    raws, st = collect.collect(BY_ID["bleepingcomputer"], full, NOW)
    assert raws == [] and st["consecutive_failures"] == 1
    monkeypatch.setattr(fetch, "http_get", lambda *a, **k: fetch.Response(200, RSS))
    raws, st = collect.collect(BY_ID["bleepingcomputer"], {"degraded": "direct network_error/None; served by firecrawl"}, NOW)
    assert len(raws) == 1 and "degraded" not in st


def test_a_source_collected_late_in_its_cycle_is_still_due_one_cadence_later():
    """Audit 01 #12: `last_run` is the collect time, up to minutes into the cycle; with a one-minute slack a 15-minute
    source collected 90 s in was not due at the next 15-minute slot and effectively ran every 20."""
    from datetime import timedelta
    slot = NOW - timedelta(minutes=15)
    late = {"bleepingcomputer": {"last_run": timeutil.iso(slot + timedelta(seconds=90))}}
    assert "bleepingcomputer" in collect.due(late, NOW)
    early = {"bleepingcomputer": {"last_run": timeutil.iso(NOW - timedelta(minutes=10))}}
    assert "bleepingcomputer" not in collect.due(early, NOW)          # still a cadence, not every cycle


def test_first_hand_structured_records_are_polled_within_minutes():
    """R2.3 (measured 2026-11-12: published → held median 48 min). These lists are the first-hand record of an event
    and cheap to poll (one request, 304 when unchanged) — they were at 30 / 60 minutes."""
    most = {"cisa_kev": 5, "chrome_releases": 10, "fortinet_psirt": 10, "defillama_hacks": 10, "slowmist_hacked": 10,
            "cisa_csaf_ot": 30, "cisa_csaf_it": 30, "defihacklabs": 30, "cve_list": 5}
    slow = {sid: BY_ID[sid].cadence_min for sid, m in most.items() if BY_ID[sid].cadence_min > m}
    assert not slow, slow
