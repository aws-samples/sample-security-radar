"""Collect station criteria: scheduling, failure recording (降级留痕), conditional GET, PoC enrichment."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from radar import collect, fetch
from radar.registry import BY_ID

NOW = datetime(2026, 10, 23, 4, 0, tzinfo=UTC)
SNAP = Path(__file__).parent / "fixtures" / "snapshots" / "2026-10-23"


def test_due_respects_cadence_and_never_run():
    states = {"cisa_kev": {"last_run": "2026-10-23T03:45:00Z"}, "bleepingcomputer": {"last_run": "2026-10-23T03:45:00Z"}}
    d = collect.due(states, NOW)
    assert "cisa_kev" not in d          # 30-min cadence, ran 15 min ago
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
    raws, st = collect.collect(BY_ID["bleepingcomputer"], {}, NOW)
    assert raws == [] and st["consecutive_failures"] == 1 and "parse_empty" in st["last_error"]


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
