"""R2.4 (audit 01 #6): the X search reaches back to the last successful run, and a search the page limit cut is said."""
import json

import pytest

from radar import fetch
from radar.limits import Limits


@pytest.fixture
def api(monkeypatch):
    calls = []
    pages = {"n": 0, "more": True}

    def get(url, key):
        calls.append(url)
        pages["n"] += 1
        return json.dumps({"tweets": [{"id": str(pages["n"])}], "has_next_page": pages["more"], "next_cursor": "c"})
    monkeypatch.setattr(fetch, "secrets", lambda: {"X_API_KEY": "k"})
    monkeypatch.setenv("X_SEARCH_URL", "https://x-data.example/search")
    monkeypatch.setattr(fetch, "_twitterapi_get", get)
    monkeypatch.setattr(fetch.time, "sleep", lambda s: None)
    return calls, pages


def _hours(url):
    import urllib.parse
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["query"][0]
    return int(q.rsplit("within_time:", 1)[1].rstrip("h"))


def test_the_window_reaches_back_to_the_last_success_and_is_capped(api):
    calls, _ = api
    fetch.twitterapi_search(("a",), 60)
    fetch.twitterapi_search(("a",), 60, since_minutes=5 * 60)
    fetch.twitterapi_search(("a",), 60, since_minutes=3 * 24 * 60)
    assert [_hours(calls[i]) for i in (0, 2, 4)] == [2, 6, Limits.X_WINDOW_MAX_H]


def test_a_search_the_page_limit_cut_says_so(api):
    _, pages = api
    assert json.loads(fetch.twitterapi_search(("a",), 60, max_pages=2)).get("truncated") is True
    pages["more"] = False
    assert "truncated" not in json.loads(fetch.twitterapi_search(("a",), 60, max_pages=2))
