"""scripts/source-onboard.py — the onboarding verdict is code: a 200 that parses to nothing, or a feed silent for a
month, never joins the registry (2026-11-09: 10 of 92 candidates answered 200 with 1–3 KB)."""
import base64
import gzip
import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path

spec = importlib.util.spec_from_file_location("onboard", Path(__file__).parents[1] / "scripts" / "source-onboard.py")
ob = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ob)
NOW = datetime(2026, 11, 10, tzinfo=UTC)

RSS = """<?xml version="1.0"?><rss version="2.0"><channel><title>x</title>
<item><title>Hackers exploit zero-day in Fortinet FortiWeb</title><link>https://x/1</link><pubDate>Mon, 09 Nov 2026 10:00:00 GMT</pubDate></item>
<item><title>Weekly product update</title><link>https://x/2</link><pubDate>Sun, 08 Nov 2026 10:00:00 GMT</pubDate></item>
</channel></rss>"""


def _fetched(body, status=200):
    return {"url": "https://x/feed", "status": status, "body": base64.b64encode(gzip.compress(body.encode())).decode()}


def test_a_live_feed_is_ok_and_counts_its_security_items():
    r = ob.judge(_fetched(RSS), NOW)
    assert r["verdict"] == "ok" and r["items"] == 2 and r["security_items"] == 1


def test_a_200_challenge_page_is_empty_not_ok():
    assert ob.judge(_fetched("<html><body>Just a moment...</body></html>"), NOW)["verdict"] == "empty"


def test_a_feed_silent_for_a_month_is_stale():
    assert ob.verdict(200, 5, NOW - timedelta(days=ob.Limits.STALE_DAYS + 1), NOW) == "stale"
    assert ob.verdict(200, 5, NOW - timedelta(days=ob.Limits.STALE_DAYS - 1), NOW) == "ok"


def test_refusals_and_errors_are_told_apart():
    assert ob.verdict(403, 0, None, NOW) == "blocked"
    assert ob.verdict(None, 0, None, NOW) == "failed"
    assert ob.judge({"url": "https://x", "exception": "timed out"}, NOW)["verdict"] == "failed"
