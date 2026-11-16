"""R2.7: VMware advisories through Broadcom's support portal list API (a POST; no feed since the move to Broadcom).
Snapshot = the live answer of 2026-11-15 to the radar's Lambda (six newest VMware Cloud Foundation advisories)."""
import json
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from radar import collect, fetch, parsers
from radar.registry import BY_ID

BODY = (Path(__file__).parent / "fixtures" / "snapshots" / "2026-11-15" / "broadcom.json").read_text()


def test_each_advisory_is_an_item_with_its_cves_day_and_page():
    rows = parsers.broadcom(BODY, "broadcom_vmsa")
    assert [r.guid for r in rows] == [v["documentId"] for v in json.loads(BODY)["data"]["list"]]
    r = next(x for x in rows if x.guid == "VCDSA38017")
    assert r.extra["cves"] == ["CVE-2026-59309", "CVE-2026-59310", "CVE-2026-47876", "CVE-2026-41703", "CVE-2026-41709"]
    assert r.published_at == datetime(2026, 7, 29, tzinfo=UTC) and r.title.startswith("VMSA-2026-0006.1:")
    assert r.url.startswith("https://support.broadcom.com/") and "CRITICAL" in r.text and r.extra["entity"] == "VMware"


def test_a_row_without_an_id_or_a_day_is_handled():
    body = json.dumps({"data": {"list": [{"title": "x"}, {"documentId": "D1", "published": "soon", "title": "t"}]}})
    rows = parsers.broadcom(body, "broadcom_vmsa")
    assert [r.guid for r in rows] == ["D1"] and rows[0].published_at is None and rows[0].extra["cves"] == []


def test_the_source_is_fetched_as_a_json_post_without_conditional_headers(monkeypatch):
    seen = {}

    class R:
        status, headers = 200, type("H", (), {"get": lambda s, k, d=None: None, "get_content_charset": lambda s: "utf-8"})()

        def read(self, n):
            return BODY.encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def urlopen(req, timeout, allow_hosts=None):
        seen["req"] = req
        return R()
    monkeypatch.setattr(fetch, "urlopen", urlopen)
    src = BY_ID["broadcom_vmsa"]
    collect._body(src, {"etag": '"x"', "last_modified": "Wed"}, datetime(2026, 11, 15, tzinfo=UTC))
    req: urllib.request.Request = seen["req"]
    assert req.get_method() == "POST" and json.loads(req.data)["segment"] == "VC"
    assert req.get_header("Content-type") == "application/json" and req.get_header("If-none-match") is None
    assert req.get_header("User-agent") == fetch.UA                    # Cloudflare answers 403 without one (probed)
