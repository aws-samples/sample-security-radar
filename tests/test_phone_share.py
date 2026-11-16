"""ROADMAP R3.6 veto data: page opens by device from CloudFront standard logs (scripts/phone_share.py)."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("phone_share", Path(__file__).resolve().parents[1] / "scripts" / "phone_share.py")
ps = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ps)

HEAD = "#Version: 1.0\n#Fields: date time x-edge-location sc-bytes c-ip cs-method cs(Host) cs-uri-stem sc-status cs(Referer) cs(User-Agent)"
IPHONE = "Mozilla/5.0%20(iPhone;%20CPU%20iPhone%20OS%2018_0%20like%20Mac%20OS%20X)%20Mobile/15E148"
MAC = "Mozilla/5.0%20(Macintosh;%20Intel%20Mac%20OS%20X%2010_15_7)%20Chrome/140.0"


def row(uri, status, ua, method="GET"):
    return f"2026-11-15\t05:00:00\tNRT57\t100\t1.2.3.4\t{method}\td.cloudfront.net\t{uri}\t{status}\t-\t{ua}"


def test_only_page_loads_count_and_by_device():
    lines = [*HEAD.split("\n"), row("/", "200", IPHONE), row("/index.html", "304", MAC), row("/", "401", IPHONE),
             row("/assets/index-x.js", "200", IPHONE), row("/", "200", "python-requests/2.32"), row("/", "200", MAC, "HEAD")]
    assert ps.opens(lines) == {"phone": 1, "desktop": 1, "bot": 1}     # 401 = the auth prompt; assets and HEAD are not opens


def test_device_kinds():
    assert ps.kind(IPHONE) == "phone" and ps.kind(MAC) == "desktop"
    assert ps.kind("Mozilla/5.0%2520(iPad;%2520CPU%2520OS%252018_0)") == "tablet"     # double-encoded spaces
    assert ps.kind("Mozilla/5.0 (Linux; Android 15; Pixel 9) Mobile Safari") == "phone"
    assert ps.kind("Mozilla/5.0 (Linux; Android 15; SM-X910)") == "tablet"
