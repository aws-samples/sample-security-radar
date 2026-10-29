"""Unit criteria for deterministic extraction. Each case is a real string shape seen in a source."""

import pytest

from radar import keys, signals, timeutil


def test_x_snowflake_time_matches_twitterapi_created_at():
    # SlowMist WAX alert: the X data source createdAt "Thu Oct 22 15:23:14 +0000 2026"
    assert timeutil.iso(timeutil.x_status_time("2113290086808990182")) == "2026-10-22T15:23:14Z"


@pytest.mark.parametrize("raw,expected", [
    ("2026-10-18", "2026-10-18T00:00:00Z"),
    ("20261018", "2026-10-18T00:00:00Z"),
    ("Fri Oct 23 03:39:57 +0000 2026", "2026-10-23T03:39:57Z"),
    ("Thu, 22 Oct 2026 10:53:08 +0800", "2026-10-22T02:53:08Z"),
    ("2026-10-22T19:06:41.000Z", "2026-10-22T19:06:41Z"),
    (1790208000, "2026-09-24T00:00:00Z"),
])
def test_time_parse_shapes(raw, expected):
    assert timeutil.iso(timeutil.parse(raw)) == expected


def test_time_parse_garbage_is_none_not_now():
    assert timeutil.parse("not a date") is None


def test_canonical_url():
    assert keys.canonical_url("https://www.Twitter.com/SlowMist_Team/status/123/?utm_source=x#frag") == \
        "https://x.com/SlowMist_Team/status/123"
    assert keys.canonical_url("https://example.com/a?id=1&utm_medium=rss") == "https://example.com/a?id=1"


def test_cve_extraction_normalises_case_and_dedupes():
    assert keys.cves("cve-2026-41940 and CVE-2026-41940, CVE-2025-1234567") == ["CVE-2025-1234567", "CVE-2026-41940"]


def test_tx_refs_infer_chain_from_explorer():
    t = keys.tx_refs("// Attack Tx : https://bscscan.com/tx/0x824b83f94bdc2e69b81f1cb2dfdf9d4aeed066114e3de29e3af59bd2d9355fc2")
    assert t == [{"chain": "bsc", "hash": "0x824b83f94bdc2e69b81f1cb2dfdf9d4aeed066114e3de29e3af59bd2d9355fc2",
                  "explorer_url": "https://bscscan.com/tx/0x824b83f94bdc2e69b81f1cb2dfdf9d4aeed066114e3de29e3af59bd2d9355fc2"}]


def test_bare_hex_is_not_a_tx():
    assert keys.tx_refs("slot 0x824b83f94bdc2e69b81f1cb2dfdf9d4aeed066114e3de29e3af59bd2d9355fc2") == []


@pytest.mark.parametrize("name,expected", [
    ("AlpsCon AI Trade Hub", "alpscon"), ("AlpsCon", "alpscon"), ("WAX Multi-Chain Bridge", "wax"),
    ("@WAX_io", "wax"), ("Ledger (Supply Chain)", "ledger"), ("Bitget", "bitget"), ("The DeFi Protocol", None),
])
def test_entity_key(name, expected):
    assert keys.entity_key(name) == expected


@pytest.mark.parametrize("text,expected", [
    ("Google is aware that an exploit for CVE-2026-1111 exists in the wild.", "yes"),
    ("Fortinet has observed this to be exploited in the wild.", "yes"),
    ("Microsoft: Exploited:Yes", "yes"),
    ("Apple is aware of a report that this issue may have been exploited", "yes"),
    ("该漏洞已发现在野利用", "yes"),
    ("There is no evidence of exploitation in the wild at this time.", "no"),
    ("We are not aware of any active exploitation.", "no"),
    ("目前未发现在野利用", "no"),
    ("A new version fixes a heap overflow.", "unclear"),
    ("", "unclear"),
])
def test_exploited_with_negation(text, expected):
    assert signals.exploited(text) == expected


@pytest.mark.parametrize("text,expected", [
    ("$ 90,500", 90500), ("Loss: ~$90.5K", 90500), ("$387.5 million stolen", 387_500_000),
    ("约 3.2 亿美元", 320_000_000), ("-", None), ("We have seen a ~$820K exploit", 820_000),
    ("drained $1.2M then $300K more", 1_200_000),
])
def test_parse_amount(text, expected):
    assert signals.parse_amount(text) == pytest.approx(expected) if expected else signals.parse_amount(text) is None
