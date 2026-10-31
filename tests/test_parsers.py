"""Parser criteria against real snapshots captured 2026-10-23 (tests/fixtures/snapshots/2026-10-23).
Expected values are facts cross-checked in docs/research/03 + 05, not parser output pasted back."""

import json
from pathlib import Path

import pytest

from radar import parsers, timeutil

SNAP = Path(__file__).parent / "fixtures" / "snapshots" / "2026-10-23"
TW = Path(__file__).parent / "fixtures" / "x_search" / "advanced_search_3handles_20261023.json"


def _read(name: str) -> str:
    return (SNAP / name).read_text()


def _by_entity(items, prefix):
    hits = [i for i in items if (i.extra.get("entity") or "").lower().startswith(prefix.lower())]
    assert hits, f"no item with entity starting {prefix!r}"
    return hits


def test_defillama_known_incidents():
    items = parsers.defillama(_read("defillama.json"), "defillama_hacks")
    assert len(items) == 141
    bitget = [i for i in _by_entity(items, "Bitget") if i.extra["amount_usd"] == 387_000_000]
    assert bitget and timeutil.iso(bitget[0].published_at) == "2026-09-24T00:00:00Z"
    wax = _by_entity(items, "WAX")[0]
    assert wax.extra["amount_usd"] == 90_500 and timeutil.iso(wax.published_at) == "2026-10-22T00:00:00Z"
    alps = _by_entity(items, "AlpsCon")[0]
    assert alps.extra["amount_usd"] == pytest.approx(152_809.36)
    ledger = _by_entity(items, "Ledger (Supply Chain)")[0]
    assert ledger.extra["amount_usd"] == 93_000_000 and ledger.extra["chains"] == []


def test_slowmist_wax_links_to_slowmist_tweet():
    items = parsers.slowmist(_read("slowmist.html"), "slowmist_hacked")
    assert len(items) >= 10
    wax = _by_entity(items, "WAX Multi-Chain Bridge")[0]
    assert timeutil.iso(wax.published_at) == "2026-10-22T00:00:00Z"
    assert wax.extra["amount_usd"] == 90_500
    assert wax.links == ["https://x.com/SlowMist_Team/status/2113290086808990182"]


def test_slowmist_exchange_has_bitget():
    items = parsers.slowmist(_read("slowmist_exchange.html"), "slowmist_hacked")
    bitget = _by_entity(items, "Bitget")[0]
    assert bitget.extra["amount_usd"] == 387_500_000


def test_defihacklabs_readme_and_poc_header():
    body = _read("defihacklabs.md")
    items = parsers.defihacklabs(body, "defihacklabs")
    headers = sum(1 for line in body.splitlines() if line.startswith(("### 20", "### 19")))
    assert headers == 155 and len(items) == headers  # every entry header parses, whatever its Lost shape
    alps = _by_entity(items, "AlpsCon")[0]
    assert timeutil.iso(alps.published_at) == "2026-10-18T00:00:00Z"
    assert alps.extra["sol_url"].endswith("src/test/2026-10/AlpsCon_exp.sol")
    poc = parsers.defihacklabs_poc(_read("AlpsCon_exp.sol"))
    assert poc["attack_tx"][0]["hash"] == "0x824b83f94bdc2e69b81f1cb2dfdf9d4aeed066114e3de29e3af59bd2d9355fc2"
    assert poc["attack_tx"][0]["chain"] == "bsc"
    assert poc["attacker_urls"] == ["https://bscscan.com/address/0x3d9DF7D20D8296286383ffe475aA7b9e548946b2"]


def test_kev_snapshot():
    items = parsers.kev(_read("kev.json"), "cisa_kev")
    assert len(items) == 98
    assert all(i.extra["kev"] and i.extra["cves"][0].startswith("CVE-") for i in items)
    assert all(timeutil.iso(i.published_at) >= "2026-08-01" for i in items)
    # M3: the weakness class rides along (WAF cwe tier); KEV lists it per CVE
    assert sum(1 for i in items if "CWE-22" in i.extra["cwes"]) >= 4 and all(isinstance(i.extra["cwes"], list) for i in items)


def test_twitterapi_fixture():
    body = json.dumps(json.loads(TW.read_text())["body"])
    items = parsers.twitterapi(body, "x_security")
    assert len(items) == 5
    wax = next(i for i in items if i.extra["x_status"] == "2113290086808990182")
    assert wax.author == "SlowMist_Team"
    assert timeutil.iso(wax.published_at) == "2026-10-22T15:23:14Z"


@pytest.mark.parametrize("name,min_items", [
    ("bleeping.xml", 10), ("thn.xml", 10), ("securityweek.xml", 5), ("anquanke.xml", 5), ("odaily.xml", 10),
    ("panews.xml", 10), ("fortinet.xml", 10), ("chrome.xml", 10), ("cisa_adv.xml", 6),
])
def test_feeds_parse_with_dates_and_plain_text(name, min_items):
    items = parsers.feed(_read(name), name.split(".")[0])
    assert len(items) >= min_items
    assert all(i.published_at is not None for i in items), "every feed entry must carry a parseable date"
    assert all(i.url.startswith("http") for i in items)
    assert not any("<p>" in i.text or "<div" in i.text for i in items), "markup must be stripped"


def test_real_in_the_wild_items_are_flagged():
    """Fortinet advisory 'reported to be exploited in the wild' and THN PHP2Shell 'broad exploitation in the
    wild' (2026-10-23 snapshots) must both be exploited=yes."""
    from radar import signals
    forti = [i for i in parsers.feed(_read("fortinet.xml"), "fortinet_psirt") if "exploited in the wild" in i.text]
    assert len(forti) == 1 and signals.exploited(forti[0].text) == "yes"
    thn = [i for i in parsers.feed(_read("thn.xml"), "thehackernews") if "PHP2Shell" in i.title]
    assert thn and signals.exploited(thn[0].text) == "yes"


SNAP30 = Path(__file__).parent / "fixtures" / "snapshots" / "2026-10-30"


@pytest.mark.parametrize("name", ["theblock", "coindesk", "decrypt", "cointelegraph", "defiant", "rekt", "slowmist_medium",
                                  "chainalysis", "trm"])
def test_m4_feeds_parse_with_dates_and_plain_text(name):
    """M4 D5 sources (2026-10-30 snapshots, fetched through firecrawl): crypto media, forensic blogs, rekt."""
    items = parsers.feed((SNAP30 / f"{name}.xml").read_text(), name)
    assert len(items) >= 5
    assert all(i.published_at is not None and i.url.startswith("http") for i in items)
    assert not any("<p>" in i.text or "<div" in i.text for i in items)


def test_binance_announcements_parse_to_dated_entries_with_their_page():
    items = parsers.binance_cms((SNAP30 / "binance_cms.json").read_text(), "binance_announcements")
    assert len(items) == 10
    inc = next(i for i in items if i.title == "Security Incident Update")
    assert inc.url == "https://www.binance.com/en/support/announcement/detail/c5a8729a97ac486d963784d96c5642d7"
    # the page renders "2026-10-29 22:23" in the viewer's time zone; the API value is UTC (Odaily relayed it at 02:24Z)
    assert timeutil.iso(inc.published_at) == "2026-10-30T02:23:22Z"


def test_the_trm_report_is_an_attribution_naming_north_korea():
    from radar import signals
    [trm] = [i for i in parsers.feed((SNAP30 / "trm.xml").read_text(), "trm_blog") if "Binance" in i.title]
    assert signals.phase(trm.title) == "attribution"
    assert signals.attribution_actor(f"{trm.title}\n{trm.text}") == "North Korea (Lazarus / TraderTraitor)"


def test_m4_sources_are_registered_with_their_tier():
    from radar.registry import BY_ID, HANDLES
    want = {"theblock": "T2", "coindesk": "T2", "decrypt": "T2", "cointelegraph": "T2", "thedefiant": "T2", "rekt": "T2",
            "slowmist_medium": "T1", "chainalysis_blog": "T1", "trm_blog": "T1", "binance_announcements": "T1"}
    assert {k: BY_ID[k].tier for k in want} == want
    assert {"embercn", "ai_9684xtpa", "arkham"} <= set(HANDLES)
