"""MySQL CVE-2026-114952 (live 2026-11-17..20) was never pushed.

- CVSS 9.1, unauthenticated; its CVE record and two public exploit listings were all catalog sources ⇒ 0 independent
  reporters ⇒ path A never fired and the event stayed P1 (PoC). Now a critical flaw with a public exploit for a CVE the
  radar saw filed is P0 (pipeline._fresh_exploit).
- SlowMist's T1 alert on X and PANews' copy were classified web3 (「unauthenticated attacker … compromise」 read as a
  theft word), were not eventful, and never reached the event. Now a CVE story is a vulnerability unless it is a crypto
  theft (an attack word AND a crypto word: pipeline._crypto_theft).
"""
from __future__ import annotations

from radar import pipeline
from radar.model import Item

SLOWMIST = ("🚨 SlowMist TI Alert 🚨 A critical vulnerability (CVE-2026-114952, CVSS 9.1) has been identified in Oracle "
            "MySQL Server. Easily exploitable: an unauthenticated attacker with network access can compromise MySQL Server.")
PANEWS = "慢雾：Oracle MySQL Server及MySQL Cluster存在严重漏洞（CVE-2026-114952，CVSS评分9.1）。未认证攻击者可能借此入侵受影响系统。"
THEFT = "Vault drained of $12M on-chain; the attacker exploited CVE-2026-1111 in the bridge contract"


def test_a_web3_handles_cve_alert_is_a_vulnerability():
    assert pipeline._classify("web3", SLOWMIST, True) == "vuln"


def test_a_crypto_outlets_cve_story_is_a_vulnerability():
    assert pipeline._classify(None, PANEWS, True, crypto_source=True) == "vuln"


def test_a_crypto_theft_naming_a_cve_stays_web3():
    assert pipeline._classify("web3", THEFT, True) == "web3"
    assert pipeline._classify(None, THEFT, True, crypto_source=True) == "web3"


def test_a_crypto_outlets_theft_without_a_cve_is_unchanged():
    t = "某 DeFi 协议漏洞被利用，链上损失 500 万美元"
    assert pipeline._classify(None, t, False, crypto_source=True) == "web3"


def _item(src: str, poc: bool = False) -> Item:
    return Item(item_id=f"it_{src}", source_id=src, tier="T1", org=src, domain="vuln", url=f"https://x/{src}",
                canonical_url=f"https://x/{src}", title="CVE-2026-114952", text="", published_at="2026-11-19T10:56:00Z",
                fetched_at="2026-11-19T10:56:00Z", content_hash=src, keys=["cve:CVE-2026-114952"], links=[], entity=None,
                eventful=True, signals={"exploited": "unclear", "kev": False, "poc": poc, "amount_usd": None}, extra={})


def test_a_public_exploit_for_a_newly_filed_cve_corroborates():
    assert pipeline._fresh_exploit([_item("cve_list"), _item("sploitus", poc=True)], "poc")


def test_an_old_cves_exploit_listing_alone_does_not():
    # a GitHub PoC of an old CVE: no CVE List record in the event
    assert not pipeline._fresh_exploit([_item("sploitus", poc=True)], "poc")


def test_a_new_cve_without_an_exploit_does_not():
    assert not pipeline._fresh_exploit([_item("cve_list")], "none")


def test_the_mysql_event_is_p0():
    """The live event's three reports (CVE record + two exploit listings, all catalogs), recomputed: P0, not P1."""
    from datetime import UTC, datetime

    from radar.model import Event

    rec = _item("cve_list")
    rec.text = ("Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple "
                "protocols to compromise MySQL Server. CVSS 3.1 Base Score 9.1 (Confidentiality and Integrity impacts).")
    rec.published_at = rec.fetched_at = "2026-11-17T21:32:07Z"
    a, b = _item("sploitus", poc=True), _item("sploitus2", poc=True)
    b.source_id, b.title = "sploitus", "MySQL Server: Auth Bypass exploit"
    a.tier = b.tier = "T2"
    ev = Event(event_id="ev_mysql", domain="vuln", title=rec.title, first_seen=rec.published_at,
               last_updated=a.published_at, item_ids=[rec.item_id, a.item_id, b.item_id], keys=["cve:CVE-2026-114952"],
               cves=["CVE-2026-114952"])
    out = pipeline.recompute(ev, [rec, a, b], datetime(2026, 11, 19, 12, tzinfo=UTC))
    assert out.exploitation == "poc" and out.severity == "P0"
