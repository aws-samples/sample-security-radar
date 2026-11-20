"""The vCenter P0 waited ~5 h (live 2026-11-19, CVE-2026-123890): three reports that would have made it P0 were not
attached to the CVE's event.

- VMSA-2026-0009 (Broadcom, T1, CRITICAL) lists 5 CVEs ⇒ the > 3 roundup rule gave it no CVE key;
- GTIG's ARMORY CASTLE report names 4 CVEs (CVE-2026-123890 ×10) ⇒ no CVE key either;
- 「A critical 9.8-rated VMware vCenter flaw」 was not read as critical (only 「CVSS 9.8」 was).
"""
from __future__ import annotations

from datetime import UTC, datetime

from radar import keys, pipeline, signals
from radar.limits import Limits
from radar.model import RawItem

NOW = datetime(2026, 11, 19, 16, 0, tzinfo=UTC)
FIVE = ", ".join(f"CVE-2026-12389{i}" for i in range(5))


def _keys(source_id: str, title: str, text: str) -> list[str]:
    raw = RawItem(source_id=source_id, url=f"https://example.org/{source_id}/1", title=title, text=text,
                  published_at=NOW, guid=f"{source_id}-1")
    return sorted(k for k in pipeline.normalize(raw, pipeline.BY_ID[source_id], NOW).keys if k.startswith("cve:"))


def test_a_vendor_advisory_keys_every_cve_it_lists():
    got = _keys("broadcom_vmsa", f"VMSA-2026-0009: VMware vCenter updates address multiple vulnerabilities ({FIVE})",
                "CRITICAL · VMware Cloud Foundation")
    assert got == [f"cve:CVE-2026-12389{i}" for i in range(5)]


def test_a_bundle_source_still_keys_nothing_for_many_cves():
    # Chrome stable releases list unrelated flaws: not an advisory source
    got = _keys("chrome_releases", "Stable Channel Update for Desktop", f"Security fixes: {FIVE}")
    assert got == []


def test_an_advisory_listing_too_many_cves_keys_nothing():
    many = ", ".join(f"CVE-2026-2{i:04d}" for i in range(Limits.ADVISORY_MAX_CVES + 1))
    assert _keys("pan_psirt", "PAN-OS bundled publication", many) == []


def test_a_vendor_bundle_of_third_party_flaws_is_not_one_advisory():
    # replay 2026-11-20: Cisco's 「Vulnerabilities in Node.js and Brotli Affecting Cisco Products」 glued Node.js CVEs
    # into the Brotli event
    got = _keys("cisco_psirt", "Vulnerabilities in Node.js and Brotli Affecting Cisco Products: October 2026", FIVE)
    assert got == []


GTIG = ("ARMORY CASTLE exploited CVE-2026-102764 in October. " + "They exploited CVE-2026-123890 in vCenter. " * 10
        + "It overlaps with CVE-2026-59309. " * 4 + "Earlier, CVE-2025-22457 was used.")


def test_a_report_about_one_of_many_cves_keys_that_one():
    assert keys.dominant(GTIG, Limits.DOMINANT_MIN_MENTIONS, Limits.DOMINANT_RATIO) == "CVE-2026-123890"
    assert _keys("gtig", "ARMORY CASTLE Exploits vSphere", GTIG) == ["cve:CVE-2026-123890"]


def test_a_roundup_has_no_dominant_cve():
    roundup = " ".join(f"CVE-2026-3{i:04d} was added." for i in range(6))
    assert keys.dominant(roundup, Limits.DOMINANT_MIN_MENTIONS, Limits.DOMINANT_RATIO) is None


def test_dominance_needs_the_ratio():
    t = "CVE-2026-1 " * 5 + "CVE-2026-2 " * 3 + "CVE-2026-3 CVE-2026-4"
    t = t.replace("CVE-2026-1 ", "CVE-2026-1111 ").replace("CVE-2026-2 ", "CVE-2026-2222 ")
    t = t.replace("CVE-2026-3 ", "CVE-2026-3333 ").replace("CVE-2026-4", "CVE-2026-4444")
    assert keys.dominant(t, Limits.DOMINANT_MIN_MENTIONS, Limits.DOMINANT_RATIO) is None     # 5 < 2 × 3


def test_dominance_needs_the_minimum():
    t = "CVE-2026-1111 CVE-2026-1111 CVE-2026-2222 CVE-2026-3333 CVE-2026-4444"
    assert keys.dominant(t, Limits.DOMINANT_MIN_MENTIONS, Limits.DOMINANT_RATIO) is None     # 2 < 3


def test_rated_scores_are_critical():
    assert signals._critical_sentence("A critical 9.8-rated VMware vCenter flaw lets attackers bypass auth") == "yes"
    assert signals._critical_sentence("The bug is rated 9.1 out of 10") == "yes"
    assert signals._critical_sentence("It carries a severity score of 10.0") == "yes"


def test_lower_or_unrelated_numbers_are_not():
    for t in ("a 7.5-rated bug", "version 19.8-rated", "rated 99.1", "rated 8.8 out of 10"):
        assert signals._critical_sentence(t) == "unclear", t


def test_a_multi_vendor_vulnerability_note_is_not_one_advisory():
    # VU#604762 「Multiple vendors vulnerable to …」: 5 CVEs of different vendors (28-day replay, 2026-11-20)
    got = _keys("certcc_vu", "VU#604762: Multiple vendors vulnerable to Unicode Normalization Collision", FIVE)
    assert got == []
