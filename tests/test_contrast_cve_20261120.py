"""A CVE named only to set it apart is not the report's (live 2026-11-19, vCenter CVE-2026-123890).

Rapid7 wrote "CVE-2026-123890 is distinct from the vCenter authentication bypass vulnerability CVE-2026-59309 that
Broadcom addressed earlier in 2026"; the older CVE became the event's, the page called the new zero-day 「旧漏洞，公开
112 天后」 and the sent P0 notice was edited to list it.
"""
from __future__ import annotations

from datetime import UTC, datetime

from radar import cvemeta, keys, pipeline
from radar.model import RawItem

RAPID7 = ("Mandiant confirmed in-the-wild exploitation of CVE-2026-123890 as early as September 2026. "
          "CVE-2026-123890 is distinct from the vCenter authentication bypass vulnerability CVE-2026-59309 that "
          "Broadcom addressed earlier in 2026.")


def test_contrasted_cve_is_dropped_when_another_is_named_plainly():
    assert keys.contrast_only(RAPID7) == {"CVE-2026-59309"}


def test_a_cve_also_named_plainly_stays():
    t = RAPID7 + " Patch CVE-2026-59309 too if you have not."
    assert keys.contrast_only(t) == set()


def test_a_lone_contrasted_cve_stays():
    # nothing else says what the report is about
    assert keys.contrast_only("This bug is unlike CVE-2021-44228 in scope.") == set()


def test_the_phrase_must_be_in_the_same_sentence():
    t = "CVE-2026-3333 is patched. Unlike last year, it was fast. CVE-2026-1111 is fixed too."
    assert keys.contrast_only(t) == set()


def test_chinese_contrast():
    assert keys.contrast_only("CVE-2026-123890 不同于此前修复的 CVE-2026-59309。") == {"CVE-2026-59309"}


def test_normalize_keys_only_the_reported_cve():
    raw = RawItem(source_id="rapid7", url="https://www.rapid7.com/blog/post/etr-cve-2026-123890",
                  title="CVE-2026-123890: Critical Authentication Bypass in VMware vCenter", text=RAPID7,
                  published_at=datetime(2026, 11, 19, 21, 6, tzinfo=UTC), guid="r7")
    it = pipeline.normalize(raw, pipeline.BY_ID["rapid7"], datetime(2026, 11, 19, 21, 10, tzinfo=UTC))
    assert [k for k in it.keys if k.startswith("cve:")] == ["cve:CVE-2026-123890"]


def test_disclosure_uses_the_cve_the_title_names():
    meta = {"CVE-2026-123890": {"published": "2026-11-19T14:02:38Z", "assigner": "vmware"},
            "CVE-2026-59309": {"published": "2026-07-30T12:19:00Z", "assigner": "vmware"}}
    d = cvemeta.disclosure(["CVE-2026-123890", "CVE-2026-59309"], meta, "2026-11-19T14:02:38Z",
                           "CVE-2026-123890 vCenter authentication-bypass vulnerability")
    assert d is not None and d["cve"] == "CVE-2026-123890" and not d["resurfaced"]
    # a title naming no CVE keeps the earliest (unchanged behaviour)
    d = cvemeta.disclosure(["CVE-2026-123890", "CVE-2026-59309"], meta, "2026-11-19T14:02:38Z", "vCenter flaw")
    assert d is not None and d["cve"] == "CVE-2026-59309"
