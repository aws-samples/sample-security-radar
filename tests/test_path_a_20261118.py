"""Path A to P0 (Neo 2026-11-18: 「爆出来就应该挺重要」): a critical flaw (unauthenticated RCE or CVSS ≥ 9) reported by
≥ 2 independent reporting sources is P0 when disclosed; catalog listings (CVE records, exploit catalogs) are not reports.
30-day backtest: counting catalogs → +118 P0s (49 on Oracle's patch day); reporting sources only → +15."""
from datetime import UTC, datetime

from test_pipeline_replay import _raw

from radar import pipeline, signals
from radar.registry import BY_ID, CATALOG_SOURCES
from radar.store import MemoryStore

NOW = datetime(2026, 11, 17, 23, 30, tzinfo=UTC)
CVE = "CVE-2026-114938"


def _ingest(*raws):
    store = MemoryStore()
    pipeline.ingest(list(raws), store, NOW)
    return next(e for e in store.events.values() if CVE in e["cves"])


RECORD = _raw("cve_list", f"{CVE} Vulnerability in the Oracle Java SE product",
              "Easily exploitable vulnerability allows unauthenticated attacker with network access to compromise "
              "Java SE. CVSS 3.1 Base Score 9.8.", extra={"cves": [CVE]}, when="2026-11-17T21:32:00Z")
EXPLOITDB = _raw("sploitus", f"Exploit for {CVE}",
                 f"Exploit for {CVE}: unauthenticated remote code execution in Oracle Java SE.", extra={"cves": [CVE]},
                 when="2026-11-17T21:50:00Z")
CATALOG = _raw("cvefeed", f"{CVE} - Oracle Java SE unauthenticated remote code execution",
               f"{CVE}: an unauthenticated attacker can achieve remote code execution in Oracle Java SE (CVSS 9.8).",
               extra={"cves": [CVE]}, when="2026-11-17T21:40:00Z")
THN = _raw("thehackernews", f"Critical OpenJDK RCE ({CVE}) Report Emerges",
           f"Reports warn of an unauthenticated remote code execution flaw in OpenJDK ({CVE}, CVSS 9.2).",
           extra={"cves": [CVE]}, when="2026-11-17T15:17:00Z")
BLEEP = _raw("bleepingcomputer", f"Critical Java4Shell flaw allows RCE attacks on major Java apps ({CVE})",
             f"The pre-auth remote code execution flaw {CVE} affects OpenJDK 17 and later.",
             extra={"cves": [CVE]}, when="2026-11-17T23:04:00Z")


def test_two_reporting_sources_make_a_critical_flaw_p0_before_any_exploitation():
    e = _ingest(THN, BLEEP)
    assert e["exploitation"] == "none" and e["severity"] == "P0"


def test_a_record_and_a_catalog_listing_are_not_two_reports():
    """Oracle's patch day, 11-17: dozens of CVSS 9.8 records, each also in an exploit catalog — not P0s."""
    e = _ingest(RECORD, CATALOG, EXPLOITDB)
    assert len(e["item_ids"]) == 2 and e["severity"] != "P0"     # cvefeed + sploitus: two T2 catalogs


def test_one_reporting_source_is_not_enough():
    e = _ingest(RECORD, THN)
    assert e["severity"] != "P0"


def test_the_critical_claim_is_read_and_its_negation_is_not():
    assert signals._critical_sentence("an unauthenticated remote code execution flaw in OpenJDK") == "yes"
    assert signals._critical_sentence("The bug carries a CVSS score of 9.8.") == "yes"
    assert signals._critical_sentence("It does not allow unauthenticated remote code execution.") == "no"
    assert signals._critical_sentence("A CVSS 7.5 denial of service.") == "unclear"


def test_every_catalog_source_is_registered():
    assert CATALOG_SOURCES <= set(BY_ID)
