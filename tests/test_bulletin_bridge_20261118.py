"""Live 2026-11-18 02:20 UTC+8: a stale PAN-OS event was pushed to the team channel as a fresh P0.

A Siemens ICS advisory (CISA CSAF, 11-17) listing 23 PAN-OS CVEs named a CVE of two separate events — the 09-10 PAN-OS
PSIRT advisory (P2, not exploited) and the 10-14 KEV entry — and merged them. The merged event took the KEV entry's
"exploited" and its escalation time became the bulletin's (11-17), so a month-old fact looked like a new P0.
Two rules: a long CVE list is not "an advisory covering both" (a bug chain names 2–3 CVEs); and an exploitation rise is
dated by the exploitation evidence, not by the newest report.
"""
from datetime import UTC, datetime

from test_pipeline_replay import _raw

from radar import pipeline
from radar.store import MemoryStore

CVES = [f"CVE-2026-0{n}" for n in (266, 272, 273, 280, 285, 290, 301, 309, 310, 311, 315, 318, 319, 320, 321, 322, 325,
                                    330, 331, 333, 340, 341, 342)]


def _at(s):
    return datetime.fromisoformat(s).astimezone(UTC)


def _psirt_and_kev(store):
    pipeline.ingest([_raw("pan_psirt", "CVE-2026-0309 PAN-OS: Authenticated Command Injection in CLI",
                          "An authenticated command injection in the PAN-OS CLI.", extra={"cves": ["CVE-2026-0309"]},
                          when="2026-09-09T16:00:00Z")], store, _at("2026-09-10T00:00:00Z"))
    pipeline.ingest([_raw("cisa_kev", "CVE-2026-0322 Palo Alto Networks PAN-OS Code Injection Vulnerability",
                          "Palo Alto Networks PAN-OS contains a code injection vulnerability.",
                          extra={"cves": ["CVE-2026-0322"], "kev": True}, when="2026-10-14T00:00:00Z")],
                    store, _at("2026-10-14T04:00:00Z"))


def _event_of(store, cve):
    return next(e for e in store.events.values() if cve in e["cves"])


def test_a_bulletin_listing_23_cves_does_not_merge_two_events():
    store = MemoryStore()
    _psirt_and_kev(store)
    pipeline.ingest([_raw("cisa_csaf_ot", "ICSA-26-202-02 Siemens RUGGEDCOM APE1808 with Palo Alto Networks Virtual NGFW",
                          "Siemens RUGGEDCOM APE1808 devices run Palo Alto Networks Virtual NGFW, affected by: "
                          + ", ".join(CVES) + ".", extra={"cves": CVES}, when="2026-11-17T07:00:00Z")],
                    store, _at("2026-11-17T18:00:00Z"))
    a, b = _event_of(store, "CVE-2026-0309"), _event_of(store, "CVE-2026-0322")
    assert a["event_id"] != b["event_id"]
    assert a["severity"] != "P0"            # the PSIRT event is not exploited


def test_an_exploitation_rise_is_dated_by_its_evidence_not_by_the_newest_report():
    """Even where a merge is legitimate (a two-CVE chain advisory), the exploited fact it brings is the KEV entry's
    (10-14): five weeks later that is not a fresh P0."""
    store = MemoryStore()
    _psirt_and_kev(store)
    pipeline.ingest([_raw("pan_psirt", "PAN-OS: CVE-2026-0309 and CVE-2026-0322 are one bug chain",
                          "CVE-2026-0309 and CVE-2026-0322 chain to root code execution on PAN-OS.",
                          extra={"cves": ["CVE-2026-0309", "CVE-2026-0322"]}, when="2026-11-17T07:00:00Z")],
                    store, _at("2026-11-17T18:00:00Z"))
    e = _event_of(store, "CVE-2026-0322")
    assert "CVE-2026-0309" in e["cves"], "precondition: the chain advisory merged the two events"
    assert e["exploitation"] == "confirmed"
    assert e["escalated_at"] <= "2026-10-14T23:59:59Z" and e["severity"] != "P0"


def test_an_event_made_of_a_list_only_still_says_which_cves_it_is_about():
    store = MemoryStore()
    pipeline.ingest([_raw("cisa_csaf_ot", "ICSA-26-202-02 Siemens RUGGEDCOM APE1808 with Palo Alto Networks Virtual NGFW",
                          "Affected by: " + ", ".join(CVES) + ".", extra={"cves": CVES}, when="2026-11-17T07:00:00Z")],
                    store, _at("2026-11-17T18:00:00Z"))
    (e,) = store.events.values()
    assert set(e["cves"]) == set(CVES)


def test_an_advisory_naming_five_cves_does_not_prove_two_events_one():
    """Below the list size (it still lends its CVEs), but above a bug chain's 2–3: no proof the two events are one."""
    store = MemoryStore()
    _psirt_and_kev(store)
    five = ["CVE-2026-0309", "CVE-2026-0322", "CVE-2026-0330", "CVE-2026-0331", "CVE-2026-0333"]
    pipeline.ingest([_raw("cisa_csaf_ot", "ICSA-26-203-01 Siemens SCALANCE with Palo Alto Networks PAN-OS",
                          "PAN-OS management interface issues " + ", ".join(five) + ".", extra={"cves": five},
                          when="2026-11-17T07:00:00Z")],
                    store, _at("2026-11-17T18:00:00Z"))
    assert _event_of(store, "CVE-2026-0309")["event_id"] != _event_of(store, "CVE-2026-0322")["event_id"]


def test_a_feed_that_gives_only_a_day_is_not_the_first_report_before_a_timed_one():
    """Live 2026-11-18: a Datadog Security Labs post dated 「2026-11-17」 (00:00Z) became Java4Shell's first report, ten
    hours before the first timed one (watchTowr 10:22Z); the notice said 首报 08:00."""
    store = MemoryStore()
    pipeline.ingest([
        _raw("x_security", "watchTowr is aware of reports of a pre-auth RCE in OpenJDK, CVE-2026-114938",
             "watchTowr is aware of public reports of an unauthenticated RCE in OpenJDK (CVE-2026-114938).",
             extra={"cves": ["CVE-2026-114938"]}, when="2026-11-17T10:22:00Z"),
        _raw("datadog_sl", "Java4Shell: Remote Code Execution in OpenJDK (CVE-2026-114938)",
             "Java4Shell is a remote code execution vulnerability in OpenJDK.", extra={"cves": ["CVE-2026-114938"]},
             when="2026-11-17T00:00:00Z"),
    ], store, _at("2026-11-17T23:00:00Z"))
    e = _event_of(store, "CVE-2026-114938")
    assert e["first_seen"] == "2026-11-17T10:22:00Z"


def test_a_report_listing_other_cves_does_not_join_an_event_it_only_names():
    """Live 2026-11-18: USN-9004-2 (an OpenJDK 25 regression notice listing CVE-2026-91415 and others) joined Java4Shell
    through 「OpenJDK」 and became its first report (11:57); the per-event repair was undone by the next full replay."""
    store = MemoryStore()
    pipeline.ingest([_raw("x_security", "watchTowr is aware of reports of a pre-auth RCE in OpenJDK, CVE-2026-114938",
                          "watchTowr is aware of public reports of an unauthenticated RCE in OpenJDK (CVE-2026-114938).",
                          extra={"cves": ["CVE-2026-114938"]}, when="2026-11-17T10:22:00Z")],
                    store, _at("2026-11-17T11:00:00Z"))
    usn = ("It was discovered that the Networking component of OpenJDK 25 did not correctly authenticate users "
           "(CVE-2026-91415). It was discovered that OpenJDK 25 mishandled TLS (CVE-2026-91416, CVE-2026-91417, "
           "CVE-2026-91418).")
    pipeline.ingest([_raw("ubuntu_usn", "USN-9004-2: OpenJDK 25 regression", usn, when="2026-11-17T03:57:30Z")],
                    store, _at("2026-11-17T12:00:00Z"))
    e = _event_of(store, "CVE-2026-114938")
    assert e["first_seen"] == "2026-11-17T10:22:00Z" and len(e["item_ids"]) == 1
