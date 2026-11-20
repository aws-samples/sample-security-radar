"""R9.6 (live 2026-11-19, four team-channel notices withdrawn): a catalog announcement — 「CISA Adds Four Known Exploited
Vulnerabilities to Catalog」 (a roundup: it attaches through its CVEs but lends none) and CISA's X post 「We added 4
CVEs to our Known Exploited Vulnerabilities Catalog」 (no CVE id at all) — each opened a vulnerability event naming no
CVE, and "exploitation confirmed" by an official source made it P0. Such an event is no single vulnerability: P2."""
from datetime import UTC, datetime

from test_pipeline_replay import _raw

from radar import pipeline
from radar.store import MemoryStore

NOW = datetime(2026, 11, 18, 21, 0, tzinfo=UTC)

ROUNDUP = _raw("cisa_advisories", "CISA Adds Four Known Exploited Vulnerabilities to Catalog",
               "CISA has added four new vulnerabilities to its Known Exploited Vulnerabilities (KEV) Catalog, based on "
               "evidence of active exploitation. CVE-2024-10441 Synology DiskStation Manager Improper Encoding; "
               "CVE-2026-90817 REDCap Code Injection; CVE-2026-90001 LiteLLM; CVE-2026-90002 Apache Axis.",
               extra={"cves": ["CVE-2024-10441", "CVE-2026-90817", "CVE-2026-90001", "CVE-2026-90002"]},
               when="2026-11-18T12:00:00Z")
X_POST = _raw("x_security", "We added 4 CVEs to our Known Exploited Vulnerabilities Catalog. Visit & apply mitigations to protect your organization",
              "We added 4 CVEs to our Known Exploited Vulnerabilities Catalog. Visit & apply mitigations to protect your "
              "organization: https://cisa.gov/kev #Cybersecurity", author="CISACyber",   # registry: T1 official handle
              extra={"x_status": "2123146190355148868"}, when="2026-11-18T20:07:00Z")


def _events(*raws):
    store = MemoryStore()
    pipeline.ingest(list(raws), store, NOW)
    return list(store.events.values())


def test_a_kev_roundup_alone_is_no_p0():
    evs = [e for e in _events(ROUNDUP) if not e["cves"]]
    assert evs and all(e["severity"] == "P2" for e in evs)


def test_cisas_list_post_naming_no_cve_is_no_p0():
    evs = [e for e in _events(X_POST) if e["domain"] == "vuln"]
    assert evs and all(e["severity"] == "P2" and not e["cves"] for e in evs)


def test_a_report_of_one_exploited_vulnerability_keeps_its_severity():
    one = _raw("thehackernews", "CISA adds REDCap flaw CVE-2026-90817 to KEV after active exploitation",
               "CISA added CVE-2026-90817, a REDCap code injection flaw that lets an unauthenticated attacker run code, "
               "to its Known Exploited Vulnerabilities catalog after attacks in the wild.",
               extra={"cves": ["CVE-2026-90817"]}, when="2026-11-18T13:00:00Z")
    e = next(e for e in _events(one) if "CVE-2026-90817" in e["cves"])
    assert e["severity"] in ("P0", "P1")      # the cap is only for events that name no CVE



def test_a_story_about_one_flaw_that_mentions_kev_is_not_a_list():
    """Live recompute 2026-11-19: 「QNAP Warns Users as Plex2Shell Flaws Are Used to Hack NAS Devices」 (no CVE yet) was
    caught by the broad KEV wording; a list is a COUNT of added entries."""
    qnap = _raw("thehackernews", "QNAP Warns Users as Plex2Shell Flaws Are Used to Hack NAS Devices",
                "QNAP warns that the Plex2Shell flaws are being used to hack NAS devices; CISA added the flaws to its "
                "Known Exploited Vulnerabilities catalog on Tuesday.", when="2026-11-18T10:00:00Z")
    from radar.registry import BY_ID
    it = pipeline.normalize(qnap, BY_ID["thehackernews"], NOW)
    assert not pipeline.is_list_announcement(it)
    for title in ("CISA Adds Six Known Exploited Vulnerabilities to Catalog",
                  "We added 4 CVEs to our Known Exploited Vulnerabilities Catalog. Visit & apply mitigations"):
        assert pipeline.LIST_ANNOUNCE_RE.search(title), title
