"""R2.7: Microsoft's own CVEs from the Security Update Guide API (sug/v2.0). Snapshot = the live response of
2026-11-15 (four rows of the newest revisions + one row Microsoft marks exploited), trimmed to the fields used."""
import json
from datetime import UTC, datetime
from pathlib import Path

from radar import parsers, pipeline
from radar.limits import Limits
from radar.registry import BY_ID

BODY = (Path(__file__).parent / "fixtures" / "snapshots" / "2026-11-15" / "msrc.json").read_text()
NOW = datetime(2026, 11, 15, 6, 0, tzinfo=UTC)


def test_every_row_is_a_cve_item_with_microsofts_own_facts():
    rows = parsers.msrc(BODY, "msrc")
    assert [r.guid for r in rows] == [v["cveNumber"] for v in json.loads(BODY)["value"]]
    out = next(r for r in rows if r.guid == "CVE-2026-124194")
    assert out.extra["vendor_exploited"] is True and "exploitation detected by Microsoft" in out.text
    assert out.extra["cvss"] == 6.5 and out.extra["cves"] == ["CVE-2026-124194"] and out.extra["entity"] == "Microsoft"
    assert out.url == "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-124194"
    assert out.published_at == datetime(2026, 11, 10, 16, 0, tzinfo=UTC)          # releaseDate, -08:00 → UTC
    assert not any(r.extra["vendor_exploited"] for r in rows if r.guid != "CVE-2026-124194")


def test_a_row_without_a_cve_or_a_score_is_kept_safe():
    body = json.dumps({"value": [{"cveTitle": "no id"}, {"cveNumber": "CVE-2026-1", "baseScore": None}]})
    rows = parsers.msrc(body, "msrc")
    assert [r.guid for r in rows] == ["CVE-2026-1"] and rows[0].extra["cvss"] is None


def test_microsofts_exploited_flag_makes_the_item_exploited_and_opens_an_event_the_rest_corroborate():
    """Like the CVE List: ~100 CVEs each Patch Tuesday must not each open an event — critical or exploited does."""
    src = BY_ID["msrc"]
    items = {r.guid: pipeline.normalize(r, src, NOW) for r in parsers.msrc(BODY, "msrc")}
    hot = items["CVE-2026-124194"]
    assert hot.signals["exploited"] == "yes" and hot.eventful
    cold = items["CVE-2026-119853"]                                                  # 7.8, not exploited
    assert cold.signals["exploited"] != "yes" and not cold.eventful and "cve:CVE-2026-119853" in cold.keys
    crit = parsers.msrc(json.dumps({"value": [{"cveNumber": "CVE-2026-9", "cveTitle": "x", "baseScore": "9.8",
                                               "exploited": "No"}]}), "msrc")[0]
    assert Limits.CVE_LIST_EVENT_CVSS <= 9.8 and pipeline.normalize(crit, src, NOW).eventful


def test_the_source_asks_for_microsofts_own_cves_newest_revision_first():
    s = BY_ID["msrc"]
    assert s.tier == "T1" and s.parser == "msrc" and s.domain == "vuln"
    for part in ("isMariner%20eq%20false", "issuingCna%20eq%20%27Microsoft%27", "$orderBy=latestRevisionDate%20desc", "$top=100"):
        assert part in s.url
