"""CVE-record metadata (cvemeta): the event page states when the CVE was published, not only when the radar saw it.

Live 2026-11-02: CVE-2026-98432 (Linux CNA, published 10-15, scored 9.8 on 10-24) showed only 「首见 10-29」 — the date
The Hacker News reported it — and read as the disclosure date."""
import json
from datetime import UTC, datetime
from pathlib import Path

from radar import cvemeta, pipeline, publish
from radar.model import RawItem
from radar.store import MemoryStore

REC = json.loads((Path(__file__).parent / "fixtures" / "cvemeta" / "CVE-2026-98432.json").read_text())
NOW = datetime(2026, 11, 2, 12, tzinfo=UTC)


def test_the_record_gives_publication_assigner_and_the_cna_score():
    m = cvemeta.parse(REC)
    assert m["published"] == "2026-10-15T12:08:22.205Z" and m["assigner"] == "Linux"
    assert m["cvss"] == 9.8 and m["severity"] == "CRITICAL" and m["cvss_source"] == "cna"


def test_an_adp_score_fills_in_when_the_cna_gave_none():
    rec = {"cveMetadata": {"datePublished": "2026-10-15T00:00:00Z"},
           "containers": {"cna": {}, "adp": [{"providerMetadata": {"shortName": "CISA-ADP"},
                                               "metrics": [{"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]}]}}
    m = cvemeta.parse(rec)
    assert (m["cvss"], m["cvss_source"]) == (7.5, "adp:CISA-ADP")


def test_disclosure_is_the_earliest_publication_and_the_radars_lag_behind_it():
    meta = {"CVE-A": {"published": "2026-10-15T12:00:00Z", "assigner": "Linux"},
            "CVE-B": {"published": "2026-10-20T00:00:00Z", "assigner": "x"}, "CVE-C": {"published": None}}
    d = cvemeta.disclosure(["CVE-B", "CVE-A", "CVE-C"], meta, "2026-10-29T15:57:05Z")
    assert d["cve"] == "CVE-A" and d["assigner"] == "Linux" and d["at"].startswith("2026-10-15T12:00")
    assert d["lag_hours"] == round((14 * 24 + 3 + 57 / 60 + 5 / 3600), 1)
    # radar ahead of the record (a 0-day reported before its CVE was published) is lag 0, never negative
    assert cvemeta.disclosure(["CVE-B"], meta, "2026-10-19T00:00:00Z")["lag_hours"] == 0.0
    assert cvemeta.disclosure(["CVE-C"], meta, "2026-10-29T00:00:00Z") is None
    assert d["resurfaced"] is False
    assert cvemeta.disclosure(["CVE-A"], meta, "2026-12-01T00:00:00Z")["resurfaced"] is True   # 47 days: back, not missed


def _get(calls):
    def get(url):
        calls.append(url)
        return json.dumps(REC)
    return get


def test_refresh_looks_up_once_then_serves_from_the_ledger():
    store, calls = MemoryStore(), []
    out = cvemeta.refresh(store, ["CVE-2026-98432"], NOW, _get(calls))
    assert out["CVE-2026-98432"]["cvss"] == 9.8 and len(calls) == 1
    cvemeta.refresh(store, ["CVE-2026-98432"], NOW, _get(calls))
    assert len(calls) == 1


def test_an_unscored_record_is_read_again_a_day_later():
    store, calls = MemoryStore(), []
    store.put_source_state(cvemeta.KEY, {"CVE-2026-98432": {"published": "2026-10-15T12:08:22Z", "cvss": None,
                                                            "checked_at": "2026-11-02T00:00:00Z"}})
    cvemeta.refresh(store, ["CVE-2026-98432"], NOW, _get(calls))
    assert calls == []
    later = datetime(2026, 11, 3, 1, tzinfo=UTC)
    assert cvemeta.refresh(store, ["CVE-2026-98432"], later, _get(calls))["CVE-2026-98432"]["cvss"] == 9.8
    assert len(calls) == 1


def test_lookups_are_capped_new_cves_first_and_a_failure_leaves_no_entry():
    store, calls = MemoryStore(), []
    store.put_source_state(cvemeta.KEY, {"CVE-OLD": {"published": None, "checked_at": "2026-10-01T00:00:00Z"}})

    def get(url):
        calls.append(url.rsplit("/", 1)[1])
        if url.endswith("CVE-BAD"):
            raise OSError("boom")
        return json.dumps(REC)
    cvemeta.refresh(store, ["CVE-OLD", "CVE-BAD", "CVE-NEW"], NOW, get, limit=2)
    assert calls == ["CVE-BAD", "CVE-NEW"]           # never-seen first; the stale one waits
    led = cvemeta.load(store)
    assert "CVE-BAD" not in led and led["CVE-NEW"]["cvss"] == 9.8


def test_the_time_budget_stops_lookups():
    store, calls = MemoryStore(), []
    ticks = iter([0, 0, 100, 100])
    cvemeta.refresh(store, ["CVE-1", "CVE-2"], NOW, _get(calls), budget_s=60, clock=lambda: next(ticks))
    assert len(calls) == 1


def _vuln_store():
    store = MemoryStore()
    pipeline.ingest([RawItem(source_id="thehackernews", url="https://thehackernews.com/2026/10/linux-tcp.html",
                             title="Linux Kernel TCP Flaw CVE-2026-98432 With 9.8 CVSS Score",
                             text="CVE-2026-98432 remote code execution",
                             published_at=datetime(2026, 10, 29, 15, 57, 5, tzinfo=UTC), guid=None, author=None,
                             links=[], extra={})], store, datetime(2026, 10, 29, 16, tzinfo=UTC))
    return store


def test_the_event_page_states_disclosure_and_the_cve_record():
    store = _vuln_store()
    cvemeta.refresh(store, ["CVE-2026-98432"], NOW, _get([]))
    docs = publish.build(store, NOW)
    [doc] = [d for k, d in docs.items() if k.startswith("events/")]
    assert doc["disclosure"]["at"].startswith("2026-10-15") and doc["disclosure"]["lag_hours"] > 14 * 24
    [cd] = doc["cve_details"]
    assert cd["published_at"].startswith("2026-10-15") and cd["cvss"] == 9.8 and cd["assigner"] == "Linux"


def test_a_full_rebuild_asks_for_every_published_cve():
    """Live 2026-11-02: the full publish collected CVEs from `changed` (None) and blanked EPSS on every event page."""
    store, asked = _vuln_store(), []
    publish.build(store, NOW, None, enrich=lambda cves: asked.extend(cves) or {})
    assert asked == ["CVE-2026-98432"]


def test_ops_lists_a_critical_cve_the_radar_saw_days_after_publication():
    store = _vuln_store()
    cvemeta.refresh(store, ["CVE-2026-98432"], NOW, _get([]))
    late = [i for i in publish.build(store, NOW)["ops.json"]["attention"] if i["code"] == "late_detection"]
    assert len(late) == 1 and "14 天" in late[0]["title"] and "CVE-2026-98432" in late[0]["detail"]
    # same CVE scored below critical ⇒ not a coverage gap worth a queue entry
    led = cvemeta.load(store)
    led["CVE-2026-98432"]["cvss"] = 7.5
    cvemeta.save(store, led, set(led))
    assert not [i for i in publish.build(store, NOW)["ops.json"]["attention"] if i["code"] == "late_detection"]


def test_publish_defers_pages_it_has_no_time_for_most_severe_first():
    store = _vuln_store()
    clock = iter([999, 10])              # time for the first page, then below the reserve
    deferred = []
    docs = publish.build(store, NOW, None, time_left=lambda: next(clock, 0), deferred=deferred)
    pages = [k for k in docs if k.startswith("events/")]
    assert len(pages) == 1 and deferred == []
    store2 = _vuln_store()
    deferred = []
    docs = publish.build(store2, NOW, None, time_left=lambda: 10, deferred=deferred)
    assert [k for k in docs if k.startswith("events/")] == [] and len(deferred) == 1
    assert "events.json" in docs and "ops.json" in docs      # the summary pages are never deferred



def test_a_cve_not_in_the_list_is_remembered_and_read_again_daily():
    from radar import fetch
    store, calls = MemoryStore(), []

    def get(url):
        calls.append(url)
        raise fetch.FetchError("http_error", "Not Found", 404, url)
    cvemeta.refresh(store, ["CVE-2026-58882"], NOW, get)
    cvemeta.refresh(store, ["CVE-2026-58882"], NOW, get)
    assert len(calls) == 1 and cvemeta.load(store)["CVE-2026-58882"]["state"] == "NOT_FOUND"
    cvemeta.refresh(store, ["CVE-2026-58882"], datetime(2026, 11, 3, 13, tzinfo=UTC), get)
    assert len(calls) == 2


def test_a_resurfaced_or_kev_first_cve_is_not_a_late_detection():
    store = _vuln_store()
    cvemeta.refresh(store, ["CVE-2026-98432"], NOW, _get([]))
    led = cvemeta.load(store)
    led["CVE-2026-98432"]["published"] = "2025-09-05T00:00:00Z"          # 14 months before the report
    cvemeta.save(store, led, set(led))
    assert not [i for i in publish.build(store, NOW)["ops.json"]["attention"] if i["code"] == "late_detection"]
    kev = MemoryStore()
    pipeline.ingest([RawItem(source_id="cisa_kev", url="https://www.cisa.gov/kev#CVE-2026-98432",
                             title="CVE-2026-98432 Linux Kernel TCP use-after-free", text="Known exploited",
                             published_at=datetime(2026, 10, 29, 15, 57, 5, tzinfo=UTC), guid=None, author=None,
                             links=[], extra={"cves": ["CVE-2026-98432"], "kev": True})], kev, datetime(2026, 10, 29, 16, tzinfo=UTC))
    cvemeta.refresh(kev, ["CVE-2026-98432"], NOW, _get([]))
    assert not [i for i in publish.build(kev, NOW)["ops.json"]["attention"] if i["code"] == "late_detection"]


def test_ops_sees_cve_records_filled_in_the_same_run():
    """Live 2026-11-02: ops.json was built before the CVE-record refresh, so the first run's late list missed the CVE
    that run had just looked up (CVE-2026-98432)."""
    store = _vuln_store()
    docs = publish.build(store, NOW, None, enrich=lambda cves: cvemeta.refresh(store, cves, NOW, _get([])) and {})
    assert [i for i in docs["ops.json"]["attention"] if i["code"] == "late_detection"]


def test_progress_starts_with_the_cve_publication_and_cards_carry_it():
    """Live 2026-11-03: the progress stepper began at 「首报 10-29」 and list cards only said 「首报 4 天前」 — the bug read as
    a 10-29 vulnerability though it was published 10-15."""
    store = _vuln_store()
    cvemeta.refresh(store, ["CVE-2026-98432"], NOW, _get([]))
    docs = publish.build(store, NOW)
    [doc] = [d for k, d in docs.items() if k.startswith("events/")]
    assert doc["progress"][0] == {"stage": "disclosed", "at": "2026-10-15T12:08:22Z"}
    assert doc["progress"][1]["stage"] == "first_report"
    [card] = docs["events.json"]["events"]
    assert card["cve_disclosed"] == {"at": "2026-10-15T12:08:22Z", "cve": "CVE-2026-98432", "resurfaced": False}
    assert doc["event"]["cve_disclosed"] == card["cve_disclosed"]


def test_an_event_without_a_cve_record_has_no_disclosed_stage():
    store = _vuln_store()                      # no CVE record looked up
    docs = publish.build(store, NOW)
    [doc] = [d for k, d in docs.items() if k.startswith("events/")]
    assert doc["progress"][0]["stage"] == "first_report" and docs["events.json"]["events"][0]["cve_disclosed"] is None


def test_cards_get_a_cve_date_in_the_same_run_it_was_looked_up():
    """The listing is built before the enrichment; a touched CVE re-lists so the card is not one cycle behind."""
    store = _vuln_store()
    docs = publish.build(store, NOW, set(), enrich=lambda cves: ({}, set(cves) if cvemeta.refresh(store, cves, NOW, _get([])) else set()))
    assert docs["events.json"]["events"][0]["cve_disclosed"]["at"].startswith("2026-10-15")


def test_the_ledger_is_sharded_and_the_legacy_record_migrates_once():
    """One record held 391 CVEs in 78.6 KB and was never trimmed: at ~2,000 CVEs it passes DynamoDB's 400 KB item
    limit and fails Publish every cycle (research/19 B1). Shards keep every record small; the legacy one empties."""
    store = MemoryStore()
    store.put_source_state(cvemeta.KEY, {"CVE-2026-0001": {"published": "2026-10-01T00:00:00Z", "cvss": 9.8}})
    led = cvemeta.load(store)
    led.update({f"CVE-2026-{i:05d}": {"published": "2026-10-01T00:00:00Z", "cvss": 5.0, "assigner": "mitre",
                                      "state": "PUBLISHED", "severity": "MEDIUM", "cvss_source": "cna",
                                      "checked_at": "2026-11-10T00:00:00Z"} for i in range(2, 2502)})
    cvemeta.save(store, led, set(led))
    assert store.get_source_state(cvemeta.KEY) == {}
    assert len(cvemeta.load(store)) == 2501
    biggest = max(len(json.dumps(store.get_source_state(f"{cvemeta.KEY}#{i}"))) for i in range(cvemeta.SHARDS))
    assert biggest < 100_000            # 2,500 CVEs in one record would be ~500 KB
