"""CISA advisories through CISA's CSAF provider (Neo 2026-11-06, option B). CISA's CDN answers the radar's AWS egress
with 403 on every dynamic page since 2026-11-04 — the RSS included — while static files pass; the CSAF ROLIE feeds on
GitHub carry the same advisories (2026-11-06 snapshots)."""
import json
from datetime import UTC, datetime
from pathlib import Path

from radar import collect, parsers, pipeline
from radar.registry import BY_ID
from radar.store import MemoryStore

SNAP = Path(__file__).parent / "fixtures" / "snapshots" / "2026-11-06"
NOW = datetime(2026, 11, 6, 2, tzinfo=UTC)
DOC = (SNAP / "icsa-26-307-01.json").read_text()


def test_a_rolie_feed_parses_and_keeps_the_rss_url_of_an_ics_advisory():
    items = parsers.rolie((SNAP / "cisa-csaf-ot-feed.json").read_text(), "cisa_csaf_ot")
    sub = next(i for i in items if i.extra["advisory_id"] == "ICSA-26-307-01")
    assert sub.url == "https://www.cisa.gov/news-events/ics-advisories/icsa-26-307-01"     # the URL the RSS gave it
    assert sub.title == "ICSA-26-307-01 Subnet Solutions PowerSYSTEM Center"
    assert sub.extra["csaf_url"].endswith("/OT/white/2026/icsa-26-307-01.json")
    assert sub.guid == "ICSA-26-307-01@2026-11-03T06:00:00.000000Z" and sub.published_at.isoformat().startswith("2026-11-03")
    it = parsers.rolie((SNAP / "cisa-csaf-it-feed.json").read_text(), "cisa_csaf_it")
    assert all(i.url.startswith("https://raw.githubusercontent.com/cisagov/CSAF/") for i in it)


def test_a_csaf_document_gives_cves_score_vendor_and_summary():
    d = parsers.csaf_doc(DOC)
    assert d["cves"] == ["CVE-2026-63017", "CVE-2026-63774"] and d["cvss"] == 9.0 and d["vendors"] == ["Subnet Solutions"]
    assert "execute unauthorized SQL commands" in d["text"] and "CVE-2026-63017" in d["text"]


def _fetching(monkeypatch, bodies):
    from radar import fetch
    calls = []

    def http_get(url, *a, **k):
        calls.append(url)
        if url in bodies:
            return fetch.Response(200, bodies[url], '"etag"', None)
        raise fetch.FetchError("http_error", "Not Found", 404, url)
    monkeypatch.setattr(fetch, "http_get", http_get)
    return calls


def test_collect_reports_only_recent_unseen_advisories_with_their_cves(monkeypatch):
    src = BY_ID["cisa_csaf_ot"]
    j = json.loads((SNAP / "cisa-csaf-ot-feed.json").read_text())
    stale = {**j["feed"]["entry"][0], "id": "ICSA-25-100-01", "updated": "2025-04-10T06:00:00Z",
             "link": [{"rel": "self", "href": "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2025/icsa-25-100-01.json"}]}
    j["feed"]["entry"].append(stale)          # the snapshot holds only the latest entries; the real feed goes back to 2016
    feed = json.dumps(j)
    doc_url = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2026/icsa-26-307-01.json"
    calls = _fetching(monkeypatch, {src.url: feed, doc_url: DOC, stale["link"][0]["href"]: DOC})
    raws, st = collect.collect(src, {}, NOW)
    got = {r.extra["advisory_id"]: r for r in raws}
    assert got["ICSA-26-307-01"].extra["cves"] == ["CVE-2026-63017", "CVE-2026-63774"]
    assert all(r.published_at >= datetime(2026, 10, 23, tzinfo=UTC) for r in raws)         # 14 days, not since 2016
    # … and an older entry's document is never even fetched (M369 died while only the reports were checked: the old
    # documents 404 in this fixture, so they dropped out anyway)
    old = [r for r in parsers.rolie(feed, src.source_id) if r.published_at < datetime(2026, 10, 23, tzinfo=UTC)]
    assert old and not {r.extra["csaf_url"] for r in old} & set(calls)
    assert st["consecutive_failures"] == 0
    # an advisory already ingested is not fetched again
    calls.clear()
    raws, _ = collect.collect(src, {}, NOW, known_item=lambda sid, guid: guid.startswith("ICSA-26-307-01@"))
    assert doc_url not in calls and "ICSA-26-307-01" not in {r.extra["advisory_id"] for r in raws}


def test_an_unreadable_document_is_retried_next_run_not_reported_without_cves(monkeypatch):
    src = BY_ID["cisa_csaf_ot"]
    _fetching(monkeypatch, {src.url: (SNAP / "cisa-csaf-ot-feed.json").read_text()})   # every document 404s
    raws, st = collect.collect(src, {}, NOW)
    assert raws == [] and st["consecutive_failures"] == 0       # the feed itself is fine; no CVE-less reports


def test_the_csaf_report_joins_the_event_its_rss_report_opened():
    # the RSS report carries no CVE id (the join is not only the CVE key); the URL itself is pinned by the parse test
    store = MemoryStore()
    from radar.model import RawItem
    rss = RawItem(source_id="cisa_advisories", url="https://www.cisa.gov/news-events/ics-advisories/icsa-26-307-01",
                  title="Subnet Solutions PowerSYSTEM Center Vulnerability",
                  text="Successful exploitation of this vulnerability could allow an attacker to execute arbitrary code.", published_at=datetime(2026, 11, 3, 12, tzinfo=UTC),
                  guid=None, author=None, links=[], extra={})
    pipeline.ingest([rss], store, datetime(2026, 11, 3, 13, tzinfo=UTC))
    [r] = [x for x in parsers.rolie((SNAP / "cisa-csaf-ot-feed.json").read_text(), "cisa_csaf_ot")
           if x.extra["advisory_id"] == "ICSA-26-307-01"]
    d = parsers.csaf_doc(DOC)
    r.text = d["text"]
    r.extra.update(cves=d["cves"], cvss=d["cvss"], entity=d["vendors"][0])
    pipeline.ingest([r], store, NOW)
    [ev] = store.events.values()
    assert len(ev["item_ids"]) == 2 and set(ev["cves"]) >= {"CVE-2026-63017", "CVE-2026-63774"}


def test_the_feed_fixtures_are_real_rolie():
    j = json.loads((SNAP / "cisa-csaf-ot-feed.json").read_text())
    assert j["feed"]["entry"] and all({"id", "updated", "link"} <= set(e) for e in j["feed"]["entry"])


def test_a_csaf_advisory_with_many_cves_keys_all_of_them():
    """EPICS Base ICSA-26-300-01 lists 4 CVEs; the ≤ 3 cap (against roundups) left it with no cve: key at all."""
    from radar.model import RawItem
    cves = ["CVE-2026-114595", "CVE-2026-114596", "CVE-2026-114597", "CVE-2026-114598"]
    raw = RawItem(source_id="cisa_csaf_ot", url="https://www.cisa.gov/news-events/ics-advisories/icsa-26-300-01",
                  title="ICSA-26-300-01 EPICS Base", text="Successful exploitation … " + " ".join(cves),
                  published_at=datetime(2026, 10, 27, tzinfo=UTC), guid="ICSA-26-300-01@2026-10-27", author=None, links=[],
                  extra={"cves": cves, "advisory_id": "ICSA-26-300-01"})
    it = pipeline.normalize(raw, BY_ID["cisa_csaf_ot"], NOW)
    assert {f"cve:{c}" for c in cves} <= set(it.keys)
    # the cap still holds for prose (a weekly roundup listing four CVEs)
    prose = RawItem(source_id="securityweek", url="https://www.securityweek.com/x", title="Weekly roundup", text=" ".join(cves),
                    published_at=datetime(2026, 10, 27, tzinfo=UTC), guid=None, author=None, links=[], extra={})
    assert not [k for k in pipeline.normalize(prose, BY_ID["securityweek"], NOW).keys if k.startswith("cve:")]


def test_the_repair_gives_a_stored_csaf_advisory_all_its_cve_keys():
    """Items stored before d609505 carry extra.cves but no cve: key; the per-event repair must add them."""
    import importlib.util
    from pathlib import Path

    from radar.model import Item
    spec = importlib.util.spec_from_file_location("recluster", Path(__file__).parents[1] / "scripts" / "recluster_web3.py")
    rc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rc)
    cves = ["CVE-2026-114595", "CVE-2026-114596", "CVE-2026-114597", "CVE-2026-114598"]
    it = Item(item_id="i", source_id="cisa_csaf_ot", tier="T1", org="cisa", domain="vuln", url="https://x",
              canonical_url="https://x", title="ICSA-26-300-01 EPICS Base", text="", published_at="2026-10-27T00:00:00Z",
              fetched_at="2026-11-06T00:00:00Z", content_hash="c", keys=["url:x"], links=[], entity=None, eventful=True,
              signals={}, extra={"cves": cves})
    assert {f"cve:{c}" for c in cves} <= set(rc.rekey(it).keys)


def test_the_repair_writes_an_event_whose_cve_list_grew():
    """Same members, same tx, same amount — only the CVE list grew: the dry run reported 'changed 0' and --apply
    would never have written ICSA-26-300-01's four CVEs."""
    import importlib.util
    from pathlib import Path

    from radar.model import Event
    spec = importlib.util.spec_from_file_location("recluster", Path(__file__).parents[1] / "scripts" / "recluster_web3.py")
    rc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rc)

    def ev(cves):
        return Event(event_id="ev_x", domain="vuln", title="ICSA-26-300-01 EPICS Base", first_seen="2026-10-27T00:00:00Z",
                     last_updated="2026-11-06T00:00:00Z", item_ids=["i"], keys=["url:x"], cves=cves)
    assert rc.changed_events({"ev_x": ev([])}, {"ev_x": ev(["CVE-2026-114595"])}) == ["ev_x"]
    assert rc.changed_events({"ev_x": ev([])}, {"ev_x": ev([])}) == []
