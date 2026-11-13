"""Late enrichment reaches its page (radar.enrich). Live 2026-11-03 audit: 4 CVEs published 11-02 had no EPSS yet and
their pages would never have been rebuilt; a CVSS added days later (CVE-2026-98432: 9 days) had the same fate."""
import json
from datetime import UTC, datetime, timedelta

from test_cvemeta import REC, _vuln_store

from radar import cvemeta, enrich, publish

NOW = datetime(2026, 11, 3, 2, tzinfo=UTC)
CVE = "CVE-2026-98432"


class Net:
    def __init__(self, epss=None):
        self.epss, self.calls = epss, []

    def __call__(self, url):
        self.calls.append(url)
        if url.startswith(enrich.EPSS_URL):
            return json.dumps({"data": [{"cve": CVE, "epss": self.epss, "percentile": 0.4}] if self.epss is not None else []})
        return json.dumps(REC)


def test_epss_that_arrives_later_rebuilds_the_page():
    store = _vuln_store()
    [eid] = store.events
    net = Net(epss=None)                                   # day 1: FIRST does not score it yet
    publish.build(store, NOW, set(), enrich=lambda cves: enrich.run(store, cves, NOW, net, 60)[:2])
    later = NOW + timedelta(days=1)
    net.epss = 0.00457                                     # day 2: scored — nothing about the event changed
    docs = publish.build(store, later, set(), enrich=lambda cves: enrich.run(store, cves, later, net, 60)[:2])
    page = docs[f"events/{eid}.json"]
    assert page["cve_details"][0]["epss"] == 0.00457
    # the next run, same day, same score: no rebuild, no FIRST call
    n = len(net.calls)
    docs = publish.build(store, later + timedelta(hours=1), set(),
                         enrich=lambda cves: enrich.run(store, cves, later + timedelta(hours=1), net, 60)[:2])
    assert f"events/{eid}.json" not in docs and len(net.calls) == n


def test_a_cvss_added_later_rebuilds_the_page():
    store = _vuln_store()
    [eid] = store.events
    unscored = json.loads(json.dumps(REC))
    unscored["containers"]["cna"]["metrics"] = []
    store.put_source_state(cvemeta.KEY, {CVE: {**cvemeta.parse(unscored), "checked_at": "2026-11-01T00:00:00Z"}})
    # today's EPSS already known and unchanged ⇒ only the CVE record can make this page rebuild
    store.put_source_state(enrich.EPSS_KEY, {"day": NOW.strftime("%Y-%m-%d"), "v": {CVE: [0.1, 0.4]}})
    docs = publish.build(store, NOW, set(), enrich=lambda cves: enrich.run(store, cves, NOW, Net(0.1), 60)[:2])
    assert docs[f"events/{eid}.json"]["cve_details"][0]["cvss"] == 9.8


def test_a_failed_epss_call_keeps_yesterdays_scores():
    store = _vuln_store()
    enrich.run(store, [CVE], NOW, Net(0.2), 60)

    def down(url):
        if url.startswith(enrich.EPSS_URL):
            raise OSError("FIRST down")
        return json.dumps(REC)
    epss, _, stats = enrich.run(store, [CVE], NOW + timedelta(days=1), down, 60)
    assert epss[CVE]["epss"] == 0.2 and stats["epss_failed"] == 1
    assert store.get_source_state(enrich.EPSS_KEY)["day"] == NOW.strftime("%Y-%m-%d")   # retried next run


def test_the_epss_ledger_stays_under_the_item_limit_at_20k_cves():
    """B7 (docs/research/action/07 §2.8): `__epss__` was one DynamoDB item that only grew; ~10k CVEs pass 400 KB and
    every Publish fails. Sharded like cvemeta: 20k CVEs ⇒ every record well under the limit, every score kept."""
    from radar.store import MemoryStore
    store = MemoryStore()
    cves = [f"CVE-2026-{i:05d}" for i in range(20_000)]

    def get(url):
        asked = url[len(enrich.EPSS_URL):].split(",")
        return json.dumps({"data": [{"cve": c, "epss": 0.000123456, "percentile": 0.123456789} for c in asked]})
    stats: dict = {}
    epss, touched = enrich._epss(store, cves, NOW, get, stats)
    assert len(epss) == 20_000 and len(touched) == 20_000 and not stats.get("epss_failed")
    assert max(len(json.dumps(v)) for v in store.sources.values()) < 300_000
    again, moved = enrich._epss(store, cves, NOW + timedelta(days=1), get, {})
    assert again == epss and moved == set()               # read back whole from the shards


def test_the_epss_ledger_costs_linear_time_in_its_cves(monkeypatch):
    """Review of B7: `c in set(cves)` rebuilt the set once per scored CVE and every changed shard rehashed every CVE
    (64 × N sha1) — at 20k CVEs one _epss took ~14 s CPU on every Publish. Now: the CVE list is walked a fixed number
    of times and each CVE is hashed at most twice (its shard, plus once more if its score changed)."""
    from radar.store import MemoryStore

    class Counted(list):
        walks = 0

        def __iter__(self):
            Counted.walks += 1
            return super().__iter__()
    hashed = []
    real = enrich._shard
    monkeypatch.setattr(enrich, "_shard", lambda c: hashed.append(c) or real(c))
    cves = Counted(f"CVE-2026-{i:05d}" for i in range(2_000))
    get = lambda url: json.dumps({"data": [{"cve": c, "epss": 0.1, "percentile": 0.2}
                                           for c in url[len(enrich.EPSS_URL):].split(",")]})
    epss, _ = enrich._epss(MemoryStore(), cves, NOW, get, {})
    assert len(epss) == 2_000
    assert Counted.walks <= 5 and len(hashed) <= 2 * 2_000


def test_a_legacy_single_record_ledger_is_migrated_into_shards():
    from radar.store import MemoryStore
    store = MemoryStore()
    store.put_source_state(enrich.EPSS_KEY, {"day": NOW.strftime("%Y-%m-%d"), "v": {CVE: [0.1, 0.4]}})
    get = lambda url: json.dumps({"data": [{"cve": "CVE-2026-2", "epss": 0.3, "percentile": 0.5}]})
    epss, _ = enrich._epss(store, [CVE, "CVE-2026-2"], NOW, get, {})      # same day: only the missing CVE is asked
    assert epss == {CVE: {"epss": 0.1, "percentile": 0.4}, "CVE-2026-2": {"epss": 0.3, "percentile": 0.5}}
    assert "v" not in store.get_source_state(enrich.EPSS_KEY)            # legacy values now live in the shards
    assert enrich._epss(store, [CVE], NOW, get, {})[0] == {CVE: {"epss": 0.1, "percentile": 0.4}}
