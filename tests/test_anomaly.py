"""R0.1 — an event that changes shape in one cycle is reported (radar.anomaly).

Live 2026-11-12 03:58Z: the Binance theft (540 reports, web3) was absorbed by a vulnerability event; the site's top event
was a 703-item, 21-CVE "P0 vuln" for eleven hours and nothing said so. The cause is fixed (pipeline._different_stories);
this is the detector for the next cause."""
from datetime import UTC, datetime

from test_pipeline_replay import FETCHED, _raw

from radar import anomaly, ops, pipeline
from radar.limits import Limits
from radar.model import Event
from radar.store import MemoryStore

NOW = datetime(2026, 11, 12, 4, 0, tzinfo=UTC)


def ev(eid, domain="web3", items=1, cves=0, loss=None, title="t"):
    return Event(event_id=eid, domain=domain, title=title, first_seen="2026-10-29T00:00:00Z", last_updated="2026-11-12T03:58:00Z",
                 item_ids=[f"it_{eid}_{n}" for n in range(items)], keys=[], cves=[f"CVE-2026-{n}" for n in range(cves)],
                 amount_usd_latest=loss)


def scan(before, after, absorbed=()):
    b = {before.event_id: anomaly.snap(before)} if before else {}
    a = {after.event_id: [anomaly.snap(x) for x in absorbed]} if absorbed else {}
    return anomaly.scan(b, a, {after.event_id: after}.get, "2026-11-12T03:58:23Z")


def kinds(found):
    return sorted(f["kind"] for f in found)


def test_the_2026_11_12_merge_is_reported():
    """The veto case of roadmap R0: replayed as it happened — a vuln event (first seen earlier, so the survivor) absorbs
    the 540-report theft: 2 items / 1 CVE → 703 items / 21 CVEs, and a $6.34B loss appears on a vulnerability."""
    flaw = ev("ev_73cf1ec6a7cf368e", "vuln", items=2, cves=1, title="Linux Kernel TCP Flaw")
    theft = ev("ev_0a4e5c3e0fce8be9", "web3", items=540, loss=6.34e9, title="Binance CEX — Key Leaked via Infrastructure")
    after = ev("ev_73cf1ec6a7cf368e", "vuln", items=703, cves=21, loss=6.34e9, title="Binance CEX — Key Leaked via Infrastructure")
    found = scan(flaw, after, [theft])
    assert {"absorbed_other_domain", "absorbed_large_event"} <= set(kinds(found))
    row = next(f for f in found if f["kind"] == "absorbed_other_domain")
    assert row["event_id"] == after.event_id and row["level"] == "error"
    assert row["absorbed"] == "ev_0a4e5c3e0fce8be9" and row["actual"] == "web3 → vuln"     # says which and what


def test_ordinary_growth_is_not_an_anomaly():
    """Negative control: one more report, one more CVE, a revised loss of the same order, a small same-domain merge."""
    assert scan(ev("e", items=30, cves=2, loss=5e6), ev("e", items=31, cves=3, loss=7e6)) == []
    assert scan(ev("e", items=3), ev("e", items=6), [ev("x", items=2)]) == []
    assert scan(None, ev("e", "vuln", items=400, cves=40)) == []        # a new event has no "before" to differ from


def test_each_shape_change_has_its_own_kind_and_limit():
    assert kinds(scan(ev("e", items=30), ev("e", items=30 + Limits.ANOMALY_ITEMS_ADDED))) == ["items_jump"]
    assert kinds(scan(ev("e", items=Limits.ANOMALY_GROWTH_MIN_ITEMS), ev("e", items=2 * Limits.ANOMALY_GROWTH_MIN_ITEMS))) == ["items_jump"]
    assert scan(ev("e", items=4), ev("e", items=8)) == []               # small events double all the time
    assert kinds(scan(ev("e", "vuln", cves=1), ev("e", "vuln", cves=1 + Limits.ANOMALY_CVES_ADDED))) == ["cves_jump"]
    assert kinds(scan(ev("e", loss=6.3e9), ev("e", loss=304_500))) == ["loss_changed"]       # ×10 either way
    assert kinds(scan(ev("e", loss=5e5), ev("e", loss=5e6))) == ["loss_changed"]
    assert scan(ev("e", loss=5e6), ev("e", loss=9e6)) == []
    assert kinds(scan(ev("e", items=30), ev("e", items=30 + Limits.ANOMALY_ABSORBED_ITEMS),
                      [ev("x", items=Limits.ANOMALY_ABSORBED_ITEMS)])) == ["absorbed_large_event"]


def test_a_row_carries_code_message_actual_and_limit():
    (row,) = scan(ev("e", items=30), ev("e", items=90, title="Binance CEX"))
    assert {"kind", "level", "event_id", "title", "at", "actual", "limit", "message"} <= set(row)
    assert row["actual"] == "30 → 90" and row["limit"] == f"+{Limits.ANOMALY_ITEMS_ADDED}"


def test_a_cycle_reports_through_ingest_and_the_ledger_is_capped_and_ages_out(monkeypatch):
    """End to end on the real pipeline: a report that bridges two CVE clusters (the allowed merge) absorbs an event; with
    the absorbed-size limit at 1 that is an anomaly, recorded once, shown on #/ops while fresh."""
    monkeypatch.setattr(Limits, "ANOMALY_ABSORBED_ITEMS", 1)
    store = MemoryStore()
    pipeline.ingest([_raw("bleepingcomputer", "Acme VPN flaw CVE-2026-90001 exploited", "actively exploited", when="2026-10-31T10:00:00Z")], store, FETCHED)
    pipeline.ingest([_raw("securityweek", "Acme gateway bug CVE-2026-90002 exploited", "exploited in the wild", when="2026-10-31T11:00:00Z")], store, FETCHED)
    res = pipeline.ingest([_raw("bleepingcomputer", "Acme: CVE-2026-90001 and CVE-2026-90002 are one bug chain", "exploited chain",
                                when="2026-10-31T12:00:00Z")], store, NOW)
    assert kinds(res.anomalies) == ["absorbed_large_event"]
    anomaly.record(store, res.anomalies, NOW)
    anomaly.record(store, [], NOW)                                                    # an empty run keeps what is there
    assert [a["kind"] for a in anomaly.recent(store, NOW)] == ["absorbed_large_event"]
    (item,) = ops.attention({"anomalies": anomaly.recent(store, NOW)})
    assert item["code"] == "event_anomaly" and item["level"] == "error" and item["link"].startswith("/events/")
    later = datetime(2026, 11, 12 + Limits.ANOMALY_SHOW_HOURS // 24 + 1, 4, 0, tzinfo=UTC)
    assert anomaly.recent(store, later) == []                                         # ages off the page
    many = [{**res.anomalies[0], "event_id": f"ev_{n}", "at": "2026-11-12T03:00:00Z"} for n in range(Limits.ANOMALY_MAX + 20)]
    anomaly.record(store, many, NOW)
    assert len(store.get_source_state(anomaly.KEY)["rows"]) == Limits.ANOMALY_MAX


def test_the_published_ops_page_carries_the_anomaly():
    from radar import publish
    store = MemoryStore()
    (row,) = scan(ev("e", items=30), ev("e", items=90, title="Binance CEX"))
    anomaly.record(store, [{**row, "at": "2026-11-12T03:58:23Z"}], NOW)
    codes = [i["code"] for i in publish.build(store, NOW)["ops.json"]["attention"]]
    assert "event_anomaly" in codes
