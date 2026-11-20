"""A brief is rewritten when a fact the CODE decided changed, not when another report arrives (live 11-19: ~203
generations a day; 7-day replay: facts-only ≈ 10 a day)."""
import datetime as dt

from radar import analyst

EV = [{"item_id": "a", "tier": "T1", "title": "Vendor fixes CVE-2026-11111 in 4.0.6", "text": "Upgrade to 4.0.6."},
      {"item_id": "b", "tier": "T3", "title": "Aggregator: CVE-2026-11111", "text": "Posted 3 hours ago."}]
F = {"severity": "P1", "exploitation": "none", "cves": ["CVE-2026-11111"], "amount": None}


def brief(ev=EV, facts=F, at="2026-11-19T00:00:00Z"):
    return {"status": "ok", "generated_at": at, "input_hash": analyst.input_hash(ev), "facts": dict(facts),
            "bluf": [{"text": "Fixed in 4.0.6.", "cite": ["a"], "grounded": True}]}


def test_new_reports_and_new_figures_keep_the_brief():
    more = EV + [{"item_id": "c", "tier": "T1", "title": "Second advisory: 1,200 instances exposed, 4.0.7", "text": "x"}]
    assert analyst.needs_rewrite(brief(), more, F, "2026-11-19T01:00:00Z") is None


def test_a_change_in_exploitation_or_severity_rewrites_at_once():
    assert analyst.needs_rewrite(brief(), EV, {**F, "exploitation": "reported"}, "2026-11-19T00:10:00Z") == "facts_exploitation"
    assert analyst.needs_rewrite(brief(), EV, {**F, "severity": "P0"}, "2026-11-19T00:10:00Z") == "facts_severity"


def test_a_new_cve_or_amount_waits_the_cooldown():
    more = {**F, "cves": ["CVE-2026-11111", "CVE-2026-22222"]}
    assert analyst.needs_rewrite(brief(), EV, more, "2026-11-19T02:00:00Z") is None
    assert analyst.needs_rewrite(brief(), EV, more, "2026-11-19T07:00:00Z") == "facts_cves"
    assert analyst.needs_rewrite(brief(), EV, {**F, "amount": 1.2e7}, "2026-11-19T07:00:00Z") == "facts_amount"


def test_a_cited_report_that_left_a_failed_brief_or_none_rewrites():
    assert analyst.needs_rewrite(brief(), [EV[1]], F, "2026-11-19T01:00:00Z") == "cited_report_gone"
    assert analyst.needs_rewrite({**brief(), "status": "failed"}, EV, F) == "failed"
    assert analyst.needs_rewrite(None, EV, F) == "new"


def test_a_legacy_brief_is_kept_while_current_and_rewritten_once_its_evidence_moved():
    legacy = {k: v for k, v in brief().items() if k != "facts"}
    assert analyst.needs_rewrite(legacy, EV, F) is None
    assert analyst.needs_rewrite(legacy, EV + [{"item_id": "c", "tier": "T3", "title": "t", "text": "u"}], F) == "legacy"


def test_facts_round_an_amount_to_two_significant_digits():
    from radar.model import Event
    e = Event(event_id="ev_1", domain="web3", title="t", first_seen="x", last_updated="x", item_ids=[], keys=[],
              severity="P0", amount_usd_latest=12_340_000)
    assert analyst.facts_of(e)["amount"] == 1.2e7


def _station(monkeypatch, analysis):
    for k, v in {"AWS_DEFAULT_REGION": "ap-northeast-1", "AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "x"}.items():
        monkeypatch.setenv(k, v)
    from radar import handlers as h
    from radar.model import Event, Item
    from radar.store import MemoryStore
    store = MemoryStore()
    its = [Item(item_id=i, source_id="cvefeed", tier=t, org="o", domain="vuln", url=f"https://x/{i}", canonical_url=f"https://x/{i}",
                title=f"CVE-2026-11111 {i}", text="Upgrade to 4.0.6." if t == "T1" else "y", published_at=f"2026-11-19T0{n}:00:00Z",
                fetched_at="2026-11-19T00:00:00Z", content_hash=i, keys=[], links=[], entity=None, eventful=True,
                signals={}, extra={}) for n, (i, t) in enumerate([("it_a", "T1"), ("it_b", "T1")])]
    for it in its:
        store.put_item(it)
    monkeypatch.setattr(h, "_store", store)
    ev = Event(event_id="ev_0000000000000009", domain="vuln", title="x", first_seen=its[0].published_at,
               last_updated="2026-11-19T02:00:00Z", item_ids=["it_a", "it_b"], keys=[], severity="P1", analysis=analysis(h, ["it_a"]))
    store.put_event(ev)
    for f in ("_daily_digest", "_cluster_judge", "_retitle_shadow"):
        monkeypatch.setattr(h, f, lambda now: [])
    monkeypatch.setattr(h, "_attack_paths", lambda now, since, left=None: [])
    calls = []
    monkeypatch.setattr(analyst, "analyze", lambda ev_in, now: calls.append(1) or {"status": "ok"})
    monkeypatch.setattr(h.timeutil, "now", lambda: dt.datetime(2026, 11, 19, 12, tzinfo=dt.UTC))
    return h, store, ev, calls


def test_the_station_keeps_a_brief_when_a_report_joins_but_no_fact_moved(monkeypatch):
    def a(h, ids):
        ev_in = analyst.trim_evidence(h._evidence(type("E", (), {"item_ids": ids})()), set())
        return {**brief(ev_in, {"severity": "P1", "exploitation": "none", "cves": [], "amount": None}),
                "bluf": [{"text": "t", "cite": ["it_a"], "grounded": True}]}
    h, _, _, calls = _station(monkeypatch, a)
    h.analyze_events({})
    assert calls == []          # a second T1 report joined; severity, exploitation, CVEs, amount unchanged


def test_the_station_stamps_a_current_legacy_brief_without_a_model_call(monkeypatch):
    def a(h, ids):
        ev_in = analyst.trim_evidence(h._evidence(type("E", (), {"item_ids": ["it_a", "it_b"]})()), set())
        return {k: v for k, v in brief(ev_in).items() if k != "facts"} | {"bluf": [{"text": "t", "cite": ["it_a"], "grounded": True}]}
    h, store, ev, calls = _station(monkeypatch, a)
    h.analyze_events({})
    assert calls == [] and store.get_event(ev.event_id).analysis["facts"]["severity"] == "P1"


def test_the_facts_record_is_internal_and_never_published():
    from radar import publish
    from radar.model import Event
    e = Event(event_id="ev_1", domain="vuln", title="t", first_seen="x", last_updated="x", item_ids=[], keys=[],
              severity="P1", analysis=brief())
    out = publish._public_analysis(e)
    assert "facts" not in out and "input_hash" not in out and out["bluf"]
