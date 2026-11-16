"""R0.5 — how long a report takes from being published to being held by the radar, measured every cycle.

Measured once by hand on 2026-11-12: median 48 minutes, 90th percentile 225 (Telegram 5, X 35, RSS 51). The roadmap's
speed target (R2) needs the number to be there every day, not when someone runs a script."""
from datetime import UTC, datetime, timedelta

from test_pipeline_replay import _raw

from radar import latency, ops, pipeline, publish, timeutil
from radar.limits import Limits
from radar.store import MemoryStore

NOW = datetime(2026, 11, 12, 12, 0, tzinfo=UTC)


def test_ingest_samples_new_reports_only_and_leaves_backfills_out():
    store = MemoryStore()
    fresh = _raw("bleepingcomputer", "Acme VPN flaw CVE-2026-90001 exploited", "actively exploited", when="2026-11-12T11:20:00Z")
    old = _raw("securityweek", "Globex gateway bug CVE-2026-90002 exploited", "exploited in the wild", when="2026-10-01T00:00:00Z")
    res = pipeline.ingest([fresh, old], store, NOW)
    assert res.held == [["T2", 40]]                     # 11:20 → 12:00; the six-week-old one is a backfill, not latency
    again = pipeline.ingest([fresh], store, NOW + timedelta(minutes=5))
    assert again.held == []                             # already held: not sampled twice


def test_the_ledger_keeps_a_day_and_summarises_by_tier():
    store = MemoryStore()
    latency.record(store, [["T1", 10], ["T1", 20], ["T2", 60]], NOW - timedelta(hours=30))    # ages out
    latency.record(store, [["T1", 4], ["T1", 6], ["T1", 8], ["T2", 50], ["T2", 70], ["T3", 300]], NOW)
    s = latency.summary(store, NOW)
    assert s["n"] == 6 and s["p50"] == 50 and s["p90"] == 300
    assert s["tiers"]["T1"] == {"n": 3, "p50": 6, "p90": 8} and s["tiers"]["T2"]["p50"] == 70
    latency.record(store, [["T2", 1]] * (Limits.LATENCY_SAMPLES_MAX + 50), NOW)
    assert len(store.get_source_state(latency.KEY)["rows"]) == Limits.LATENCY_SAMPLES_MAX
    assert latency.summary(MemoryStore(), NOW) is None                                        # nothing measured ≠ 0 minutes


def test_ops_states_the_number_and_warns_past_the_limit():
    ok = {"n": 40, "p50": 12, "p90": 60, "tiers": {"T1": {"n": 10, "p50": 5, "p90": 9}}}
    (item,) = [i for i in ops.attention({"latency": ok}) if i["code"] == "collect_latency"]
    assert item["level"] == "info" and "中位 12 分钟" in item["title"] and "T1 5" in item["detail"]
    slow = {**ok, "p50": Limits.LATENCY_WARN_P50_MIN + 1}
    (item,) = [i for i in ops.attention({"latency": slow}) if i["code"] == "collect_latency"]
    assert item["level"] == "warn" and str(Limits.LATENCY_WARN_P50_MIN) in item["detail"]     # actual + limit
    assert [i for i in ops.attention({"latency": None}) if i["code"] == "collect_latency"] == []
    few = {**slow, "n": Limits.LATENCY_MIN_SAMPLES - 1}
    (item,) = [i for i in ops.attention({"latency": few}) if i["code"] == "collect_latency"]
    assert item["level"] == "info"                                                            # too few to judge


def test_the_published_ops_page_carries_the_latency():
    store = MemoryStore()
    latency.record(store, [["T2", 30]] * Limits.LATENCY_MIN_SAMPLES, NOW)
    codes = [i["code"] for i in publish.build(store, NOW)["ops.json"]["attention"]]
    assert "collect_latency" in codes
    assert timeutil.iso(NOW)                                                                  # (import used)


# --- second half: first report published → first P0 push -------------------------------------------------------------

def test_a_sent_p0_push_is_timed_from_the_first_report_and_a_baseline_is_not(monkeypatch):
    from test_notify_station import AT, CFG, ev

    from radar import notify, notify_station
    store = MemoryStore()
    monkeypatch.setattr(publish, "_response", lambda e, s, now: None)
    senders = {c: (lambda cfg, sub, msg, thread, cache: "T") for c in notify.CHANNELS}
    now = datetime(2026, 11, 11, 4, 0, tzinfo=UTC)                      # AT (the events' first_seen) is 03:00
    store.put_event(ev("ev_00000000000000a0", "P0", "vuln", "Old P0"))
    notify_station.run(store, CFG, now, "https://site", senders)         # baseline: recorded as sent, nothing sent
    assert latency.summary(store, now, latency.PUSH_KEY, latency.PUSH_HOURS) is None
    store.put_event(ev("ev_00000000000000a1", "P0", "vuln", "New P0"))
    notify_station.run(store, CFG, now, "https://site", senders)
    s = latency.summary(store, now, latency.PUSH_KEY, latency.PUSH_HOURS)
    assert s["n"] == 1 and s["p50"] == 60 and AT == "2026-11-11T03:00:00Z"
    assert latency.summary(store, now + timedelta(days=6), latency.PUSH_KEY, latency.PUSH_HOURS)["n"] == 1   # a week, not a day
    assert latency.summary(store, now + timedelta(hours=latency.PUSH_HOURS + 1), latency.PUSH_KEY, latency.PUSH_HOURS) is None


def test_ops_states_the_push_latency_next_to_the_collection_latency():
    f = {"latency": {"n": 40, "p50": 12, "p90": 60, "tiers": {}}, "push_latency": {"n": 3, "p50": 21, "p90": 55, "tiers": {}}}
    titles = [i["title"] for i in ops.attention(f) if i["code"] == "collect_latency"]
    assert len(titles) == 2 and any("推送" in t and "中位 21 分钟" in t for t in titles)
    store = MemoryStore()
    latency.record(store, [["P0", 30]], NOW, latency.PUSH_KEY, latency.PUSH_HOURS)
    items = [i for i in publish.build(store, NOW)["ops.json"]["attention"] if i["code"] == "collect_latency"]
    assert any("推送" in i["title"] for i in items)


def test_a_push_is_timed_from_when_the_event_became_p0_not_from_its_first_report(monkeypatch):
    """Live 2026-11-14: median 1,597 minutes over 6 pushes — events first reported days earlier and raised to P0
    later. That number measured how long the story took to become urgent, not how late the push was."""
    import dataclasses

    from test_notify_station import CFG, ev

    from radar import notify, notify_station
    store = MemoryStore()
    monkeypatch.setattr(publish, "_response", lambda e, s, now: None)
    senders = {c: (lambda cfg, sub, msg, thread, cache: "T") for c in notify.CHANNELS}
    now = datetime(2026, 11, 11, 4, 0, tzinfo=UTC)
    notify_station.run(store, CFG, now, "https://site", senders)                         # baseline on an empty store
    raised = dataclasses.replace(ev("ev_00000000000000a2", "P0", "vuln", "Raised late"),
                                 first_seen="2026-11-10T06:00:00Z", escalated_at="2026-11-11T03:30:00Z")
    store.put_event(raised)
    notify_station.run(store, CFG, now, "https://site", senders)
    s = latency.summary(store, now, latency.PUSH_KEY, latency.PUSH_HOURS)
    assert s["n"] == 1 and s["p50"] == 30                                                # not 22 hours
