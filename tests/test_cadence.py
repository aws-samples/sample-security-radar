"""R2.3: the cadence follows the source's history — twice as fast for free T1 sources while a P0 moves, half as fast for
a source that has been empty for a week — and a failing source's backoff (R2.5) still wins."""
from datetime import UTC, datetime, timedelta

from radar import collect, timeutil
from radar.limits import Limits
from radar.registry import SOURCES

NOW = datetime(2026, 11, 15, 12, tzinfo=UTC)
T1 = next(s for s in SOURCES if s.enabled and s.tier == "T1" and s.parser != "twitterapi" and s.via != "firecrawl"
          and s.cadence_min >= 20)
X = next(s for s in SOURCES if s.parser == "twitterapi")


def days(n_zero, total=20):
    return {(NOW - timedelta(days=d)).strftime("%Y-%m-%d"): (0 if d < n_zero else 3) for d in range(total)}


def test_surge_halves_a_free_t1_source_but_never_a_paid_one():
    assert collect.cadence(T1, {}, surge=True) == max(Limits.CYCLE_MINUTES, T1.cadence_min / 2)
    assert collect.cadence(X, {}, surge=True) == X.cadence_min


def test_a_week_of_nothing_doubles_the_interval_but_a_short_history_does_not():
    assert collect.cadence(T1, {"days": days(Limits.SOURCE_IDLE_DAYS)}) == min(Limits.SOURCE_IDLE_MAX_MIN, T1.cadence_min * 2)
    assert collect.cadence(T1, {"days": days(Limits.SOURCE_IDLE_DAYS - 1)}) == T1.cadence_min
    assert collect.cadence(T1, {"days": days(7, total=8)}) == T1.cadence_min          # < 14 days of history


def test_failing_backoff_outranks_surge():
    assert collect.cadence(T1, {"consecutive_failures": 4}, surge=True) > T1.cadence_min


def test_publish_writes_the_surge_flag_from_a_recent_p0_and_plan_reads_it(monkeypatch):
    import importlib

    from radar.store import MemoryStore
    for k, v in {"AWS_DEFAULT_REGION": "ap-northeast-1", "AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "x"}.items():
        monkeypatch.setenv(k, v)                      # importing handlers builds an S3 client
    monkeypatch.delenv("TABLE", raising=False)
    from radar import handlers
    h = importlib.reload(handlers)
    store = MemoryStore()
    monkeypatch.setattr(h, "_store", store)
    from radar.model import Event
    def ev(eid, first_h, esc_h=None):
        store.put_event(Event(event_id=eid, domain="vuln", title=eid, first_seen=timeutil.iso(NOW - timedelta(hours=first_h)),
                              last_updated=timeutil.iso(NOW), item_ids=[], keys=[], severity="P0",
                              escalated_at=timeutil.iso(NOW - timedelta(hours=esc_h)) if esc_h is not None else None))
    ev("ev_1", 30, esc_h=1)          # escalated to P0 an hour ago ⇒ surge
    ev("ev_2", 9)                    # P0 for 9 h, updated now ⇒ not a surge (big P0s update every cycle)
    rows = [{"event_id": "ev_1", "severity": "P0"}, {"event_id": "ev_2", "severity": "P0"}]
    h._surge(rows, NOW)
    st = store.get_source_state(collect.SURGE_KEY)
    assert st == {"until": timeutil.iso(NOW + timedelta(hours=Limits.SURGE_HOURS - 1)), "events": ["ev_1"]}
    assert collect.surging({collect.SURGE_KEY: st}, NOW) and not collect.surging({collect.SURGE_KEY: st}, NOW + timedelta(hours=6))
    h._surge(rows[1:], NOW)
    assert store.get_source_state(collect.SURGE_KEY) == {}


def test_plan_reads_the_surge_flag_with_the_source_states(monkeypatch):
    import importlib

    from radar.store import MemoryStore
    for k, v in {"AWS_DEFAULT_REGION": "ap-northeast-1", "AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "x"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("TABLE", raising=False)
    from radar import handlers
    h = importlib.reload(handlers)
    store = MemoryStore()
    monkeypatch.setattr(h, "_store", store)
    monkeypatch.setattr(h.timeutil, "now", lambda: NOW)
    monkeypatch.setattr(h, "_earlier_cycle_running", lambda *a: "none")
    ran = NOW - timedelta(minutes=T1.cadence_min * 0.6)              # due at half cadence, not at full
    store.put_source_state(T1.source_id, {"last_run": timeutil.iso(ran)})
    due = lambda: {i for b in h.plan({})["sources"] for i in b["source_ids"]}
    assert T1.source_id not in due()
    store.put_source_state(collect.SURGE_KEY, {"until": timeutil.iso(NOW + timedelta(hours=1)), "events": ["ev_1"]})
    assert T1.source_id in due()
