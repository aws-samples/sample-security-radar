"""R0.6 — a source that stopped being collected, or stopped producing, is on #/ops.

Audit 01 #3 / #8: `_status` looked only at consecutive failures. A source whose run crashed outside FetchError never
reached the state write — "ok" with an old last_success, forever; a feed that still parses but went quiet looked the
same as a quiet week."""
from datetime import UTC, datetime, timedelta

from radar import collect, ops, publish, timeutil
from radar import handlers as h
from radar.limits import Limits
from radar.registry import BY_ID, SOURCES
from radar.store import MemoryStore

NOW = datetime(2026, 11, 12, 12, 0, tzinfo=UTC)
A, B, C = (s.source_id for s in [s for s in SOURCES if s.enabled][:3])


def iso(**ago):
    return timeutil.iso(NOW - timedelta(**ago))


def test_a_crash_outside_fetch_errors_is_written_to_the_source_state():
    st = collect.crashed({"last_success": iso(hours=1), "consecutive_failures": 1}, NOW, RuntimeError("boom"))
    assert st["consecutive_failures"] == 2 and st["last_run"] == timeutil.iso(NOW)
    assert st["last_error"] == "crashed: RuntimeError: boom" and st["last_error_at"] == timeutil.iso(NOW)
    assert st["last_success"] == iso(hours=1)                           # what was true stays


def test_the_collect_handler_records_a_crash_instead_of_leaving_the_source_ok(monkeypatch):
    store = MemoryStore()
    monkeypatch.setattr(h, "_store", store)
    monkeypatch.delenv("TABLE", raising=False)
    monkeypatch.setattr(h, "_collect_source", lambda s, sid, slot: (_ for _ in ()).throw(OSError("connection reset")))
    out = h.collect_batch({"slot": "2026-11-12T12:00:00Z", "source_ids": [A]})
    assert out["results"][0]["ok"] is False
    st = store.get_source_state(A)
    assert st["consecutive_failures"] == 1 and "OSError" in st["last_error"]


def test_each_day_keeps_its_count_for_a_month():
    st = {}
    for d in range(40):
        st = collect.count_day(st, NOW - timedelta(days=40 - d), 2)
    st = collect.count_day(st, NOW - timedelta(days=1), 3)             # same day twice: added
    assert len(st["days"]) == Limits.SOURCE_DAYS_KEPT and st["days"][(NOW - timedelta(days=1)).strftime("%Y-%m-%d")] == 5


def _days(per_day, quiet):
    """A source that handed over `per_day` items a day, then nothing for the last `quiet` days."""
    return {(NOW - timedelta(days=d)).strftime("%Y-%m-%d"): per_day
            for d in range(quiet, Limits.SOURCE_SILENT_DAYS + Limits.SOURCE_SILENT_BASELINE_DAYS)}   # a full baseline


def test_overdue_and_silent_sources_are_found_and_healthy_ones_are_not():
    cad = BY_ID[A].cadence_min
    late = max(Limits.SOURCE_OVERDUE_CADENCES * cad, Limits.SOURCE_OVERDUE_MIN_MINUTES) + 1
    states = {
        A: {"last_run": iso(minutes=late)},                                            # not collected for 3 cadences
        B: {"last_run": iso(minutes=1), "days": _days(4, Limits.SOURCE_SILENT_DAYS)},   # productive, then nothing
        C: {"last_run": iso(minutes=1), "days": _days(4, 1)},                           # negative control: quiet one day
    }
    got = {r["source_id"]: r for r in publish.stalled_sources(states, NOW)}
    assert set(got) == {A, B}
    assert got[A]["kind"] == "overdue" and got[A]["minutes"] == late
    assert got[B]["kind"] == "silent" and got[B]["days"] == Limits.SOURCE_SILENT_DAYS and got[B]["usual_per_day"] == 4
    # a source that never produced much is not "silent" when it produces nothing; a never-run source is never_run
    assert publish.stalled_sources({A: {"last_run": iso(minutes=1), "days": _days(0, Limits.SOURCE_SILENT_DAYS)}, B: {}}, NOW) == []


def test_ops_lists_them_once_per_kind_not_once_per_source():
    rows = [{"source_id": f"s{n}", "name": f"S{n}", "kind": "overdue", "minutes": 90, "limit_min": 45} for n in range(12)]
    rows.append({"source_id": "q", "name": "Quiet", "kind": "silent", "days": 3, "usual_per_day": 4})
    items = [i for i in ops.attention({"stalled_sources": rows}) if i["code"] == "source_stalled"]
    assert [i["level"] for i in items] == ["error", "warn"]
    assert "12 个信源" in items[0]["title"] and "S0" in items[0]["detail"] and "Quiet" in items[1]["detail"]


def test_the_published_ops_page_carries_stalled_sources():
    store = MemoryStore()
    store.put_source_state(A, {"last_run": iso(days=2)})
    codes = [i["code"] for i in publish.build(store, NOW)["ops.json"]["attention"]]
    assert "source_stalled" in codes
