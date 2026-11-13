"""radar.decisions wired into the stations: the station's window / severity filter IS the table's (no restatement),
the station records whether it is configured (N_STATION_OFF reads that, not "a ledger exists"), and a fire row carries
the result of the op it issued (a failed call never reads as a success)."""
from __future__ import annotations

from datetime import timedelta

from respond_world import doc, targets_of
from test_handlers import env  # noqa: F401  (fixture)
from test_mitigate_station import NOW as M_NOW
from test_mitigate_station import FakeWaf, _seed
from test_respond_station import station  # noqa: F401  (fixture)
from test_store_contract import table as _table  # noqa: F401  (fixture used by env)

from radar import decisions, mitigate_station, respond
from radar.store import MemoryStore

NOW = "2026-10-23T18:00:00Z"
ON = {decisions.STATION_KEY: {"status": decisions.STATION_ON, "at": NOW}}


# ------------------------------------------------------------------ the station records configured / not configured

def test_an_unconfigured_station_records_it_once_and_republishes_every_page(env, monkeypatch):  # noqa: F811
    h, _ = env
    monkeypatch.delenv("SA_AGENT_SPACE_ID", raising=False)
    h._store.put_source_state(h.CONTINUUM_KEY, {"counters": {"inventory_scans": 3}, **ON})   # last cycle: running
    out = h.respond_events({"changed": ["a"]})
    led = h._store.get_source_state(h.CONTINUUM_KEY)
    assert led[decisions.STATION_KEY]["status"] == decisions.STATION_OFF_STATUS and led["counters"]["inventory_scans"] == 3
    assert out == {"changed": ["a"], "full": True}       # every page drops last cycle's rows once
    assert not decisions.station_on(led)
    assert h.respond_events({"changed": []}) == {"changed": [], "full": False}   # unchanged ⇒ no write, no republish


def test_a_configured_station_records_it_and_a_flip_republishes_once(station):  # noqa: F811
    h, _fake, clock = station
    out = h.respond_events({"changed": []})
    assert decisions.station_on(h._store.get_source_state(h.CONTINUUM_KEY)) and out["full"] is True
    clock["now"] += timedelta(minutes=10)
    assert h.respond_events({"changed": []})["full"] is False


# ------------------------------------------------------------------ one window / severity filter: the table's

def test_mitigate_station_reads_the_tables_window(monkeypatch):
    store = MemoryStore()
    eid = _seed(store)
    waf = FakeWaf({"demo-shop": {"name": "security-radar-waf-demo", "id": "a1"}})
    assert eid in mitigate_station.run(store, waf, M_NOW)["events"]
    # the table says nothing is in window: the station follows
    monkeypatch.setattr(decisions, "window_start", lambda action, code, n: "2999-01-01T00:00:00Z")
    assert eid not in mitigate_station.run(store, waf, M_NOW)["events"]


# ------------------------------------------------------------------ a fire row carries its op's result

def _cycle(prev, now, fail: set[str]):
    ev, items, analysis = doc("php2shell")
    st, ops = respond.decide(ev, items, analysis, prev, targets_of("targets"), respond.Budget(6, True, "2026-10-23", now=now))
    for o in ops:
        if o.kind.startswith("poll_") or o.kind == "start_review":
            continue
        err = "continuum_unavailable" if o.kind in fail else None
        st = respond.apply(st, o, {"error": err} if err else {"finding_id": "cf-1", "status": "SUBMITTED",
                                                               "scan_run_id": "s1"}, now)
    return st


def test_a_failed_op_marks_its_fire_row_error_and_a_failing_retry_shows_its_latest_attempt():
    st = _cycle(None, NOW, {"write_context"})
    ctx, req = st["decisions"]["cn_context"], st["decisions"]["sa_requirement"]
    assert (ctx["outcome"], ctx["result"], ctx["error"], ctx["result_at"]) == ("fire", "error", "continuum_unavailable", NOW)
    assert (req["outcome"], req["result"]) == ("fire", "ok")
    later = "2026-10-23T18:05:00Z"
    again = _cycle(st, later, {"write_context"})["decisions"]["cn_context"]
    assert again["at"] == NOW and (again["result"], again["result_at"]) == ("error", later)   # retried, failed again
    assert _cycle(st, later, set())["decisions"]["cn_context"]["result"] == "ok"


def test_one_failed_submit_of_several_makes_the_row_an_error():
    rows = {"cn_finding:t": {"action": "cn_finding", "scope": "t", "outcome": "fire"}}
    decisions.mark_result(rows, "submit_finding", "t", "boom", NOW)
    decisions.mark_result(rows, "submit_finding", "t", None, NOW)
    assert rows["cn_finding:t"]["result"] == "error"
    held = {"cn_scan:s3": {"action": "cn_scan", "scope": "s3", "outcome": "blocked"}}
    decisions.mark_result(held, "request_scan", "s3", None, NOW)
    assert "result" not in held["cn_scan:s3"]   # only an issued call has a result


