"""Station run-time ledger + #/ops station_slow (live 2026-11-02: publish crept 89 s → 256 s, then hit 300 s)."""
from datetime import UTC, datetime, timedelta

from radar import handlers, ops, stationtime
from radar.store import MemoryStore

T0 = datetime(2026, 11, 2, 12, tzinfo=UTC)



def _no_such_key(self, **kw):
    from botocore.exceptions import ClientError
    raise ClientError({"Error": {"Code": "NoSuchKey", "Message": "x"}}, "GetObject")

def test_the_ledger_keeps_the_last_runs_and_the_timeout():
    store = MemoryStore()
    for k in range(15):
        stationtime.record(store, "publish", 10 + k, 300, T0 + timedelta(minutes=10 * k))
    led = store.get_source_state(stationtime.PREFIX + "publish")
    assert len(led["runs"]) == stationtime.KEEP and led["runs"][-1]["s"] == 24 and led["timeout_s"] == 300


def test_slow_fires_at_sixty_percent_of_the_timeout_among_recent_runs():
    store = MemoryStore()
    for s in (15, 15, 179, 15):
        stationtime.record(store, "publish", s, 300, T0)
    assert stationtime.slow(stationtime.facts(store)) == []
    stationtime.record(store, "publish", 181, 300, T0)
    [hit] = stationtime.slow(stationtime.facts(store))
    assert hit["station"] == "publish" and hit["worst_s"] == 181 and hit["timeout_s"] == 300
    item = ops._slow({"slow_stations": [hit]})[0]
    assert item["level"] == "warn" and "181" in item["title"] and "300" in item["title"]   # actual + limit
    for _ in range(stationtime.RECENT):        # a slow run that left the recent window no longer warns
        stationtime.record(store, "publish", 15, 300, T0)
    assert stationtime.slow(stationtime.facts(store)) == []


class _Ctx:
    def __init__(self, s): self.s = s
    def get_remaining_time_in_millis(self): return int(self.s * 1000)


def test_a_station_records_its_run_even_when_it_fails(monkeypatch):
    store = MemoryStore()
    monkeypatch.setattr(handlers, "_store", store)

    @handlers._timed("respond")
    def boom(event, _ctx=None):
        raise RuntimeError("x")
    try:
        boom({}, _Ctx(600))
    except RuntimeError:
        pass
    led = store.get_source_state(stationtime.PREFIX + "respond")
    assert len(led["runs"]) == 1 and led["timeout_s"] == 600


def test_deferred_pages_are_published_by_the_next_run(monkeypatch):
    from test_cvemeta import _vuln_store
    store, put = _vuln_store(), []
    monkeypatch.setattr(handlers, "_store", store)
    monkeypatch.setattr(handlers, "_s3", type("S3", (), {"put_object": lambda self, **kw: put.append(kw["Key"]), "get_object": _no_such_key})())
    monkeypatch.setenv("SITE_BUCKET", "b")
    from radar import fetch
    monkeypatch.setattr(fetch, "http_get", lambda *a, **k: (_ for _ in ()).throw(fetch.FetchError("network_error", "offline", None, "x")))
    [eid] = store.events
    r = handlers.publish_site({"changed": [eid]}, _Ctx(30))            # below the 45 s reserve
    assert r["deferred"] == 1 and f"data/events/{eid}.json" not in put
    assert store.get_source_state(handlers.PENDING_KEY)["ids"] == [eid]
    put.clear()
    r = handlers.publish_site({"changed": []}, _Ctx(300))              # next cycle, nothing new changed
    assert f"data/events/{eid}.json" in put and r["deferred"] == 0
    assert store.get_source_state(handlers.PENDING_KEY)["ids"] == []


def test_enrichment_failures_reach_ops_in_the_same_run(monkeypatch):
    """Live 2026-11-02: EPSS went blank on every page and only a reader noticed. A failed lookup is now a warn in
    #/ops of the very run that failed (the ledger is written before ops.json is built)."""
    from test_cvemeta import _vuln_store

    from radar import fetch, publish
    store, put = _vuln_store(), []
    monkeypatch.setattr(handlers, "_store", store)
    monkeypatch.setattr(handlers, "_s3", type("S3", (), {"put_object": lambda self, **kw: put.append(kw), "get_object": _no_such_key})())
    monkeypatch.setenv("SITE_BUCKET", "b")
    monkeypatch.setattr(fetch, "http_get", lambda *a, **k: (_ for _ in ()).throw(fetch.FetchError("http_error", "503", 503, "x")))
    handlers.publish_site({"full": True}, _Ctx(300))
    import json
    ops_doc = json.loads(next(kw["Body"] for kw in put if kw["Key"] == "data/ops.json"))
    codes = [i["code"] for i in ops_doc["attention"]]
    assert codes.count("enrich_degraded") == 2          # EPSS and the CVE record
    assert store.get_source_state(publish.ENRICH_KEY)["epss_failed"] == 1


# --- R0.3: a station that fails every run, or stopped running, is on #/ops ------------------------------------------

def test_a_failed_run_is_recorded_as_failed(monkeypatch):
    """The cycle catches Analyze / Respond / Mitigate / Notify failures and still succeeds (infra/stack.py add_catch):
    the ledger was the only trace, and it recorded a failed run as an ordinary duration."""
    import pytest
    store = MemoryStore()
    monkeypatch.setattr(handlers, "_store", store)

    @handlers._timed("respond")
    def boom(event, _ctx=None):
        raise RuntimeError("x")

    @handlers._timed("respond")
    def fine(event, _ctx=None):
        return {}
    with pytest.raises(RuntimeError):
        boom({})
    fine({})
    runs = store.get_source_state(stationtime.PREFIX + "respond")["runs"]
    assert [r.get("ok", True) for r in runs] == [False, True]


def test_a_station_failing_every_recent_run_or_not_running_is_reported():
    store = MemoryStore()
    for k in range(stationtime.FAILING_RUNS):
        stationtime.record(store, "respond", 2, 600, T0 + timedelta(minutes=5 * k), ok=False)
    stationtime.record(store, "mitigate", 2, 300, T0 - timedelta(minutes=stationtime.SILENT_MINUTES + 1))
    stationtime.record(store, "notify", 2, 300, T0)                                       # negative control: healthy
    stationtime.record(store, "analyze", 2, 600, T0, ok=False)                            # one failure is not a pattern
    stationtime.record(store, "analyze", 2, 600, T0 + timedelta(minutes=5))
    now = T0 + timedelta(minutes=5 * stationtime.FAILING_RUNS)
    got = {s["station"]: s for s in stationtime.silent(stationtime.facts(store), now)}
    assert set(got) == {"respond", "mitigate"}
    assert got["respond"]["kind"] == "failing" and got["respond"]["runs"] == stationtime.FAILING_RUNS
    assert got["mitigate"]["kind"] == "silent" and got["mitigate"]["limit_min"] == stationtime.SILENT_MINUTES
    items = [i for i in ops.attention({"silent_stations": list(got.values())}) if i["code"] == "station_silent"]
    assert len(items) == 2 and all(i["level"] == "error" for i in items)


def test_the_published_ops_page_reports_a_silent_station():
    from radar import publish
    store = MemoryStore()
    stationtime.record(store, "mitigate", 2, 300, T0 - timedelta(hours=2))
    codes = [i["code"] for i in publish.build(store, T0)["ops.json"]["attention"]]
    assert "station_silent" in codes
