"""Criteria for the code-computed insight layer (M2-PLAN; research/09 §C②: ranking, reasons, headline,
funnel and lifecycle are D-class — never LLM)."""

from datetime import UTC, datetime, timedelta

from test_pipeline_replay import FETCHED, _raw, snapshot_raws

from radar import insights, pipeline, timeutil
from radar.model import Event
from radar.store import MemoryStore


def _ev(**kw) -> Event:
    base = {"event_id": "ev_0000000000000001", "domain": "vuln", "title": "Acme VPN zero-day", "first_seen": "2026-10-22T00:00:00Z",
                "last_updated": "2026-10-22T00:00:00Z", "item_ids": [], "keys": [], "level": "V3", "severity": "P0",
                "exploitation": "confirmed", "independent_sources": 2}
    return Event(**{**base, **kw})


def test_lifecycle_words():
    now = datetime(2026, 10, 23, tzinfo=UTC)
    assert insights.lifecycle(_ev(level="V4", last_updated="2026-10-22T00:00:00Z"), 0, now) == "finalized"
    assert insights.lifecycle(_ev(escalated_at="2026-10-22T12:00:00Z"), 0, now) == "escalating"
    assert insights.lifecycle(_ev(last_updated="2026-10-21T00:00:00Z", first_seen="2026-10-10T00:00:00Z"), 0, now) == "active"
    assert insights.lifecycle(_ev(last_updated="2026-10-15T00:00:00Z", first_seen="2026-10-10T00:00:00Z"), 0, now) == "cooling"
    assert insights.lifecycle(_ev(last_updated="2026-09-01T00:00:00Z", first_seen="2026-09-01T00:00:00Z"), 0, now) == "dormant"
    assert insights.lifecycle(_ev(last_updated="2026-10-15T00:00:00Z", first_seen="2026-10-10T00:00:00Z"), 2, now) == "escalating"


def test_velocity_counts_only_new_independent_groups():
    store = MemoryStore()
    now = datetime(2026, 10, 23, 12, tzinfo=UTC)
    pipeline.ingest([
        _raw("bleepingcomputer", "CVE-2026-55555 Acme flaw exploited", "actively exploited", when="2026-10-23T02:00:00Z"),
        _raw("securityweek", "Attackers hit Acme gateway (CVE-2026-55555)", "exploited in the wild", when="2026-10-23T10:00:00Z"),
        _raw("thehackernews", "Acme bug CVE-2026-55555 under attack", "exploited in the wild", when="2026-10-23T11:00:00Z"),
        # same outlet as the 02:00 story ⇒ an echo of an OLD group, not a new source
        _raw("bleepingcomputer", "Acme confirms CVE-2026-55555 fix timeline", "update", when="2026-10-23T11:30:00Z"),
    ], store, now)
    [ev] = [Event.from_dict(e) for e in store.events.values()]
    assert insights.velocity(ev, store.get_items(ev.item_ids), now, hours=6) == 2


def test_now_board_is_short_ranked_explained_and_deterministic():
    store = MemoryStore()
    pipeline.ingest(snapshot_raws(), store, FETCHED)
    evs = [Event.from_dict(e) for e in store.events.values()]
    board = insights.now_board(evs, store, FETCHED)
    assert 1 <= len(board) <= 3
    assert [b["score"] for b in board] == sorted((b["score"] for b in board), reverse=True)
    for b in board:
        ev = next(e for e in evs if e.event_id == b["event_id"])
        assert ev.severity in ("P0", "P1") and b["reasons"], b
    assert board == insights.now_board(evs, store, FETCHED)


def test_now_board_never_shows_stale_or_p2():
    now = datetime(2026, 10, 23, tzinfo=UTC)
    stale = _ev(event_id="ev_0000000000000002", severity="P1", first_seen="2026-08-01T00:00:00Z", last_updated="2026-08-01T00:00:00Z")
    p2 = _ev(event_id="ev_0000000000000003", severity="P2")
    assert insights.now_board([stale, p2], MemoryStore(), now) == []


def test_headline_is_templated_and_degrades_visibly():
    now = datetime(2026, 10, 23, 7, 18, tzinfo=UTC)
    ev = _ev(title="PHP core RCE vulnerability patches (CVE-2026-109618 and CVE-2026-109619)")
    h = insights.headline([{"event_id": ev.event_id, "score": 1.0, "reasons": ["在野利用·已报道", "7 个独立来源"]}],
                          {ev.event_id: ev}, sources_ok=14, sources_total=14, now=now)
    assert h.startswith("PHP core RCE") and "在野利用·已报道" in h
    empty = insights.headline([], {}, sources_ok=13, sources_total=14, now=now)
    assert "当前无必须处理事件" in empty and "13/14" in empty and "07:18" in empty


def test_funnel_rolls_24h_window():
    now = datetime(2026, 10, 23, 12, tzinfo=UTC)
    runs = [[timeutil.iso(now - timedelta(hours=30)), 100, 50], [timeutil.iso(now - timedelta(hours=2)), 40, 7]]
    f = insights.funnel(runs, events_touched=5, corroborated=2, p0=1, now=now)
    assert f == {"window_hours": 24, "fetched": 40, "new_or_updated_items": 7, "events_touched": 5, "corroborated": 2, "p0": 1}


STAGES = ["first_report", "second_source", "corroborated", "confirmed", "exploited", "analyzed", "finalized"]


def _replayed_event(cve):
    store = MemoryStore()
    pipeline.ingest(snapshot_raws(), store, FETCHED)
    ev = next(Event.from_dict(e) for e in store.events.values() if cve in e["cves"])
    return ev, store.get_items(ev.item_ids)


def test_progress_has_fixed_stages_with_evidence_times():
    ev, items = _replayed_event("CVE-2026-109618")  # PHP2Shell
    prog = insights.progress(ev, items, FETCHED)
    assert [p["stage"] for p in prog] == STAGES
    at = {p["stage"]: p["at"] for p in prog}
    assert at["first_report"] == "2026-10-21T07:00:00Z"            # Fortinet advisory
    assert at["second_source"] and at["second_source"] >= at["first_report"]
    exploited_items = sorted(i.published_at for i in items if i.signals["exploited"] == "yes")
    assert at["exploited"] == exploited_items[0]                   # earliest evidence saying exploited
    assert at["finalized"] is None and at["analyzed"] is None     # not V4, no analysis yet
    times = [t for t in at.values() if t]
    assert all(t <= timeutil.iso(FETCHED) for t in times)          # never "processing time in the future"


def test_progress_stage_times_are_evidence_times_not_processing_time():
    ev, items = _replayed_event("CVE-2026-109618")
    later = FETCHED + timedelta(days=30)
    a = {p["stage"]: p["at"] for p in insights.progress(ev, items, FETCHED)}
    b = {p["stage"]: p["at"] for p in insights.progress(ev, items, later)}
    assert {k: v for k, v in a.items() if k != "finalized"} == {k: v for k, v in b.items() if k != "finalized"}


def test_pipeline_steps_report_unconfigured_and_unconnected_explicitly():
    ev, items = _replayed_event("CVE-2026-109618")
    steps = {s["step"]: s for s in insights.pipeline_steps(ev, items)}
    assert list(steps) == ["collected", "clustered", "verified", "analyzed", "impact_match", "remediated", "notified"]
    assert steps["collected"]["status"] == "done" and str(len(items)) in steps["collected"]["detail"]
    assert steps["analyzed"]["status"] == "pending"          # P0 without analysis yet
    assert steps["impact_match"]["status"] == "pending"      # P0 vuln, respond station has not run yet
    assert steps["notified"]["status"] == "not_connected"
