"""R3.1 — the listing says how much it left out, and what changed today is always in it (audit 03 6.2 / 6.3)."""
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jsonschema

from radar import publish, timeutil
from radar.limits import Limits
from radar.model import Event
from radar.store import MemoryStore

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)
SCHEMA = json.loads((Path(__file__).parents[1] / "schemas" / "site-data.schema.json").read_text())


def ev(n, sev, hours_ago, domain="vuln"):
    at = timeutil.iso(NOW - timedelta(hours=hours_ago))
    return Event(event_id=f"ev_{n:016x}", domain=domain, title=f"event {n}", first_seen=at, last_updated=at,
                 item_ids=[], keys=[], severity=sev)


def test_severity_wins_over_recency_and_today_leads_each_severity(monkeypatch):
    """Live 2026-11-15: the first R3.1 rule listed everything updated today first — 343 P2s pushed 4 of 6 P0s off the
    page (site_diff top_event_gone caught it after the deploy). A P0 / P1 is never cut for a P2 updated today."""
    monkeypatch.setattr(Limits, "PUBLISH_MAX_EVENTS", 5)
    old_p0 = [ev(n, "P0", 72 + n) for n in range(2)]                 # three days old
    old_p1 = [ev(10 + n, "P1", 48 + n) for n in range(2)]
    today_p1 = [ev(20, "P1", 1)]
    today_p2 = [ev(100 + n, "P2", 2 + n) for n in range(9)]          # a busy day of P2 updates
    got = publish.select_listing(old_p0 + old_p1 + today_p1 + today_p2, timeutil.iso(NOW - timedelta(days=1)))
    assert [e.event_id for e in got] == [e.event_id for e in [*old_p0, *today_p1, *old_p1]]
    # room left over ⇒ today's P2s come next, newest first
    monkeypatch.setattr(Limits, "PUBLISH_MAX_EVENTS", 7)
    got = publish.select_listing(old_p1 + today_p2, timeutil.iso(NOW - timedelta(days=1)))
    assert [e.severity for e in got] == ["P1", "P1", "P2", "P2", "P2", "P2", "P2"]
    assert got[2].event_id == today_p2[0].event_id


def test_the_document_counts_the_window_before_the_cut_and_validates(monkeypatch):
    monkeypatch.setattr(Limits, "PUBLISH_MAX_EVENTS", 3)
    monkeypatch.setattr(publish, "_response", lambda e, s, now: None)
    store = MemoryStore()
    for e in [ev(1, "P0", 1), ev(2, "P1", 30, "web3"), ev(3, "P2", 40), ev(4, "P2", 50, "incident"), ev(5, "P1", 2)]:
        store.put_event(e)
    doc, listed = publish.events_doc(store, NOW)
    assert len(doc["events"]) == len(listed) == 3
    assert doc["window"] == {"days": Limits.PUBLISH_WINDOW_DAYS, "total": 5, "listed": 3, "cap": 3,
                             "by_severity": {"P0": 1, "P1": 2, "P2": 2}, "by_domain": {"vuln": 3, "web3": 1, "incident": 1}}
    # the funnel counts the window, not the cut list (it said 24 h / P0 numbers that moved with the cap)
    assert doc["funnel"]["p0"] == 1
    monkeypatch.setattr(Limits, "PUBLISH_MAX_EVENTS", 1)
    store.put_event(ev(6, "P0", 3))
    doc, _ = publish.events_doc(store, NOW)
    assert len(doc["events"]) == 1 and doc["funnel"]["p0"] == 2 and doc["funnel"]["events_touched"] == 3
    events_schema = next(x for x in SCHEMA["oneOf"] if x["properties"]["kind"].get("const") == "events")
    jsonschema.validate(doc["window"], events_schema["properties"]["window"])
    assert "window" not in events_schema["required"]                            # an older publisher is still valid


def test_no_listed_event_is_less_severe_than_one_left_out_over_random_windows(monkeypatch):
    """The invariant behind the 2026-11-15 regression, independent of how select_listing is written: whatever is cut,
    nothing more severe than the least severe listed event is cut. 300 seeded windows around the cap."""
    import random
    rank = {"P0": 0, "P1": 1, "P2": 2}
    rnd = random.Random(1115)
    monkeypatch.setattr(Limits, "PUBLISH_MAX_EVENTS", 20)
    for _ in range(300):
        window = [ev(n, rnd.choice(["P0", "P1", "P1", "P2", "P2", "P2", "P2"]), rnd.uniform(0, 24 * 60))
                  for n in range(rnd.randint(1, 60))]
        got = publish.select_listing(window, timeutil.iso(NOW - timedelta(days=1)))
        listed = {e.event_id for e in got}
        assert len(got) == min(20, len(window))
        worst_listed = max((rank[e.severity] for e in got), default=-1)
        assert all(rank[e.severity] >= worst_listed for e in window if e.event_id not in listed)
