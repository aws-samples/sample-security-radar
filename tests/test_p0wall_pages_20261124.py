"""Every event the P0 wall shows has a current detail page (live 2026-11-24: MySQL CVE-2026-114952 was demoted to P1, fell
outside the PUBLISH_MAX_EVENTS listing, and a full rebuild left its 11-23 page — with a WAF block its empty rule pack did
not have — while the wall and the P0 notice linked to it)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from radar import publish, timeutil
from radar.limits import Limits
from radar.model import Event
from radar.store import MemoryStore

NOW = datetime(2026, 11, 24, 6, 0, tzinfo=UTC)


def _ev(n, sev, hours, became_p0=None, domain="vuln"):
    at = timeutil.iso(NOW - timedelta(hours=hours))
    tl = [{"at": became_p0, "kind": "severity_change", "from": "P1", "to": "P0", "item_id": None}] if became_p0 else []
    return Event(event_id=f"ev_{n:016x}", domain=domain, title=f"CVE-2026-{n} flaw {n}", first_seen=at, last_updated=at,
                 item_ids=[], keys=[], severity=sev, exploitation="none", entities=[], timeline=tl)


def _store(monkeypatch):
    monkeypatch.setattr(Limits, "PUBLISH_MAX_EVENTS", 2)
    s = MemoryStore()
    was_p0 = timeutil.iso(NOW - timedelta(hours=30))
    for e in [_ev(1, "P0", 1), _ev(2, "P1", 2), _ev(3, "P1", 3),          # the listing: P0 first, then newest
              _ev(4, "P1", 40, became_p0=was_p0),                         # was P0, demoted, outside the cap
              _ev(5, "P2", 50), _ev(6, "P1", 60, domain="web3")]:         # never P0 / a theft: not on the wall
        s.put_event(e)
    return s


def test_a_wall_event_outside_the_listing_still_gets_its_page(monkeypatch):
    docs = publish.build(_store(monkeypatch), NOW)
    wall = {x["event_id"] for x in docs["p0.json"]["events"]}
    listed = {x["event_id"] for x in docs["events.json"]["events"]}
    assert "ev_0000000000000004" in wall - listed
    assert all(f"events/{i}.json" in docs for i in wall)
    assert "events/ev_0000000000000005.json" not in docs and "events/ev_0000000000000006.json" not in docs


def test_an_incremental_run_rebuilds_a_changed_wall_event(monkeypatch):
    docs = publish.build(_store(monkeypatch), NOW, changed={"ev_0000000000000004"})
    assert "events/ev_0000000000000004.json" in docs and "events/ev_0000000000000001.json" not in docs
