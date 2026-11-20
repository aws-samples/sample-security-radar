"""Live 2026-11-19: the analyze station ran 448 s on average of its 600 s timeout (max = 600, timed out); the briefs
ran first, so the attack paths after them rarely started (36 events in 14 h, 660 P1s without one)."""
import datetime as dt

import pytest


@pytest.fixture
def station(monkeypatch):
    for k, v in {"AWS_DEFAULT_REGION": "ap-northeast-1", "AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "x"}.items():
        monkeypatch.setenv(k, v)
    from radar import analyst, attack_path
    from radar import handlers as h
    from radar.model import Event, Item
    from radar.store import MemoryStore
    store = MemoryStore()
    for n in range(4):
        it = Item(item_id=f"it_{n}", source_id="cvefeed", tier="T2", org="cvefeed", domain="vuln", url=f"https://x/{n}",
                  canonical_url=f"https://x/{n}", title=f"CVE-2026-{n:04} RCE", text="x", published_at="2026-11-19T00:00:00Z",
                  fetched_at="2026-11-19T00:00:00Z", content_hash=str(n), keys=[], links=[], entity=None, eventful=True,
                  signals={}, extra={})
        store.put_item(it)
        store.put_event(Event(event_id=f"ev_{n:016}", domain="vuln", title=it.title, first_seen=it.published_at,
                              last_updated=it.published_at, item_ids=[it.item_id], keys=[], severity="P0" if n == 0 else "P1"))
    calls = []
    monkeypatch.setattr(h, "_store", store)
    for f in ("_daily_digest", "_cluster_judge", "_retitle_shadow"):
        monkeypatch.setattr(h, f, lambda now: [])
    monkeypatch.setattr(analyst, "analyze", lambda ev_in, now: calls.append("brief") or {"status": "ok", "input_hash": "h"})
    monkeypatch.setattr(attack_path, "build", lambda ev, now: calls.append("path") or
                        {"status": "ok", "input_hash": "p", "steps": {}, "defenses": []})
    monkeypatch.setattr(h.timeutil, "now", lambda: dt.datetime(2026, 11, 19, 12, tzinfo=dt.UTC))
    return h, calls


class Ctx:
    """Each model call costs 60 s of the invocation (the fake calls append; the clock reads how many happened)."""

    def __init__(self, start_s, calls):
        self.start, self.calls = start_s, calls

    def get_remaining_time_in_millis(self):
        return (self.start - 60 * len(self.calls)) * 1000


def test_attack_paths_run_before_the_briefs(station):
    h, calls = station
    h.analyze_events({}, Ctx(600, calls))
    assert calls[:2] == ["path", "path"] and "brief" in calls


def test_no_model_call_starts_with_less_than_the_reserve_and_the_rest_is_said_deferred(station):
    h, calls = station
    out = h.analyze_events({}, Ctx(300, calls))     # 300 s: 2 calls fit before 180 s < … reserve 120 after the 3rd
    left = 300 - 60 * len(calls)
    assert left >= h.Limits.MODEL_CALL_RESERVE_S - 60      # the last call started with at least the reserve left
    assert out["analysis_deferred"] > 0
