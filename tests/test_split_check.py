"""Harness for split events (Neo 2026-11-02 「务必修复，尽可能 harness」): each publish re-matches the first report of
every event opened in the last ENTITY_WINDOW_DAYS against the current rules; an event whose first report now belongs to
an older event is a split and queues in #/ops with the repair command."""
from datetime import UTC, datetime

from test_pipeline_replay import _binance_open_event, _web3, _web3_events

from radar import ops, pipeline
from radar.model import Event
from radar.store import MemoryStore

NOW = datetime(2026, 11, 2, 1, tzinfo=UTC)


def _split_store():
    """Binance opened under the old rule (fixed window), then a follow-up opened a second event."""
    store = MemoryStore()
    _binance_open_event(store)
    late = pipeline.normalize(_web3("theblock", "Binance hack: $250K of stolen funds deposited to Gate, 2 accounts frozen",
                                    "2026-11-01T23:59:00Z", NOW), __import__("radar.registry").registry.BY_ID["theblock"], NOW)
    store.put_item(late)
    ev = Event(event_id="ev_ffffffffffffffff", domain="web3", title=late.title, first_seen=late.published_at,
               last_updated=late.published_at, item_ids=[late.item_id], keys=pipeline.indexed_keys(late))
    store.put_event(ev)
    store.add_keys(ev.event_id, ev.keys)
    return store


def test_an_event_whose_first_report_now_belongs_to_an_older_event_is_listed():
    store = _split_store()
    [pair] = pipeline.split_candidates(store, NOW)
    older = _web3_events(store)[0]
    assert pair == {"older": older["event_id"], "newer": "ev_ffffffffffffffff", "domain": "web3",
                    "older_title": older["title"], "newer_title": "Binance hack: $250K of stolen funds deposited to Gate, 2 accounts frozen"}


def test_an_unrelated_new_event_is_not_listed():
    store = MemoryStore()
    _binance_open_event(store)
    pipeline.ingest([_web3("theblock", "zkLink Nova exploited for $780K via forged messages", "2026-11-01T22:00:00Z", NOW)], store, NOW)
    assert pipeline.split_candidates(store, NOW) == []


def test_splits_queue_in_ops_with_the_repair_command():
    pair = {"older": "ev_aaaaaaaaaaaaaaaa", "newer": "ev_bbbbbbbbbbbbbbbb", "domain": "web3", "older_title": "Binance", "newer_title": "Binance net outflows"}
    [item] = ops.RULES["event_split"]({"splits": [pair]})
    assert item["level"] == "warn" and item["link"] == "/events/ev_bbbbbbbbbbbbbbbb"
    assert "--event ev_aaaaaaaaaaaaaaaa --event ev_bbbbbbbbbbbbbbbb" in item["detail"]
