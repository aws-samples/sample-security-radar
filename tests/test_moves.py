"""R1.2 — one report can be moved from an event to another, and stays there.

Audit 02 Q5: the only repairs were "merge two events" and "replay a whole domain"; a single misplaced report needed a
rule change. Fixture: the 2026-10-23 snapshot replay (AlpsCon = three sources, one event)."""
from datetime import timedelta

import pytest
from test_pipeline_replay import FETCHED, events_with_entity, snapshot_raws

from radar import moves, pipeline, removals, timeutil
from radar.model import Event
from radar.store import MemoryStore

NOW = FETCHED + timedelta(hours=1)


@pytest.fixture
def store():
    s = MemoryStore()
    pipeline.ingest(snapshot_raws(), s, FETCHED)
    return s


def alpscon(s) -> Event:
    return Event.from_dict(events_with_entity(s, "AlpsCon")[0])


def other(s, not_id) -> Event:
    """An unrelated web3 event with several reports."""
    return next(Event.from_dict(e) for e in s.events.values()
                if e["event_id"] != not_id and e["domain"] == "web3" and len(e["item_ids"]) >= 2)


def rows(s, eid):
    return sorted(k for k, ids in s.keys.items() if eid in ids)


def test_a_moved_report_leaves_with_its_keys_and_both_events_are_recomputed(store):
    src = alpscon(store)
    moved = next(i for i in src.item_ids if store.items[i]["source_id"] == "defihacklabs")
    own = set(pipeline.indexed_keys(store.get_item(moved)))
    out = moves.move_item(store, moved, src.event_id, None, NOW)
    a, b = store.get_event(src.event_id), store.get_event(out["to"])
    assert out == {"from": src.event_id, "to": b.event_id, "removed": False}
    assert moved not in a.item_ids and b.item_ids == [moved] and len(a.item_ids) == len(src.item_ids) - 1
    # an event's keys are exactly what its reports contribute — and the index agrees, row for row
    assert a.keys == moves.event_keys(store.get_items(a.item_ids)) == rows(store, a.event_id)
    assert b.keys == sorted(own) == rows(store, b.event_id)
    gone = own - set(a.keys)
    assert gone and all(a.event_id not in store.event_ids_for_key(k) for k in gone)
    # recomputed, not patched: the source lost one independent source
    assert {store.items[i]["source_id"] for i in a.item_ids} == {"defillama_hacks", "slowmist_hacked"}
    assert a.timeline[-1]["kind"] == "repaired" and a.timeline[-1]["item_id"] == moved


def test_a_revision_of_a_moved_report_keeps_its_pin_and_its_event(store):
    src = alpscon(store)
    moved = next(i for i in src.item_ids if store.items[i]["source_id"] == "defihacklabs")
    raw = next(r for r in snapshot_raws() if r.source_id == "defihacklabs" and r.extra["entity"] == "AlpsCon")
    to = moves.move_item(store, moved, src.event_id, None, NOW)["to"]
    raw.text = (raw.text or "") + " (updated)"
    res = pipeline.ingest([raw], store, NOW, NOW)
    assert res.updated_items == 1
    assert store.get_item(moved).extra["event_pin"] == to
    assert moved in store.get_event(to).item_ids and moved not in store.get_event(src.event_id).item_ids
    assert store.get_event(src.event_id) is not None


def test_a_report_moves_into_an_existing_event_and_a_replay_keeps_it_there(store):
    src = alpscon(store)
    dst = other(store, src.event_id)
    moved = src.item_ids[0]
    moves.move_item(store, moved, src.event_id, dst.event_id, NOW)
    got = store.get_event(dst.event_id)
    assert moved in got.item_ids and got.keys == moves.event_keys(store.get_items(got.item_ids)) == rows(store, dst.event_id)
    # a replay (scripts/recluster_web3.py) re-attaches stored reports in order: the rules would return the moved one to
    # the event of its story, the pin sends it to the event it was moved to — opened by it when not there yet
    fresh, res = MemoryStore(), pipeline.IngestResult()
    for i in [*store.get_event(src.event_id).item_ids, moved]:
        fresh.put_item(store.get_item(i))
        pipeline.attach(store.get_item(i), fresh, timeutil.iso(NOW), NOW, res)
    assert fresh.get_event(dst.event_id).item_ids == [moved]
    assert all(moved not in e["item_ids"] for eid, e in fresh.events.items() if eid != dst.event_id)


def test_moving_the_last_report_removes_the_event_and_says_where_it_went(store):
    src = alpscon(store)
    dst = other(store, src.event_id)
    store.put_response(src.event_id, {"event_id": src.event_id, "jobs": {}})
    for i in src.item_ids:
        last = moves.move_item(store, i, src.event_id, dst.event_id, NOW)
    assert last["removed"] and store.get_event(src.event_id) is None and rows(store, src.event_id) == []
    assert removals.pending(store)[src.event_id]["to"] == dst.event_id
    assert store.get_response(src.event_id) is None and store.get_response(dst.event_id) is not None


def test_a_move_that_cannot_be_made_says_why(store):
    src = alpscon(store)
    for args, code in [((src.item_ids[0], src.event_id, src.event_id), "same_event"),
                       ((src.item_ids[0], src.event_id, "ev_nope"), "destination_missing"),
                       (("nope", src.event_id, None), "item_not_in_event")]:
        with pytest.raises(moves.MoveError) as e:
            moves.move_item(store, *args, NOW)
        assert e.value.detail["error"] == code
    assert alpscon(store).to_dict() == src.to_dict()                      # nothing written


def test_misplaced_reports_are_listed_and_pinned_ones_are_not(store):
    evs = lambda: [Event.from_dict(e) for e in store.events.values()]
    base = moves.misplaced_candidates(store, evs())
    src = alpscon(store)
    dst = other(store, src.event_id)
    moved = next(i for i in src.item_ids if store.items[i]["source_id"] == "defihacklabs")
    moves.move_item(store, moved, src.event_id, dst.event_id, NOW)
    # pinned = a human's decision: the moved report is never a candidate. (Since stablecoin amounts read as USD, its
    # siblings may become candidates — they now carry the same figure; that is the rules being consistent.)
    assert moved not in {c.get("item_id") for c in moves.misplaced_candidates(store, evs())}
    it = store.get_item(moved)
    it.extra.pop("event_pin")
    store.put_item(it)
    new = [c for c in moves.misplaced_candidates(store, evs()) if c not in base and c["item_id"] == moved]
    assert [(c["item_id"], c["event_id"], c["kind"], c["to"]) for c in new] == [(moved, dst.event_id, "elsewhere", src.event_id)]
    assert moves.misplaced_candidates(store, evs(), limit=0)[-1] == {"truncated": True, "limit": 0}
