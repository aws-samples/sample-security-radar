"""D (half) · disposition set by an operator CLI (IAM), shown read-only (radar.triage)."""
from datetime import UTC, datetime

import pytest

from radar import ops, triage
from radar.model import Event
from radar.store import MemoryStore

NOW = datetime(2026, 10, 31, 3, tzinfo=UTC)
EID = "ev_0a4e5c3e0fce8be9"


def store_with_event():
    s = MemoryStore()
    s.put_event(Event(event_id=EID, domain="web3", title="Binance", first_seen="2026-10-29T20:51:50Z",
                      last_updated="2026-10-30T08:00:00Z", item_ids=[], keys=[], severity="P0"))
    return s


@pytest.mark.parametrize(("eid", "status", "note", "code"), [
    ("ev_0a4e5c3e0fce8be9\n", "triage", "", "bad_event_id"),          # fullmatch, not match(...$)
    ("../x", "triage", "", "bad_event_id"),
    ("ev_ffffffffffffffff", "triage", "", "unknown_event"),
    (EID, "done", "", "bad_status"),
    (EID, "triage", "x" * 281, "note_too_long"),
])
def test_bad_input_is_refused_with_the_four_part_error(eid, status, note, code):
    with pytest.raises(triage.TriageError) as e:
        triage.set_status(store_with_event(), eid, status, note, "operator", NOW)
    assert e.value.detail["error"] == code and {"message", "actual", "limit"} <= e.value.detail.keys()


def test_a_disposition_is_republished_once_and_keeps_its_predecessor():
    s = store_with_event()
    triage.set_status(s, EID, "triage", "看链上复盘", "operator", NOW)
    assert triage.changed(s) == [EID]
    assert triage.changed(s) == []                                        # seen ⇒ not republished again
    e = triage.set_status(s, EID, "tracking", "", "operator", datetime(2026, 10, 31, 4, tzinfo=UTC))
    assert e["previous"] == {"status": "triage", "at": "2026-10-31T03:00:00Z"} and triage.changed(s) == [EID]
    assert triage.public(e) == {"status": "tracking", "label": "跟进中", "note": "", "by": "operator", "at": "2026-10-31T04:00:00Z"}


def test_ops_lists_p0_events_nobody_has_triaged():
    facts = {"events": [{"event_id": EID, "severity": "P0", "title": "Binance", "triage": None},
                        {"event_id": "ev_1111111111111111", "severity": "P0", "title": "X", "triage": {"status": "tracking"}},
                        {"event_id": "ev_2222222222222222", "severity": "P1", "title": "Y", "triage": None}]}
    items = ops.RULES["p0_untriaged"](facts)
    assert [i["link"] for i in items] == [f"/events/{EID}"] and items[0]["level"] == "info"
