"""Item 6 · C4 overrides: an operator labels a pair of events same / different with their own IAM credentials (no web
write surface, like radar.triage). The human label beats the model on the page; confirmed duplicates queue in #/ops;
the labels measure the judge's precision — the gate for any automatic merge (docs/research/12 §11)."""
from datetime import UTC, datetime

import pytest

from radar import cluster_judge, duplabels, ops
from radar.model import Event
from radar.store import MemoryStore

NOW = datetime(2026, 11, 1, 3, tzinfo=UTC)
A, B, C = "ev_aaaaaaaaaaaaaaaa", "ev_bbbbbbbbbbbbbbbb", "ev_cccccccccccccccc"


def store():
    s = MemoryStore()
    for eid, t in ((A, "Quest Diagnostics breach"), (B, "Quest Diagnostics data breach hits 3M"), (C, "Plex CVE-2026-1")):
        s.put_event(Event(event_id=eid, domain="incident", title=t, first_seen="2026-10-30T00:00:00Z",
                          last_updated="2026-10-30T00:00:00Z", item_ids=[], keys=[]))
    return s


@pytest.mark.parametrize(("a", "b", "label", "note", "code"), [
    (A + "\n", B, "same", "", "bad_event_id"),
    (A, A, "same", "", "same_event"),
    (A, "ev_ffffffffffffffff", "same", "", "unknown_event"),
    (A, B, "merge", "", "bad_label"),
    (A, B, "same", "x" * 281, "note_too_long"),
])
def test_bad_input_is_refused_with_the_four_part_error(a, b, label, note, code):
    with pytest.raises(duplabels.LabelError) as e:
        duplabels.set_label(store(), a, b, label, note, "operator", NOW)
    assert e.value.detail["error"] == code and {"message", "actual", "limit"} <= e.value.detail.keys()


def test_a_pair_is_one_entry_whatever_the_order_and_keeps_its_predecessor():
    s = store()
    duplabels.set_label(s, B, A, "different", "", "operator", NOW)
    e = duplabels.set_label(s, A, B, "same", "同一份新闻稿", "operator", datetime(2026, 11, 1, 4, tzinfo=UTC))
    assert list(s.get_source_state(duplabels.KEY)) == [f"{A}|{B}"]
    assert e["previous"] == {"label": "different", "at": "2026-11-01T03:00:00Z"}


def _judge(verdict):
    return {"k1": {"verdict": verdict, "why": "model says so", "a": A, "b": B}}


def test_the_human_label_beats_the_model_on_the_page():
    titles = {A: "Quest", B: "Quest copy"}
    s = store()
    duplabels.set_label(s, A, B, "different", "两家不同实验室", "operator", NOW)
    assert cluster_judge.possible_duplicates(A, _judge("same"), titles, s.get_source_state(duplabels.KEY)) == []
    duplabels.set_label(s, A, B, "same", "同一份新闻稿", "operator", NOW)
    [d] = cluster_judge.possible_duplicates(A, _judge("unsure"), titles, s.get_source_state(duplabels.KEY))
    assert d["event_id"] == B and d["why"] == "人工确认：同一份新闻稿"


def test_confirmed_duplicates_queue_in_ops():
    s = store()
    duplabels.set_label(s, A, B, "same", "", "operator", NOW)
    duplabels.set_label(s, A, C, "different", "", "operator", NOW)
    items = ops.RULES["duplicate_confirmed"]({"dup_labels": s.get_source_state(duplabels.KEY),
                                              "events": [{"event_id": x, "title": x} for x in (A, B, C)]})
    assert [i["link"] for i in items] == [f"/events/{A}"] and items[0]["level"] == "info"


def test_the_report_measures_the_judge_against_the_labels():
    s = store()
    duplabels.set_label(s, A, B, "same", "", "operator", NOW)
    duplabels.set_label(s, A, C, "different", "", "operator", NOW)
    judged = {"k1": {"verdict": "same", "a": A, "b": B}, "k2": {"verdict": "same", "a": C, "b": A},
              "k3": {"verdict": "unsure", "a": B, "b": C}, "k4": {"verdict": "same", "a": B, "b": C}}   # k4: nobody labelled it
    r = duplabels.report(s.get_source_state(duplabels.KEY), judged)
    assert r == {"labelled": 2, "judged_same": 2, "judged_same_correct": 1, "precision": 0.5, "unlabelled_judged": 2}
