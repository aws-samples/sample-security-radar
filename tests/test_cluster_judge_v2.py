"""C4 v2 cluster judge (Neo 2026-11-17): candidates from what the reports say, a grounded verdict, a merge policy in
code that is SHADOW by default. Fixture: the live 2026-11-16 miss — Lighter's theft as two web3 events, the second one
titled by a tweet (t.co link + quote), with no entities, sharing tok:lighter with the first."""
from __future__ import annotations

import json
from dataclasses import dataclass, replace
from datetime import timedelta

import pytest
from test_pipeline_replay import FETCHED, snapshot_raws

from radar import cluster_judge as CJ
from radar import llm, ops, pipeline
from radar.limits import Limits
from radar.model import Event
from radar.store import MemoryStore


@dataclass
class It:                      # what headlines() reads of an Item
    item_id: str
    title: str
    published_at: str


def ev(eid, title, first, keys=(), entities=(), amount=None, items=(), **kw):
    return Event(event_id=eid, domain="web3", title=title, first_seen=first, last_updated=first,
                 item_ids=list(items), keys=list(keys), entities=list(entities), amount_usd_latest=amount,
                 severity="P0", **kw)


LIGHTER_A = ev("ev_024bc", "Lighter Perps — API Key Compromised", "2026-11-16T02:10:00Z",
               keys=["ent:lighter", "tok:lighter", "tt:lighter", "tok:perps"], entities=["Lighter"], amount=5_200_000,
               items=["a1", "a2"])
LIGHTER_B = ev("ev_9ff98", "https://t.co/Xy12AbCd > We are actively investigating a security incident…",
               "2026-11-16T05:40:00Z", keys=["tok:lighter", "xs:1990000000000000001"], amount=5_000_000,
               items=["b1", "b2", "b3"])
KAVA = ev("ev_kava", "Kava bridge drained of USDC", "2026-11-16T06:00:00Z", keys=["ent:kava", "tok:kava", "tok:usdc"],
          entities=["Kava"], amount=5_100_000, items=["k1", "k2"])
ITEMS = {i.item_id: i for i in [
    It("a1", "Lighter Perps — API Key Compromised", "2026-11-16T02:10:00Z"),
    It("a2", "Lighter confirms API key compromise, about $5.2M drained", "2026-11-16T03:00:00Z"),
    It("b1", "https://t.co/Xy12AbCd > We are actively investigating a security incident…", "2026-11-16T05:40:00Z"),
    It("b2", "Lighter says it is investigating a security incident on its perps exchange", "2026-11-16T06:10:00Z"),
    It("b3", "Lighter pauses withdrawals after $5M USDC exploit", "2026-11-16T07:00:00Z"),
    It("k1", "Kava bridge drained of USDC", "2026-11-16T06:00:00Z"),
    It("k2", "Kava halts bridge after USDC drained", "2026-11-16T06:30:00Z")]}


def get_items(ids):
    return [ITEMS[i] for i in ids if i in ITEMS]


def model(**answer):
    calls = []

    def call(prompt, m, max_tokens):
        calls.append(prompt)
        return llm.LlmResult("ok", json.dumps(answer), {}, m, 0.1)
    call.calls = calls
    return call


SAME_LIGHTER = {"verdict": "same", "why": "both are Lighter's API-key theft", "victim": "Lighter",
                "evidence_a": "API Key Compromised", "evidence_b": "Lighter says it is investigating a security incident"}


def test_the_lighter_pair_is_a_candidate_although_it_shares_a_key_and_has_no_similar_title():
    assert set(LIGHTER_A.keys) & set(LIGHTER_B.keys) and not LIGHTER_B.entities          # v1 skipped it here
    assert (LIGHTER_A, LIGHTER_B) in CJ.candidates([LIGHTER_A, LIGHTER_B])
    bare = [replace(e, amount_usd_latest=None) for e in (LIGHTER_A, LIGHTER_B)]   # the shared name alone is enough
    assert [(x.event_id, y.event_id) for x, y in CJ.candidates(bare)] == [("ev_024bc", "ev_9ff98")]
    far = ev("ev_far", LIGHTER_B.title, "2026-11-18T03:00:00Z", keys=["tok:lighter"])  # 49 h after A
    assert (LIGHTER_A, far) not in CJ.candidates([LIGHTER_A, far])


def test_a_shared_token_word_alone_is_not_a_name():
    a = ev("x1", "Alpha drained", "2026-11-16T02:00:00Z", keys=["tok:usdc"])
    b = ev("x2", "Beta hacked", "2026-11-16T03:00:00Z", keys=["tok:usdc"])
    assert CJ.candidates([a, b]) == []


def test_loss_figures_within_15_percent_make_a_candidate():
    a = ev("x1", "Alpha drained", "2026-11-16T02:00:00Z", amount=1_000_000)
    b = ev("x2", "Gamma incident", "2026-11-16T03:00:00Z", amount=1_140_000)
    c = ev("x3", "Delta incident", "2026-11-16T03:00:00Z", amount=1_300_000)
    got = {(p.event_id, q.event_id) for p, q in CJ.candidates([a, b, c])}
    assert ("x1", "x2") in got and ("x1", "x3") not in got


def test_the_prompt_shows_report_headlines_amount_and_first_seen():
    call = model(**SAME_LIGHTER)
    CJ.run([LIGHTER_A, LIGHTER_B], {}, "t", call, get_items)
    p = call.calls[0]
    assert "Lighter pauses withdrawals after $5M USDC exploit" in p and "5200000" in p and "2026-11-16T05:40:00Z" in p
    assert "t.co" not in p and '"evidence_a"' in p


def test_a_grounded_same_with_two_code_evidences_would_merge():
    state, calls = CJ.run([LIGHTER_A, LIGHTER_B], {}, "t", model(**SAME_LIGHTER), get_items)
    row = next(iter(state.values()))
    assert calls == 1 and row["verdict"] == "same" and row["would_merge"] is True
    assert {e["kind"] for e in row["evidence"]} == {"name", "loss", "time"}


def test_a_same_whose_quote_is_not_in_the_headlines_is_downgraded():
    bad = {**SAME_LIGHTER, "evidence_b": "Lighter lost $5M in an API key compromise"}     # paraphrase, not a quote
    state, _ = CJ.run([LIGHTER_A, LIGHTER_B], {}, "t", model(**bad), get_items)
    row = next(iter(state.values()))
    assert row["verdict"] == "unsure" and row["by"] == "grounding" and row["would_merge"] is False
    assert "evidence_b" in row["why"]
    assert CJ.possible_duplicates("ev_024bc", state, {"ev_024bc": "a", "ev_9ff98": "b"}) == []


def test_kava_and_lighter_both_naming_usdc_are_not_merged():
    assert (LIGHTER_B, KAVA) in CJ.candidates([LIGHTER_B, KAVA])       # loss figures within 15 %: worth a look
    for victim, q in (("USDC", "drained of USDC"), ("Lighter", "Kava bridge drained")):
        say = {"verdict": "same", "why": "x", "victim": victim, "evidence_a": "investigating a security incident",
               "evidence_b": q}
        state, _ = CJ.run([LIGHTER_B, KAVA], {}, "t", model(**say), get_items)
        row = next(iter(state.values()))
        assert row["verdict"] == "unsure" and row["by"] == "grounding" and not row["would_merge"], victim


def test_a_grounded_same_with_one_code_evidence_is_shown_but_would_not_merge():
    # one headline per side naming Acme (name needs 2), 42 h apart (time needs ≤ 24 h), losses within 15 %: one evidence
    a = ev("y1", "Acme vault exploited", "2026-11-16T02:00:00Z", keys=["tok:acme"], items=["y1a"], amount=1_000_000)
    b = ev("y2", "Acme says funds are safe", "2026-11-17T20:00:00Z", keys=["tok:acme"], items=["y2a"], amount=1_050_000)
    its = {"y1a": It("y1a", a.title, a.first_seen), "y2a": It("y2a", b.title, b.first_seen)}
    say = {"verdict": "same", "why": "x", "victim": "Acme", "evidence_a": "Acme vault", "evidence_b": "Acme says"}
    state, _ = CJ.run([a, b], {}, "t", model(**say), lambda ids: [its[i] for i in ids])
    row = next(iter(state.values()))
    assert row["verdict"] == "same" and [e["kind"] for e in row["evidence"]] == ["loss"] and row["would_merge"] is False
    assert CJ.possible_duplicates("y1", state, {"y1": "a", "y2": "b"})[0]["event_id"] == "y2"   # still a hint


def test_a_contradiction_is_decided_by_code_without_a_call():
    a = ev("t1", "Lighter drained", "2026-11-16T02:00:00Z", keys=["tok:lighter"], tx=[{"hash": "0xaa"}])
    b = ev("t2", "Lighter drained again", "2026-11-16T03:00:00Z", keys=["tok:lighter"], tx=[{"hash": "0xbb"}])
    call = model(**SAME_LIGHTER)
    state, calls = CJ.run([a, b], {}, "t", call, get_items)
    assert calls == 0 and not call.calls and state == {} and CJ.contradiction(a, b) == "different attack transactions"


# --- merge policy -------------------------------------------------------------------------------------------------

@pytest.fixture
def store():
    s = MemoryStore()
    pipeline.ingest(snapshot_raws(), s, FETCHED)
    return s


def _pairs(store, n):
    """n disjoint pairs of stored web3 events the contradiction guard lets through, as would_merge rows."""
    evs = sorted((Event.from_dict(e) for e in store.events.values() if e["domain"] == "web3"),
                 key=lambda e: e.event_id)
    free, rows = list(evs), {}
    while len(rows) < n:
        a = free.pop(0)
        # sizes differ, so "the smaller moves into the larger" is checkable
        b = next(x for x in free if CJ.contradiction(a, x) is None and len(x.item_ids) != len(a.item_ids))
        free.remove(b)
        rows[f"p{len(rows)}"] = {"verdict": "same", "would_merge": True, "a": a.event_id, "b": b.event_id,
                                 "at": f"2026-11-16T0{len(rows)}:00:00Z", "evidence": [], "by": "haiku"}
    return rows


def test_flag_off_nothing_merges(store):
    assert Limits.CLUSTER_AUTO_MERGE is False                          # shadow is the shipped default
    before = json.dumps(store.events, sort_keys=True)
    state = _pairs(store, 1)
    assert CJ.merge(store, state, FETCHED + timedelta(hours=1)) == []
    assert json.dumps(store.events, sort_keys=True) == before and "merged" not in state["p0"]


def test_flag_on_merges_the_smaller_into_the_larger_with_an_undo_and_a_cap(store, monkeypatch):
    monkeypatch.setattr(Limits, "CLUSTER_AUTO_MERGE", True)
    state = _pairs(store, 4)
    state["p0"]["would_merge"] = False                                  # the oldest row, but not a merge: left alone
    sizes = {r["a"]: len(store.get_event(r["a"]).item_ids) for r in state.values()} | \
            {r["b"]: len(store.get_event(r["b"]).item_ids) for r in state.values()}
    got = CJ.merge(store, state, FETCHED + timedelta(hours=1))
    assert [m["pair"] for m in got] == ["p1", "p2"] and Limits.CLUSTER_MERGES_PER_CYCLE == 2    # oldest verdicts first
    assert "merged" not in state["p0"] and store.get_event(state["p0"]["a"]) and store.get_event(state["p0"]["b"])
    for m in got:
        big = store.get_event(m["into"])
        assert store.get_event(m["from"]) is None and set(m["items"]) <= set(big.item_ids)
        assert sizes[m["into"]] > sizes[m["from"]] and len(big.item_ids) == sizes[m["into"]] + sizes[m["from"]]
        assert m["undo"][0] == f"uv run python scripts/move_item.py --item {m['items'][0]} --from {m['into']} --to new --apply"
        assert len(m["undo"]) == len(m["items"]) and state[m["pair"]]["merged"] == m
    assert [m["pair"] for m in CJ.merge(store, state, FETCHED + timedelta(hours=2))] == ["p3"]   # merged ones not redone


def test_ops_shows_each_would_merge_pair_with_its_evidence_and_command():
    state, _ = CJ.run([LIGHTER_A, LIGHTER_B], {}, "2026-11-16T08:00:00Z", model(**SAME_LIGHTER), get_items)
    f = {"events": [{"event_id": "ev_024bc", "title": LIGHTER_A.title}, {"event_id": "ev_9ff98", "title": "Lighter tweet"},
                    {"event_id": "ev_kava", "title": KAVA.title}],
         "cluster_judge": {**state, "ungrounded": {"verdict": "unsure", "by": "grounding", "would_merge": False,
                                                   "a": "ev_9ff98", "b": "ev_kava", "evidence": []}}}
    got = [i for i in ops.attention(f) if i["title"].startswith("聚类裁判建议合并")]
    assert len(got) == 1 and got[0]["level"] == "info" and got[0]["link"] == "/events/ev_024bc"
    assert "Lighter Perps — API Key Compromised ↔ Lighter tweet" in got[0]["title"]
    assert "首见相隔 3.5 小时" in got[0]["detail"] and "scripts/dup_label.py ev_024bc ev_9ff98 same" in got[0]["detail"]
    # an operator's label (either way) or an unpublished side takes it off the list
    assert not [i for i in ops.attention({**f, "dup_labels": {"ev_024bc|ev_9ff98": {"label": "different"}}})
                if i["title"].startswith("聚类裁判")]
    assert not [i for i in ops.attention({**f, "events": f["events"][:1]}) if i["title"].startswith("聚类裁判")]


def test_reports_are_read_only_for_judged_pairs_and_bounded():
    big = replace(LIGHTER_A, item_ids=[f"a{i}" for i in range(50)])
    lone = ev("ev_lone", "Unrelated Zeta news", "2026-11-10T00:00:00Z", keys=["tok:zeta"], items=["z1"])
    asked = []
    CJ.run([big, LIGHTER_B, lone], {}, "t", model(**SAME_LIGHTER), lambda ids: asked.append(list(ids)) or get_items(ids))
    assert "z1" not in {i for ids in asked for i in ids}
    assert max(len(ids) for ids in asked) == Limits.CLUSTER_ITEMS_READ and ["a0", "a49"] == [asked[0][0], asked[0][-1]]


def test_the_web3_window_fits_inside_the_sweep():
    """candidates() sweeps WINDOW_H (vuln) and checks web3's window per pair: a longer web3 window would be cut silently."""
    assert Limits.CLUSTER_WINDOW_H <= CJ.WINDOW_H
