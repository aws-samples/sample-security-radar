"""C4 cluster_judge: code picks candidate pairs and rules out contradictions; Haiku only judges the rest; the result
is an advisory 'possible duplicate' — never a merge."""
from __future__ import annotations

import json

from radar import cluster_judge as CJ
from radar import llm
from radar.model import Event


def ev(eid, title, first="2026-10-27T03:00:00Z", domain="vuln", sev="P2", keys=(), **kw):
    return Event(event_id=eid, domain=domain, title=title, first_seen=first, last_updated=first, item_ids=[],
                 keys=list(keys), severity=sev, **kw)


def model(verdict="same", status="ok"):
    calls = []

    def call(prompt, m, max_tokens):
        calls.append(prompt)
        return llm.LlmResult(status, json.dumps({"verdict": verdict, "why": "same victim, same day"}), {}, m, 0.1)
    call.calls = calls
    return call


QUEST_A = ev("q1", "Quest Diagnostics Data Breach Exposed ‘Certain Patient Information’")
QUEST_B = ev("q2", "Quest Diagnostics confirms data breach exposed patient information")


def test_candidates_are_similar_unkeyed_same_domain_events_within_72_hours():
    far = ev("q3", "Quest Diagnostics confirms data breach exposed patient information", first="2026-10-20T00:00:00Z")
    other = ev("w", "Quest Diagnostics confirms data breach exposed patient information", domain="web3")
    keyed = ev("k", "Quest Diagnostics confirms data breach exposed patient data", keys=["ent:quest"])
    keyed_twin = ev("k2", "Quest Diagnostics Data Breach Exposed patient data", keys=["ent:quest"])
    got = {(a.event_id, b.event_id) for a, b in CJ.candidates([QUEST_A, QUEST_B, far, other, keyed, keyed_twin])}
    assert ("q1", "q2") in got and not any("q3" in p or "w" in p for p in got)
    assert ("k", "k2") not in got and ("k2", "k") not in got          # share a key ⇒ the rules already decided


def test_contradicting_facts_are_decided_by_code_without_a_model_call():
    a = ev("p1", "CVE-2026-96655 Plex Media Server: Plex Media Server Server", cves=["CVE-2026-96655"])
    b = ev("p2", "CVE-2026-96652 Plex Media Server: Plex Media Server Server", cves=["CVE-2026-96652"])
    call = model("same")
    state, calls = CJ.run([a, b], {}, "2026-10-28T00:00:00Z", call)
    assert calls == 0 and not call.calls and next(iter(state.values()))["verdict"] == "different"


def test_a_same_verdict_shows_on_both_pages_and_is_not_asked_again():
    call = model("same")
    state, calls = CJ.run([QUEST_A, QUEST_B], {}, "2026-10-28T00:00:00Z", call)
    titles = {"q1": QUEST_A.title, "q2": QUEST_B.title}
    assert calls == 1 and CJ.possible_duplicates("q1", state, titles)[0]["event_id"] == "q2"
    assert CJ.possible_duplicates("q2", state, titles)[0]["event_id"] == "q1"
    _, again = CJ.run([QUEST_A, QUEST_B], state, "2026-10-28T00:10:00Z", call)
    assert again == 0 and len(call.calls) == 1                        # cached per pair (and per titles)


def test_anything_but_a_clear_same_is_not_shown():
    for verdict, status in (("unsure", "ok"), ("different", "ok"), ("SAME!!", "ok"), ("same", "refused")):
        state, _ = CJ.run([QUEST_A, QUEST_B], {}, "t", model(verdict, status))
        assert CJ.possible_duplicates("q1", state, {"q1": "a", "q2": "b"}) == [], (verdict, status)


def test_model_calls_per_cycle_are_capped():
    evs = [ev(f"e{i}", f"Acme Corp confirms data breach exposed customer records batch {i}") for i in range(8)]
    call = model("unsure")
    _, calls = CJ.run(evs, {}, "t", call)
    assert calls == CJ.MAX_PAIRS_PER_CYCLE == len(call.calls)


def test_a_duplicate_that_left_the_board_is_not_linked():
    state, _ = CJ.run([QUEST_A, QUEST_B], {}, "t", model("same"))
    assert CJ.possible_duplicates("q1", state, {"q1": QUEST_A.title}) == []
