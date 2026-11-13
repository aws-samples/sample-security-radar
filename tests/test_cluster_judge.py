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
    # never even a candidate (cluster_judge.candidates filters contradictions): no call, no row to store
    assert calls == 0 and not call.calls and CJ.candidates([a, b]) == [] and state == {}
    assert CJ.contradiction(a, b) == "different CVE ids"


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


def test_the_verdict_ledger_is_sharded_and_keeps_model_verdicts_only():
    """Live 2026-11-11: one record held 1,658 pairs in 399,029 bytes (1,027 of them code verdicts) and the Analyze
    station's next write failed with 413 every cycle."""
    import json

    from radar import cluster_judge
    from radar.store import MemoryStore
    store = MemoryStore()
    store.put_source_state("__cluster_judge__", {"pairs": {"legacy": {"verdict": "same", "by": "haiku", "a": "ev_1", "b": "ev_2"}}})
    pairs = {f"p{i}": {"verdict": "different", "by": "code" if i % 2 else "haiku", "why": "x" * 200, "a": "ev_a", "b": "ev_b"}
             for i in range(4000)}
    cluster_judge.save(store, "__cluster_judge__", {**cluster_judge.load(store, "__cluster_judge__"), **pairs})
    got = cluster_judge.load(store, "__cluster_judge__")
    assert "legacy" in got and all(v["by"] != "code" for v in got.values()) and len(got) == 2001
    assert store.get_source_state("__cluster_judge__") == {}
    assert max(len(json.dumps(store.get_source_state(f"__cluster_judge__#{i}"))) for i in range(cluster_judge.SHARDS)) < 100_000


def test_the_sweep_finds_exactly_the_pairs_of_the_all_pairs_loop_and_is_fast():
    """The all-pairs loop took 5.5 min per Analyze run on ~1,500 window events (live 2026-11-11)."""
    import itertools
    from datetime import timedelta
    from difflib import SequenceMatcher

    from radar import cluster_judge, timeutil
    from radar.model import Event

    def reference(evs):
        out = []
        for a, b in itertools.combinations(evs, 2):
            if a.domain != b.domain or set(a.keys) & set(b.keys):
                continue
            ta, tb = timeutil.parse(a.first_seen), timeutil.parse(b.first_seen)
            if not ta or not tb or abs(ta - tb) > timedelta(hours=cluster_judge.WINDOW_H):
                continue
            if cluster_judge.contradiction(a, b) is not None:
                continue
            if {e.lower() for e in a.entities} & {e.lower() for e in b.entities} or \
                    SequenceMatcher(None, a.title.lower(), b.title.lower()).ratio() >= cluster_judge.TITLE_SIMILARITY:
                out.append((a, b))
        out.sort(key=lambda p: -max({"P0": 2, "P1": 1}.get(p[0].severity, 0), {"P0": 2, "P1": 1}.get(p[1].severity, 0)))
        return out

    words = ["Fortinet", "FortiWeb", "zero-day", "exploited", "Binance", "hot", "wallet", "drained", "Ivanti", "VPN",
             "SQL", "injection", "patch", "critical", "Cisco", "router", "bridge", "hack"]
    evs = []
    for i in range(600):
        title = " ".join(words[(i * 7 + k * 3) % len(words)] for k in range(4 + i % 3))
        evs.append(Event(event_id=f"ev_{i}", domain=("vuln", "web3")[i % 2], title=title,
                         first_seen=f"2026-11-{1 + (i % 9):02d}T{(i * 5) % 24:02d}:00:00Z", last_updated="2026-11-10T00:00:00Z",
                         item_ids=[], keys=[f"k:{i % 37}"], entities=[["fortinet"], ["binance"], [], ["cisco"]][i % 4],
                         cves=[[], [f"CVE-2026-{i % 5}"]][i % 2],
                         severity=("P0", "P1", "P2")[i % 3]))
    want = [(a.event_id, b.event_id) for a, b in reference(evs)]
    built = {"n": 0}

    cap = 600 * 599 // 2 // 5           # all-pairs builds one per pair (179,700); the sweep ~21 k

    class Counted(SequenceMatcher):     # the cost is the matchers built, not wall time (CI runners differ: 2.45 s)
        def __init__(self, *a, **k):
            built["n"] += 1
            # fail at the bound, not after all-pairs finishes: a regressed sweep must go red fast, not hang the run
            assert built["n"] < cap, "the sweep builds as many matchers as the all-pairs loop"
            super().__init__(*a, **k)
    real = cluster_judge.SequenceMatcher
    cluster_judge.SequenceMatcher = Counted
    try:
        got = [(a.event_id, b.event_id) for a, b in cluster_judge.candidates(evs)]
    finally:
        cluster_judge.SequenceMatcher = real
    # compared outside the assert: pytest's diff of two long differing lists is quadratic and hung the CI mutation run
    same = got == want
    assert same and len(want) > 50, f"{len(got)} pairs vs {len(want)} expected; {len(set(got) ^ set(want))} differ"
