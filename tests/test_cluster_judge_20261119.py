"""Harness audit 11-19 (P2 / P3): 51,404 candidate pairs, 49,838 never judged (most "<repo> exploit" listings, similar
only through the suffix); web3 pairs waited ~13 days behind them; 119 verdicts cut by MAX_TOKENS=400, never retried."""
import importlib.util
from pathlib import Path

from radar import cluster_judge as CJ

_spec = importlib.util.spec_from_file_location("cj_helpers", Path(__file__).with_name("test_cluster_judge.py"))
_h = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_h)
QUEST_A, QUEST_B, ev, model = _h.QUEST_A, _h.QUEST_B, _h.ev, _h.model


def test_listings_similar_only_in_vulnerability_words_are_not_candidates():
    a, b = ev("p1", "utfp-poc exploit"), ev("p2", "secure-headers-project exploit")
    assert CJ.candidates([a, b]) == []
    c = ev("c1", "Google patches Chrome's eighth actively exploited zero-day of 2026")
    d = ev("c2", "Google fixes the eighth actively exploited Chrome zero-day of 2026")
    assert len(CJ.candidates([c, d])) == 1                    # live 'same' pair: shares "chrome" / "eighth"
    assert "chrome" in CJ.distinct_words(c.title) and "exploit" not in CJ.distinct_words(a.title)


def test_an_error_verdict_is_judged_again_up_to_the_retry_limit():
    state, _ = CJ.run([QUEST_A, QUEST_B], {}, "t1", model(status="max_tokens"))
    (row,) = state.values()
    assert row["by"] == "error" and row["attempts"] == 1
    for n in (2, 3):
        state, calls = CJ.run([QUEST_A, QUEST_B], state, f"t{n}", model(status="max_tokens"))
        assert calls == 1 and next(iter(state.values()))["attempts"] == n
    state, calls = CJ.run([QUEST_A, QUEST_B], state, "t4", model(status="max_tokens"))
    assert calls == 0                                          # three attempts, then it stays unsure
    state2, _ = CJ.run([QUEST_A, QUEST_B], {k: {**v, "attempts": 1} for k, v in state.items()}, "t5", model("same"))
    assert next(iter(state2.values()))["by"] != "error"


def test_web3_pairs_are_judged_before_other_pairs():
    vulns = [ev(f"v{i}", f"Acme Corp confirms data breach exposed customer records batch {i}") for i in range(8)]
    w = [ev("w1", "Lighter exchange hacked, $5M drained", domain="web3"),
         ev("w2", "Lighter exchange hacked: $5M drained", domain="web3")]
    call = model("unsure")
    CJ.run(vulns + w, {}, "t", call)
    assert "Lighter" in call.calls[0]


def test_the_token_budget_fits_a_reasoned_verdict():
    assert CJ.MAX_TOKENS >= 1500


# ---- delayed truth (step 2): facts the code reads later decide judged pairs, no person labels
def test_delayed_truth_from_shared_keys_merges_contradictions_and_hack_database_records():
    a = ev("d1", "Acme exploited", domain="web3", keys=["tx:0xabc"])
    b = ev("d2", "Acme drained", domain="web3", keys=["tx:0xabc"])
    assert CJ.delayed_truth(a, b) == "same"                                     # one attack transaction
    assert CJ.delayed_truth(a, b, "ev_x", "ev_x") == "same"                      # the pipeline merged them
    c = ev("d3", "Acme", cves=["CVE-2026-11111"])
    d = ev("d4", "Acme", cves=["CVE-2026-22222"])
    assert CJ.delayed_truth(c, d) == "different"                                # disjoint CVEs
    w1, w2 = ev("w1", "Pool Party", domain="web3"), ev("w2", "PennysiaSettlement", domain="web3")
    assert CJ.delayed_truth(w1, w2, ra={("defillama_hacks", "it_1")}, rb={("defillama_hacks", "it_2")}) == "different"
    assert CJ.delayed_truth(w1, w2, ra={("defillama_hacks", "it_1")}, rb={("defillama_hacks", "it_1")}) == "same"
    # two databases' rows of one incident under different names decide nothing (live: the Safe multisig on Avalanche)
    assert CJ.delayed_truth(w1, w2, ra={("defillama_hacks", "it_1")}, rb={("slowmist_hacked", "it_9")}) is None
    assert CJ.delayed_truth(w1, w2) is None


def test_the_truth_report_scores_only_old_model_verdicts_that_a_fact_decides():
    a = ev("d1", "Acme exploited", domain="web3", keys=["tx:0xabc"])
    b = ev("d2", "Acme drained", domain="web3", keys=["tx:0xabc"])
    c, d = ev("d3", "x", domain="web3"), ev("d4", "y", domain="web3")
    state = {"k1": {"a": "d1", "b": "d2", "verdict": "same", "by": "model", "at": "2026-11-10T00:00:00Z", "would_merge": True},
             "k2": {"a": "d3", "b": "d4", "verdict": "same", "by": "model", "at": "2026-11-10T00:00:00Z"},
             "k3": {"a": "d1", "b": "d2", "verdict": "same", "by": "model", "at": "2026-11-19T11:00:00Z"},   # too new
             "k4": {"a": "d1", "b": "d2", "verdict": "different", "by": "code", "at": "2026-11-10T00:00:00Z"}}  # code's
    rec = {"d3": {("defillama_hacks", "it_1")}, "d4": {("defillama_hacks", "it_2")}}
    out = CJ.truth_report(state, {e.event_id: e for e in (a, b, c, d)}, {}, "2026-11-19T12:00:00Z", records=rec)
    assert (out["decided"], out["same_said"], out["same_precision"], out["would_merge_wrong"]) == (2, 2, 0.5, 0)


def test_the_station_writes_the_truth_report_once_a_day(monkeypatch):
    import datetime as dt
    for k, v in {"AWS_DEFAULT_REGION": "ap-northeast-1", "AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "x"}.items():
        monkeypatch.setenv(k, v)
    from radar import handlers as h
    from radar.model import Item
    from radar.store import MemoryStore
    store = MemoryStore()
    for n in (1, 2):
        store.put_item(Item(item_id=f"it_{n}", source_id="defillama_hacks", tier="T1", org="defillama", domain="web3",
                            url=f"https://x/{n}", canonical_url=f"https://x/{n}", title="t", text="x",
                            published_at="2026-11-10T00:00:00Z", fetched_at="2026-11-10T00:00:00Z", content_hash=str(n),
                            keys=[], links=[], entity=None, eventful=True, signals={}, extra={}))
    a = ev("w1", "Pool Party", domain="web3"); a.item_ids = ["it_1"]
    b = ev("w2", "PennysiaSettlement", domain="web3"); b.item_ids = ["it_2"]
    pairs = {"k": {"a": "w1", "b": "w2", "verdict": "different", "by": "model", "at": "2026-11-10T00:00:00Z"}}
    now = dt.datetime(2026, 11, 19, 12, tzinfo=dt.UTC)
    h._judge_truth(store, pairs, [a, b], now)
    rep = store.get_source_state(h.JUDGE_TRUTH_KEY)
    assert rep["day"] == "2026-11-19" and rep["decided"] == 1 and rep["rows"][0]["truth"] == "different"
    store.put_source_state(h.JUDGE_TRUTH_KEY, {**rep, "decided": 99})
    h._judge_truth(store, pairs, [a, b], now)                     # same day: not recomputed
    assert store.get_source_state(h.JUDGE_TRUTH_KEY)["decided"] == 99
