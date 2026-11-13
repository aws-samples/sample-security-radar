"""Shadow-mode root-cause titles (radar.retitle_judge): the model proposes, code verifies, nothing is applied.
Live 2026-11-02: "Binance CEX — Key Leaked via Infrastructure" while Binance said no wallet key leaked."""
import json
from datetime import UTC, datetime

from radar import ops, publish, retitle, retitle_judge
from radar.llm import LlmResult
from radar.model import Event, Item
from radar.store import MemoryStore

NOW = datetime(2026, 11, 2, 12, tzinfo=UTC)
OLD = "Binance CEX — Key Leaked via Infrastructure"
NEW = "Binance CEX — Hot Wallets Drained via Compromised DevOps Laptop"
OFFICIAL = ("An attacker compromised a DevOps engineer's laptop and abused the signing service. "
            "There is no evidence of any wallet private key leak.")


def _item(iid, tier, org, title, text, when="2026-10-30T10:00:00Z"):
    return Item(item_id=iid, source_id="x", tier=tier, org=org, domain="web3", url=f"https://{org}.example/{iid}",
                canonical_url=f"https://{org}.example/{iid}", title=title, text=text, published_at=when, fetched_at=when,
                content_hash=iid, keys=[], links=[], entity="Binance CEX", eventful=True,
                signals={"exploited": "none", "kev": False, "poc": False, "amount_usd": None}, extra={})


ITEMS = [_item("it_binance", "T1", "binance", "Binance security update", OFFICIAL),
         _item("it_coindesk", "T2", "coindesk", "Binance hack traced to DevOps laptop", "a DevOps laptop was compromised"),
         _item("it_block", "T2", "theblock", "Binance says hot wallets drained", "hackers may have used a DevOps laptop"),
         _item("it_odaily", "T3", "odaily", "币安被盗", "据称私钥泄露")]
EV = Event(event_id="ev_0a4e5c3e0fce8be9", domain="web3", title=OLD, first_seen="2026-10-29T20:51:00Z",
           last_updated="2026-11-01T00:00:00Z", item_ids=[i.item_id for i in ITEMS], keys=[], severity="P0")


def _call(ans, status="ok"):
    calls = []

    def call(prompt, model, max_tokens):
        calls.append(prompt)
        return LlmResult(status, json.dumps(ans), {}, model)
    call.calls = calls
    return call


GOOD = {"keep": False, "title": NEW, "item_id": "it_binance",
        "quote": "An attacker compromised a DevOps engineer's laptop and abused the signing service.", "terms": ["DevOps"]}


def test_a_quoted_t1_cause_becomes_a_proposal():
    row = retitle_judge.judge(EV, ITEMS, _call(GOOD))
    assert row["verdict"] == "propose" and row["title"] == NEW and row["source"] == "https://binance.example/it_binance"


def test_each_gate_rejects_with_its_reason():
    cases = {
        "not found verbatim": {**GOOD, "quote": "An attacker stole the private keys."},
        "hedged": {**GOOD, "item_id": "it_block", "quote": "hackers may have used a DevOps laptop"},
        "victim prefix": {**GOOD, "title": "Binance — DevOps laptop"},
        "terms": {**GOOD, "terms": ["phishing"]},
        "not in the event": {**GOOD, "item_id": "it_nope"},
    }
    for why, ans in cases.items():
        row = retitle_judge.judge(EV, ITEMS, _call(ans))
        assert row["verdict"] == "rejected" and why in row["reason"], (why, row)


def test_a_t2_quote_needs_a_second_independent_report():
    ans = {**GOOD, "item_id": "it_coindesk", "quote": "a DevOps laptop was compromised", "terms": ["DevOps"]}
    assert retitle_judge.judge(EV, ITEMS, _call(ans))["verdict"] == "propose"   # coindesk + binance + theblock mention it
    alone = [ITEMS[1], ITEMS[3], _item("it_x", "T2", "decrypt", "Binance hack", "hot wallets drained")]
    ev = Event(**{**EV.__dict__, "item_ids": [i.item_id for i in alone]})
    row = retitle_judge.judge(ev, alone, _call(ans))
    assert row["verdict"] == "rejected" and row["reason"].startswith("support")


def test_keep_and_model_failure_are_not_proposals():
    assert retitle_judge.judge(EV, ITEMS, _call({"keep": True}))["verdict"] == "keep"
    assert retitle_judge.judge(EV, ITEMS, _call({}, status="refused"))["verdict"] == "error"


def test_run_caches_per_title_and_report_count_and_retries_errors():
    call = _call(GOOD)
    st, n = retitle_judge.run([EV], lambda ids: ITEMS, {}, {}, NOW, call)
    assert n == 1 and st[EV.event_id]["verdict"] == "propose"
    st, n = retitle_judge.run([EV], lambda ids: ITEMS, st, {}, NOW, call)
    assert n == 0                                                       # same title, same count bucket
    st[EV.event_id]["verdict"] = "error"
    _, n = retitle_judge.run([EV], lambda ids: ITEMS, st, {}, NOW, call)
    assert n == 1
    # an operator title takes the event out of the queue
    st, n = retitle_judge.run([EV], lambda ids: ITEMS, st, {EV.event_id: {"title": NEW}}, NOW, call)
    assert n == 0 and st == {}


def test_only_recent_p0_p1_web3_incident_events_with_enough_reports_are_asked():
    def ev(**kw):
        return Event(**{**EV.__dict__, **kw})
    evs = [ev(event_id="ev_a"), ev(event_id="ev_b", severity="P2"), ev(event_id="ev_c", domain="vuln"),
           ev(event_id="ev_d", item_ids=["x", "y"]), ev(event_id="ev_e", last_updated="2026-10-01T00:00:00Z")]
    assert [e.event_id for e in retitle_judge.candidates(evs, {}, NOW)] == ["ev_a"]


def test_a_proposal_shows_in_ops_and_changes_no_title():
    store = MemoryStore()
    store.put_event(EV)
    for i in ITEMS:
        store.put_item(i)
    st, _ = retitle_judge.run([EV], store.get_items, {}, {}, NOW, _call(GOOD))
    store.put_source_state(retitle_judge.KEY, st)
    docs = publish.build(store, NOW)
    got = [i for i in docs["ops.json"]["attention"] if i["code"] == "title_proposal"]
    assert len(got) == 1 and "scripts/retitle.py ev_0a4e5c3e0fce8be9" in got[0]["detail"] and "未生效" in got[0]["title"]
    assert docs["events.json"]["events"][0]["title"] == OLD and store.get_source_state(retitle.KEY) == {}
    # once the title differs from the one judged, the stale proposal is not shown
    f = {"events": [{"event_id": EV.event_id, "title": NEW}], "title_proposals": st}
    assert not ops._title_proposals(f)
