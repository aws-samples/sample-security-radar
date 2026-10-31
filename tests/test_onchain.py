"""On-chain reconstruction (radar.onchain, M4 D6) replayed from the real RPC responses of the 2026-10-29 Binance theft
(tests/fixtures/onchain/binance_20261029.json — recorded 2026-10-30 from radar.chain.RPC; logs below the $1M floor and
unused fields stripped). The expected rows are the ones Ondology Labs / TRM published, to the second."""
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from radar import chain, onchain, timeutil

FIX = json.loads((Path(__file__).parent / "fixtures" / "onchain" / "binance_20261029.json").read_text())
NOW = timeutil.parse(FIX["now"])
RECV = "0x5227f603c1ee34ce3c06efe6477003bdfccb2f8c"
B14 = "0x28c6c06298d514db089934071355e5743bf21d60"
SPLIT = "0x9749292d"            # prefix of the first USDT split wallet (Ondology: "the receiver and the first USDT wallet")


def tape_call(fail: set[str] = frozenset()):
    by = {(t["url"], t["method"], json.dumps(t["params"], sort_keys=True)): t["result"] for t in FIX["tape"]}
    calls = []

    def call(url, method, params):
        calls.append((method, params))
        key = (url, method, json.dumps(params, sort_keys=True))
        if any(f in json.dumps(params) for f in fail) or key not in by:
            raise chain.RpcError(f"not in tape: {method}")
        return by[key]
    call.calls = calls
    return call


def event(**over):
    e = FIX["event"]
    return SimpleNamespace(event_id=e["event_id"], domain="web3", severity="P0", first_seen=e["first_seen"], title=e["title"],
                           entities=e["entities"], chains=e["chains"], amount_usd_latest=e["amount_usd_latest"], **over)


def run(call, budget=40, cycles=12):
    case = onchain.new_case(event(), FIX["texts"], NOW)
    used = []
    for _ in range(cycles):
        used.append(onchain.step(case, NOW, call, budget))
    return case, used


@pytest.fixture(scope="module")
def replay():
    case, used = run(tape_call())
    return case, onchain.doc(case), used


def rows(doc, kind):
    return [r for r in doc["rows"] if r["kind"] == kind]


def test_the_main_sweep_is_reconstructed_to_the_second(replay):
    _, doc, _ = replay
    sweep = next(r for r in rows(doc, "outflow") if r["t"] == "2026-10-29T20:24:23Z")
    assert (sweep["from"], sweep["to"], sweep["token"], round(sweep["amount"] / 1e6, 1)) == (B14, RECV, "USDT", 1615.4)
    assert sweep["from_label"] == "Binance 14" and sweep["to_evidence"] == "0x5227…cb2f8c"   # the reports' short form
    assert sweep["tx"].startswith("0x53bd38b8")                                              # Ondology's linked tx


def test_the_split_wallets_and_their_freezes_are_followed(replay):
    _, doc, _ = replay
    splits = {(r["t"], round(r["amount"] / 1e6)) for r in rows(doc, "outflow") if r["from"] == RECV and r["token"] == "USDT"}
    assert {("2026-10-29T20:30:11Z", 500), ("2026-10-29T20:33:23Z", 200)} <= splits
    fr = {(r["t"], r["issuer"], r["address"][:10]) for r in rows(doc, "freeze")}
    assert {("2026-10-29T21:01:35Z", "Tether", RECV[:10]), ("2026-10-29T21:01:35Z", "Tether", SPLIT),
            ("2026-10-29T21:04:59Z", "Circle", RECV[:10]), ("2026-10-29T22:06:23Z", "Tether", B14[:10])} <= fr


def test_rows_are_incident_scale_and_the_budget_holds(replay):
    case, doc, used = replay
    assert case["min_usd"] == 10_000_000                       # 0.5 % of $6.3B, capped: routine $1–3M withdrawals stay out
    assert all(r["amount"] >= 10_000_000 for r in rows(doc, "outflow"))
    assert max(used) <= 40 and used[-1] < used[0]               # converges once the cursors reach the head
    assert len(case["receivers"]) <= 8


def test_what_was_not_queried_is_published_not_hidden(replay):
    _, doc, _ = replay
    assert any("trace" in x for x in doc["not_queried"]) and any("非 EVM" in x for x in doc["not_queried"])
    assert doc["complete"] is False                               # the window is still open at NOW
    assert {d["label"] for d in doc["delegation"]} == {"Binance 14", "Binance 16", "Binance Hot Wallet 34"}


def test_a_failed_call_is_recorded_and_retried_not_skipped():
    call = tape_call(fail={B14[2:]})
    case, _ = run(call, cycles=2)
    assert any(B14 in e["query"] for e in case["errors"])
    assert all(r["from"] != B14 for r in case["rows"])
    cur = case["cursors"]["out|ethereum|USDT|" + B14]
    assert cur["failed"] and "next" not in cur                    # no block position ⇒ the next cycle reads that range again


@pytest.mark.parametrize(("over", "ok"), [({}, True), ({"severity": "P1"}, False), ({"domain": "vuln"}, False)])
def test_only_young_p0_web3_events_are_reconstructed(over, ok):
    ev = event()
    for k, v in over.items():
        setattr(ev, k, v)
    assert onchain.eligible(ev, NOW) is ok
    assert onchain.eligible(event(), NOW + timedelta(days=4)) is False


def test_victim_wallets_come_from_the_registry_by_name():
    assert "0x28c6c06298d514db089934071355e5743bf21d60" in onchain.victim_wallets(["币安热钱包被盗"])["ethereum"]
    assert onchain.victim_wallets(["Bybit hot wallet"]) == {}


def test_a_short_address_resolves_only_when_unambiguous():
    full = [RECV, "0x5227000000000000000000000000000000cb2f8c"]
    assert onchain.resolve([("5227", "cb2f8c")], full) == {}
    assert onchain.resolve([("5227", "cb2f8c")], [RECV]) == {RECV: "0x5227…cb2f8c"}


def test_min_usd_scales_with_the_loss_within_bounds():
    assert onchain.min_usd(None) == 1_000_000 and onchain.min_usd(50_000_000) == 1_000_000
    assert onchain.min_usd(400_000_000) == 2_000_000 and onchain.min_usd(6.3e9) == 10_000_000


def test_the_published_section_validates_against_the_schema(replay):
    import jsonschema
    schema = json.loads((Path(__file__).parents[1] / "schemas" / "site-data.schema.json").read_text())
    jsonschema.validate(replay[1], {"$ref": "#/$defs/Onchain", "$defs": schema["$defs"]})


def test_the_station_cycle_builds_a_case_shares_the_budget_and_reports_changes():
    from radar.model import Event
    from radar.store import MemoryStore
    store = MemoryStore()
    e = FIX["event"]
    ev = Event(event_id=e["event_id"], domain="web3", title=e["title"], first_seen=e["first_seen"], last_updated=FIX["now"],
               item_ids=[], keys=[], severity="P0", entities=e["entities"], chains=e["chains"], amount_usd_latest=e["amount_usd_latest"])
    store.put_event(ev)
    other = Event.from_dict({**ev.to_dict(), "event_id": "ev_other", "severity": "P1"})
    store.put_event(other)
    call = tape_call()
    changed = onchain.cycle(store, NOW, call)
    assert changed == [e["event_id"]]                                   # P1 is not reconstructed
    case = store.get_source_state(onchain.case_key(e["event_id"]))
    assert case["event_id"] == e["event_id"] and len(call.calls) <= 40
    assert store.get_source_state(onchain.INDEX)["active"] == [e["event_id"]]


def test_a_small_budget_still_reaches_every_query_round_robin():
    """While the window is open every query has a tail to re-read; a fixed order let the first ones eat the budget."""
    case = onchain.new_case(event(), FIX["texts"], NOW)
    call = tape_call()
    for _ in range(30):
        onchain.step(case, NOW, call, 6)
    assert {"|".join(q) for q in onchain._queries(case)} <= {k for k, c in case["cursors"].items() if c.get("ran_at")}


# ── M4.2 · follow the attacker: an attack tx the radar verified seeds the reconstruction ───────────────────────────────

def _tranche_store():
    """P1 web3 event + its decoded attack txs (real receipts, tests/fixtures/attacktx)."""
    import test_attacktx as T

    from radar import attacktx
    from radar.model import Event
    from radar.store import MemoryStore
    store = MemoryStore()
    e = T.FIX["events"][T.TRANCHE]
    store.put_event(Event(event_id=T.TRANCHE, domain="web3", title=e["title"], first_seen=e["first_seen"],
                          last_updated=T.FIX["now"], item_ids=[], keys=[], tx=e["tx"], severity="P1", chains=["avalanche"]))
    for _ in range(3):
        attacktx.cycle(store, T.NOW, T.tape())
    # the station runs while the incident is young (first seen 10-27, date-only)
    return store, T.TRANCHE, datetime(2026, 10, 28, 12, tzinfo=UTC)


def test_the_attack_tx_sender_is_followed_on_its_own_chain():
    from radar import attacktx
    store, eid, now = _tranche_store()
    att = attacktx.attackers(store.get_source_state(attacktx.case_key(eid)))
    assert att and all(a["chain"] == "avalanche" for a in att.values())
    sender = next(iter(att))
    def refuse(url, method, params):
        raise chain.RpcError("not in tape")
    onchain.cycle(store, now, refuse)
    case = store.get_source_state(onchain.case_key(eid))
    assert sender in case["attackers"] and "out|avalanche|USDC|" + sender in case["cursors"]
    assert case["window"][1] >= "2026-10-29T00:00:03Z"          # covers 24 h after the drain tx, not only after first_seen


def test_a_p1_incident_is_reconstructed_only_when_it_has_an_attacker():
    ev = event()
    ev.severity = "P1"
    assert onchain.eligible(ev, NOW) is False
    assert onchain.eligible(ev, NOW, attackers={"0x" + "1" * 40: {"chain": "ethereum", "t": "2026-10-29T20:00:00Z"}}) is True


def test_an_attacker_found_after_the_case_was_built_is_added():
    store, eid, now = _tranche_store()
    from radar import attacktx
    sender = next(iter(attacktx.attackers(store.get_source_state(attacktx.case_key(eid)))))
    def refuse(url, method, params):
        raise chain.RpcError("not in tape")
    tx_case = store.get_source_state(attacktx.case_key(eid))
    store.put_source_state(attacktx.case_key(eid), {})            # first cycle: nothing decoded yet
    # a P1 without an attacker is not eligible: build the case as a P0 for this step
    ev = store.get_event(eid); ev.severity = "P0"; store.put_event(ev)
    onchain.cycle(store, now, refuse)
    assert sender not in store.get_source_state(onchain.case_key(eid)).get("attackers", {})
    store.put_source_state(attacktx.case_key(eid), tx_case)       # decoded on a later cycle
    onchain.cycle(store, now, refuse)
    assert sender in store.get_source_state(onchain.case_key(eid))["attackers"]
