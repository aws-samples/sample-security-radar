"""Attack-transaction breakdown (radar.attacktx, M4.1 E3), replayed from real receipts recorded 2026-10-30 from the
radar's own RPC (tests/fixtures/attacktx/tranche_zklink.json): Tranche Vault (Avalanche, 2 txs) and zkLink Nova
(Ethereum, 2 txs, 44 ERC-20 transfers, 45 tokens)."""
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from radar import attacktx, chain

FIX = json.loads((Path(__file__).parent / "fixtures" / "attacktx" / "tranche_zklink.json").read_text())
NOW = datetime(2026, 10, 30, 9, tzinfo=UTC)
TRANCHE, ZKLINK = "ev_455fc4965a8fa20b", "ev_59caef3e0465ad86"


def tape(fail: str = ""):
    by = {(t["url"], t["method"], json.dumps(t["params"], sort_keys=True)): t["result"] for t in FIX["tape"]}
    calls = []

    def call(url, method, params):
        calls.append(method)
        if fail and fail in json.dumps(params):
            raise chain.RpcError("rpc_unreachable: Too Many Requests")
        return by[(url, method, json.dumps(params, sort_keys=True))]
    call.calls = calls
    return call


def event(eid, **over):
    return SimpleNamespace(**{**FIX["events"][eid], "domain": "web3", **over})


def run(eid, call, meta=None, budget=200):
    case, meta = {}, ({} if meta is None else meta)
    while attacktx.step(case, event(eid), meta, NOW, call, budget):
        pass
    return case, meta, attacktx.doc(case, meta)


def test_the_tranche_drain_is_the_reported_loss_to_the_cent():
    _, _, doc = run(TRANCHE, tape())
    drain = doc["txs"][1]
    assert (drain["t"], drain["chain"], drain["status"]) == ("2026-10-28T00:00:03Z", "avalanche", "success")
    usdc = drain["tokens"][0]
    assert usdc["symbol"] == "USDC" and usdc["gainer"]["role"] == "发起地址"
    assert usdc["gainer"]["amount"] == pytest.approx(1_013_353.611687)        # DeFiLlama / SlowMist: $1.013M


def test_one_holder_paid_out_every_token_of_the_zklink_spoof():
    _, _, doc = run(ZKLINK, tape())
    first = doc["txs"][0]
    assert first["transfers"] == 11 and first["tokens_total"] == 11
    assert {t["loser"]["address"][:10] for t in first["tokens"]} == {"0xad16edcf"}
    assert all(t["gainer"]["role"] == "发起地址" for t in first["tokens"])
    assert first["tokens"][0]["symbol"] in attacktx.MAJOR                      # equal counts ⇒ majors first


def test_the_budget_holds_and_the_token_ledger_is_shared():
    call = tape()
    case = {}
    meta: dict = {}
    used = [attacktx.step(case, event(ZKLINK), meta, NOW, call, 6) for _ in range(30)]
    assert max(used) <= 6 and used[-1] == 0 and len(meta) == 44
    again = tape()
    run(ZKLINK, again, meta=meta)
    assert "eth_call" not in again.calls                                         # metadata is never fetched twice


def test_a_failed_receipt_is_recorded_and_retried_not_shown_as_empty():
    h = FIX["events"][TRANCHE]["tx"][1]["hash"]
    case, meta = {}, {}
    attacktx.step(case, event(TRANCHE), meta, NOW, tape(fail=h), 200)
    assert any(e["tx"] == h for e in case["errors"]) and h not in case["txs"]
    attacktx.step(case, event(TRANCHE), meta, NOW, tape(), 200)
    assert "receipt" in case["txs"][h]


def test_only_verified_attack_txs_are_read():
    txs = [{**t, "verified": "failed"} for t in FIX["events"][TRANCHE]["tx"]]
    case, meta = {}, {}
    assert attacktx.step(case, event(TRANCHE, tx=txs), meta, NOW, tape(), 200) == 0
    assert attacktx.doc(case, meta) is None


def test_erc721_transfers_are_not_counted_and_symbols_decode():
    nft = {"logs": [{"address": "0xA", "topics": [attacktx.TRANSFER, "0x" + "0" * 64, "0x" + "1" * 64, "0x" + "0" * 63 + "7"], "data": "0x"}]}
    assert attacktx.transfers(nft) == []
    abi = "0x" + f"{32:064x}" + f"{4:064x}" + b"USDC".hex().ljust(64, "0")
    assert attacktx._symbol(abi) == "USDC"
    assert attacktx._symbol("0x" + b"MKR".hex().ljust(64, "0")) == "MKR"   # bytes32 style
    assert attacktx._symbol("0x") is None


def test_the_published_section_validates_against_the_schema():
    import jsonschema
    schema = json.loads((Path(__file__).parents[1] / "schemas" / "site-data.schema.json").read_text())
    jsonschema.validate(run(ZKLINK, tape())[2], {"$ref": "#/$defs/AttackTxs", "$defs": schema["$defs"]})


def test_the_station_republishes_once_per_change():
    from radar.model import Event
    from radar.store import MemoryStore
    store = MemoryStore()
    for eid in (TRANCHE, ZKLINK):
        e = FIX["events"][eid]
        store.put_event(Event(event_id=eid, domain="web3", title=e["title"], first_seen=e["first_seen"], last_updated=FIX["now"],
                              item_ids=[], keys=[], tx=e["tx"]))
    changed = set()
    for _ in range(8):
        changed |= set(attacktx.cycle(store, NOW, tape()))
    assert changed == {TRANCHE, ZKLINK}
    assert attacktx.cycle(store, NOW, tape()) == []                            # nothing new ⇒ nothing republished


def test_the_event_document_carries_the_breakdown():
    from radar import publish
    from radar.model import Event
    from radar.store import MemoryStore
    store = MemoryStore()
    e = FIX["events"][TRANCHE]
    ev = Event(event_id=TRANCHE, domain="web3", title=e["title"], first_seen=e["first_seen"], last_updated=FIX["now"],
               item_ids=[], keys=[], tx=e["tx"])
    store.put_event(ev)
    for _ in range(3):
        attacktx.cycle(store, NOW, tape())
    doc = publish.event_doc(ev, store, NOW)
    assert doc["attack_txs"]["txs"][1]["tokens"][0]["gainer"]["amount"] == pytest.approx(1_013_353.611687)


def test_a_plain_native_transfer_shows_its_value_not_an_empty_table():
    """"682 ETH drained in under 2 hours": the verified tx has no ERC-20 log at all; the 200 ETH it sends is the fact."""
    _, _, doc = run("ev_afd1c1acf73f2445", tape())
    [tx] = doc["txs"]
    assert tx["transfers"] == 0 and tx["native"] == {"symbol": "ETH", "amount": 200.0}
    _, _, tranche = run(TRANCHE, tape())
    assert all(t["native"] is None for t in tranche["txs"])                  # a contract call sending no coin: omitted


def test_the_shared_token_ledger_stays_bounded(monkeypatch):
    """A DynamoDB item is ≤ 400 KB (~4,000 token entries); the ledger keeps the newest ATTACKTX_TOKEN_LEDGER_MAX.
    An evicted token is simply fetched again when a later tx needs it."""
    from radar.limits import Limits
    monkeypatch.setattr(Limits, "ATTACKTX_TOKEN_LEDGER_MAX", 10)
    meta = {f"ethereum|0x{i:040x}": {"symbol": "OLD", "decimals": 18, "at": f"2026-01-{i % 28 + 1:02d}T00:00:00Z"} for i in range(20)}
    _, meta, doc = run(TRANCHE, tape(), meta=meta)
    assert len(meta) == 10
    assert "avalanche|0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e" in meta          # the token just fetched is kept
    assert doc["txs"][1]["tokens"][0]["symbol"] == "USDC"
