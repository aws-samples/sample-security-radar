"""C6: attack transactions are checked on-chain (receipt status) and a confirmed one raises a web3 event to V2."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from radar import chain, pipeline
from radar.limits import Limits
from radar.store import MemoryStore

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
TX = "0x38c60844f1923d53fdce7d99e9bc2a2d8c73a08e793341dfbb479f8cc74d81d0"   # X100 attack tx (live event)


def rpc(answers):
    """Fake JSON-RPC: hash → receipt dict / None / Exception; records calls."""
    calls = []

    def call(url, method, params):
        calls.append((url, method, params[0]))
        a = answers[params[0]]
        if isinstance(a, Exception):
            raise a
        return a
    call.calls = calls
    return call


@pytest.mark.parametrize("receipt, want", [({"status": "0x1", "blockNumber": "0x10"}, "confirmed"),
                                           ({"status": "0x0", "blockNumber": "0x10"}, "failed"), (None, "not_found")])
def test_receipt_status_maps_to_a_verdict(receipt, want):
    v = chain.verdict("Ethereum", TX, rpc({TX: receipt}))
    assert v["verified"] == want and (want == "not_found" or v["block"] == 16)


def test_an_unsupported_chain_is_said_so_and_no_call_is_made():
    call = rpc({})
    assert chain.verdict("Solana", TX, call) == {"verified": "unsupported"} and not call.calls
    assert chain.canon("BSC") == "bsc" and chain.canon("Arbitrum One") == "arbitrum"


def test_an_rpc_failure_keeps_the_verdict_and_leaves_a_trace():
    txs, used = chain.check_txs([{"chain": "ethereum", "hash": TX, "verified": "unchecked"}], NOW, 5,
                                rpc({TX: chain.RpcError("rpc_unreachable: boom")}))
    assert used == 1 and txs[0]["verified"] == "unchecked" and txs[0]["check_error"].startswith("rpc_unreachable")


def test_rechecks_back_off_and_stop_and_final_verdicts_are_never_rechecked():
    t = {"chain": "ethereum", "hash": TX, "verified": "not_found", "attempts": 1, "checked_at": "2026-10-28T11:00:00Z"}
    assert not chain.due(t, NOW)                                                     # 1 h < CHAIN_RECHECK_H
    assert chain.due(t, NOW + timedelta(hours=Limits.CHAIN_RECHECK_H))
    assert not chain.due({**t, "attempts": Limits.CHAIN_MAX_ATTEMPTS}, NOW + timedelta(days=1))
    assert not chain.due({**t, "verified": "confirmed"}, NOW + timedelta(days=1))


def test_the_budget_bounds_rpc_calls_per_cycle():
    txs = [{"chain": "ethereum", "hash": f"0x{i:064x}", "verified": "unchecked"} for i in range(5)]
    call = rpc({t["hash"]: None for t in txs})
    _, used = chain.check_txs(txs, NOW, 2, call)
    assert used == 2 and len(call.calls) == 2


def test_a_real_rpc_error_class_does_not_escape(monkeypatch):
    import http.client

    def boom(*_a, **_k):
        raise http.client.RemoteDisconnected("node closed the connection")
    monkeypatch.setattr(chain.urllib.request, "urlopen", boom)
    with pytest.raises(chain.RpcError):
        chain.rpc_call("https://example.invalid", "eth_getTransactionReceipt", [TX])


def _web3_event(store, sources=("defillama_hacks",)):
    """One web3 incident reported by a single T2 database, carrying the attack tx."""
    from radar.model import Event, Item
    items = [Item(item_id=f"it-{s}", source_id=s, tier="T2", org=s, domain="web3", url=f"https://x/{s}",
                  canonical_url=f"https://x/{s}", title="X100 — Flash Loan Governance Attack", text="flash loan",
                  published_at="2026-10-27T10:00:00Z", fetched_at="2026-10-27T10:00:00Z", content_hash=s, keys=[],
                  links=[], entity="x100", eventful=True, signals={"amount_usd": 100000},
                  extra={"tx": [{"chain": "ethereum", "hash": TX, "explorer_url": f"https://etherscan.io/tx/{TX}"}]})
             for s in sources]
    for it in items:
        store.put_item(it)
    ev = pipeline.recompute(Event(event_id="ev_x100", domain="web3", title="X100", first_seen="2026-10-27T10:00:00Z",
                                  last_updated="2026-10-27T10:00:00Z", item_ids=[i.item_id for i in items], keys=[]),
                            items, NOW)
    store.put_event(ev)
    return ev


def test_a_confirmed_attack_tx_raises_a_single_source_web3_event_to_v2():
    store = MemoryStore()
    ev = _web3_event(store)
    assert ev.level == "V1" and ev.tx[0]["verified"] == "unchecked"
    changed = pipeline.verify_onchain(store, NOW, rpc({TX: {"status": "0x1", "blockNumber": "0x1"}}))
    after = store.get_event("ev_x100")
    assert changed == ["ev_x100"] and after.level == "V2" and "on-chain" in after.level_reason
    assert after.tx[0]["verified"] == "confirmed" and any(t.get("kind") == "level_change" and t["to"] == "V2" for t in after.timeline)


def test_the_verdict_survives_the_next_recompute():
    """recompute rebuilds tx from the items (which only carry the hash): it must not reset a verdict to unchecked."""
    store = MemoryStore()
    _web3_event(store)
    pipeline.verify_onchain(store, NOW, rpc({TX: {"status": "0x1", "blockNumber": "0x1"}}))
    ev = store.get_event("ev_x100")
    again = pipeline.recompute(ev, store.get_items(ev.item_ids), NOW + timedelta(hours=1))
    assert again.tx[0]["verified"] == "confirmed" and again.level == "V2"


def test_a_reverted_tx_does_not_corroborate():
    store = MemoryStore()
    _web3_event(store)
    pipeline.verify_onchain(store, NOW, rpc({TX: {"status": "0x0", "blockNumber": "0x1"}}))
    assert store.get_event("ev_x100").level == "V1"


def test_every_verdict_is_publishable():
    """The site-data schema's tx enum must contain every verdict radar.chain can produce (it had verified / mismatch)."""
    import json as _json
    from pathlib import Path as _P
    enum = _json.loads((_P(__file__).resolve().parents[1] / "schemas" / "site-data.schema.json").read_text())["$defs"]["TxRef"]["properties"]["verified"]["enum"]
    assert set(enum) == {"unchecked", "confirmed", "failed", "not_found", "unsupported"}


def test_an_unmapped_explorer_host_resolves_and_a_newly_supported_chain_is_rechecked():
    """Live 10-29: Avalanche txs were stored with chain `snowscan.xyz` and marked unsupported forever."""
    t = {"chain": "snowscan.xyz", "hash": TX, "verified": "unsupported", "attempts": 1, "checked_at": NOW.isoformat()}
    assert chain.canon("snowscan.xyz") == "avalanche" and chain.due(t, NOW)
    assert not chain.due({**t, "chain": "solana"}, NOW)                           # still unsupported ⇒ left alone
