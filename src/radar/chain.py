"""C6 · on-chain verification of attack transactions (code only, no LLM): eth_getTransactionReceipt on a keyless
public RPC per chain turns a tx's `verified: unchecked` into a verdict the level rules can use.

  confirmed     receipt exists, status 0x1 — the transaction happened and succeeded
  failed        receipt exists, status 0x0 — mined but reverted (an attempt, not a theft)
  not_found     no receipt (wrong chain, typo, not yet indexed) — re-checked, then given up after CHAIN_MAX_ATTEMPTS
  unsupported   chain without an EVM receipt endpoint here (Solana, Tron, …) — said so, never guessed
A failed RPC call never changes the verdict: the error is recorded beside it (check_error) and retried next cycle.

Endpoints: PublicNode, keyless (read 2026-10-28 via firecrawl on each chain's page: ethereum / bsc / base / polygon /
arbitrum, each page names the HTTPS endpoint, no key stated). One registry, one place to change a provider.
"""
from __future__ import annotations

import http.client
import json
import logging
import time
import urllib.request
from datetime import datetime, timedelta
from typing import Any

from radar import fetch, timeutil
from radar.fetch import UA
from radar.limits import Limits

log = logging.getLogger(__name__)

# bsc: BNB Chain's own endpoint (docs.bnbchain.org json-rpc page: 10K requests / 5 min) — PublicNode's BSC endpoint
# answered 403 Forbidden to the Lambda (live 2026-10-29). avalanche: PublicNode C-Chain.
RPC = {"ethereum": "https://ethereum-rpc.publicnode.com", "bsc": "https://bsc-dataseed.bnbchain.org",
       "avalanche": "https://avalanche-c-chain-rpc.publicnode.com",
       "base": "https://base-rpc.publicnode.com", "polygon": "https://polygon-bor-rpc.publicnode.com",
       "arbitrum": "https://arb1.arbitrum.io/rpc"}   # publicnode refuses blocks older than ~12 h ("Archive requests require a personal token", 403; live 2026-10-30)
# Tried in order when the primary refuses (403 / 429 / timeout / "archive" in the body). Probe 2026-10-31 (eth_getLogs
# with an address filter, 5,000 blocks; the Binance 20:24:23 sweep read back): publicnode Ethereum refuses logs older
# than ~1 day; Tenderly's public gateway serves 30 days with receipts and getCode; MEV Blocker serves logs (its
# receipts timed out). One public node per chain was a single point of failure for the on-chain station.
FALLBACK = {"ethereum": ("https://mainnet.gateway.tenderly.co", "https://rpc.mevblocker.io"),
            "arbitrum": ("https://arbitrum-one-rpc.publicnode.com",)}
FINAL = ("confirmed", "failed")   # unsupported is final only while the chain stays unsupported (see due)
# names as sources write them (DeFiLlama "BSC", "Ethereum", "Arbitrum One" …) → registry key
ALIAS = {"eth": "ethereum", "ethereum": "ethereum", "bsc": "bsc", "bnb": "bsc", "bnb chain": "bsc", "binance": "bsc",
         "base": "base", "polygon": "polygon", "matic": "polygon", "arbitrum": "arbitrum", "arbitrum one": "arbitrum"}


class RpcError(Exception):
    pass


def canon(chain: str) -> str:
    """Source spelling or an explorer host (items stored before a host was mapped keep the host as chain, e.g.
    `snowscan.xyz`, live 10-29) → registry key."""
    from radar.keys import EXPLORERS
    c = (chain or "").strip().lower()
    c = EXPLORERS.get(c, c)
    return ALIAS.get(c, c)


def _one(url: str, method: str, params: list[Any]) -> Any:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": UA})
    try:
        with fetch.urlopen(req, timeout=Limits.CHAIN_RPC_TIMEOUT_S) as r:
            doc = json.loads(r.read(1_000_000))
    # OSError covers URLError, timeouts and RemoteDisconnected; HTTPException covers IncompleteRead & co. — a public node
    # misbehaving must degrade this one check, never the process station
    except (OSError, http.client.HTTPException, ValueError) as e:
        raise RpcError(f"rpc_unreachable: {str(getattr(e, 'reason', e))[:160]}") from e
    if doc.get("error"):
        raise RpcError(f"rpc_error: {str(doc['error'])[:160]}")
    return doc.get("result")


_REFUSED = ("rpc_unreachable", "archive", "limit", "range", "rate")
# wall-clock RPC budget of one process-station run (start_cycle); None = unbounded (scripts, tests)
_budget: dict[str, float | None] = {"left": None}


def start_cycle(budget_s: float | None = Limits.RPC_WALL_S_PER_CYCLE) -> None:
    """Called once per process-station run: every RPC call of the run (C6 verify, on-chain station, attack-tx station)
    shares this wall-clock budget, so fallbacks × timeouts can never outlive the Lambda."""
    _budget["left"] = budget_s


def rpc_call(url: str, method: str, params: list[Any]) -> Any:
    """One JSON-RPC call; when `url` is a registered primary and refuses (unreachable / HTTP error / archive or range
    limit), the chain's FALLBACK nodes are tried in order. All failing ⇒ RpcError naming every node's reason."""
    ch = next((c for c, u in RPC.items() if u == url), None)
    errors = []
    for u in (url, *FALLBACK.get(ch or "", ())):
        if _budget["left"] is not None and _budget["left"] <= 0:
            errors.append("rpc_budget_exhausted: this cycle's RPC time is spent — retried next cycle")
            break
        t0 = time.monotonic()
        try:
            return _one(u, method, params)
        except RpcError as e:
            errors.append(f"{u.split('//')[-1].split('/')[0]}: {e}")
            if not any(k in str(e).lower() for k in _REFUSED):
                break                     # a real answer (e.g. invalid params) is the same on every node
        finally:
            if _budget["left"] is not None:
                _budget["left"] -= time.monotonic() - t0
    raise RpcError(" | ".join(errors)[:480])


def verdict(chain: str, tx_hash: str, call: Any = rpc_call) -> dict[str, Any]:
    """One tx → {verified, block?} or raises RpcError (the caller keeps the previous verdict)."""
    url = RPC.get(canon(chain))
    if not url:
        return {"verified": "unsupported"}
    receipt = call(url, "eth_getTransactionReceipt", [tx_hash])
    if not receipt:
        return {"verified": "not_found"}
    status = str(receipt.get("status", "")).lower()
    out = {"verified": "confirmed" if status == "0x1" else "failed" if status == "0x0" else "not_found"}
    if receipt.get("blockNumber"):
        out["block"] = int(receipt["blockNumber"], 16)
    return out


def due(t: dict[str, Any], now: datetime) -> bool:
    """Final verdicts are never re-checked; not_found / errors back off CHAIN_RECHECK_H, up to CHAIN_MAX_ATTEMPTS."""
    if t.get("verified") in FINAL or int(t.get("attempts", 0)) >= Limits.CHAIN_MAX_ATTEMPTS:
        return False
    if t.get("verified") == "unsupported":
        return canon(t.get("chain", "")) in RPC        # supported since ⇒ check it (no back-off: it was never called)
    last = t.get("checked_at")
    return not last or timeutil.parse(last) <= now - timedelta(hours=Limits.CHAIN_RECHECK_H)


def check_txs(txs: list[dict[str, Any]], now: datetime, budget: int, call: Any = rpc_call) -> tuple[list[dict[str, Any]], int]:
    """Check the due txs of one event (≤ budget calls). Returns (txs, calls used); never raises."""
    used, out = 0, []
    for t in txs:
        t = dict(t)
        if used < budget and due(t, now):
            used += 1
            t["attempts"] = int(t.get("attempts", 0)) + 1
            t["checked_at"] = timeutil.iso(now)
            try:
                t.update(verdict(t.get("chain", ""), t["hash"], call))
                t.pop("check_error", None)
            except RpcError as e:      # verdict unchanged, the reason is visible (degradation leaves a trace)
                t["check_error"] = str(e)
                log.warning(json.dumps({"station": "process", "degraded": "chain_rpc", "chain": t.get("chain"),
                                        "tx": t["hash"][:18], "error": str(e)}))
        out.append(t)
    return out, used


def onchain_confirmed(txs: list[dict[str, Any]]) -> bool:
    return any(t.get("verified") == "confirmed" for t in txs)
