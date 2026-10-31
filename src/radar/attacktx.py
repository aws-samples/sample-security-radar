"""Attack-transaction breakdown (M4.1 E3). Code only, no LLM.

For every web3 event whose attack transaction the radar has verified on chain (chain.verdict → "confirmed"), read the
receipt once (receipts never change), decode its ERC-20 Transfer logs and publish, per token, who gained and who lost
in that transaction — the second-level view of a contract exploit (the Binance-style follow-the-money table is
radar.onchain; most incidents are one exploit transaction instead).

Calls: eth_getTransactionReceipt + eth_getBlockByNumber (timestamp) + eth_getTransactionByHash (native value) per tx, eth_call symbol() / decimals() per token —
token metadata is shared by every event through one ledger (TOKEN_KEY). At most Limits.ATTACKTX_CALLS_PER_CYCLE per
cycle; a tx that fails is recorded and retried, never shown as "no transfers". What is not decoded is stated:
native-coin value moved inside contracts (needs traces) and NFT transfers (ERC-721, 4-topic Transfer).
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from radar import chain, timeutil
from radar.limits import Limits

TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
SYMBOL, DECIMALS = "0x95d89b41", "0x313ce567"
# shown first among tokens with as many transfers (stablecoins and the ETH / BTC families a reader can value at a glance)
NATIVE = {"ethereum": "ETH", "arbitrum": "ETH", "base": "ETH", "bsc": "BNB", "avalanche": "AVAX", "polygon": "POL"}
MAJOR = {"USDT", "USDC", "DAI", "USDE", "FDUSD", "WETH", "ETH", "STETH", "WSTETH", "WBTC", "CBBTC", "BTCB", "WBNB", "WAVAX"}
KEY_PREFIX = "__attacktx__"
TOKEN_KEY = "__tokenmeta__"
NOT_DECODED = ("原生币（ETH / BNB / AVAX）在合约内部的转移：公共节点不提供 trace",
               "NFT（ERC-721）转移")


def case_key(event_id: str) -> str:
    return f"{KEY_PREFIX}#{event_id}"


def _addr(word: str) -> str:
    return "0x" + word[-40:].lower()


def _symbol(raw: Any) -> str | None:
    """ABI string, or bytes32 (MKR-style); None when undecodable."""
    if not isinstance(raw, str) or not raw.startswith("0x") or len(raw) < 66:
        return None
    b = bytes.fromhex(raw[2:])
    try:
        if len(b) >= 96 and int.from_bytes(b[:32], "big") == 32:
            n = int.from_bytes(b[32:64], "big")
            s = b[64:64 + n].decode("utf-8")
        else:
            s = b[:32].rstrip(b"\0").decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return None
    s = "".join(ch for ch in s if ch.isprintable()).strip()
    return s[:16] or None


def transfers(receipt: dict[str, Any]) -> list[dict[str, Any]]:
    """ERC-20 Transfer logs (3 topics, 32-byte value) as {token, from, to, raw}; ERC-721 (4 topics) is skipped."""
    out = []
    for lg in receipt.get("logs") or []:
        t = lg.get("topics") or []
        data = lg.get("data") or "0x"
        if len(t) == 3 and t[0] == TRANSFER and len(data) == 66:
            out.append({"token": lg["address"].lower(), "from": _addr(t[1]), "to": _addr(t[2]), "raw": int(data, 16)})
    return out


def net(moves: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """token → address → net raw amount (in − out) inside the transaction."""
    out: dict[str, dict[str, int]] = {}
    for m in moves:
        per = out.setdefault(m["token"], {})
        per[m["from"]] = per.get(m["from"], 0) - m["raw"]
        per[m["to"]] = per.get(m["to"], 0) + m["raw"]
    return out


def _amount(raw: int, dec: Any) -> float | None:
    """Token units, or None when decimals() is unknown (the raw integer is published beside it)."""
    return round(raw / 10 ** dec, 6) if isinstance(dec, int) else None


def breakdown(tx: str, ch: str, receipt: dict[str, Any], ts: str, meta: dict[str, dict[str, Any]],
              value: str | None = None) -> dict[str, Any]:
    """The published view of one attack tx: per token (most transfers first) the largest net gainer and loser, with
    the roles the receipt names (发起地址 = tx sender, 被调用合约 = tx target)."""
    moves = transfers(receipt)
    sender, target = (receipt.get("from") or "").lower(), (receipt.get("to") or "").lower()
    role = {sender: "发起地址", target: "被调用合约"}
    count: dict[str, int] = {}
    for m in moves:
        count[m["token"]] = count.get(m["token"], 0) + 1
    tokens = []
    def rank(kv: tuple[str, dict[str, int]]) -> tuple[int, int, str]:
        sym = ((meta.get(f"{ch}|{kv[0]}") or {}).get("symbol") or "").upper()
        return (-count[kv[0]], 0 if sym in MAJOR else 1, kv[0])
    for tok, per in sorted(net(moves).items(), key=rank):
        md = meta.get(f"{ch}|{tok}") or {}
        dec = md.get("decimals")
        gain = max(per.items(), key=lambda kv: (kv[1], kv[0]))
        loss = min(per.items(), key=lambda kv: (kv[1], kv[0]))
        tokens.append({"token": tok, "symbol": md.get("symbol"), "transfers": count[tok],
                       "gainer": {"address": gain[0], "role": role.get(gain[0]), "amount": _amount(gain[1], dec), "raw": str(gain[1])} if gain[1] > 0 else None,
                       "loser": {"address": loss[0], "role": role.get(loss[0]), "amount": _amount(-loss[1], dec), "raw": str(-loss[1])} if loss[1] < 0 else None})
    return {"tx": tx, "chain": ch, "block": int(receipt["blockNumber"], 16), "t": ts,
            "status": "success" if str(receipt.get("status", "")).lower() == "0x1" else "reverted",
            "sender": sender, "target": target, "transfers": len(moves), "tokens": tokens[: Limits.ATTACKTX_MAX_TOKENS],
            "tokens_total": len(tokens),
            # the native coin the transaction itself sends (a plain "682 ETH drained" tx has no ERC-20 log at all);
            # None = not read yet, 0 ⇒ omitted
            "native": {"symbol": NATIVE.get(ch, "native"), "amount": round(int(value) / 1e18, 6)} if value and int(value) > 0 else None}


def _due(ev: Any, now: datetime) -> list[dict[str, Any]]:
    return [t for t in (getattr(ev, "tx", None) or []) if t.get("verified") == "confirmed" and chain.canon(t.get("chain", "")) in chain.RPC]


def step(case: dict[str, Any], ev: Any, meta: dict[str, dict[str, Any]], now: datetime,
         call: Callable[[str, str, list[Any]], Any], budget: int) -> int:
    """Advance one event: receipts first, then the token metadata its breakdowns still lack. Returns calls used."""
    used = 0
    done = case.setdefault("txs", {})
    for t in _due(ev, now):
        h, ch = t["hash"].lower(), chain.canon(t["chain"])
        if h in done and "receipt" in done[h]:
            continue
        if used + 2 > budget:
            break
        url = chain.RPC[ch]
        try:
            used += 1
            receipt = call(url, "eth_getTransactionReceipt", [h])
            used += 1
            block = call(url, "eth_getBlockByNumber", [receipt["blockNumber"], False])
        except (chain.RpcError, KeyError, TypeError) as e:
            case["errors"] = (case.get("errors", []) + [{"at": timeutil.iso(now), "tx": h, "error": str(e)[:160]}])[-10:]
            continue
        ts = timeutil.iso(datetime.fromtimestamp(int(block["timestamp"], 16), tz=UTC))
        # only what the breakdown needs (a receipt can be hundreds of KB; the ledger entry stays small)
        done[h] = {"chain": ch, "t": ts, "receipt": {k: receipt.get(k) for k in ("blockNumber", "status", "from", "to")}
                   | {"logs": [{"address": lg["address"], "topics": lg["topics"], "data": lg["data"]} for lg in receipt.get("logs") or []
                               if (lg.get("topics") or [None])[0] == TRANSFER]}}
    for h, d in done.items():
        if d.get("receipt") and "value" not in d:
            if used + 1 > budget:
                return used
            used += 1
            try:
                d["value"] = str(int(call(chain.RPC[d["chain"]], "eth_getTransactionByHash", [h])["value"], 16))
            except (chain.RpcError, KeyError, TypeError, ValueError) as e:
                case["errors"] = (case.get("errors", []) + [{"at": timeutil.iso(now), "tx": h, "error": f"value: {e}"[:160]}])[-10:]
    for h, d in done.items():
        for tok in {m["token"] for m in transfers(d.get("receipt") or {})}:
            k = f"{d['chain']}|{tok}"
            if k in meta:
                continue
            if used + 2 > budget:
                return used
            url = chain.RPC[d["chain"]]
            got: dict[str, Any] = {}
            for sel, field in ((SYMBOL, "symbol"), (DECIMALS, "decimals")):
                used += 1
                try:
                    raw = call(url, "eth_call", [{"to": tok, "data": sel}, "latest"])
                except chain.RpcError:
                    raw = None                    # a token without symbol()/decimals(): shown by address, amount raw
                if field == "symbol":
                    got["symbol"] = _symbol(raw)
                else:
                    got["decimals"] = int(raw, 16) if isinstance(raw, str) and raw.startswith("0x") and len(raw) >= 3 and int(raw, 16) <= 36 else None
            meta[k] = got | {"at": timeutil.iso(now)}
            prune(meta)
    return used


def prune(meta: dict[str, dict[str, Any]]) -> None:
    """Keep the newest Limits.ATTACKTX_TOKEN_LEDGER_MAX entries (one DynamoDB item ≤ 400 KB); entries written before
    timestamps existed count as oldest. An evicted token is fetched again when a later tx needs it."""
    over = len(meta) - Limits.ATTACKTX_TOKEN_LEDGER_MAX
    if over > 0:
        for k in sorted(meta, key=lambda k: meta[k].get("at", ""))[:over]:
            del meta[k]


def attackers(case: dict[str, Any] | None) -> dict[str, dict[str, str]]:
    """M4.2: the sender of every successful verified attack tx — address → {chain, t: first tx, last: last tx}. radar.onchain
    follows these addresses' outflows and freezes like the evidence addresses of a P0."""
    out: dict[str, dict[str, str]] = {}
    for d in ((case or {}).get("txs") or {}).values():
        r = d.get("receipt") or {}
        a = (r.get("from") or "").lower()
        if str(r.get("status", "")).lower() == "0x1" and re.fullmatch(r"0x[0-9a-f]{40}", a):
            o = out.setdefault(a, {"chain": d["chain"], "t": d["t"], "last": d["t"]})
            o["t"], o["last"] = min(o["t"], d["t"]), max(o["last"], d["t"])     # a probe tx often precedes the drain
    return out


def doc(case: dict[str, Any] | None, meta: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    """The published `attack_txs` section, or None when the event has no decoded attack tx yet."""
    if not case or not case.get("txs"):
        return None
    txs = [breakdown(h, d["chain"], d["receipt"], d["t"], meta, d.get("value")) for h, d in case["txs"].items() if d.get("receipt")]
    if not txs:
        return None
    return {"txs": sorted(txs, key=lambda x: (x["t"], x["tx"])), "not_decoded": list(NOT_DECODED),
            "errors": (case.get("errors") or [])[-3:]}


def cycle(store: Any, now: datetime, call: Callable[[str, str, list[Any]], Any] = chain.rpc_call) -> list[str]:
    """Process-station step: newest web3 events with verified attack txs first, inside ATTACKTX_CALLS_PER_CYCLE.
    Returns the events whose published breakdown changed — compared by digest, because token metadata fetched for
    one event completes another event's table too."""
    since = timeutil.iso(now - timedelta(days=Limits.PUBLISH_WINDOW_DAYS))
    evs = sorted((e for e in store.events_updated_since(since) if e.domain == "web3" and _due(e, now)),
                 key=lambda e: e.first_seen, reverse=True)
    meta = store.get_source_state(TOKEN_KEY)
    n_meta = len(meta)
    budget, cases = Limits.ATTACKTX_CALLS_PER_CYCLE, {}
    for ev in evs:
        case = cases[ev.event_id] = store.get_source_state(case_key(ev.event_id))
        if budget <= 0:
            continue
        try:
            budget -= step(case, ev, meta, now, call, budget)
        except Exception as e:    # noqa: BLE001 — recorded on the case (degradation leaves a trace), other events go on
            case["errors"] = (case.get("errors", []) + [{"at": timeutil.iso(now), "tx": "step", "error": f"{type(e).__name__}: {e}"[:160]}])[-10:]
            case["dirty"] = True
    if len(meta) != n_meta:
        store.put_source_state(TOKEN_KEY, meta)
    changed = []
    for ev in evs:
        case = cases[ev.event_id]
        digest = hashlib.sha256(json.dumps(doc(case, meta), sort_keys=True).encode()).hexdigest()[:16]
        if digest != case.get("digest") or case.pop("dirty", False):
            case["digest"] = digest
            store.put_source_state(case_key(ev.event_id), case)
            changed.append(ev.event_id)
    return changed
