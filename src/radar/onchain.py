"""On-chain reconstruction of a P0 web3 incident, minute by minute (M4 D6). Code only, no LLM.

What it reads, all through the radar's own public RPC (radar.chain.RPC) and only eth_blockNumber / eth_getLogs / eth_getCode:
  · outflows  — ERC-20 transfers ≥ Limits.ONCHAIN_MIN_USD out of the seed wallets (victim hot wallets from WALLETS, full
                addresses stated in the evidence), then out of the large receivers (one hop, ≤ ONCHAIN_MAX_DOWNSTREAM);
  · freezes   — issuer blacklist events (Tether AddedBlackList, Circle Blacklisted) that hit any wallet in the case;
  · delegation— whether a victim wallet currently runs EIP-7702 code (eth_getCode starts with 0xef0100).
Every row carries its transaction hash. A chain or token that was not queried is listed as unchecked — never as "no
outflow". Limits that a public node imposes (no archive state, no traces ⇒ no historical delegation, no native-coin
internal transfers) are published with the result.

It is incremental: a cursor per (query, chain, token, address) advances each cycle inside a call budget, so one event is
finished over a few cycles and later sweeps / freezes keep arriving. State lives in the "__onchain__" ledger.
Verified against the 2026-10-29 Binance theft (tests/fixtures/onchain/binance_20261029.json, recorded from the RPC):
the 20:24:23 1,615.4M USDT sweep and Tether's 9 + Circle's 1 freezes, to the second, match Ondology Labs / TRM.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from radar import chain, timeutil
from radar.limits import Limits

TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


@dataclass(frozen=True)
class Token:
    symbol: str
    address: str
    decimals: int
    issuer: str | None = None            # who can freeze it
    freeze_topic: str | None = None      # issuer blacklist event topic0
    freeze_in_topic: bool = False        # frozen address in topics[1] (Circle) or in data (Tether)


# Contract addresses and decimals checked on chain with symbol() / decimals() on 2026-10-30 (BSC's are 18 decimals).
# Freeze events: Ethereum only so far — Tether's newer contracts (USDT0, Avalanche USDt) use other events: unchecked.
TOKENS: dict[str, tuple[Token, ...]] = {
    "ethereum": (Token("USDT", "0xdac17f958d2ee523a2206206994597c13d831ec7", 6, "Tether",
                       "0x42e160154868087d6bfdc0ca23d96a1c1cfa32f1b72ba9ba27b69b98a0d819dc"),
                 Token("USDC", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", 6, "Circle",
                       "0xffa4e6181777692565cf28528fc88fd1516ea86b56da075235fa575af6a4b855", True)),
    "arbitrum": (Token("USDT", "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9", 6),
                 Token("USDC", "0xaf88d065e77c8cc2239327c5edb3a432268e5831", 6)),
    "avalanche": (Token("USDT", "0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7", 6),
                  Token("USDC", "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e", 6)),
    "base": (Token("USDC", "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", 6),),
    "bsc": (Token("USDT", "0x55d398326f99059ff775485246999027b3197955", 18),
            Token("USDC", "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d", 18)),
}
# average block time (s) — only to estimate the first block of the window; rows are filtered on blockTimestamp
BLOCK_S = {"ethereum": 12.0, "arbitrum": 0.25, "avalanche": 2.0, "base": 2.0, "bsc": 0.75}
# eth_getLogs block span per call (public nodes reject wide spans; filtered by address + topics a span this size is small)
SPAN = {"ethereum": 5_000, "arbitrum": 100_000, "avalanche": 50_000, "base": 50_000, "bsc": 20_000}   # bsc: 100k ⇒ -32005 limit exceeded

# Publicly labelled exchange hot wallets (Etherscan public labels; the Binance 2026-10-29 reconstructions by Ondology Labs
# and TRM name the same wallets). Matched on the event's entity / title token; a registry, not a code path.
WALLETS: dict[str, dict[str, dict[str, str]]] = {
    "binance": {"ethereum": {"0x28c6c06298d514db089934071355e5743bf21d60": "Binance 14",
                             "0xdfd5293d8e347dfe59e90efd55b2956a1343963d": "Binance 16",
                             "0xee7ae85f2fe2239e27d9c1e23fffe168d63b4055": "Binance Hot Wallet 34"}},
}
NOT_QUERIED = ("原生币（ETH / AVAX 等）的合约内部转出：公共节点不提供 trace",
               "历史时刻的 EIP-7702 委托状态：公共节点不提供归档状态（只查当前）",
               "非 EVM 链（Bitcoin / Tron / XRP Ledger / Solana）",
               "Ethereum 以外的发行方冻结事件（USDT0、Avalanche USDt 等新合约）",
               # publicnode Ethereum refuses logs older than ~1 day; chain.FALLBACK (Tenderly, MEV Blocker) serves them —
               # probed from the radar's Lambda egress 2026-10-31. A range every node refuses stays an error, retried
               "公共节点的历史日志有限：主节点拒绝时依次换备用节点；所有节点都拒绝的区间列在错误里，不算「无转出」")

_ADDR = re.compile(r"(?<![0-9a-fA-Fx])0x[0-9a-fA-F]{40}(?![0-9a-fA-F])")
_TRUNC = re.compile(r"(?<![0-9a-fA-Fx])0x([0-9a-fA-F]{3,8})(?:…|\.\.\.)([0-9a-fA-F]{3,8})(?![0-9a-fA-F])")


def _pad(a: str) -> str:
    return "0x" + "0" * 24 + a[2:].lower()


def _addr(word: str) -> str:
    return "0x" + word[-40:].lower()


def eligible(ev: Any, now: datetime, attackers: dict[str, Any] | None = None) -> bool:
    """Web3 incidents first seen within ONCHAIN_ACTIVE_DAYS: every P0, and a P1 once the radar knows its attacker (a
    verified attack tx — M4.2; a P1 has no victim wallet to start from otherwise)."""
    seen = timeutil.parse(ev.first_seen)
    young = ev.domain == "web3" and bool(seen) and now - seen <= timedelta(days=Limits.ONCHAIN_ACTIVE_DAYS)
    return young and (ev.severity == "P0" or (ev.severity == "P1" and bool(attackers)))


def victim_wallets(names: list[str]) -> dict[str, dict[str, str]]:
    """chain → {address: label} for every registered exchange named in the event's entities / title."""
    blob = " ".join(names).lower()
    out: dict[str, dict[str, str]] = {}
    for key, per_chain in WALLETS.items():
        if re.search(rf"(?<![a-z0-9]){key}(?![a-z0-9])", blob) or (key == "binance" and "币安" in blob):
            for ch, wallets in per_chain.items():
                out.setdefault(ch, {}).update(wallets)
    return out


def evidence_addresses(texts: list[str]) -> list[str]:
    """Full EVM addresses in the evidence, minus precompile / burn-style ones (≥ 30 leading zero nibbles: "0x…0da0")."""
    return sorted({a.lower() for t in texts for a in _ADDR.findall(t) if not a[2:].startswith("0" * 30)})


def min_usd(loss: float | None) -> float:
    """Threshold for a row / a followed receiver, scaled to the incident: 0.5 % of the loss within [1M, 10M]. A fixed $1M
    filled the Binance case with routine customer withdrawals ($1–3M, 18:21–19:55) and its receiver slots with them —
    the attacker's 500M / 200M split wallets were never followed."""
    return min(Limits.ONCHAIN_MAX_MIN_USD, max(Limits.ONCHAIN_MIN_USD, (loss or 0) * Limits.ONCHAIN_LOSS_SHARE))


def truncated(texts: list[str]) -> list[tuple[str, str]]:
    """Shortened addresses the evidence uses ("0x5227…CB2f8c"): (prefix, suffix), lower-case, without 0x."""
    return sorted({(p.lower(), s.lower()) for t in texts for p, s in _TRUNC.findall(t)})


def resolve(short: list[tuple[str, str]], full: list[str]) -> dict[str, str]:
    """full address → "0xprefix…suffix" as the evidence wrote it, when exactly one full address matches."""
    out: dict[str, str] = {}
    for p, s in short:
        hits = [a for a in full if a[2:].startswith(p) and a.endswith(s)]
        if len(hits) == 1:
            out[hits[0]] = f"0x{p}…{s}"
    return out


def new_case(ev: Any, texts: list[str], now: datetime, attackers: dict[str, dict[str, str]] | None = None) -> dict[str, Any]:
    first = timeutil.parse(ev.first_seen) or now
    victims = victim_wallets([*ev.entities, ev.title])
    evidence = [a for a in evidence_addresses(texts) if not any(a in w for w in victims.values())]
    # an evidence address is queried on the EVM chains the event names (Ethereum always): 5 chains × every address cost
    # 961 calls for the Binance case
    named = {chain.canon(c) for c in getattr(ev, "chains", []) or []} | {"ethereum"}
    case = {"event_id": ev.event_id, "created_at": timeutil.iso(now),
            "window": [timeutil.iso(first - timedelta(hours=Limits.ONCHAIN_WINDOW_BEFORE_H)),
                       timeutil.iso(first + timedelta(hours=Limits.ONCHAIN_WINDOW_AFTER_H))],
            "victims": victims, "evidence": evidence, "short": truncated(texts),
            "evidence_chains": sorted(ch for ch in TOKENS if ch in named),
            "min_usd": min_usd(getattr(ev, "amount_usd_latest", None)),
            "receivers": {}, "cursors": {}, "rows": [], "delegation": {}, "errors": [], "attackers": {}}
    add_attackers(case, attackers or {})
    return case


def add_attackers(case: dict[str, Any], attackers: dict[str, dict[str, str]]) -> bool:
    """Attack-tx senders join the case on their own chain; the window stretches to 24 h after the last attack tx (a
    date-only first_seen can sit a day before it — Tranche Vault: 10-27 00:00 vs the drain at 10-28 00:00:03).
    Returns whether anything was added."""
    new = {a: v for a, v in attackers.items() if a not in case.setdefault("attackers", {})
           and v.get("chain") in TOKENS and not any(a in w for w in case["victims"].values())}
    for a, v in new.items():
        case["attackers"][a] = {"chain": v["chain"], "t": v["t"]}
        t0, t1 = timeutil.parse(v["t"]), timeutil.parse(v.get("last") or v["t"])
        if t0 and t1:
            lo = timeutil.iso(t0 - timedelta(hours=Limits.ONCHAIN_WINDOW_BEFORE_H))
            hi = timeutil.iso(t1 + timedelta(hours=Limits.ONCHAIN_WINDOW_AFTER_H))
            case["window"] = [min(case["window"][0], lo), max(case["window"][1], hi)]
    return bool(new)


def _queries(case: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    """(kind, chain, token symbol, address) still to run, in priority order: victim outflows, freezes, evidence wallets,
    receivers (one hop)."""
    q: list[tuple[str, str, str, str]] = []
    for ch, wallets in case["victims"].items():
        for tok in TOKENS.get(ch, ()):
            q += [("out", ch, tok.symbol, a) for a in wallets]
    for ch, toks in TOKENS.items():
        q += [("freeze", ch, t.symbol, "") for t in toks if t.freeze_topic]
    for a, v in (case.get("attackers") or {}).items():
        q += [("out", v["chain"], t.symbol, a) for t in TOKENS.get(v["chain"], ())]
    for a in case["evidence"]:
        q += [("out", ch, t.symbol, a) for ch in case.get("evidence_chains", ["ethereum"]) for t in TOKENS[ch]]
    for a, r in case["receivers"].items():
        q += [("out", r["chain"], t.symbol, a) for t in TOKENS.get(r["chain"], ())]
    return q


def _token(ch: str, sym: str) -> Token:
    return next(t for t in TOKENS[ch] if t.symbol == sym)


def _label(case: dict[str, Any], ch: str, a: str) -> str:
    if a in case["victims"].get(ch, {}):
        return case["victims"][ch][a]
    if a in case["receivers"]:
        return case["receivers"][a]["label"]
    if a in (case.get("attackers") or {}):
        return f"攻击发起地址 {a[:6]}…{a[-4:]}"
    return f"{a[:6]}…{a[-4:]}"


def step(case: dict[str, Any], now: datetime, call: Callable[[str, str, list[Any]], Any], budget: int) -> int:
    """Advance the case by at most `budget` RPC calls; returns the calls used. Rows are appended once (keyed by tx +
    log index); a failed call is recorded and retried next cycle (the cursor does not move)."""
    used = 0
    start, end = (timeutil.parse(x) for x in case["window"])
    latest: dict[str, int] = {}
    seen = {r["id"] for r in case["rows"]} | {f["id"] for f in case.get("freezes", [])}

    def head(ch: str) -> int:
        nonlocal used
        if ch not in latest:
            latest[ch] = int(call(chain.RPC[ch], "eth_blockNumber", []), 16)
            used += 1
        return latest[ch]

    def block_at(ch: str, t: datetime) -> int:
        return max(0, head(ch) - int((now - t).total_seconds() / BLOCK_S[ch]))

    # current EIP-7702 delegation of the victim wallets first (cheap and the most urgent fact), at most hourly per wallet
    for ch, wallets in case["victims"].items():
        for a in wallets:
            last = (case["delegation"].get(a) or {}).get("checked_at", "")
            if used >= budget or (last and now - timeutil.parse(last) < timedelta(minutes=Limits.ONCHAIN_CODE_RECHECK_MIN)):
                continue
            used += 1
            try:
                code = call(chain.RPC[ch], "eth_getCode", [a, "latest"])
            except chain.RpcError as e:
                case["errors"] = (case["errors"] + [{"at": timeutil.iso(now), "query": f"code|{ch}|{a}", "error": str(e)[:160]}])[-20:]
                continue
            case["delegation"][a] = {"chain": ch, "checked_at": timeutil.iso(now),
                                     "delegate": "0x" + code[8:48] if isinstance(code, str) and code.startswith("0xef0100") else None}
    # round-robin: never-run queries first, then the least recently run — while the window is open every query has a
    # tail to re-read, and a fixed order would let the first ones eat the budget forever
    pending = [q for q in _queries(case) if not case["cursors"].get("|".join(q), {}).get("done")]
    pending.sort(key=lambda q: case["cursors"].get("|".join(q), {}).get("ran_at", ""))
    for kind, ch, sym, addr in pending:
        if used >= budget:
            break
        key = f"{kind}|{ch}|{sym}|{addr}"
        cur = case["cursors"].get(key)
        try:
            last = min(head(ch), block_at(ch, end)) if end < now else head(ch)
            frm = cur["next"] if cur and "next" in cur else block_at(ch, start)
            if frm > last:
                case["cursors"][key] = {"next": frm, "done": end < now, "ran_at": timeutil.iso(now)}
                continue
            to = min(last, frm + SPAN[ch] - 1)
            tok = _token(ch, sym)
            if kind == "out":
                logs = call(chain.RPC[ch], "eth_getLogs", [{"fromBlock": hex(frm), "toBlock": hex(to), "address": tok.address,
                                                            "topics": [TRANSFER, _pad(addr)]}])
            else:
                logs = call(chain.RPC[ch], "eth_getLogs", [{"fromBlock": hex(frm), "toBlock": hex(to), "address": tok.address,
                                                            "topics": [tok.freeze_topic]}])
            used += 1
        except chain.RpcError as e:
            case["errors"] = (case["errors"] + [{"at": timeutil.iso(now), "query": key, "error": str(e)[:160]}])[-20:]
            used += 1
            # ran_at moves (a query that keeps failing must not stay first in the round-robin and starve the others);
            # "next" does not (that block range is read again)
            case["cursors"][key] = {**(cur or {}), "ran_at": timeutil.iso(now), "failed": True}
            continue
        for lg in logs:
            _ingest_log(case, kind, ch, tok, addr, lg, seen)
        case["cursors"][key] = {"next": to + 1, "done": to >= last and end < now, "ran_at": timeutil.iso(now)}
    return used


def _ingest_log(case: dict[str, Any], kind: str, ch: str, tok: Token, addr: str, lg: dict[str, Any], seen: set[str]) -> None:
    rid = f"{lg['transactionHash']}:{int(lg['logIndex'], 16)}"
    if rid in seen:
        return
    ts = timeutil.iso(datetime.fromtimestamp(int(lg["blockTimestamp"], 16), tz=UTC))
    start, end = case["window"]
    if not start <= ts <= end:
        return
    if kind == "freeze":
        # every freeze of the window is kept (a handful per hour) and matched to the case wallets when the doc is built:
        # a split wallet found after the freeze query ran (Binance: Tether froze 0x9749… at 21:01:35) must still count
        target = _addr(lg["topics"][1]) if tok.freeze_in_topic else _addr(lg["data"][:66])
        case.setdefault("freezes", []).append({"id": rid, "t": ts, "kind": "freeze", "chain": ch, "tx": lg["transactionHash"],
                                               "token": tok.symbol, "issuer": tok.issuer, "address": target})
        seen.add(rid)
        return
    else:
        value = int(lg["data"], 16) / 10 ** tok.decimals       # stablecoins only ⇒ value ≈ USD
        if value < case.get("min_usd", Limits.ONCHAIN_MIN_USD):
            return
        to = _addr(lg["topics"][2])
        is_victim = addr in case["victims"].get(ch, {})
        if to not in case["receivers"] and to not in case["victims"].get(ch, {}) and len(case["receivers"]) < Limits.ONCHAIN_MAX_DOWNSTREAM \
                and not to[2:].startswith("0" * 30):
            hop = 1 if is_victim or addr in case["evidence"] or addr in (case.get("attackers") or {}) \
                else case["receivers"].get(addr, {}).get("hop", 0) + 1
            if hop <= 2:
                case["receivers"][to] = {"chain": ch, "hop": hop, "first_at": ts, "label": f"接收方 {to[:6]}…{to[-4:]}"}
        row = {"id": rid, "t": ts, "kind": "outflow", "chain": ch, "tx": lg["transactionHash"], "token": tok.symbol,
               "amount": round(value, 2), "from": addr, "to": to, "from_label": _label(case, ch, addr), "to_label": _label(case, ch, to)}
    case["rows"].append(row)
    seen.add(rid)


def doc(case: dict[str, Any] | None) -> dict[str, Any] | None:
    """The published `onchain` section of an event document (sorted rows, totals, coverage, limits)."""
    if not case:
        return None
    wallets = {a for w in case["victims"].values() for a in w} | set(case["receivers"]) | set(case["evidence"]) \
        | set(case.get("attackers") or {})
    freezes = [{**f, "label": _label(case, f["chain"], f["address"])} for f in case.get("freezes", []) if f["address"] in wallets]
    rows = sorted([*case["rows"], *freezes], key=lambda r: (r["t"], r["id"]))
    short = resolve([tuple(x) for x in case["short"]], [*case["receivers"], *(a for w in case["victims"].values() for a in w)])
    for r in rows:
        for side in ("from", "to", "address"):
            a = r.get(side)
            if a in short:
                r[f"{side}_evidence"] = short[a]        # the shortened form a report used for this address
    out_by: dict[str, float] = {}
    frozen_by: dict[str, int] = {}
    for r in rows:
        if r["kind"] == "outflow" and r["from"] in {a for w in case["victims"].values() for a in w}:
            out_by[r["token"]] = round(out_by.get(r["token"], 0) + r["amount"], 2)
        if r["kind"] == "freeze":
            frozen_by[r["issuer"]] = frozen_by.get(r["issuer"], 0) + 1
    checked = sorted({k.split("|")[1] for k in case["cursors"]})
    return {"window": case["window"], "rows": rows,
            "totals": {"victim_outflow_by_token": out_by, "freezes_by_issuer": frozen_by,
                       "receivers": len(case["receivers"])},
            "delegation": [{"address": a, "label": _label(case, d["chain"], a), **d} for a, d in sorted(case["delegation"].items())],
            "coverage": {"chains_checked": checked, "tokens": {ch: [t.symbol for t in toks] for ch, toks in TOKENS.items() if ch in checked}},
            "not_queried": list(NOT_QUERIED), "errors": case["errors"][-5:],
            "complete": bool(case["cursors"]) and all(c.get("done") for c in case["cursors"].values())}


INDEX = "__onchain__"


def case_key(event_id: str) -> str:
    """One ledger entry per case (a DynamoDB item is ≤ 400 KB; one shared ledger would outgrow it)."""
    return f"{INDEX}#{event_id}"


def cycle(store: Any, now: datetime, call: Callable[[str, str, list[Any]], Any] = chain.rpc_call) -> list[str]:
    """Process-station step: advance every eligible case inside ONCHAIN_CALLS_PER_CYCLE RPC calls (newest P0 first).
    Returns the events whose rows / delegation changed (their detail documents are republished). A case that raises is
    recorded on its own ledger entry and the others go on — the station never silently skips one."""
    since = timeutil.iso(now - timedelta(days=Limits.ONCHAIN_ACTIVE_DAYS))
    from radar import attacktx  # local: attacktx imports chain only, no cycle
    att = {e.event_id: attacktx.attackers(store.get_source_state(attacktx.case_key(e.event_id)))
           for e in store.events_updated_since(since) if e.domain == "web3" and e.severity == "P1" or e.severity == "P0"}
    evs = sorted((e for e in store.events_updated_since(since) if eligible(e, now, att.get(e.event_id))),
                 key=lambda e: e.first_seen, reverse=True)
    idx = store.get_source_state(INDEX)
    active, budget, changed = [], Limits.ONCHAIN_CALLS_PER_CYCLE, []
    for ev in evs:
        active.append(ev.event_id)
        if budget <= 0:
            continue
        case = store.get_source_state(case_key(ev.event_id))
        if not case.get("event_id"):
            texts = [f"{i.title}\n{i.text}" for i in store.get_items(ev.item_ids)]
            case = new_case(ev, texts, now, att.get(ev.event_id))
        elif add_attackers(case, att.get(ev.event_id) or {}):
            case.setdefault("errors", [])
        before = (len(case["rows"]), len(case.get("freezes", [])), json.dumps(case["delegation"], sort_keys=True))
        try:
            budget -= step(case, now, call, budget)
        except Exception as e:    # noqa: BLE001 — recorded on the case (degradation leaves a trace), other cases go on
            case["errors"] = (case["errors"] + [{"at": timeutil.iso(now), "query": "step", "error": f"{type(e).__name__}: {e}"[:160]}])[-20:]
        case["rows"] = case["rows"][-Limits.ONCHAIN_MAX_ROWS:]
        store.put_source_state(case_key(ev.event_id), case)
        if (len(case["rows"]), len(case.get("freezes", [])), json.dumps(case["delegation"], sort_keys=True)) != before:
            changed.append(ev.event_id)
    store.put_source_state(INDEX, {**idx, "active": active, "updated_at": timeutil.iso(now)})
    return changed
