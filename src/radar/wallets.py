"""Exchange wallets on the EVM chains the on-chain station reads (radar.onchain.TOKENS) — a registry, not a code path.

Every entry is an explorer's public name tag that was read, with the page it was read on and the day (docs/research/15):
Etherscan / BscScan / Arbiscan / BaseScan label pages (anonymous view: first rows only) and the USDT / USDC holder lists,
where exchanges dominate. Included: an exchange's own numbered / hot / cold wallets. Left out on purpose: per-customer
deposit addresses (millions exist — a handful would pose as coverage), token contracts, deployers, DEX routers,
self-custody products (Bitget Wallet), and every "… Exploiter N" tag — Etherscan names the 2026-10-29 Binance thief's
wallets "Binance Hot Wallet Exploiter N", which must stay followed, never be read as Binance.

Used by radar.onchain: `seed` wallets are the victim hot wallets queried when an event names the exchange; any wallet
here that receives funds in a case is a terminal — labelled 「交易所 …」, flagged 进入交易所, never followed as a receiver.

  uv run python -m radar.wallets --check      # every entry well-formed, sourced, unique (also a pytest)
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

CHAINS = {"ethereum": "etherscan.io", "bsc": "bscscan.com", "arbitrum": "arbiscan.io", "base": "basescan.org",
          "avalanche": "snowtrace.io"}
KINDS = {"exchange": "", "hot": "热钱包", "cold": "冷钱包"}       # "exchange": numbered wallet, the tag does not say which


@dataclass(frozen=True)
class W:
    chain: str
    address: str
    exchange: str
    tag: str            # the explorer's name tag, verbatim
    kind: str
    source: str         # the page the tag was read on
    verified: str       # ISO date the page showed it (firecrawl cache date when served from cache)
    seed: bool = False  # a victim hot wallet: its outflows are queried when an event names the exchange


ENTRIES: tuple[W, ...] = (
    W('ethereum', '0x3f5ce5fbfe3e9af3971dd833d26ba9b5c936f0be', 'Binance', 'Binance', 'exchange',
      'https://etherscan.io/accounts/label/binance', '2026-11-01'),
    W('ethereum', '0x22132139bf7f3921b1cadeab931f4fbf7bf2bc9e', 'Binance', 'Binance 124', 'exchange',
      'https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7#balances', '2026-11-01'),
    W('ethereum', '0x28c6c06298d514db089934071355e5743bf21d60', 'Binance', 'Binance 14', 'exchange',
      'https://etherscan.io/address/0x28c6c06298d514db089934071355e5743bf21d60', '2026-10-30', seed=True),
    W('ethereum', '0xdfd5293d8e347dfe59e90efd55b2956a1343963d', 'Binance', 'Binance 16', 'exchange',
      'https://etherscan.io/address/0xdfd5293d8e347dfe59e90efd55b2956a1343963d', '2026-10-30', seed=True),
    W('ethereum', '0xd551234ae421e3bcba99a0da6d736074f22192ff', 'Binance', 'Binance 2', 'exchange',
      'https://etherscan.io/accounts/label/binance', '2026-11-01'),
    W('ethereum', '0x564286362092d8e7936f0549571a803b203aaced', 'Binance', 'Binance 3', 'exchange',
      'https://etherscan.io/accounts/label/binance', '2026-11-01'),
    W('ethereum', '0x0681d8db095565fe8a346fa0277bffde9c0edbbf', 'Binance', 'Binance 4', 'exchange',
      'https://etherscan.io/accounts/label/binance', '2026-11-01'),
    W('ethereum', '0xfe9e8709d3215310075d67e3ed32a380ccf451c8', 'Binance', 'Binance 5', 'exchange',
      'https://etherscan.io/accounts/label/binance', '2026-11-01'),
    W('ethereum', '0x4e9ce36e442e55ecd9025b9a6e0d88485d628a67', 'Binance', 'Binance 6', 'exchange',
      'https://etherscan.io/accounts/label/binance', '2026-11-01'),
    W('ethereum', '0xa7c0d36c4698981fab42a7d8c783674c6fe2592d', 'Binance', 'Binance 74', 'exchange',
      'https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7#balances', '2026-11-01'),
    W('ethereum', '0xad354cfbaa4a8572dd6df021514a3931a8329ef5', 'Binance', 'Binance 90', 'exchange',
      'https://etherscan.io/token/0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48#balances', '2026-11-01'),
    W('ethereum', '0xe1940f578743367f38d3f25c2d2d32d6636929b6', 'Binance', 'Binance 91', 'exchange',
      'https://etherscan.io/token/0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48#balances', '2026-11-01'),
    W('ethereum', '0x98adef6f2ac8572ec48965509d69a8dd5e8bba9d', 'Binance', 'Binance 93', 'exchange',
      'https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7#balances', '2026-11-01'),
    W('ethereum', '0x835678a611b28684005a5e2233695fb6cbbb0007', 'Binance', 'Binance: Cold Wallet 10', 'cold',
      'https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7#balances', '2026-11-01'),
    W('ethereum', '0xf977814e90da44bfa03b6295a0616a897441acec', 'Binance', 'Binance: Cold Wallet 20', 'cold',
      'https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7#balances', '2026-11-01'),
    W('ethereum', '0x5a52e96bacdabb82fd05763e25335261b270efcb', 'Binance', 'Binance: Cold Wallet 28', 'cold',
      'https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7#balances', '2026-11-01'),
    W('ethereum', '0xee7ae85f2fe2239e27d9c1e23fffe168d63b4055', 'Binance', 'Binance: Hot Wallet 34', 'hot',
      'https://etherscan.io/address/0xee7ae85f2fe2239e27d9c1e23fffe168d63b4055', '2026-10-31', seed=True),
    W('bsc', '0x092fe28430bade62c7c044b9c77d0aaa06241319', 'Bitget', 'Bitget 28', 'exchange',
      'https://bscscan.com/accounts/label/bitget', '2026-11-01'),
    W('bsc', '0x0edd5b0de0fe748be331186bf0aa878f47f601db', 'Bitget', 'Bitget 32', 'exchange',
      'https://bscscan.com/accounts/label/bitget', '2026-11-01'),
    W('bsc', '0x1982fadf1dca6683fbf1e80cf51419d87d39de01', 'Bitget', 'Bitget 38', 'exchange',
      'https://bscscan.com/accounts/label/bitget', '2026-11-01'),
    W('bsc', '0x0639556f03714a74a5feeaf5736a4a64ff70d206', 'Bitget', 'Bitget 4', 'exchange',
      'https://bscscan.com/accounts/label/bitget', '2026-11-01'),
    W('bsc', '0x149ded7438caf5e5bfdc507a6c25436214d445e1', 'Bitget', 'Bitget: Hot Wallet 4', 'hot',
      'https://bscscan.com/accounts/label/bitget', '2026-11-01'),
    W('ethereum', '0xdfe4b89cf009bffa33d9bca1f19694fc2d4d943d', 'Bitget', 'Bitget 12', 'exchange',
      'https://etherscan.io/accounts/label/bitget', '2026-11-01'),
    W('ethereum', '0x5051e9860c1889eb1bfa394365364b3dd61787f1', 'Bitget', 'Bitget 14', 'exchange',
      'https://etherscan.io/accounts/label/bitget', '2026-11-01'),
    W('ethereum', '0xbc942e2250ec7ab83bfc4516bca4e281dbfbb393', 'Bitget', 'Bitget 17', 'exchange',
      'https://etherscan.io/accounts/label/bitget', '2026-11-01'),
    W('ethereum', '0x51971c86b04516062c1e708cdc048cb04fbe959f', 'Bitget', 'Bitget 2', 'exchange',
      'https://etherscan.io/accounts/label/bitget', '2026-11-01'),
    W('ethereum', '0x97b9d2102a9a65a26e1ee82d59e42d1b73b68689', 'Bitget', 'Bitget 3', 'exchange',
      'https://etherscan.io/accounts/label/bitget', '2026-11-01'),
    W('ethereum', '0x0639556f03714a74a5feeaf5736a4a64ff70d206', 'Bitget', 'Bitget 4', 'exchange',
      'https://etherscan.io/accounts/label/bitget', '2026-11-01'),
    W('ethereum', '0x5bdf85216ec1e38d6458c870992a69e38e03f7ef', 'Bitget', 'Bitget 5', 'exchange',
      'https://etherscan.io/accounts/label/bitget', '2026-11-01'),
    W('base', '0x0a7e3e04fb45af4233a27bcf23f2c94f5babcf39', 'Bybit', 'Bybit: Wallet 10', 'exchange',
      'https://basescan.org/accounts/label/bybit', '2026-11-01'),
    W('base', '0x01eadbed08832ba3a12b571b299075dc6b503dca', 'Bybit', 'Bybit: Wallet 129', 'exchange',
      'https://basescan.org/accounts/label/bybit', '2026-11-01'),
    W('base', '0x07bdf2aa3fe611bde1d7d03d00bd57fda9f3b633', 'Bybit', 'Bybit: Wallet 13', 'exchange',
      'https://basescan.org/accounts/label/bybit', '2026-11-01'),
    W('base', '0x01e2fb8f565d5e3cb9e0e8f0b607a96169b94393', 'Bybit', 'Bybit: Wallet 19', 'exchange',
      'https://basescan.org/accounts/label/bybit', '2026-11-01'),
    W('base', '0x036c43bebe5fa5dff3c299584b4a6c1923c7d932', 'Bybit', 'Bybit: Wallet 20', 'exchange',
      'https://basescan.org/accounts/label/bybit', '2026-11-01'),
    W('base', '0x04fcd675f63b1ac987c650567977523e85a78135', 'Bybit', 'Bybit: Wallet 21', 'exchange',
      'https://basescan.org/accounts/label/bybit', '2026-11-01'),
    W('base', '0x076d55c8998da29531ef7fcac2a01fa21582eed2', 'Bybit', 'Bybit: Wallet 22', 'exchange',
      'https://basescan.org/accounts/label/bybit', '2026-11-01'),
    W('ethereum', '0xf833685f98eba1b99947d418c9512d27c8193b1a', 'Bybit', 'Bybit: Wallet 112', 'exchange',
      'https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7#balances', '2026-11-01'),
    W('ethereum', '0x13f52026493dccf09065952d44101c3e42b41dda', 'Bybit', 'Bybit: Wallet 24', 'exchange',
      'https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7#balances', '2026-11-01'),
    W('ethereum', '0x25c76fa90e90f5a5a6914da07baed9a9647c3dfd', 'Bybit', 'Bybit: Wallet 28', 'exchange',
      'https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7#balances', '2026-11-01'),
    W('ethereum', '0x448c642074d7be4c5fc25929bb5536f772cd9d5c', 'Bybit', 'Bybit: Wallet 43', 'exchange',
      'https://etherscan.io/token/0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48#balances', '2026-11-01'),
    W('ethereum', '0xa9acc15d8b74a01e5605eb0f1e815ba98e3a16af', 'Bybit', 'Bybit: Wallet 86', 'exchange',
      'https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7#balances', '2026-11-01'),
    W('arbitrum', '0xe9f7ecae3a53d2a67105292894676b00d1fab785', 'Kraken', 'Kraken: Hot Wallet 1', 'hot',
      'https://arbiscan.io/accounts/label/kraken', '2026-11-01'),
    W('ethereum', '0x12c5e4eeeaa20e25847b5453d23246983c512db7', 'MEXC', 'MEXC 21', 'exchange',
      'https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7#balances', '2026-11-01'),
    W('ethereum', '0xc411ab12837f63935b71b6c6643d0f7000e55e4b', 'MEXC', 'MEXC 22', 'exchange',
      'https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7#balances', '2026-11-01'),
    W('ethereum', '0x1f7370792a057227024e7a8cc15b40e3ed171ffc', 'MEXC', 'MEXC 23', 'exchange',
      'https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7#balances', '2026-11-01'),
    W('ethereum', '0x76bf215ade956642b056b9043e014988941bbddd', 'MEXC', 'MEXC 25', 'exchange',
      'https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7#balances', '2026-11-01'),
    W('ethereum', '0xf016e1d45ef23bdd414e7a2e4d46e1b34577b508', 'MEXC', 'MEXC 27', 'exchange',
      'https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7#balances', '2026-11-01'),
    W('ethereum', '0xc5451b523d5fffe1351337a221688a62806ad91a', 'OKX', 'OKX 10', 'exchange',
      'https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7#balances', '2026-11-01'),
    W('ethereum', '0x42436286a9c8d63aafc2eebbca193064d68068f2', 'OKX', 'OKX 11', 'exchange',
      'https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7#balances', '2026-11-01'),
    W('ethereum', '0x69a722f0b5da3af02b4a205d6f0c285f4ed8f396', 'OKX', 'OKX 12', 'exchange',
      'https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7#balances', '2026-11-01'),
    W('ethereum', '0xb0a27099582833c0cb8c7a0565759ff145113d64', 'OKX', 'OKX 153', 'exchange',
      'https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7#balances', '2026-11-01'),
    W('ethereum', '0x65a0947ba5175359bb457d3b34491edf4cbf7997', 'OKX', 'OKX 16', 'exchange',
      'https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7#balances', '2026-11-01'),
    W('ethereum', '0x5c52cc7c96bde8594e5b77d5b76d042cb5fae5f2', 'OKX', 'OKX 18', 'exchange',
      'https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7#balances', '2026-11-01'),
    W('ethereum', '0xe9172daf64b05b26eb18f07ac8d6d723acb48f99', 'OKX', 'OKX 19', 'exchange',
      'https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7#balances', '2026-11-01'),
    W('ethereum', '0x236f9f97e0e62388479bf9e5ba4889e46b0273c3', 'OKX', 'OKX 2', 'exchange',
      'https://etherscan.io/accounts/label/okx', '2026-11-01'),
    W('ethereum', '0x445f16314284b43dfa1fd3cd77b9dea4a1bebd97', 'OKX', 'OKX 225', 'exchange',
      'https://etherscan.io/token/0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48#balances', '2026-11-01'),
    W('ethereum', '0xa7efae728d2936e78bda97dc267687568dd593f3', 'OKX', 'OKX 3', 'exchange',
      'https://etherscan.io/accounts/label/okx', '2026-11-01'),
    W('ethereum', '0x2c8fbb630289363ac80705a1a61273f76fd5a161', 'OKX', 'OKX 4', 'exchange',
      'https://etherscan.io/accounts/label/okx', '2026-11-01'),
    W('ethereum', '0x59fae149a8f8ec74d5bc038f8b76d25b136b9573', 'OKX', 'OKX 5', 'exchange',
      'https://etherscan.io/accounts/label/okx', '2026-11-01'),
    W('ethereum', '0x98ec059dc3adfbdd63429454aeb0c990fba4a128', 'OKX', 'OKX 6', 'exchange',
      'https://etherscan.io/accounts/label/okx', '2026-11-01'),
    W('ethereum', '0x5041ed759dd4afc3a72b8192c143f72f4724081a', 'OKX', 'OKX 7', 'exchange',
      'https://etherscan.io/accounts/label/okx', '2026-11-01'),
    W('ethereum', '0xcba38020cd7b6f51df6afaf507685add148f6ab6', 'OKX', 'OKX 8', 'exchange',
      'https://etherscan.io/accounts/label/okx', '2026-11-01'),
    W('ethereum', '0x461249076b88189f8ac9418de28b365859e46bfd', 'OKX', 'OKX 9', 'exchange',
      'https://etherscan.io/token/0xdac17f958d2ee523a2206206994597c13d831ec7#balances', '2026-11-01'),
)

_BY = {(w.chain, w.address): w for w in ENTRIES}
_ADDR = re.compile(r"0x[0-9a-f]{40}")


def lookup(chain: str, address: str) -> W | None:
    return _BY.get((chain, (address or "").lower()))


def display(w: W) -> str:
    """The tag as a reader-facing name: "Binance: Hot Wallet 34" → "Binance Hot Wallet 34"."""
    return w.tag.replace(": ", " ")


def label(w: W) -> str:
    return f"交易所{KINDS[w.kind]} {display(w)}"


def seeds(exchange: str) -> dict[str, dict[str, str]]:
    """chain → {address: display name} of the exchange's victim hot wallets."""
    out: dict[str, dict[str, str]] = {}
    for w in ENTRIES:
        if w.seed and w.exchange.lower() == exchange.lower():
            out.setdefault(w.chain, {})[w.address] = display(w)
    return out


def check(entries: tuple[W, ...] | list[W] = ENTRIES) -> list[str]:
    """Every problem of the registry, one line each (empty = fine)."""
    errs, seen = [], set()
    # a verified date is the operator's calendar day (GMT+8); the latest calendar date anywhere on Earth is UTC+14 —
    # compared with the host's local day, a UTC CI runner failed every entry verified on 2026-11-01 HKT (pipeline 3895960)
    today = (datetime.now(UTC) + timedelta(hours=14)).date().isoformat()
    for w in entries:
        where = f"{w.chain}:{w.address}"
        if w.chain not in CHAINS:
            errs.append(f"{where}: unknown chain")
        if not _ADDR.fullmatch(w.address):
            errs.append(f"{where}: address must be lower-case 0x + 40 hex")
        if w.kind not in KINDS:
            errs.append(f"{where}: unknown kind {w.kind!r}")
        if not w.exchange or not w.tag.startswith(w.exchange):
            errs.append(f"{where}: tag {w.tag!r} does not name the exchange {w.exchange!r}")
        if re.search(r"exploit|hack|drainer|phish", w.tag, re.IGNORECASE):
            errs.append(f"{where}: {w.tag!r} is an attacker tag, not an exchange wallet")
        if not re.fullmatch(r"https://[a-z.]+/\S+", w.source):
            errs.append(f"{where}: no source page")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", w.verified) or w.verified > today:
            errs.append(f"{where}: verified must be an ISO date, not in the future")
        if (w.chain, w.address) in seen:
            errs.append(f"{where}: duplicate")
        seen.add((w.chain, w.address))
    return errs


if __name__ == "__main__":
    if "--check" in sys.argv:
        problems = check()
        print("\n".join(problems) or f"{len(ENTRIES)} entries ok")
        sys.exit(1 if problems else 0)
    for w in ENTRIES:
        print(f"{w.chain:9} {w.address}  {w.exchange:8} {w.tag:28} {w.verified}  {w.source}")
