"""Exchange wallet registry (radar.wallets) and how the on-chain reconstruction uses it: a flow into an exchange is a
terminal (a cash-out or deposit), labelled and totalled, never followed as a receiver. docs/research/15."""
from datetime import UTC, datetime

import pytest

from radar import onchain, wallets

NOW = datetime(2026, 10, 30, 9, tzinfo=UTC)
RECV = "0x5227f603c1ee34ce3c06efe6477003bdfccb2f8c"      # Etherscan: "Binance Hot Wallet Exploiter 2" — an attacker wallet
B14 = "0x28c6c06298d514db089934071355e5743bf21d60"
OKX10 = "0xc5451b523d5fffe1351337a221688a62806ad91a"
COLD20 = "0xf977814e90da44bfa03b6295a0616a897441acec"


def test_every_entry_is_sourced_well_formed_and_unique():
    assert wallets.check() == []
    assert len(wallets.ENTRIES) >= 50 and {w.exchange for w in wallets.ENTRIES} >= {"Binance", "OKX", "Bybit", "Bitget"}


@pytest.mark.parametrize("bad", [
    wallets.W("ethereum", "0x28c6", "Binance", "Binance 14", "exchange", "https://etherscan.io/address/0x28c6", "2026-11-01"),
    wallets.W("solana", B14, "Binance", "Binance 14", "exchange", "https://etherscan.io/address/x", "2026-11-01"),
    wallets.W("ethereum", B14, "Binance", "Binance 14", "exchange", "", "2026-11-01"),
    wallets.W("ethereum", B14, "Binance", "Binance 14", "exchange", "https://etherscan.io/x", "yesterday"),
    wallets.W("ethereum", RECV, "Binance", "Binance Hot Wallet Exploiter 2", "exchange", "https://etherscan.io/x", "2026-11-01"),
    wallets.W("ethereum", B14, "Binance", "Binance 14", "vault", "https://etherscan.io/x", "2026-11-01"),
])
def test_the_check_refuses_a_bad_entry(bad):
    assert wallets.check([bad])


def test_a_duplicate_is_refused():
    w = wallets.ENTRIES[0]
    assert any("duplicate" in e for e in wallets.check([w, w]))


def test_an_attacker_wallet_tagged_with_the_victims_name_is_not_an_exchange():
    assert wallets.lookup("ethereum", RECV) is None
    assert wallets.lookup("ethereum", OKX10.upper().replace("0X", "0x")).exchange == "OKX"       # case-insensitive
    assert wallets.lookup("bsc", OKX10) is None                                               # per chain


def test_the_victim_seed_wallets_are_unchanged():
    assert onchain.victim_wallets(["Binance CEX"]) == {"ethereum": {
        B14: "Binance 14", "0xdfd5293d8e347dfe59e90efd55b2956a1343963d": "Binance 16",
        "0xee7ae85f2fe2239e27d9c1e23fffe168d63b4055": "Binance Hot Wallet 34"}}


def _case():
    case = onchain.new_case(type("E", (), {"event_id": "ev_x", "first_seen": "2026-10-29T20:00:00Z", "entities": ["Binance CEX"],
                                           "title": "Binance CEX", "chains": ["ethereum"], "amount_usd_latest": 0})(), [], NOW)
    case["receivers"][RECV] = {"chain": "ethereum", "hop": 1, "first_at": "2026-10-29T20:24:23Z", "label": "接收方 0x5227…2f8c"}
    return case


def _log(frm, to, usd, n):
    pad = lambda a: "0x" + "0" * 24 + a[2:]
    return {"transactionHash": f"0x{n:064x}", "logIndex": "0x1", "blockTimestamp": hex(int(datetime(2026, 10, 29, 21, n, tzinfo=UTC).timestamp())),
            "topics": [onchain.TRANSFER, pad(frm), pad(to)], "data": hex(int(usd * 10 ** 6))}


def test_a_flow_into_an_exchange_is_a_labelled_terminal_and_is_totalled():
    case, usdt = _case(), onchain._token("ethereum", "USDT")
    onchain._ingest_log(case, "out", "ethereum", usdt, RECV, _log(RECV, OKX10, 20_000_000, 1), set())
    onchain._ingest_log(case, "out", "ethereum", usdt, B14, _log(B14, COLD20, 30_000_000, 2), set())   # the victim's own cold wallet
    assert OKX10 not in case["receivers"] and COLD20 not in case["receivers"]
    doc = onchain.doc(case)
    into = next(r for r in doc["rows"] if r["to"] == OKX10)
    assert into["to_exchange"] == "OKX" and into["to_label"] == "交易所 OKX 10"
    # a cash-out is a flow out of the attacker's side; the victim moving funds between its own wallets is not one
    assert doc["totals"]["exchange_inflow_by_exchange"] == {"OKX": 20_000_000.0}


def test_an_exchange_wallet_already_followed_as_a_receiver_is_no_longer_queried():
    case = _case()
    case["receivers"][OKX10] = {"chain": "ethereum", "hop": 2, "first_at": "2026-10-29T21:00:00Z", "label": "接收方 0xc545…1a"}
    addrs = {q[3] for q in onchain._queries(case)}
    assert RECV in addrs and OKX10 not in addrs


def test_a_date_verified_today_in_gmt8_passes_on_a_utc_runner(monkeypatch):
    """CI runs in UTC: 2026-10-31 19:29Z is already 11-01 in Hong Kong, where the entries were verified."""
    import dataclasses
    from datetime import UTC, datetime

    from radar import wallets
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 10, 31, 19, 29, tzinfo=UTC)
    monkeypatch.setattr(wallets, "datetime", Clock)
    e = dataclasses.replace(wallets.ENTRIES[0], verified="2026-11-01")
    assert wallets.check((e,)) == []
    assert wallets.check((dataclasses.replace(e, verified="2026-11-03"),))      # a real future date still fails
