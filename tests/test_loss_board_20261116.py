"""The 2026-11-16 Web3 loss board: four of its six rows were not thefts or not their figures (Neo: 「币安应该是第一大的」).

  #1 「Is」 $8.83B   — CryptoSlate on BitMine's unrealised loss: a valuation, not an incident
  #3 「Whale」 $6.30B — a trader closing a long "at a $2.45M loss" (then commentary quoting Binance's $6.3B)
  #4 t.co… $6.00B   — Protos 「Abraxas may have lost $17M in Lighter API leak」 read as $6B from its body
  #5 「Upbit」 $1.50B — Dunamu's Q3 net loss / first operating loss: a company result
The loss word alone made each an incident, and a report's figure was the largest of its headline AND body."""
import pytest

from radar import signals

NOT_INCIDENTS = [
    "Is Ethereum the “worst asset of all time,” amid estimated $8.83 billion BitMine loss ?",
    "Whale 0xc8b5 has finally given up, closing his long on 190,952 $NVDA ($30.67M) at a $2.45M loss.",
    "Upbit Operator Dunamu Swings to $13.8 Million Q3 Net Loss as Revenue Falls 60.7%",
    "Korea's Top Crypto Exchange Posts First Operating Loss Since 2017",
    "某交易所第三季度净亏损1380万美元",
    "巨鲸平仓 ETH 多单，浮亏 230 万美元",
    "Live updates: Bitcoin trades near $65,000 as Nasdaq closes with 2.5% loss",
    "Machi (@machibigbrother) got liquidated again! The $223K he raised was gone in hours",
    "某巨鲸超1.4亿美元多头仓位过去两日遭完全清算，损失1769万美元",
    "Machi is dumping his Bored Apes to fund leveraged long positions, down $1.2M loss on the week",
]
INCIDENTS = [
    "Kava Lend suffers $3.8M loss in arithmetic error exploit",
    "Protocol X suffered a $5M loss after an oracle manipulation",
    "Lighter Halts Crypto Withdrawals After $15.5M Security Breach as LIT Falls",
    "Lighter 疑似发生安全事件，约 1039 万 USDC 被转出",
    "Binance CEX — Hot Wallets Drained via Compromised DevOps Laptop",
    "Trader loses $2M after his wallet was drained by a phishing site",      # a theft word wins over a position word
]


@pytest.mark.parametrize("text", NOT_INCIDENTS)
def test_a_result_a_position_or_a_valuation_is_not_a_web3_incident(text):
    assert not signals.web3_incident(text)


@pytest.mark.parametrize("text", INCIDENTS)
def test_a_theft_a_breach_or_a_loss_by_an_exploit_is_one(text):
    assert signals.web3_incident(text)


def test_the_headline_decides_the_loss_a_body_figure_does_not_outbid_it():
    body = ("Abraxas Capital Management has reportedly lost $17 million after an API key leak. It comes weeks after "
            "Binance lost $6.3 billion in October.")       # a stated loss of ANOTHER story, larger than the headline's
    assert signals.loss_amount("Tether-backed Abraxas may have lost $17M in Lighter API leak", body) == 17_000_000
    assert signals.loss_amount("Lighter Pins Drain on Trader’s Leaked API Key as Sleuths Say $15M Lost",
                               "Lighter, valued at $388 million, said a leaked key drained $15 million.") == 15_000_000


def test_a_body_that_states_the_headline_figure_more_precisely_refines_it():
    assert signals.loss_amount("Binance Drained of $5.5 Billion in Suspected Hack",
                               "Binance was drained of $5.57 billion in a suspected hack.") == 5_570_000_000


def test_without_a_headline_loss_the_body_still_decides():
    assert signals.loss_amount("Lighter update", "The exchange said attackers drained $15.5 million.") == 15_500_000


def _rc():
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location("recluster", Path(__file__).parents[1] / "scripts" / "recluster_web3.py")
    rc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rc)
    return rc


def _stored(source_id, title, eventful=True):
    from radar.model import Item
    return Item(item_id=f"it_{source_id}", source_id=source_id, tier="T2", org=source_id, domain="web3", url="https://x",
                canonical_url="https://x", title=title, text="", published_at="2026-11-16T12:00:00Z",
                fetched_at="2026-11-16T12:05:00Z", content_hash="c", keys=[], links=[], entity=None, eventful=eventful,
                signals={}, extra={})


def test_reclassify_turns_a_stored_non_incident_into_context_and_keeps_a_theft():
    """scripts/recluster_web3.py --reclassify: reports stored eventful under the old "loss" rule are context today."""
    rc = _rc()
    assert rc.reclassify(_stored("wublock", "Upbit Operator Dunamu Swings to $13.8 Million Q3 Net Loss as Revenue Falls 60.7%")).eventful is False
    assert rc.reclassify(_stored("cryptonews", "Lighter Halts Crypto Withdrawals After $15.5M Security Breach as LIT Falls")).eventful is True
    # a tweet (tier from an unstored handle): judged by the incident rule alone
    assert rc.reclassify(_stored("x_security", "Whale 0xc8b5 closing his long on $NVDA at a $2.45M loss")).eventful is False
    assert rc.reclassify(_stored("x_security", "Protocol X drained of $5M via a flash loan exploit")).eventful is True
    assert rc.reclassify(_stored("x_security", "Protocol X drained of $5M", eventful=False)).eventful is False   # never promoted
