"""Chainflip 2026-11-22: ~20 reports said the protocol confirmed $12M from 05:28 UTC, the hack databases still read $4.86M,
and the event kept $4.86M for 21 hours — the ≥ $10M team notice waited (sent 11-23 02:51). Two fixes in
pipeline._amounts: the latest hack-database update wins (DeFiLlama's $11.96M sat 2.7 h behind SlowMist's older T1
figure), and a larger loss that ≥ 3 independent reporters (one T1 / T2) agree on after it raises the headline."""
from __future__ import annotations

from radar import pipeline
from radar.model import Item


def _it(n, src, tier, title, value, at, db=False, entity=None, org=None):
    extra = {"amount_history": [{"value": value, "observed_at": at}]}
    if db:
        extra["amount_usd"] = value
    return Item(item_id=f"it_{n}", source_id=src, tier=tier, org=org or src, domain="web3", url=f"https://{src}.x/{n}",
                canonical_url=f"https://{src}.x/{n}", title=title, text="", published_at=at, fetched_at=at,
                content_hash=str(n), keys=[], links=[], entity=entity, eventful=True, signals={}, extra=extra)


DB = [_it(1, "slowmist_hacked", "T1", "Chainflip — Private Key Leak", 4_860_000, "2026-11-21T00:00:00Z", True, "Chainflip"),
      _it(2, "defillama_hacks", "T2", "Chainflip AMM — Validator Key", 4_860_000, "2026-11-21T00:00:00Z", True, "Chainflip AMM")]
CONFIRMED = [_it(10, "cointelegraph", "T2", "Chainflip confirms $12M hack, offers attacker 10% bounty", 12e6, "2026-11-22T05:28:43Z"),
             _it(11, "techflowpost", "T2", "Chainflip 攻击事件损失约 1200 万美元", 12e6, "2026-11-22T05:39:52Z"),
             _it(12, "odaily", "T3", "Chainflip确认约1200万美元资产被盗，向攻击者提供10%赏金", 12e6, "2026-11-22T05:41:13Z")]


def _loss(items):
    return pipeline._amounts(items, pipeline.independent_groups(items))[1]


def test_three_independent_reports_of_a_larger_loss_raise_the_databases_figure():
    assert _loss(DB) == 4_860_000
    assert _loss(DB + CONFIRMED[:2]) == 4_860_000          # two reporters are not a consensus
    assert _loss(DB + CONFIRMED) == 12e6


def test_the_consensus_needs_a_t1_or_t2_reporter():
    t3 = [_it(20 + k, s, "T3", f"Chainflip loses $12M ({s})", 12e6, "2026-11-22T06:00:00Z")
          for k, s in enumerate(("gn_crypto_hack", "w3igg", "panews"))]
    assert _loss(DB + t3) == 4_860_000


def test_a_report_about_another_incident_does_not_count():
    """Replay 2026-11-23: Gonka AI's event held K3 Capital's $3.43M sBOLD reports (a clustering error)."""
    db = [_it(1, "defillama_hacks", "T2", "Gonka AI — Bridge Logic Flaw", 1_050_000, "2026-11-18T00:00:00Z", True, "Gonka AI")]
    k3 = [_it(30, "techflowpost", "T2", "Blockaid：K3 Capital sBOLD 遭攻击，约 343 万美元被盗", 3.43e6, "2026-11-18T12:46:00Z"),
          _it(31, "odaily", "T3", "约343万美元被提取，K3 Capital sBOLD金库遭攻击", 3.43e6, "2026-11-18T12:50:00Z"),
          _it(32, "panews", "T3", "以太坊上K3 Capital sBOLD金库遭攻击，约343万美元被窃取", 3.43e6, "2026-11-18T12:53:00Z")]
    assert _loss(db + k3) == 1_050_000


def test_only_upward_and_only_later_than_the_database():
    smaller = [_it(40, "cointelegraph", "T2", "Chainflip lost $1M from its Bitcoin vault", 1e6, "2026-11-22T06:00:00Z"),
               _it(41, "theblock", "T2", "Hacker drained $1 million from Chainflip BTC vault", 1e6, "2026-11-22T06:10:00Z"),
               _it(42, "decrypt", "T2", "Chainflip says attacker stole about $1M in bitcoin", 1e6, "2026-11-22T06:20:00Z")]
    assert _loss(DB + smaller) == 4_860_000                 # a side story (a freeze, a sub-amount) never lowers it
    later_db = [_it(3, "slowmist_hacked", "T1", "Chainflip — Private Key Leak", 4_860_000, "2026-11-23T00:00:00Z", True,
                    "Chainflip")]
    assert _loss(later_db + CONFIRMED) == 4_860_000         # what the database reconciled after the reports stands


def test_the_latest_database_update_wins_whichever_database():
    update = [_it(4, "defillama_hacks", "T2", "Chainflip AMM — Validator Key", 11_960_000, "2026-11-23T00:04:44Z", True,
                  "Chainflip AMM")]
    assert _loss(DB + update) == 11_960_000                 # was SlowMist's older T1 $4.86M for 2.7 hours


def test_without_a_database_the_top_tier_figure_yields_to_the_consensus():
    peck = [_it(50, "x_security", "T1", "#PeckShieldAlert #Chainflip has been exploited for ~$4M", 4e6,
                "2026-11-21T12:12:41Z", entity="Chainflip")]
    assert _loss(peck) == 4e6
    assert _loss(peck + CONFIRMED) == 12e6


def test_one_organisation_on_two_channels_is_one_reporter():
    same_org = [CONFIRMED[0],
                _it(60, "techflowpost", "T2", "Chainflip 攻击事件损失约 1200 万美元", 12e6, "2026-11-22T05:39:52Z", org="techflow"),
                _it(61, "tg_techflow", "T3", "Chainflip 攻击事件损失约 1200 万美元（快讯）", 12e6, "2026-11-22T05:40:10Z",
                    org="techflow")]
    assert _loss(DB + same_org) == 4_860_000
