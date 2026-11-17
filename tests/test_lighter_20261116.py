"""The 2026-11-16 Lighter theft (a market maker's leaked API key, ~10.4M USDC drained, later reported as $15M–$17M)
became two web3 events. The first two reports stated the loss in USDC (no amount ⇒ context-only, their name lent
nothing); Protos and Unchained wrote no crypto word (⇒ domain "incident", their figures and names in another domain).

Third-party text is minimised: titles as published, at most one paraphrased body sentence per report."""
from datetime import UTC, datetime

import pytest
from test_pipeline_replay import _raw

from radar import pipeline, registry, signals
from radar.registry import BY_ID, SOURCES
from radar.store import MemoryStore

FETCHED = datetime(2026, 11, 16, 17, 0, tzinfo=UTC)

LIGHTER = [
    ("tg_foresight", "【Lighter 疑似遭攻击，相关地址提取约 1039 万 USDC 后兑换为 ETH】", "", "2026-11-16T03:05:00Z"),
    ("tg_wublock", "Lighter 疑似发生安全事件，约 1039 万 USDC 被转出，LIT 短时跌超 17%", "", "2026-11-16T10:51:00Z"),
    ("unchained", "Lighter Pins Drain on Trader’s Leaked API Key as Sleuths Say $15M Lost",
     "Perpetual futures exchange Lighter said an attacker used a trader's leaked API key to drain funds.",
     "2026-11-16T13:25:00Z"),
    ("cryptonews", "Lighter Halts Crypto Withdrawals After $15.5M Security Breach as LIT Falls",
     "Decentralized exchange Lighter paused withdrawals while it investigates the breach.", "2026-11-16T13:50:00Z"),
    ("cryptopolitan", "Perp DEX rivals Lighter and Aster point fingers outward after $15M drain and flash crash", "",
     "2026-11-16T14:04:00Z"),
    ("protos", "Tether-backed Abraxas may have lost $17M in Lighter API leak", "", "2026-11-16T16:39:00Z"),
]


def _ingest(rows):
    store = MemoryStore()
    for sid, title, body, when in rows:
        pipeline.ingest([_raw(sid, title, body, when=when)], store, FETCHED)
    return store


def _events_of(store):
    """source_id list of every event, in event order."""
    return [[store.items[i]["source_id"] for i in e["item_ids"]] for e in store.events.values()]


# ------------------------------------------------------------------ amounts in stablecoin units

@pytest.mark.parametrize("text,usd", [
    ("约 1039 万 USDC 被转出", 1.039e7),
    ("attacker drained 10.4M USDC", 1.04e7),
    ("swapped $10M in USDT", 1e7),
    ("1,000,000 USDT moved", 1e6),
    ("约 5000万枚USDT", 5e7),
    ("2.5 亿 FDUSD", 2.5e8),
    ("3 million PYUSD", 3e6),
])
def test_a_dollar_stablecoin_amount_reads_as_usd(text, usd):
    assert signals.parse_amount(text) == pytest.approx(usd)


@pytest.mark.parametrize("text", ["USDC 100 pairs", "v2.500 USDC pool", "500 DAIly users", "1039 万 ETH"])
def test_a_stablecoin_word_without_its_own_figure_is_no_amount(text):
    assert signals.parse_amount(text) is None


def test_the_usdc_quick_news_is_a_report_of_the_theft():
    raw = _raw("tg_wublock", LIGHTER[1][1], when=LIGHTER[1][3])
    item = pipeline.normalize(raw, BY_ID["tg_wublock"], FETCHED)
    assert item.domain == "web3" and item.eventful
    assert item.signals["amount_usd"] == pytest.approx(1.039e7)


# ------------------------------------------------------------------ domain from the source

def test_every_crypto_media_org_is_a_registry_org():
    assert registry.CRYPTO_MEDIA_ORGS <= {s.org for s in SOURCES}


@pytest.mark.parametrize("sid,title", [(r[0], r[1]) for r in LIGHTER if r[0] in ("protos", "unchained")])
def test_a_crypto_outlet_report_without_crypto_words_is_web3(sid, title):
    item = pipeline.normalize(_raw(sid, title, when="2026-11-16T16:39:00Z"), BY_ID[sid], FETCHED)
    assert item.domain == "web3"


def test_the_same_words_from_a_general_outlet_stay_an_incident():
    item = pipeline.normalize(_raw("bleepingcomputer", LIGHTER[5][1]), BY_ID["bleepingcomputer"], FETCHED)
    assert item.domain == "incident"


def test_a_crypto_outlet_cve_story_stays_a_vulnerability():
    item = pipeline.normalize(_raw("decrypt", "Apple patches CVE-2026-12345 zero-day in Safari"), BY_ID["decrypt"],
                              FETCHED)
    assert item.domain == "vuln"


# ------------------------------------------------------------------ the replay

def test_the_six_lighter_reports_are_one_web3_event():
    store = _ingest(LIGHTER)
    assert _events_of(store) == [[r[0] for r in LIGHTER]]
    [ev] = store.events.values()
    assert ev["domain"] == "web3"
    assert 10e6 <= ev["amount_usd_latest"] <= 18e6
    assert {"tok:lighter", "tt:lighter"} & set(ev["keys"])


def test_kava_lend_and_lighter_on_the_same_day_both_naming_usdc_stay_apart():
    store = _ingest([
        ("tg_foresight", "【Kava Lend 遭攻击，攻击者转出约 213 万 USDC】", "", "2026-11-16T02:00:00Z"),
        LIGHTER[1],
        ("cryptonews", "Kava Lend Exploited for $2.1M in USDC as Attacker Drains Lending Pools",
         "Lending protocol Kava Lend said an attacker drained about 2.13M USDC.", "2026-11-16T12:00:00Z"),
        LIGHTER[4],
    ])
    groups = sorted(sorted(g) for g in _events_of(store))
    assert groups == [["cryptonews", "tg_foresight"], ["cryptopolitan", "tg_wublock"]]


def test_a_company_net_loss_joins_no_theft():
    store = _ingest(LIGHTER[:4] + [("coindesk", "Upbit Operator Dunamu Swings to $13.8 Million Q3 Net Loss", "",
                                    "2026-11-16T14:30:00Z")])
    dunamu = next(i for i in store.items.values() if i["source_id"] == "coindesk")
    assert not dunamu["eventful"]
    assert all("coindesk" not in g for g in _events_of(store))


def test_two_victims_with_the_same_round_figure_share_no_name():
    """「$20M」 is a figure, not a $ticker: before, tok:20m / tt:20m were name keys of every "$20M" headline (a round
    figure carries no amt: key, so the false name was the only link)."""
    store = _ingest([
        ("unchained", "Lighter drained for $20M after a leaked API key", "", "2026-11-16T13:25:00Z"),
        ("protos", "SomeOtherDEX drained for $20M after oracle exploit", "", "2026-11-16T15:00:00Z"),
    ])
    assert sorted(_events_of(store)) == [["protos"], ["unchained"]]
    assert not any(k.endswith(":20m") for e in store.events.values() for k in e["keys"])


@pytest.mark.xfail(strict=True, reason=(
    "known gap: an exact specific figure (amt:15000000) still joins two unnamed-entity web3 reports. A headline-name "
    "veto on amt: hits was tried and cost the labelled corpus precision 0.9674 → 0.9586 (the EU-entity / Crédit Mutuel "
    "story split: its headlines' tt: words are 'cex', 'according', 'bit'). strict: turns red the day a rule fixes it."))
def test_two_victims_with_the_same_specific_figure_stay_apart():
    store = _ingest([
        LIGHTER[2],
        ("protos", "SomeOtherDEX drained for $15M after oracle exploit", "", "2026-11-16T15:00:00Z"),
    ])
    assert sorted(_events_of(store)) == [["protos"], ["unchained"]]
