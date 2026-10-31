"""Unit criteria for deterministic extraction. Each case is a real string shape seen in a source."""

import pytest

from radar import keys, signals, timeutil


def test_x_snowflake_time_matches_twitterapi_created_at():
    # SlowMist WAX alert: the X data source createdAt "Thu Oct 22 15:23:14 +0000 2026"
    assert timeutil.iso(timeutil.x_status_time("2113290086808990182")) == "2026-10-22T15:23:14Z"


@pytest.mark.parametrize("raw,expected", [
    ("2026-10-18", "2026-10-18T00:00:00Z"),
    ("20261018", "2026-10-18T00:00:00Z"),
    ("Fri Oct 23 03:39:57 +0000 2026", "2026-10-23T03:39:57Z"),
    ("Thu, 22 Oct 2026 10:53:08 +0800", "2026-10-22T02:53:08Z"),
    ("2026-10-22T19:06:41.000Z", "2026-10-22T19:06:41Z"),
    (1790208000, "2026-09-24T00:00:00Z"),
])
def test_time_parse_shapes(raw, expected):
    assert timeutil.iso(timeutil.parse(raw)) == expected


def test_time_parse_garbage_is_none_not_now():
    assert timeutil.parse("not a date") is None


def test_canonical_url():
    assert keys.canonical_url("https://www.Twitter.com/SlowMist_Team/status/123/?utm_source=x#frag") == \
        "https://x.com/SlowMist_Team/status/123"
    assert keys.canonical_url("https://example.com/a?id=1&utm_medium=rss") == "https://example.com/a?id=1"


def test_cve_extraction_normalises_case_and_dedupes():
    assert keys.cves("cve-2026-41940 and CVE-2026-41940, CVE-2025-1234567") == ["CVE-2025-1234567", "CVE-2026-41940"]


def test_tx_refs_infer_chain_from_explorer():
    t = keys.tx_refs("// Attack Tx : https://bscscan.com/tx/0x824b83f94bdc2e69b81f1cb2dfdf9d4aeed066114e3de29e3af59bd2d9355fc2")
    assert t == [{"chain": "bsc", "hash": "0x824b83f94bdc2e69b81f1cb2dfdf9d4aeed066114e3de29e3af59bd2d9355fc2",
                  "explorer_url": "https://bscscan.com/tx/0x824b83f94bdc2e69b81f1cb2dfdf9d4aeed066114e3de29e3af59bd2d9355fc2"}]


def test_bare_hex_is_not_a_tx():
    assert keys.tx_refs("slot 0x824b83f94bdc2e69b81f1cb2dfdf9d4aeed066114e3de29e3af59bd2d9355fc2") == []


@pytest.mark.parametrize("name,expected", [
    ("AlpsCon AI Trade Hub", "alpscon"), ("AlpsCon", "alpscon"), ("WAX Multi-Chain Bridge", "wax"),
    ("@WAX_io", "wax"), ("Ledger (Supply Chain)", "ledger"), ("Bitget", "bitget"), ("The DeFi Protocol", None),
    ("Hifi Finance", "hifi"), ("BeefyFi", "beefy"), ("@Uniswap_Official", "uniswap"),
])
def test_entity_key(name, expected):
    assert keys.entity_key(name) == expected


@pytest.mark.parametrize("text,expected", [
    ("Google is aware that an exploit for CVE-2026-1111 exists in the wild.", "yes"),
    ("Fortinet has observed this to be exploited in the wild.", "yes"),
    ("Microsoft: Exploited:Yes", "yes"),
    ("Apple is aware of a report that this issue may have been exploited", "yes"),
    ("该漏洞已发现在野利用", "yes"),
    ("There is no evidence of exploitation in the wild at this time.", "no"),
    ("We are not aware of any active exploitation.", "no"),
    ("目前未发现在野利用", "no"),
    ("A new version fixes a heap overflow.", "unclear"),
    ("", "unclear"),
])
def test_exploited_with_negation(text, expected):
    assert signals.exploited(text) == expected


@pytest.mark.parametrize("text,expected", [
    ("$ 90,500", 90500), ("Loss: ~$90.5K", 90500), ("$387.5 million stolen", 387_500_000),
    ("约 3.2 亿美元", 320_000_000), ("-", None), ("We have seen a ~$820K exploit", 820_000),
    ("drained $1.2M then $300K more", 1_200_000),
])
def test_parse_amount(text, expected):
    assert signals.parse_amount(text) == pytest.approx(expected) if expected else signals.parse_amount(text) is None


def test_entity_tokens_drop_words_that_name_no_victim():
    # live 2026-10-29: these glued the Binance theft into "682 ETH … Tornado Cash" and Circle's freeze into Tranche Vault
    assert keys.entity_tokens("682 ETH drained, ~281 ETH moved to Tornado Cash (USDC, USDT) #CertiKInsight report") == set()


def test_entity_tokens_read_names_next_to_chinese_text():
    assert keys.entity_tokens("数据：Polymarket疑似攻击者将约265万美元资金换成POL") == {"polymarket"}
    assert keys.entity_tokens("以太坊上zkLink跨链桥正遭攻击") == {"zklink"}


def test_entity_tokens_map_chinese_exchange_names_and_skip_urls():
    assert keys.entity_tokens("Tether在疑似币安黑客攻击中冻结价值 9.71 亿美元的 USDT") == {"tether", "binance"}
    assert keys.entity_tokens("hack https://t.co/B0dnMWdyZn") == set()


@pytest.mark.parametrize(("title", "kind"), [
    # real titles of the 2026-10-29 Binance theft (events.json / raw batches)
    ("币安热钱包疑似遭攻击，约25亿美元资产被转出", "loss"),
    ("Binance probes potential $5.8 billion crypto-theft hack", "loss"),
    ("Chainalysis：币安被盗金额在案发时约为59.12亿美元", "loss"),
    ("Tether在疑似币安黑客攻击中冻结价值 9.71 亿美元的 USDT", "frozen"),
    ("BREAKING: Arbitrum Security Council has executed a transaction to freeze ~$30.5M", "frozen"),
    ("Specter：目前已冻结币安黑客资金总额达到28.29亿美元", "frozen"),
    ("江卓尔：币安潜在损失占用户资产比例为1.6%，预计不会出现大规模提币潮", "context"),
    ("数据：币安疑似被盗关联地址从Aave借出约1.98万枚ETH", "context"),
    ("币安疑似被盗关联地址已售出约470万枚UNI，持有约12283.8枚ETH", "context"),
    ("某鲸鱼在币安被盗事件后重仓做空ETH和BTC，目前浮盈229万美元", "context"),
    ("分析：币安被盗期间出现链上套利窗口，单地址两小时获利约347万美元", "context"),
])
def test_amount_kind_separates_loss_frozen_and_context(title, kind):
    assert signals.amount_kind(title) == kind


@pytest.mark.parametrize(("title", "mentions"), [
    # live 2026-10-30: these titles state the loss AND the freeze; the whole title was judged "frozen" and its largest
    # number (the loss) became the frozen headline — $6.3B frozen
    ("币安披露安全事件初步调查结果：损失约63亿美元，已冻结约30亿美元资产，将全额赔付", [(6.3e9, "loss"), (3e9, "frozen")]),
    ("Binance Drained of $5.5 Billion in Suspected Hack, Tether and Circle Freeze $1.8 Billion",
     [(5.5e9, "loss"), (1.8e9, "frozen")]),
    ("Over $5.8B in assets has been stolen from Binance. More than $2.435B in stablecoins has been frozen.",
     [(5.8e9, "loss"), (2.435e9, "frozen")]),
    ("Tether在疑似币安黑客攻击中冻结价值 9.71 亿美元的 USDT", [(9.71e8, "frozen")]),
    ("Binance has $5,800,000 in reserves", [(5.8e6, "context")]),          # a thousands comma is not a clause break
    # live 2026-10-30 (The Defiant body): two measures inside one clause — each amount reads its own stretch of text
    ("Binance estimates the impact at $6.3 billion and says about $3 billion has been frozen onchain",
     [(6.3e9, "loss"), (3e9, "frozen")]),
    ("Tether froze $500 million and $200 million of the funds", [(5e8, "frozen"), (2e8, "frozen")]),   # no own word: clause
])
def test_each_amount_takes_the_measure_of_its_own_clause(title, mentions):
    got = signals.amount_mentions(title)
    assert [(round(v / 1e6, 1), k) for v, k in got] == [(round(v / 1e6, 1), k) for v, k in mentions]


def test_a_stated_loss_beats_a_context_word_in_the_same_tweet():
    t = "🚨SlowMist TI Alert🚨 💸 $NEM Loss: ~$821,920 🔍 Root Cause: NemTokenV2 credited transfers into the LP pair as sell volume"
    assert signals.amount_kind(t) == "loss"



@pytest.mark.parametrize("title", ["江卓尔：币安潜在损失占用户资产比例为1.6%，预计不会出现大规模提币潮",
                                   "数据：某地址从Aave借出约1.98万枚ETH"])
def test_chinese_crypto_reports_are_web3(title):
    from radar import pipeline
    assert pipeline._classify(None, title, False) == "web3"



def test_a_chinese_report_naming_the_hacker_is_a_web3_incident():
    assert signals.web3_incident("Arbitrum安全委员会冻结币安黑客约3050万美元资产")


@pytest.mark.parametrize(("title", "phase"), [
    # real titles from the 2026-10-29 Binance event (events.json, raw batches)
    ("神鱼披露币安被盗细节：攻击者提前数小时演练，3分钟转走巨额资产", "prep"),
    ("币安热钱包疑似遭攻击，约25亿美元资产被转出", "drain"),
    ("Multiple Binance (@binance) hot wallets across several chains, including Ethereum", "drain"),
    ("数据：币安疑似被盗关联地址已抛售约470万枚UNI换成ETH", "laundering"),
    ("数据：币安疑似被盗关联地址从Aave借出约1.98万枚ETH", "laundering"),
    ("TRX stolen from Binance was moved through Bitget Wallet’s bridge during the la", "laundering"),
    ("Tether在疑似币安黑客攻击中冻结价值 9.71 亿美元的 USDT", "freeze"),
    ("BREAKING: Arbitrum Security Council has executed a transaction to freeze ~$30.", "freeze"),
    ("币安：安全事件或涉DevOps工程师电脑被入侵，未发现私钥泄露，预计总损失约63亿美元", "statement"),
    ("币安：正调查潜在安全问题，尚未确认用户资金受影响", "statement"),
    ("ZachXBT：币安与Bitget黑客事件被盗资金流入同一地址，或为同一攻击者所为", "attribution"),
    ("Chainalysis Links $6.4 Billion Binance Hack to North Korea", "attribution"),
    ("Kamino：未受币安事件影响，已暂停SOL/BTC市场借款功能", "impact"),
    ("BNB日内下跌6.23%，盘中最低触及678美元", "impact"),
    # live 2026-10-30 audit: web3 events whose only report had no phase
    ("⚠️ Another victim lost $50K in USDT to an address poisoning attack on Ethereum", "drain"),
    ("以太坊和BNB Chain上100多个钱包疑似遭窃，共损失约120万美元", "drain"),
    ("Pando Rings黑客2小时前买入7548枚ETH，约合1672万美元", "laundering"),
    ("Threat Intelligence | Analysis of the DarkSword Trojan Backend and iOS", "other"),   # research, not an attack phase
])
def test_phase_of_a_report(title, phase):
    assert signals.phase(title) == phase


@pytest.mark.parametrize(("text", "actor"), [
    ("TRM attributes the attack to TraderTraitor, North Korea’s elite hacking unit", "North Korea (Lazarus / TraderTraitor)"),
    ("Chainalysis Links $6.4 Billion Binance Hack to North Korea", "North Korea (Lazarus / TraderTraitor)"),
    ("朝鲜黑客组织Lazarus疑为币安被盗幕后黑手", "North Korea (Lazarus / TraderTraitor)"),
    ("ZachXBT：币安与Bitget被盗资金汇入同一地址，或为同一攻击者所为", None),
    ("Binance probes potential $5.8 billion crypto-theft hack", None),
])
def test_attribution_actor_is_only_a_named_actor(text, actor):
    assert signals.attribution_actor(text) == actor
