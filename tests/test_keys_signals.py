"""Unit criteria for deterministic extraction. Each case is a real string shape seen in a source."""

import pytest

from radar import keys, signals, stages, timeutil


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


# docs/research/16: the only explorer form live posts used that tx_refs missed (14 days, 54 web3 events) — Phalcon's
# path names the chain: app.blocksec.com/phalcon/explorer/tx/<chain>/<hash> (X100 "Attack TX", Binance sweeper call)
PHALCON = "https://app.blocksec.com/phalcon/explorer/tx/eth/0x53bd38b816c23e74134786c29a8c18d792777998a3b9326047b583100e88e2f3"


def test_a_phalcon_explorer_link_is_a_tx_on_the_chain_its_path_names():
    [t] = keys.tx_refs(f"Dozens of assets were swept through several batch calls. {PHALCON}")
    assert t == {"chain": "ethereum", "hash": PHALCON.rsplit("/", 1)[-1], "explorer_url": PHALCON}
    [b] = keys.tx_refs(PHALCON.replace("/tx/eth/", "/tx/bsc/"))
    assert b["chain"] == "bsc"


def test_a_phalcon_link_on_an_unknown_chain_segment_is_skipped_not_guessed():
    assert keys.tx_refs(PHALCON.replace("/tx/eth/", "/tx/somechain/")) == []


@pytest.mark.parametrize("text", [
    # live 2026-10-30 (ZachXBT): a labelled hash of the Arbitrum Security Council's FREEZE tx — not an attack tx
    ("BREAKING: Arbitrum Security Council has executed a transaction to freeze ~$30.5M from the Binance Exploit. "
     "Trsanction hash: 0xb69c81774f507d46ce776aeaed8b4d31df96dd66ce6fd05073481011835355d6"),
    "block hash 0x824b83f94bdc2e69b81f1cb2dfdf9d4aeed066114e3de29e3af59bd2d9355fc2 at height 23,512,004",
    "signature hash: 0x824b83f94bdc2e69b81f1cb2dfdf9d4aeed066114e3de29e3af59bd2d9355fc2",
])
def test_a_bare_hash_without_an_explorer_link_is_never_a_tx(text):
    assert keys.tx_refs(text) == []


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
    ("币安热钱包疑似遭攻击，约25亿美元资产被转出", "asset_transfer"),
    ("Multiple Binance (@binance) hot wallets across several chains, including Ethereum", "asset_transfer"),
    ("数据：币安疑似被盗关联地址已抛售约470万枚UNI换成ETH", "laundering"),
    ("数据：币安疑似被盗关联地址从Aave借出约1.98万枚ETH", "laundering"),
    ("TRX stolen from Binance was moved through Bitget Wallet’s bridge during the la", "laundering"),
    ("Tether在疑似币安黑客攻击中冻结价值 9.71 亿美元的 USDT", "freeze"),
    ("BREAKING: Arbitrum Security Council has executed a transaction to freeze ~$30.", "freeze"),
    ("币安：安全事件或涉DevOps工程师电脑被入侵，未发现私钥泄露，预计总损失约63亿美元", "disclosure"),
    ("币安：正调查潜在安全问题，尚未确认用户资金受影响", "disclosure"),
    ("ZachXBT：币安与Bitget黑客事件被盗资金流入同一地址，或为同一攻击者所为", "attribution"),
    ("Chainalysis Links $6.4 Billion Binance Hack to North Korea", "attribution"),
    ("Kamino：未受币安事件影响，已暂停SOL/BTC市场借款功能", "impact"),
    ("BNB日内下跌6.23%，盘中最低触及678美元", "impact"),
    # live 2026-10-30 audit: web3 events whose only report had no phase
    ("⚠️ Another victim lost $50K in USDT to an address poisoning attack on Ethereum", "asset_transfer"),
    ("以太坊和BNB Chain上100多个钱包疑似遭窃，共损失约120万美元", "asset_transfer"),
    ("Pando Rings黑客2小时前买入7548枚ETH，约合1672万美元", "laundering"),
    ("Threat Intelligence | Analysis of the DarkSword Trojan Backend and iOS", "other"),   # research, not an attack phase
])
def test_phase_of_a_report(title, phase):
    assert stages.of_title(title) == phase


@pytest.mark.parametrize(("text", "actor"), [
    ("TRM attributes the attack to TraderTraitor, North Korea’s elite hacking unit", "North Korea (Lazarus / TraderTraitor)"),
    ("Chainalysis Links $6.4 Billion Binance Hack to North Korea", "North Korea (Lazarus / TraderTraitor)"),
    ("朝鲜黑客组织Lazarus疑为币安被盗幕后黑手", "North Korea (Lazarus / TraderTraitor)"),
    ("ZachXBT：币安与Bitget被盗资金汇入同一地址，或为同一攻击者所为", None),
    ("Binance probes potential $5.8 billion crypto-theft hack", None),
])
def test_attribution_actor_is_only_a_named_actor(text, actor):
    assert signals.attribution_actor(text) == actor


def test_the_repair_rekey_picks_up_a_phalcon_tx_on_a_stored_item():
    import importlib.util
    from pathlib import Path

    from radar.model import Item
    spec = importlib.util.spec_from_file_location("recluster", Path(__file__).parents[1] / "scripts" / "recluster_web3.py")
    rc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rc)
    h = "0x" + "ab" * 32
    it = Item(item_id="i1", source_id="x_security", tier="T1", org="x", domain="web3", url="https://x.com/a/status/1",
              canonical_url="https://x.com/a/status/1", title="sweeper call", text="", published_at="2026-10-29T21:00:00Z",
              fetched_at="2026-10-29T21:00:00Z", content_hash="c", keys=["xs:1"], extra={"tx": []}, entity=None, eventful=True, signals={},
              links=[f"https://app.blocksec.com/phalcon/explorer/tx/eth/{h}"])
    out = rc.rekey(it)
    assert f"tx:{h}" in out.keys and out.extra["tx"][0]["chain"] == "ethereum"
    assert rc.rekey(out).extra["tx"] == out.extra["tx"]                         # idempotent


def test_common_english_words_at_a_sentence_start_are_not_names():
    """Live 2026-11-02: SlowMist's "One Fish, Multiple Meals — Analysis of the $780K zkLink Exploit" and SlowMist's
    "On October 29, …" tweet joined the Binance event through tok:one / multiple / after / every / october / these /
    point / full / used / erc — capitalised by title case or a sentence start, shared with Binance reports."""
    from radar import keys
    toks = keys.entity_tokens("One Fish, Multiple Meals — Analysis of the $780K zkLink Exploit. After the attack, "
                              "Every relayer… These points were Used in Full on October 29 via ERC-20 transfers.")
    assert "zklink" in toks
    assert not toks & {"one", "multiple", "after", "every", "these", "used", "full", "october", "erc", "analysis", "point"}


# --- P0 signals (docs/research/action/07-code-quality.md §2.4 / §2.5, 04-reconstruction.md §2 B1–B3) ---

@pytest.mark.parametrize("text", ["微软修复CVE-2026-12345漏洞", "漏洞CVE-2026-1234已修复", "（CVE-2026-1234）"])
def test_a_cve_next_to_chinese_text_is_extracted(text):
    """\\b never fires between a CJK character (a word character) and "CVE": 「微软修复CVE-2026-12345漏洞」 had no cve: key."""
    assert len(keys.cves(text)) == 1 and keys.cves(text)[0].startswith("CVE-2026-")


def test_a_cve_inside_a_longer_ascii_token_is_still_not_one():
    assert keys.cves("XCVE-2026-1234 CVE-2026-12345678") == []


def test_a_named_vulnerability_next_to_chinese_text_is_a_token():
    assert keys.named_tokens("PHP2Shell漏洞遭利用") == {"php2shell"}
    assert keys.named_tokens("新型PHP2Shell漏洞遭利用") == {"php2shell"}


def test_a_chinese_cve_report_is_vuln_and_a_security_event():
    from radar import pipeline
    assert pipeline._classify(None, "厂商发布CVE-2026-1234修复", False) == "vuln"
    assert signals.security_event("厂商发布CVE-2026-1234修复")


@pytest.mark.parametrize(("text", "expected"), [
    (("Microsoft fixed CVE-2026-1111 which is actively exploited in the wild. Microsoft said there is no evidence of "
      "exploitation for the other critical bugs."), "yes"),
    ("Fortinet confirms CVE-2026-2 actively exploited; Ivanti says it is not aware of any exploitation", "yes"),
    ("This flaw has not been exploited in the wild.", "no"),
    ("There is no evidence of exploitation in the wild. A fix is available.", "no"),
])
def test_a_negation_in_one_sentence_does_not_cancel_exploitation_in_another(text, expected):
    assert signals.exploited(text) == expected


@pytest.mark.parametrize("text", [
    "No evidence links the hack to North Korea, researchers say",
    "ZachXBT: attack not related to Lazarus",
    "Binance denies North Korea was behind the hack",
    "North Korea rejects blame for the Binance hack",
    "Lazarus not responsible for the exploit, says SlowMist",
    "币安否认朝鲜黑客参与此次事件",
    "No evidence, as of today, links the hack to Lazarus",      # a rebuttal reaches past its own clause
])
def test_a_denial_is_not_a_naming(text):
    assert signals.attribution_actor(text) is None


def test_a_denial_in_one_sentence_does_not_hide_a_naming_in_another():
    assert signals.attribution_actor("Chainalysis links the hack to Lazarus.\nThe exchange denies any insider role.") == \
        "North Korea (Lazarus / TraderTraitor)"
    assert signals.attribution_actor("Chainalysis links the hack to Lazarus. There is no evidence of insider help.") == \
        "North Korea (Lazarus / TraderTraitor)"


@pytest.mark.parametrize("text", [
    "朝鲜黑客组织Lazarus所为，与此前Phemex事件无关",
    "Lazarus stole $1.5B from Bybit, unrelated to the earlier Phemex hack",
    "Lazarus Group behind the hack, says ZachXBT, who denied any role of insiders",
    "North Korea's Lazarus behind hack, not tied to Kim's regime officials",
])
def test_a_negation_of_something_else_does_not_hide_the_naming(text):
    """Review of p0/signals: a plain negation voided its whole sentence, so these four lost the Lazarus naming they had."""
    assert signals.attribution_actor(text) == "North Korea (Lazarus / TraderTraitor)"


@pytest.mark.parametrize(("title", "phase"), [
    ("Exchange recovered $10M of stolen assets", "recovery"),
    ("Protocol prepares compensation plan for users", "other"),
    ("Anthropic IPO难参与？投资者转向加密衍生品提前布局", "other"),
    ("Attacker prepared the exploit contract days in advance", "prep"),
    ("黑客提前数日部署攻击合约", "prep"),
    ("Exchange prepares to compensate users after hacker drained hot wallet", "asset_transfer"),   # the victim making good
    ("Tether froze $5M linked to the exploit", "freeze"),
    ("黑客攻击后平台准备赔付用户", "asset_transfer"),                                              # the victim making good
    ("Exchange prepares to reopen deposits after hacker attack", "other"),             # the victim preparing
    ("遭黑客攻击后，交易所准备重新开放充值", "asset_transfer"),
    ("Exploit contract funded by Tornado Cash", "prep"),                               # funding is the attacker's
    ("Exploit wallet funded via Tornado Cash ahead of attack", "prep"),
    ("Bitcoin price recovers after Bybit hack", "asset_transfer"),                              # a price recovering is not funds
    ("Market recovers", "impact"),
])
def test_phase_recovery_and_prep_are_not_borrowed_from_other_measures(title, phase):
    assert stages.of_title(title) == phase


def test_memoised_amount_readers_hand_each_caller_its_own_list():
    """signals memoises its pure text readers (insights.progress replays every prefix); a caller extending a result
    must not change what the next caller gets."""
    from radar import signals
    t = "Hackers stole $5 million from the bridge; $2 million was frozen."
    a = signals.amount_mentions(t)
    a.append((1.0, "loss"))
    assert signals.amount_mentions(t) == a[:-1] and signals.amount_mentions.cache_info().hits >= 1


def test_every_sha1_and_md5_says_it_is_not_for_security():
    """Probe / bandit B324 (2026-11-11): sha1 / md5 here only shard ledgers and fingerprint fixtures. Saying so keeps a
    FIPS build from refusing them and keeps a real security use from hiding among them."""
    import ast
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    bad = []
    for f in [*root.glob("src/**/*.py"), *root.glob("scripts/**/*.py"), *root.glob("tests/**/*.py")]:
        for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("sha1", "md5") \
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib" \
                    and not any(k.arg == "usedforsecurity" for k in node.keywords):
                bad.append(f"{f.relative_to(root)}:{node.lineno}")
    assert not bad, bad


def test_a_months_tally_is_a_roundup_and_company_accounts_are_not_a_theft():
    """Live 2026-11-11 loss ranking: CertiK's monthly tally ($9.2B) and Bitmine's / Bitdeer's net losses ranked as Web3 thefts."""
    from radar import signals
    assert signals.is_roundup_report("#CertiKStatsAlert 🚨 In October we’ve confirmed ~$6.5B lost to exploits")
    assert signals.amount_kind("Bitmine posts $6.3B net loss for fiscal 2026 as Ether prices slide") == "context"
    assert signals.amount_kind("Bitdeer reports record Q3 revenue as net loss widens to $125.5 million") == "context"
    assert signals.stated_losses("Bitmine booked $6.2 billion in unrealized losses on digital assets.") == []
    assert signals.amount_kind("Binance hot wallets drained, $6.3B stolen") == "loss"           # a theft stays a theft
    assert not signals.is_roundup_report("Binance hot wallets drained, $6.3B stolen")


def test_an_amount_called_stolen_is_the_loss_even_in_a_clause_about_a_freeze():
    """Live 2026-11-11: Binance's frozen total ($6.43B) exceeded its loss — Decrypt's 「$2.85 billion of the $6.43 billion
    stolen … has been frozen」 and Cointelegraph's 「accounts tied to the $6.3 billion theft」 read as freezes."""
    from radar import signals
    assert signals.amount_mentions("$2.85 billion of the $6.43 billion stolen from Binance has been frozen or seized.") == \
        [(2_850_000_000.0, "frozen"), (6_430_000_000.0, "loss")]
    assert signals.amount_mentions("Gate froze two accounts tied to the $6.3 billion theft.") == [(6_300_000_000.0, "loss")]
    assert signals.amount_mentions("Tether froze $971 million of USDT linked to the hack") == [(971_000_000.0, "frozen")]
    assert signals.amount_mentions("币安已冻结约30亿美元被盗资产") == [(3_000_000_000.0, "frozen")]      # 被盗 modifies 资产
    assert signals.amount_mentions("Tether froze $971 million of stolen funds") == [(971_000_000.0, "frozen")]
    assert signals.amount_mentions("markets recovered some losses following the record $6.3 billion Binance hack.") == \
        [(6_300_000_000.0, "loss")]                                                       # a name between, then hack
    assert signals.amount_mentions("币安损失约63亿美元，已冻结约30亿美元资产") == [(6_300_000_000.0, "loss"), (3_000_000_000.0, "frozen")]
    assert signals.stated_losses("$2.85 billion of the $6.43 billion stolen from Binance has been frozen or seized.") == [6_430_000_000.0]
