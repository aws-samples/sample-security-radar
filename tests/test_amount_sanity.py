"""Web3 loss figures are what the reports state as the loss (live 2026-11-04, a colleague's question: why is the top of
the 「Web3 损失排行」 $235B?). PANews: 「遭攻击损失超1.33亿美元的欧盟金融机构据称是法国银行Crédit Mutuel Arkéa，该行资产规模达
2350亿美元」 — the largest number was the bank's balance sheet, and the same theft was 5 events (4 anonymous 「欧盟实体」 +
SlowMist's named record)."""
from datetime import UTC, datetime

import pytest

from radar import pipeline, signals
from radar.model import RawItem
from radar.store import MemoryStore

ARKEA = ("PANews 11月4日消息，链上侦探ZachXBT 更新调查 称，遭攻击损失超1.33亿美元的欧盟金融机构据称是法国银行Crédit Mutuel"
         " Arkéa，该行资产规模达2350亿美元。")


def test_the_loss_is_the_stated_loss_not_the_largest_number():
    assert signals.loss_amount("ZachXBT：被盗1.33亿美元的欧盟实体据称是法国银行Crédit Mutuel Arkéa", ARKEA) == 133_000_000
    # … and from the body alone (a headline without a figure): still the stated loss, not the bank's size
    assert signals.loss_amount("ZachXBT：欧盟实体据称是法国银行Crédit Mutuel Arkéa", ARKEA) == 133_000_000
    assert dict(signals.amount_mentions(ARKEA))[235_000_000_000] == "context"


def test_the_attacker_buying_or_moving_funds_is_not_the_loss():
    """Pando Rings: 「黑客2小时前买入7548枚ETH，约合1672万美元」 / 「价值约922万美元，…将4000枚ETH通过Tornado转移」."""
    for t in ("Pando Rings黑客2小时前买入7548枚ETH，约合1672万美元", "Pando Rings黑客将价值约922万美元的4000枚ETH通过Tornado转移",
              "The hacker bought 7,548 ETH for $16.7 million"):
        assert all(k == "context" for _, k in signals.amount_mentions(t)), t


def test_a_victims_size_is_context_in_english_too_but_stolen_assets_are_a_loss():
    assert dict(signals.amount_mentions("a bank with ~$235 billion in assets"))[235e9] == "context"
    assert dict(signals.amount_mentions("Over $5.8B in assets has been stolen from Binance"))[5.8e9] == "loss"


def _raw(src, title, text, when):
    return RawItem(source_id=src, url=f"https://{src}.example/{abs(hash(title))}", title=title, text=text,
                   published_at=when, guid=None, author=None, links=[], extra={})


def _ingest(store, *raws):
    for r in raws:
        pipeline.ingest([r], store, r.published_at)


def test_one_anonymous_theft_reported_by_its_figure_is_one_event():
    store = MemoryStore()
    d = lambda h, day=2: datetime(2026, 11, day, h, tzinfo=UTC)
    _ingest(store,
            _raw("odaily", "ZachXBT：某欧盟实体疑似遭窃超1.06亿美元，攻击者正通过跨链及隐私币转移资金",
                 "链上侦探 ZachXBT 称，某欧盟实体多个中心化交易所账户被盗，损失超过 1.06 亿美元。", d(12)),
            _raw("panews", "疑似损失超1.06亿美元，欧盟实体多个中心化交易所账户遭攻击",
                 "一家欧盟实体疑似从多个中心化交易所账户中损失逾1.06亿美元。", d(13)),
            _raw("panews", "ZachXBT：疑似被盗欧盟实体再次发生2700万异常提款，总额已超1.33亿美元",
                 "PANews 11月3日消息，链上侦探ZachXBT更新调查称， 此前疑似遭盗的欧洲机构 又被发现超过2700万美元的中心化交易所"
                 "异常提款，使事件涉及资金总额升至1.33亿美元以上，其中部分提款发生在他首次公开披露之后。此前其社区警报显示，该欧盟实体"
                 "疑似于11月1日从多个中心化交易所账户损失超1.06亿美元，资金被非法行为者以USDC和USDT提取。", d(7, 3)),
            _raw("panews", "ZachXBT：被盗1.33亿美元的欧盟实体据称是法国银行Crédit Mutuel Arkéa", ARKEA, d(2, 4)))
    evs = [e for e in store.events.values() if e["domain"] == "web3"]
    assert len(evs) == 1, [e["title"] for e in evs]
    assert evs[0]["amount_usd_latest"] == 133_000_000


def test_a_lone_implausible_figure_never_becomes_the_headline():
    hist = [{"value": 106e6, "source_id": "odaily", "observed_at": "a", "kind": "loss"},
            {"value": 133e6, "source_id": "panews", "observed_at": "b", "kind": "loss"},
            {"value": 235e9, "source_id": "panews", "observed_at": "c", "kind": "loss"}]
    pipeline._mark_outliers(hist, set())
    assert [p["kind"] for p in hist] == ["loss", "loss", "outlier"]
    lone = [{"value": 30e9, "source_id": "odaily", "observed_at": "a", "kind": "loss"}]
    pipeline._mark_outliers(lone, set())
    assert lone[0]["kind"] == "outlier"                       # > MAX_PLAUSIBLE_LOSS_USD with nothing backing it


def test_a_backed_or_structured_big_figure_is_not_an_outlier():
    """Binance: DeFiLlama's structured $6.36B and a revision ×10 from one source are real, not outliers."""
    hist = [{"value": 6.36e9, "source_id": "defillama_hacks", "observed_at": "a", "kind": "loss"},
            {"value": 1e6, "source_id": "odaily", "observed_at": "b", "kind": "loss"}]
    pipeline._mark_outliers(hist, {"defillama_hacks"})
    assert hist[0]["kind"] == "loss"
    two = [{"value": 30e9, "source_id": "a", "observed_at": "a", "kind": "loss"},
           {"value": 30.1e9, "source_id": "b", "observed_at": "b", "kind": "loss"}]
    pipeline._mark_outliers(two, set())
    assert [p["kind"] for p in two] == ["loss", "loss"]        # two sources agree
    grew = [{"value": 5e6, "source_id": "a", "observed_at": "a", "kind": "loss"},
            {"value": 120e6, "source_id": "a", "observed_at": "b", "kind": "loss"}]
    pipeline._mark_outliers(grew, set())
    assert grew[1]["kind"] == "loss"                           # ×24 is a revision, not two orders of magnitude


def test_a_round_figure_does_not_glue_two_stories():
    store = MemoryStore()
    d = lambda day: datetime(2026, 11, day, 9, tzinfo=UTC)
    _ingest(store, _raw("odaily", "某DeFi协议遭攻击，损失约1亿美元", "某DeFi协议遭攻击，损失约1亿美元。", d(2)),
            _raw("panews", "另一交易所热钱包被盗1亿美元", "另一交易所热钱包被盗1亿美元。", d(3)))
    assert len([e for e in store.events.values() if e["domain"] == "web3"]) == 2


def test_a_ransom_demand_and_a_unit_price_are_not_losses():
    gmo = "收到约 80 亿日元（约合 5070 万美元）的赎金要求"
    assert all(k == "context" for _, k in signals.amount_mentions(gmo))
    ai = "疑似盗走欧盟实体1.06亿美元资金的黑客昨日单日买入2.7553万枚ETH（6283万美元），建仓操作均在链上完成，均价2280.34美元"
    got = dict(signals.amount_mentions(ai))
    assert got[106e6] == "loss" and got[2280.34] == "context"
    assert signals.loss_amount("疑似盗走欧盟实体1.06亿美元资金的黑客昨日买入2.75万枚ETH", ai) == 106e6


def test_a_hack_database_record_carries_its_amount_key():
    """SlowMist's named Crédit Mutuel Arkéa record ($133M) must meet the anonymous 「欧盟实体」 reports of the same figure."""
    store = MemoryStore()
    rec = RawItem(source_id="slowmist_hacked", url="https://hacked.slowmist.io/#2026-11-01-Credit",
                  title="Crédit Mutuel Arkéa — Account Credentials Stolen", text="losses exceeding $133 million",
                  published_at=datetime(2026, 11, 1, tzinfo=UTC), guid=None, author=None, links=[],
                  extra={"entity": "Crédit Mutuel Arkéa", "amount_usd": 133_000_000})
    pipeline.ingest([rec], store, datetime(2026, 11, 4, 3, tzinfo=UTC))
    [it] = store.items.values()
    assert "amt:133000000" in it["keys"]


def test_ops_shows_outliers_and_one_theft_split_by_its_figure():
    from radar import publish
    from radar.model import Event
    store = MemoryStore()
    base = {"domain": "web3", "first_seen": "2026-11-02T12:30:00Z", "last_updated": "2026-11-04T02:26:00Z",
            "item_ids": [], "keys": ["amt:106000000"]}
    store.put_event(Event(event_id="ev_00000000000000a1", title="ZachXBT：某欧盟实体疑似遭窃超1.06亿美元", **base,
                          amount_history=[{"value": 106e6, "source_id": "odaily", "observed_at": "2026-11-02T12:30:13Z", "kind": "loss"},
                                          {"value": 235e9, "source_id": "panews", "observed_at": "2026-11-04T02:26:43Z", "kind": "outlier"}]))
    store.put_event(Event(event_id="ev_00000000000000a2", title="疑似损失超1.06亿美元，欧盟实体多个中心化交易所账户遭攻击", **base))
    items = publish.build(store, datetime(2026, 11, 4, 12, tzinfo=UTC))["ops.json"]["attention"]
    out = [i for i in items if i["code"] == "amount_outlier"]
    shared = [i for i in items if i["code"] == "amount_shared"]
    assert len(out) == 1 and "235,000,000,000" in out[0]["detail"]
    assert len(shared) == 1 and "--event ev_00000000000000a1 --event ev_00000000000000a2" in shared[0]["detail"]


def test_a_comparison_in_the_body_does_not_glue_two_thefts():
    """A Binance report citing Bitget's $387M for comparison lends only its own headline figure: the event it joins
    must not become findable by Bitget's amount (title-only amt: keys; body figures are lookup-only)."""
    from radar.registry import BY_ID
    raw = _raw("panews", "币安热钱包被盗约63亿美元", "币安热钱包被盗约63亿美元，规模远超此前Bitget被盗的3.87亿美元，USDT。",
               datetime(2026, 10, 29, 9, tzinfo=UTC))
    it = pipeline.normalize(raw, BY_ID["panews"], raw.published_at)
    assert "amt:6300000000" not in it.keys          # a round figure: no key at all
    assert "amt:387000000" not in it.keys            # the comparison is not lent …
    assert "amt:387000000" in pipeline._lookup_keys(it)   # … but may still be looked up


def test_users_withdrawing_is_not_the_loss():
    assert dict(signals.amount_mentions("Binance net outflows surge to $5.8B as withdrawals resume"))[5.8e9] == "context"
    assert dict(signals.amount_mentions("币安24小时净流出约58亿美元"))[5.8e9] == "context"


def _rc():
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location("recluster", Path(__file__).parents[1] / "scripts" / "recluster_web3.py")
    rc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rc)
    return rc


def test_a_targeted_repair_folds_only_strays_that_share_a_key(monkeypatch):
    """2026-11-04 dry run: eleven unrelated events passed with --event — GMO, PrimeFinance, Cysic … — were all folded into
    Binance. A one-report event joins the largest successor only when it shares a (non-url) key with it."""
    from radar.model import Event
    rc = _rc()
    big = Event(event_id="ev_big", domain="web3", title="Binance", first_seen="2026-10-29T20:51:00Z",
                last_updated="2026-11-01T00:00:00Z", item_ids=["a", "b"], keys=["tok:binance", "amt:106000000"])
    eu = Event(event_id="ev_eu", domain="web3", title="欧盟实体", first_seen="2026-11-02T00:00:00Z",
               last_updated="2026-11-02T00:00:00Z", item_ids=["c"], keys=["amt:106000000", "url:https://x/1"])
    gmo = Event(event_id="ev_gmo", domain="web3", title="GMO", first_seen="2026-10-29T00:00:00Z",
                last_updated="2026-10-29T00:00:00Z", item_ids=["d"], keys=["url:https://x/2"])
    stats = Event(event_id="ev_stats", domain="web3", title="CertiK October stats", first_seen="2026-10-31T13:00:00Z",
                  last_updated="2026-10-31T13:00:00Z", item_ids=["e"], keys=["url:https://x/3"])
    new = {e.event_id: e for e in (big, eu, gmo, stats)}
    # before the repair the stats tweet was inside Binance ("as it was" ⇒ it goes back); GMO and the EU report were not
    old = {"ev_big": Event.from_dict({**big.to_dict(), "item_ids": ["a", "b", "e"]})}
    monkeypatch.setattr(rc.pipeline, "recompute",
                        lambda ev, items, now: Event.from_dict({**ev.to_dict(), "item_ids": [i.item_id for i in items]}))
    by_id = {i: type("I", (), {"item_id": i})() for i in "abcde"}
    rc.fold_strays(new, by_id, None, old)
    assert set(new) == {"ev_big", "ev_gmo"} and sorted(new["ev_big"].item_ids) == ["a", "b", "c", "e"]


def test_the_repair_reextracts_a_stored_prose_loss():
    """The stored $235B (PANews) becomes $133M on repair; a hack database's structured figure is never changed."""
    from radar.model import Item
    rc = _rc()
    mk = lambda src, title, text, extra: Item(item_id=src, source_id=src, tier="T3", org=src, domain="web3", url="https://x",
                                             canonical_url="https://x", title=title, text=text, published_at="2026-11-04T02:26:43Z",
                                             fetched_at="2026-11-04T02:26:43Z", content_hash="c", keys=[], links=[], entity=None,
                                             eventful=True, signals={"amount_usd": 235e9}, extra=extra)
    it = mk("panews", "ZachXBT：被盗1.33亿美元的欧盟实体据称是法国银行Crédit Mutuel Arkéa", ARKEA,
            {"amount_history": [{"value": 235e9, "observed_at": "2026-11-04T02:26:43Z"}]})
    rc.reextract(it)
    assert it.signals["amount_usd"] == 133e6 and it.extra["amount_history"][0]["value"] == 133e6 and "amt:133000000" in it.keys
    db = mk("slowmist_hacked", "Crédit Mutuel Arkéa — Account Credentials Stolen", "", {"amount_usd": 133e6})
    db.signals = {"amount_usd": 133e6}
    rc.reextract(db)
    assert db.signals["amount_usd"] == 133e6 and "amt:133000000" in db.keys


def test_a_specific_figure_beats_a_big_events_word_bag():
    """Live 2026-11-04: an 「欧盟实体」 report scored higher on Binance (277 reports, every common word) than on its own
    1.06亿 story. A shared specific loss figure outweighs a few shared names."""
    store = MemoryStore()
    d = lambda day, h: datetime(2026, 11, day, h, tzinfo=UTC)
    words = "ZachXBT 称 Binance Kraken Crypto.com USDT USDC 跨链 交易所"
    _ingest(store, _raw("odaily", "Binance热钱包被盗约63亿美元", f"{words}，Binance热钱包被盗约63亿美元。", d(1, 9)),
            _raw("panews", "ZachXBT：某欧盟实体疑似遭窃超1.06亿美元，攻击者正通过跨链及隐私币转移资金",
                 "某欧盟实体中心化交易所账户被盗，损失超过1.06亿美元，USDT。", d(2, 12)))
    _ingest(store, _raw("odaily", "Kraken限制涉欧盟实体1.06亿美元疑似被盗资金相关账户，Crypto.com称已阻断资金流转",
                        f"{words}，涉1.06亿美元被盗资金。", d(3, 9)))
    eu = next(e for e in store.events.values() if "欧盟" in e["title"])
    assert len(eu["item_ids"]) == 2


def test_a_leading_conversion_and_a_price_are_not_losses():
    """Pando Rings (live): the headline 「价值约922万美元，Pando Rings黑客将4000枚ETH通过Tornado转移」 and 「价格 2,249 美元」;
    the loss stays the 22M the hacker stole 4 years ago."""
    title = "价值约922万美元，Pando Rings黑客将4000枚ETH通过Tornado转移"
    assert all(k == "context" for _, k in signals.amount_mentions(title))
    body = ("4 年前从 Pando Rings 项目盗取约 2200 万美元资产的黑客，花 1698 万 DAI 抄底买入 7,548 枚 ETH，价格 2,249 美元。"
            "2 小时前，Pando Rings 黑客把其中 4,000 枚 ETH（约 922 万美元）通过 Tornado 洗走。")
    got = dict(signals.amount_mentions(body))
    assert got[2249.0] == "context"
    # the 22M was stolen 「4 年前」: history, not this event's loss (live 2026-11-05, #6 on the wall's ranking)
    assert got[22e6] == "context" and 22e6 not in signals.stated_losses(body)


def test_an_unstated_body_figure_is_not_a_loss():
    """Live 2026-11-04, the Binance event: four body figures with no loss cue became loss points (then outliers) —
    「币安托管资产约1440亿美元」, 「USDT 下降 6.3%至 341 亿美元」, 「低于3000亿美元」, 「$171 billion in customer assets」."""
    store = MemoryStore()
    when = datetime(2026, 10, 31, 9, tzinfo=UTC)
    _ingest(store, _raw("odaily", "分析师：币安遭攻击后储备资产仅小幅下降，用户受影响有限，USDT",
                        # 34.1亿, below MAX_PLAUSIBLE_LOSS_USD: the outlier guard must not be what saves this case
                        "币安遭攻击后，USDT 下降 6.3%至 34.1 亿美元，整体影响有限。", when))
    pts = [p for e in store.events.values() for p in e["amount_history"]]
    assert pts and all(p["kind"] != "loss" for p in pts)
    assert signals.stated_losses("USDT 下降 6.3%至 341 亿美元") == []
    assert signals.stated_losses("币安热钱包约25亿美元资产被盗") == [2.5e9]


def test_a_hack_database_record_is_a_loss_whichever_way_it_reads():
    """DeFiHackLabs MUS (live): 「Lost: ~0.400168 ETH per deposit-withdraw cycle …; reported campaign total ~$36.9k」 —
    no structured amount field, and the semicolon split the cue from the figure."""
    store = MemoryStore()
    text = ("deposit refunds a first-deposit bonus\\nLost: ~0.400168 ETH per deposit-withdraw cycle (exactly reproduced) on "
            "Ethereum; the MUS pool's standing 5.335 ETH was drained to 0 across the attack block, reported campaign total "
            "~$36.9k across many fresh addresses")
    raw = RawItem(source_id="defihacklabs", url="https://github.com/SunWeb3Sec/DeFiHackLabs#MUS", title="MUS — deposit refunds",
                  text=text, published_at=datetime(2026, 10, 30, tzinfo=UTC), guid=None, author=None, links=[],
                  extra={"entity": "MUS", "lost_text": "Lost: ~0.400168 ETH per cycle, campaign total ~$36.9k"})
    pipeline.ingest([raw], store, datetime(2026, 10, 30, 1, tzinfo=UTC))
    [ev] = store.events.values()
    assert ev["amount_usd_latest"] == 36_900 and {p["kind"] for p in ev["amount_history"]} == {"loss"}


def test_title_case_headline_words_are_not_names():
    """Live 2026-11-04: Decrypt's Title Case headline made mystery / million / theft / hits / entity / days "names"; the
    report kept returning to Binance (whose word bag then held them) instead of its own 1.06亿 story."""
    from radar import keys
    t = "Mystery $106 Million Crypto Theft Hits EU Entity Days After Binance Hack"
    body = ("A European entity lost more than $106 million in a suspected theft, according to ZachXBT, days after Binance "
            "was drained. The stolen funds were swapped on Kraken.")
    assert keys.headline_names(t, body) == {"binance"}
    # name-shaped words survive a Title Case headline even when the body opens with them
    assert {"zklink", "nova"} <= keys.headline_names("zkLink Nova — Cross-Chain Message Spoofing", "zkLink Nova was exploited, Nova said")
    # an ordinary headline keeps its capitalised words, and so does a Chinese one (every ASCII word there is a name)
    assert "polymarket" in keys.headline_names("Polymarket International hit by supply chain attack", "")
    assert {"liquid", "bitget"} <= keys.headline_names("Liquid Network跨链桥被盗3.2亿美元，手法与Bitget事件相似，USDT", "")



def test_a_big_loss_beside_one_tiny_figure_keeps_its_headline():
    """Found by the mutation run (M184): with two figures, $6.3B and a user's $100, the ratio test flagged the $6.3B."""
    hist = [{"value": 6.3e9, "source_id": "panews", "observed_at": "a", "kind": "loss"},
            {"value": 100.0, "source_id": "odaily", "observed_at": "b", "kind": "loss"}]
    pipeline._mark_outliers(hist, set())
    assert [p["kind"] for p in hist] == ["loss", "loss"]


def test_usd_prefix_amounts_are_parsed():
    assert signals.parse_amount("Bitget Loses USD 351.6 Million in Hot Wallet Breach") == 351_600_000
    assert dict(signals.amount_mentions("TRM traced USD 351.6 million stolen from Bitget"))[351.6e6] == "loss"


@pytest.mark.parametrize("outlet", ["bleepingcomputer", "theblock"])
def test_an_incident_report_of_the_same_figure_joins_the_web3_story(outlet):
    """The Block's 「French bank Crédit Mutuel Arkéa exploited for over $133 million, ZachXBT says」 (no crypto word ⇒
    incident) stood apart from the web3 Arkéa event with the same $133M. Since crypto outlets are web3 (2026-11-17),
    The Block's report joins as web3; the same words from a general outlet are an INCIDENT report and must still join
    through the figure (the cross-domain amt: link, M360)."""
    store = MemoryStore()
    _ingest(store, _raw("panews", "ZachXBT：被盗1.33亿美元的欧盟实体据称是法国银行Crédit Mutuel Arkéa", ARKEA,
                        datetime(2026, 11, 4, 2, tzinfo=UTC)),
            _raw(outlet, "French bank Crédit Mutuel Arkéa exploited for over $133 million, ZachXBT says",
                 "ZachXBT said he has a 'high degree of confidence' that the attacker is not associated with Lazarus.",
                 datetime(2026, 11, 4, 4, 57, tzinfo=UTC)))
    assert len(store.events) == 1


def test_a_backfilled_story_is_checked_for_a_split():
    """TRM's September Bitget report, fetched weeks later, opened its own event (first_seen 09-25) beside DeFiLlama's
    09-24 Bitget record; the split check only looked at events whose first REPORT was recent."""
    from radar.model import Event
    store = MemoryStore()
    old = _raw("odaily", "Bitget热钱包被盗约3.87亿美元，涉及ETH与USDT", "Bitget热钱包被盗约3.87亿美元。", datetime(2026, 9, 24, tzinfo=UTC))
    pipeline.ingest([old], store, datetime(2026, 9, 24, 1, tzinfo=UTC))
    late = _raw("panews", "3.5亿美元一夜蒸发！Bitget热钱包被盗事件复盘，USDT", "Bitget热钱包被盗约3.5亿美元。", datetime(2026, 9, 25, tzinfo=UTC))
    it = pipeline.normalize(late, pipeline.BY_ID["panews"], datetime(2026, 11, 4, tzinfo=UTC))
    store.put_item(it)
    store.put_event(Event(event_id="ev_00000000000000b1", domain="web3", title=it.title, first_seen=it.published_at,
                          last_updated=it.published_at, item_ids=[it.item_id], keys=it.keys,   # evidence time, as live
                          timeline=[{"at": "2026-11-04T00:00:00Z", "kind": "created", "from": None, "to": "V0",
                                     "item_id": it.item_id}]))
    published = [pipeline.Event.from_dict(e) for e in store.events.values()]
    got = pipeline.split_candidates(store, datetime(2026, 11, 5, tzinfo=UTC), published)
    assert [g["newer"] for g in got] == ["ev_00000000000000b1"]
    # the store's own "updated since" query cannot see it (evidence time is September) — publish must pass its list
    assert pipeline.split_candidates(store, datetime(2026, 11, 5, tzinfo=UTC)) == []


def test_a_later_report_of_the_victim_with_a_matching_loss_is_the_same_theft():
    """Live 2026-11-05: Bitget's $387M theft (09-24) and 安全客's retrospective 「3.5亿美元一夜蒸发！…Bitget是怎么被掏空的」
    (09-29, outside the 3-day name window) were two events. Same victim + a loss within 20 % ⇒ same theft; a different
    loss is another theft of the same exchange and stays apart."""
    store = MemoryStore()
    _ingest(store, _raw("odaily", "Bitget热钱包被盗约3.87亿美元，涉及ETH与USDT", "Bitget热钱包被盗约3.87亿美元。",
                        datetime(2026, 9, 24, tzinfo=UTC)),
            _raw("panews", "3.5亿美元一夜蒸发！黑客没偷密钥，Bitget是怎么被掏空的，USDT", "Bitget热钱包被盗约3.5亿美元。",
                 datetime(2026, 9, 29, 16, tzinfo=UTC)))
    assert len(store.events) == 1
    _ingest(store, _raw("odaily", "Bitget遭攻击，热钱包被盗约1200万美元，USDT", "Bitget热钱包被盗约1200万美元。",
                        datetime(2026, 10, 10, tzinfo=UTC)))
    assert len(store.events) == 2


def test_a_similar_loss_does_not_join_another_victims_event():
    """Domain-plan diff 2026-11-05: 安全客's Bitget article ($350M) joined Liquid Network ($320M). Liquid's title is its
    structured record's, but one of its reports had Bitget in its OWN headline (a comparison), so the event held tt:bitget.
    The name must be the EVENT's victim (title / entity), not any headline word one of its reports used."""
    store = MemoryStore()
    rec = RawItem(source_id="defillama_hacks", url="https://defillama.com/hacks#Liquid", title="Liquid Network — Unbacked Cross-Chain Mint",
                  text="", published_at=datetime(2026, 9, 6, tzinfo=UTC), guid=None, author=None, links=[],
                  extra={"entity": "Liquid Network", "amount_usd": 320_000_000})
    pipeline.ingest([rec], store, datetime(2026, 9, 6, 1, tzinfo=UTC))
    _ingest(store, _raw("odaily", "Liquid Network跨链桥被盗3.2亿美元，手法与Bitget事件相似，USDT", "Liquid Network被盗3.2亿美元。",
                        datetime(2026, 9, 7, tzinfo=UTC)))
    assert len(store.events) == 1 and any(k == "tt:bitget" for e in store.events.values() for k in e["keys"])
    _ingest(store, _raw("panews", "3.5亿美元一夜蒸发！黑客没偷密钥，Bitget是怎么被掏空的，USDT", "Bitget热钱包被盗约3.5亿美元。",
                        datetime(2026, 9, 29, 16, tzinfo=UTC)))
    assert len(store.events) == 2


def test_a_similar_loss_does_not_join_an_unnamed_victims_event_through_a_word_of_one_report():
    """The same, for an event with no structured victim: there the name rule of find_events does not apply (it needs
    the event's entities), and only _same_loss_later's "the name is in the event's TITLE" keeps the late Bitget report
    out. CI 2026-11-13: with a structured victim the name rule decides first and this check's mutation survived."""
    store = MemoryStore()
    _ingest(store, _raw("panews", "Liquid Network跨链桥被盗3.2亿美元，USDT", "Liquid Network被盗3.2亿美元。", datetime(2026, 9, 6, tzinfo=UTC)))
    _ingest(store, _raw("odaily", "Liquid Network跨链桥被盗3.2亿美元，手法与Bitget事件相似，USDT", "Liquid Network被盗3.2亿美元。",
                        datetime(2026, 9, 7, tzinfo=UTC)))
    [ev] = store.events.values()
    assert not ev["entities"] and "Bitget" not in ev["title"] and "tt:bitget" in ev["keys"]
    _ingest(store, _raw("panews", "3.5亿美元一夜蒸发！黑客没偷密钥，Bitget是怎么被掏空的，USDT", "Bitget热钱包被盗约3.5亿美元。",
                        datetime(2026, 9, 29, 16, tzinfo=UTC)))
    assert len(store.events) == 2


def test_the_repair_gives_an_incident_report_its_amount_key():
    from radar.model import Item
    rc = _rc()
    it = Item(item_id="i", source_id="theblock", tier="T2", org="theblock", domain="incident", url="https://x",
              canonical_url="https://x", title="French bank Crédit Mutuel Arkéa exploited for over $133 million, ZachXBT says",
              text="", published_at="2026-11-04T04:57:00Z", fetched_at="2026-11-04T04:58:00Z", content_hash="c", keys=[],
              links=[], entity=None, eventful=True, signals={"amount_usd": None}, extra={})
    assert "amt:133000000" in rc.rekey(it).keys


def test_a_theft_from_years_ago_is_not_this_events_loss():
    assert dict(signals.amount_mentions("4 年前从 Pando Rings 项目被盗约 2200 万美元的黑客"))[22e6] == "context"
    assert dict(signals.amount_mentions("The hacker who stole $22 million from Pando Rings 4 years ago moved funds"))[22e6] == "context"
    assert dict(signals.amount_mentions("Pando Rings被盗约2200万美元"))[22e6] == "loss"


def _liquid(store):
    rec = RawItem(source_id="defillama_hacks", url="https://defillama.com/hacks#Liquid", title="Liquid Network — Unbacked Cross-Chain Mint",
                  text="", published_at=datetime(2026, 9, 6, tzinfo=UTC), guid=None, author=None, links=[],
                  extra={"entity": "Liquid Network", "amount_usd": 320_000_000})
    pipeline.ingest([rec], store, datetime(2026, 9, 6, 1, tzinfo=UTC))
    (ev,) = store.events
    return ev


def _decrypt(title, body, when):
    return _raw("decrypt", title, body, when)      # live: the body never repeats the headline's names


def test_a_title_case_follow_up_months_later_with_the_same_figure_is_the_same_theft():
    """Live 2026-11-03: Decrypt's 「Liquid Network Restores Full Bitcoin Backing Two Months After $320M Exploit」 — Title Case,
    its body never says Liquid, so the headline lost the name; 58 days on it was past the 30-day late-loss window too. It
    opened a second Liquid Network event ($320M twice in the loss ranking)."""
    store = MemoryStore()
    ev = _liquid(store)
    _ingest(store, _decrypt("Liquid Network Restores Full Bitcoin Backing Two Months After $320M Exploit",
                            "Blockstream CEO Adam Back said the sidechain's defenses have been hardened.",
                            datetime(2026, 11, 3, 11, tzinfo=UTC)))
    assert len(store.events) == 1 and len(store.events[ev]["item_ids"]) == 2


def test_a_close_but_not_equal_figure_months_later_is_another_theft():
    """±20 % still decides inside LATE_LOSS_DAYS; beyond it only the same figure (±2 %) does — a second theft of the
    victim months later is not the first one restated."""
    store = MemoryStore()
    _liquid(store)
    _ingest(store, _decrypt("Liquid Network Sidechain Drained Of $290M, Blockstream Says",
                            "Blockstream said attackers drained the sidechain bridge.", datetime(2026, 11, 3, 11, tzinfo=UTC)))
    assert len(store.events) == 2


def test_a_dropped_headline_word_finds_a_story_only_through_the_figure():
    """The extra ent: lookups are not names: a Title Case headline sharing only a word with a victim (no figure) stays
    apart, however close in time."""
    store = MemoryStore()
    _liquid(store)
    _ingest(store, _decrypt("Liquid Staking Protocol Drained Of $4.1M In Oracle Exploit",
                            "The protocol paused deposits after an oracle exploit drained $4.1 million from its vaults.",
                            datetime(2026, 9, 7, tzinfo=UTC)))       # inside the name window: a plain name would match
    assert len(store.events) == 2


def test_a_targeted_repair_can_keep_what_the_replay_split_off():
    """2026-11-14: repairing the 21-report FBI event, the default fold put the former agent's theft, the Binance suspect
    and a seizure back into the largest successor ("as it was") — right for a story that lost a report, wrong for an
    event that held several stories. --split says which it is."""
    from pathlib import Path
    src = (Path(__file__).parents[1] / "scripts" / "recluster_web3.py").read_text()
    assert "if args.event and not args.split:\n        fold_strays(" in src and '"--split", action="store_true"' in src


def test_the_attacker_losing_funds_is_not_the_victims_loss():
    """Audit 02 Q1 #11 (reproduced): after two reports of the $6.3B Binance theft, ZachXBT's 「Binance hacker just lost
    $2.1M of the stolen ETH to an MEV bot」 (T1) became the headline loss. Order matters: the victim losing to the hacker
    is still the loss."""
    assert signals.amount_mentions("Binance hacker just lost $2.1M of the stolen ETH to an MEV bot") == [(2_100_000.0, "context")]
    assert signals.amount_mentions("Users lost $5M to the hacker") == [(5_000_000.0, "loss")]
    assert [k for _, k in signals.amount_mentions("The exploiter stole $3M; the attacker lost $200K to MEV")] == ["loss", "context"]
    T = datetime(2026, 10, 29, 12, tzinfo=UTC)
    store = MemoryStore()
    _ingest(store, _raw("panews", "币安遭黑客攻击，损失约63亿美元", "币安遭黑客攻击，热钱包损失约63亿美元。", T),
            _raw("odaily", "币安热钱包被盗63亿美元", "据报道，币安热钱包被盗约63亿美元。", T.replace(hour=13)),
            RawItem(source_id="x_security", url="https://x.example/zach", title="Binance hacker just lost $2.1M of the stolen "
                    "ETH to an MEV bot", text="Binance hacker just lost $2.1M of the stolen ETH to an MEV bot.",
                    published_at=T.replace(hour=14), guid=None, author="zachxbt", links=[], extra={}))
    [ev] = store.events.values()
    assert ev["amount_usd_latest"] == 6_300_000_000
