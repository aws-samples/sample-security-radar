"""Rule-based signals from free text. M2 adds an LLM extractor on top; these rules stay as the floor and
as the regression oracle for it."""

from __future__ import annotations

import re
from collections.abc import Callable

from radar.limits import Limits
from radar.model import Exploited


def _memo_text(fn):
    """Memoise a pure text → amounts function. Live 2026-11-11: insights.progress replays every prefix of an event,
    so one page re-ran these regexes over the same report bodies k times (Publish: one page > 200 s, every cycle
    failed). Lists come back as fresh copies — callers may extend them."""
    import functools

    @functools.lru_cache(maxsize=8192)
    def cached(text):
        r = fn(text)
        return tuple(r) if isinstance(r, list) else r

    @functools.wraps(fn)
    def call(text):
        r = cached(text)
        return list(r) if isinstance(r, tuple) else r
    call.cache_info = cached.cache_info     # type: ignore[attr-defined]
    call.cache_clear = cached.cache_clear   # type: ignore[attr-defined]
    return call


# negations are checked first: "no evidence of exploitation in the wild" must be "no", not "yes"
_NEG = re.compile(
    r"\b(no (?:evidence|indication|reports?|known)\b[^.]{0,60}\b(?:exploit|in the wild|attack)"
    r"|not aware of (?:any )?(?:active )?(?:exploit|attacks?|in[- ]the[- ]wild|malicious)"
    r"|not (?:been |being )?(?:actively )?exploited"
    r"|has not been exploited"
    # live 2026-11-18: Cyberscoop on Java4Shell — 「No exploitation in the wild had been reported as of this article's
    # publication」 — read as exploited, and the event became a P0 the team channel received
    r"|no (?:active |known |confirmed )?exploitation\b[^.]{0,60}\b(?:reported|observed|seen|detected|known|confirmed)"
    r"|(?:none|no one|nothing)\b[^.]{0,60}\b(?:added to|listed in)\b[^.]{0,30}\b(?:KEV|Known Exploited)"
    # Tenable's Java4Shell FAQ, 11-17: 「we are not aware of any reports of exploitation …, and it is not listed in CISA's
    # Known Exploited Vulnerabilities (KEV) catalog」 — 「Known Exploited」 was read as exploited
    r"|not aware of (?:any )?(?:public )?reports? of (?:active )?exploitation"
    # ZDI's monthly review: 「None of the other Adobe bugs … are listed as publicly known or under active attack」
    r"|\b(?:none|no)\b[^.]{0,100}\b(?:under active attack|actively exploited|exploited in the wild)"
    r"|\bnot (?:been |yet )?(?:listed|included|added)\b[^.]{0,40}\b(?:KEV|Known Exploited))"
    r"|未(?:发现|监测到|观察到)[^。]{0,10}在野|暂无在野"
    # an advisory's status table: 「在野利用状态 未发现」 is a field name followed by "not found" (live 2026-11-11: 奇安信's
    # Apache HTTP/2 advisory read as exploited in the wild, T1 ⇒ P0)
    r"|在野利用(?:状态|情况)?\s*[:：]?\s*(?:未发现|未知|暂无|无\b|否)",
    re.IGNORECASE,
)
_YES = re.compile(
    r"\b(exploited in the wild|actively exploited|active exploitation|under active attack"
    r"|exploits? (?:for [^.]{0,60} )?exists? in the wild|exploitation in the wild"
    r"|may have been exploited|limited,? (?:and )?targeted attacks?|observed (?:being )?exploited"
    r"|exploited as a zero-?day|zero-?day (?:attacks?|exploited)|known exploited"
    # 「QNAP Warns Users as Plex2Shell Flaws Are Used to Hack NAS Devices」: a headline that says the flaws are in use
    r"|(?:are|were|is|was|being|been) (?:actively )?used (?:to|in attacks to) (?:hack|attack|breach|compromise|hijack))\b"
    r"|Exploited:Yes|在野利用|已被(?:黑客)?利用|已发现在野",
    re.IGNORECASE,
)
_POC = re.compile(r"\b(proof[- ]of[- ]concept|PoC (?:exploit|released|published|available)|exploit code (?:released|published))\b"
                  r"|PoC已公开|POC公开|公开了?(?:PoC|POC|利用代码)", re.IGNORECASE)

# the loss words: on their own they make an incident only outside a result / position / valuation (web3_incident).
# The theft words are _THEFT, next to web3_incident — one list, not two (two copies left M162 / M1347 testing a dead one)
_LOSS_WORD_INCIDENT = re.compile(r"\b(?:loss|lost)\b|损失", re.IGNORECASE)
_SEC_EVENT = re.compile(
    r"\b(zero-?day|0-?day|ransomware|data breach|breach(?:ed)?|hack(?:ed)?|exploit(?:ed|ation)?|backdoor"
    r"|supply[- ]chain attack|malware|leak(?:ed)?|vulnerabilit(?:y|ies)|RCE|remote code execution)\b"
    r"|(?<![A-Za-z0-9])CVE-\d{4}"     # lookbehind, not \b: a CVE next to Chinese text (「厂商发布CVE-2026-1234修复」)
    r"|漏洞|勒索|泄露|攻击|在野|被黑|入侵",
    re.IGNORECASE,
)

_AMOUNT = re.compile(
    # 「$137 万」 / 「$1.2 亿」: a dollar sign with a Chinese unit (live 2026-11-13: a tweet's 「滑点损失 $137 万」 read as
    # $137 and, being T1, replaced the event's $1.37M headline). 万 / 亿 end a number without a word boundary before 美元.
    r"(?:US)?\$\s?~?\s?([0-9][0-9,]*(?:\.[0-9]+)?)\s*(k|thousand|m|mn|million|b|bn|billion|万|亿)?(?:\b|(?<=[万亿]))"
    r"|([0-9][0-9,]*(?:\.[0-9]+)?)\s*(万|亿)?\s*美元"
    # a dollar stablecoin is dollars (live 2026-11-16, Lighter: 「提取约 1039 万 USDC」 / 「约 1039 万 USDC 被转出」 named no
    # amount, so the first two reports opened no event and their name never reached the one that formed later)
    r"|(?<![A-Za-z0-9.,])([0-9][0-9,]*(?:\.[0-9]+)?)\s*(k|thousand|m|mn|million|b|bn|billion|万|亿)?\s*枚?\s*"
    r"(?:USDC|USDT|DAI|FDUSD|USDe|PYUSD|BUSD)(?![A-Za-z0-9])"
    # 「Bitget Loses USD 351.6 Million」 (TRM, live 2026-11-05: no amount, so the theft stayed a separate event)
    r"|\bUSD\s?~?\s?([0-9][0-9,]*(?:\.[0-9]+)?)\s*(k|thousand|m|mn|million|b|bn|billion)?\b",
    re.IGNORECASE,
)
_MULT = {"k": 1e3, "thousand": 1e3, "m": 1e6, "mn": 1e6, "million": 1e6, "b": 1e9, "bn": 1e9, "billion": 1e9,
         "万": 1e4, "亿": 1e8}


# Which measure an amount in a report is (live 2026-10-30, the Binance theft: one headline number mixed the loss with
# freezes, borrows / sales inside the story and an estimate of user assets). Frozen wins over context, context over loss;
# a headline with neither cue is a loss figure. Decided on the report's title — that is where 快讯 / tweets state what the
# number is.
_FROZEN = re.compile(r"\b(?:froze|frozen|freez\w*|blacklist\w*|recover(?:ed|s)?|seiz(?:ed|ure)|returned)\b"
                     r"|冻结|追回|返还|归还|没收", re.IGNORECASE)
# 「（未扣除已冻结及返还资金）」 says the number is *before* freezes: the negated phrase is removed before any cue is read
# (live 2026-11-01, PANews' monthly roundup — its yearly total read as a freeze)
_NEGATED = re.compile(r"(?:未扣除|不含|未计入|不包括|扣除前|before|excluding|not including)[^，。；;,)）]{0,24}", re.IGNORECASE)

# An industry roundup ("10月加密行业重大黑客事件达56起，损失达64.8亿美元", "Crypto hacks in October: $6.5B") reports
# statistics across incidents: none of its amounts is the event's loss or freeze (live 2026-11-01: its yearly $8.6B
# total became the Binance frozen headline). Decided on the title.
_ROUNDUP = re.compile(
    r"\d+\s*起|(?:月度|年度|季度|上半年|下半年|全年|今年|年内|本月|本周|周报|月报)|(?:\d{1,2}|[一二三四五六七八九十]+)月[^，。]{0,8}(?:黑客|攻击|安全)事件"
    r"|\b(?:monthly|weekly|quarterly|year-to-date|ytd|roundup|recap|this year|so far in 20\d\d)\b"
    r"|\b(?:hacks?|exploits?|losses)\b[^.]{0,40}\bin (?:january|february|march|april|may|june|july|august|september|october"
    r"|november|december|q[1-4]|20\d\d)\b|\b\d+\s+(?:hacks|exploits|incidents)\b"
    # live 2026-11-11: 「#CertiKStatsAlert 🚨 In October we've confirmed ~$6.5B lost to exploits」 — a month's tally that
    # became a $9.2B "incident" at the top of the loss ranking
    r"|\bin (?:january|february|march|april|may|june|july|august|september|october|november|december|q[1-4])\b"
    r"[^.]{0,60}\blost to (?:hacks?|exploits?|scams?|attacks?)\b|#\w*stats\w*alert", re.IGNORECASE)


@_memo_text
def is_roundup_report(title: str | None) -> bool:
    return bool(_ROUNDUP.search(title or ""))


# A digest tells several stories under one headline: a weekly newsletter, a bulletin, a Patch Tuesday review, a market
# wrap. It is not a report OF an event (roadmap R8.3). In one week digests were the largest single source of wrong
# events: a bulletin lent the Apache event a $26M email scam and an "exploited" that was about Outlook; a newsletter
# naming two CVEs opened a P0 of its own; a threat-intelligence weekly merged unrelated incidents.
# "Security Bulletin" alone is a vendor's advisory (Android, NVIDIA, AWS) and is not matched.
_DIGEST_TITLE = re.compile(
    # "newsletter" / "weekly" as what the piece IS, not as its subject (「SEGA newsletter data breach」, 「Weekly Loss」)
    r"\bnewsletter\s*(?:round|edition|issue|#|\d|[:–-])|\b(?:weekly|monthly|daily) (?:newsletter|recap|roundup|round-up"
    r"|digest|review|report|update|threat|security|intel\w*)\b|\bweek in (?:security|review)\b|\bthis week in\b"
    r"|\b(?:roundup|round-up|recap|month in review|patch tuesday|threat intelligence report|security update review)\b"
    r"|\b(?:news|security|threat) digest\b|^(?:srsly )?risky (?:bulletin|biz|business)\b"
    r"|(?:安全|威胁|情报|漏洞|行业)(?:日报|周报|月报)|周报|要闻一览|要闻速览|(?:^|[：:｜|\s])(?:加密)?[早晚]报"
    r"|一周(?:安全)?(?:回顾|速览|盘点|要闻)|本周(?:安全)?(?:回顾|速览|要闻)"
    # daily round-ups (R1.6, live 2026-11-15: 「每日安全动态推送(26/11/9)」 chained an OpenSSH event to a Linux TCP CVE and
    # an APT flaw — one CVE key to one story, one name key to another)
    r"|每日(?:安全)?(?:动态|简讯|简报|资讯|速递|推送|情报)|安全(?:动态|资讯)(?:推送|汇总|速递)"
    # industry statistics across incidents (R1.3, corpus story "ark-report": ARK Invest's 「自2017年以来加密行业因黑客攻击
    # 累计损失约269亿美元」 joined the Binance event through a body mention — 8 of its 15 reports)
    r"|累计损失|行业(?:累计|全年|总)?损失|自\s*20\d\d\s*年(?:以)?来|首超链上收入"
    r"|\bhack(?:ing)? losses (?:head|equal|hit|exceed|surpass|top)|\bsince 20\d\d\b[^.]{0,40}\blosses\b",
    re.IGNORECASE)
# a newsletter whose headline says nothing ("Never be afraid to ask questions"): it introduces itself in its opening
_DIGEST_LEAD = re.compile(r"this week'?s (?:edition|newsletter|episode)|welcome to this week|threat source newsletter", re.IGNORECASE)


def is_digest(title: str | None, text: str | None = None) -> bool:
    return bool(_DIGEST_TITLE.search(title or "") or _DIGEST_LEAD.search((text or "")[:600]))


def digest_kind(title: str | None, text: str | None = None) -> str | None:
    """What kind of digest: the phrase that makes it one, as a slug ("patch-tuesday", "weekly-recap", "newsletter").
    Two digests are the same thing only if they are the same kind (pipeline._digest_keys adds who and when)."""
    m = _DIGEST_TITLE.search(title or "") or _DIGEST_LEAD.search((text or "")[:600])
    if not m:
        return None
    slug = re.sub(r"[^a-z0-9\u4e00-\u9fff]+", "-", m.group(0).lower()).strip("-")
    return "newsletter" if "newsletter" in slug or "edition" in slug or "this-week" in slug else slug
_CONTEXT = re.compile(
    r"\b(?:liquidat\w*|short(?:ed|ing|s)?|long(?:ed|s)?|profit\w*|arbitrag\w*|reserves?|market cap|volume|borrow\w*"
    r"|sold|sell(?:s|ing)?|dump\w*|swap\w*|holds?|holding"
    # a company's accounts, not a theft (live 2026-11-11: 「Bitmine posts $6.3B net loss for fiscal 2026」 read as a
    # $6.3B Web3 loss; Bitdeer's Q3 「net loss widens to $125.5 million」 likewise)
    r"|net loss\w*|operating loss\w*|unrealized|impairment\w*|revenue|earnings|fiscal|净亏损|未实现|浮亏|减值|营收|财报"
    # the victim's size, not its loss (live 2026-11-04: 「该行资产规模达2350亿美元」 became a $235B Web3 loss)
    r"|in assets|assets under management|AUM|TVL|total value locked|valuation|valued at|raised|funding"
    # the attacker spending / moving stolen funds — a part of the loss, never the loss (Pando: 「买入7548枚ETH，约合1672万」)
    r"|bought|buys?|buying|purchas\w*|launder\w*|tornado"
    # a demand or a unit price, not money lost (GMO: 「约80亿日元（约合5070万美元）的赎金要求」; 「均价2280.34美元」)
    r"|ransom\w*|average price|per (?:ETH|BTC|token|coin)|stakes?|shares|customer assets"
    # users withdrawing, not the attacker (「Binance net outflows surge to $5.8B as withdrawals resume」)
    r"|net (?:out|in)flows?)\b"
    r"|爆仓|做空|做多|浮盈|获利|盈利|套利|用户资产|储备|市值|交易量|借出|抛售|售出|卖出|兑换|换成|持有"
    r"|资产规模|资产总额|总资产|管理资产|管理规模|锁仓|估值|融资|买入|购入|抄底|洗走|洗钱|混币|Tornado|转移"
    r"|赎金|勒索金|均价|单价|价格|每枚|净流出|净流入|股份|股权|托管资产"
    # an old theft retold — the hacker of 「4 年前从 Pando Rings 项目盗取约 2200 万美元」 is moving funds now; that loss
    # is history, not this event's (live 2026-11-05: #6 on the wall's loss ranking)
    r"|(?:\d+|[一二三四五六七八九十两]+)\s*年前|\d+\s+years?\s+ago", re.IGNORECASE)


# an amount stated *as* the loss beats a context word elsewhere in a tweet ("$NEM Loss: ~$821,920 … as sell volume")
_LOSS_STATED = re.compile(r"\bloss:?\s*~?\s*\$|\b(?:lost|stolen|drained|exploited for|hacked for)\b[^.]{0,24}\$"
                          r"|\$\s?[0-9][0-9,.]*\s*(?:k|m|mn|b|bn|million|billion)?\b[^.]{0,30}\b(?:stolen|drained)\b"
                          r"|(?:被盗|损失|盗走|转走|(?<!净)流出|遭窃|失窃)(?:约|超过?|逾|达|近)?\s*[0-9]"
                          # a few words may sit between (「盗走欧盟实体1.06亿美元资金」) — then the number must be dollars and
                          # the gap no trade / ratio (「被盗关联地址已售出约470万枚UNI」, 「损失占用户资产比例为1.6%」)
                          r"|(?:被盗|损失|盗走|遭窃|失窃)[^，。；;0-9售卖买兑换借持占比]{1,8}?(?:约|超过?|逾|达|近)?\s*"
                          r"[0-9][0-9,.]*\s*(?:万|亿)?美元", re.IGNORECASE)




# a report saying the victim was hit AGAIN is a new incident (live 2026-11-11: 「Initia confirms second exploit in 3
# weeks, $3.27M stolen」 joined the 10-23 Initia event by name while the 11-10 one stood alone)
_REPEAT = re.compile(r"\b(?:second|another|new|fresh|third|latest)\s+(?:\w+\s+){0,2}(?:exploit|hack|attack|breach|incident|drain)s?\b"
                     r"|\b(?:hacked|exploited|attacked|drained|breached)\s+again\b|再次|又一次|第二次|第三次|又遭|再度", re.IGNORECASE)


def repeat_incident(title: str | None) -> bool:
    return bool(_REPEAT.search(title or ""))


@_memo_text
def amount_kind(text: str | None) -> str:
    """'frozen' | 'context' | 'loss' for the amount a report states: frozen > stated loss > context > loss."""
    t = _NEGATED.sub("", text or "")
    if _FROZEN.search(t):
        return "frozen"
    if _ATTACKER_LOSS.search(t):
        return "context"
    if _LOSS_STATED.search(t) or not _CONTEXT.search(t):
        return "loss"
    return "context"


# Shared text helpers. The attack-stage rules that lived here (phase / PHASES) moved to radar.stages, the one stage enum.
_A = r"(?<![A-Za-z0-9])"          # ASCII lookarounds: \b never fires next to CJK text
_Z = r"(?![A-Za-z0-9])"
_CLAUSE = re.compile(r"[，,；;。：:！？!?\n]|\.(?=\s)")


_ACTORS = ((re.compile(_A + r"(?:North Korea\w*|DPRK|Lazarus|TraderTraitor|BlueNoroff|APT38)" + _Z + r"|朝鲜", re.IGNORECASE),
            "North Korea (Lazarus / TraderTraitor)"),)


# A denial or rebuttal of the link names nobody (04-reconstruction B1: a T1/T2 「No evidence links the hack to North
# Korea」 showed 「归因 North Korea · 已点名」). Two reaches:
# - a rebuttal ("no evidence", "rejects blame", 辟谣 …) is about the attribution itself, so it voids its whole sentence:
#   in 「no evidence, as of today, links … to Lazarus」 the actor sits in a later clause than the negation;
# - a plain negation ("unrelated", "denied", "not tied", 无关, 并非 …) is about whatever its clause says, so it voids only
#   that clause: 「朝鲜黑客组织Lazarus所为，与此前Phemex事件无关」 and "Lazarus behind the hack, says ZachXBT, who denied any
#   role of insiders" still name Lazarus (review of p0/signals: the sentence-wide reach lost both).
# not 未发现 / 不是: 「…或涉朝鲜，未发现私钥泄露」 denies something else in the same clause
_REBUTTAL = re.compile(_A + r"(?:no evidence|rejects? (?:blame|claims?|reports?|attribution)|rebut\w*|refut\w*"
                       r"|no (?:link|connection))" + _Z + r"|驳斥|辟谣|没有证据", re.IGNORECASE)
_NEGATION = re.compile(_A + r"(?:not (?:related|linked|connected|tied|involved|responsible|behind)|unrelated"
                       r"|den(?:y|ies|ied))" + _Z + r"|否认|无关|并非", re.IGNORECASE)
_SENTENCE = re.compile(r"[。！？；;!?\n]|\.(?=\s)")


def _strip_denials(text: str) -> str:
    return "\n".join(c for s in _SENTENCE.split(text) if not _REBUTTAL.search(s)
                     for c in _CLAUSE.split(s) if not _NEGATION.search(c))


@_memo_text
def attribution_actor(text: str | None) -> str | None:
    """A named threat actor the text attributes the incident to — a linkage ("same attacker as …") is not an actor, nor
    is a sentence denying the link."""
    text = _strip_denials(text or "")
    return next((name for rx, name in _ACTORS if rx.search(text or "")), None)


# an FAQ heading asks, it does not say: 「Has Java4Shell been exploited in the wild?」 (Tenable, 11-17 — answered "no")
_QUESTION = re.compile(r"(?i)^\s*(?:has|have|is|are|was|were|do|does|did|can|could|will|would)\b[^.!]{0,160}?(?:\?|$)")


def _exploited_sentence(text: str) -> Exploited:
    if _NEG.search(text):
        return "no"
    if _QUESTION.match(text):
        return "unclear"
    return "yes" if _YES.search(text) else "unclear"


# Path A to P0 (Neo 2026-11-18: 「爆出来就应该挺重要」, 「CVSS ≥ 9 或明确未认证 RCE」): a sentence that says the flaw is
# critical — an unauthenticated / pre-auth remote code execution, or a CVSS base score of 9.0–10.0
_CRITICAL = re.compile(
    r"(?i)\b(?:unauthenticated|pre-?auth(?:entication)?|without (?:any )?authentication|no authentication)\b[^.]{0,80}?"
    r"\b(?:remote code execution|RCE|arbitrary code execution|code execution)\b"
    r"|\b(?:remote code execution|RCE)\b[^.]{0,40}?\b(?:unauthenticated|pre-?auth(?:entication)?|without (?:any )?authentication)\b"
    r"|(?:未认证|无需认证|免认证|未经身份验证|无需身份验证)[^。]{0,30}?(?:远程代码执行|代码执行|RCE)"
    r"|\bCVSS(?:\s*v?[234](?:\.\d)?)?(?:\s*base)?(?:\s*score)?(?:\s*of)?\s*[:：]?\s*(?:9\.\d|10(?:\.0)?)\b"
    # 「a critical 9.8-rated flaw」, 「rated 9.8 out of 10」, 「severity score of 9.8」 (live 2026-11-19: the vCenter tweet
    # "A critical 9.8-rated VMware vCenter flaw" was not read as critical — only 「CVSS 9.8」 was)
    r"|(?<![\d.])(?:9\.\d|10(?:\.0)?)[- ]rated\b"
    r"|\brated (?:a )?(?:9\.\d|10(?:\.0)?)(?:\s*(?:/|out of)\s*10)?(?![\d.])"
    r"|\bseverity (?:score|rating) of (?:9\.\d|10(?:\.0)?)(?![\d.])")
# 「does not allow unauthenticated RCE」 / 「requires authentication」 next to it is not the claim
_CRITICAL_NEG = re.compile(r"(?i)\b(?:does not|doesn't|cannot|can't|not)\s+(?:allow|lead to|enable|permit)\b"
                           r"|\brequires? (?:prior |valid )?authentication\b")


def _critical_sentence(text: str) -> Exploited:
    if not _CRITICAL.search(text):
        return "unclear"
    return "no" if _CRITICAL_NEG.search(text) else "yes"


def critical_about(title: str, text: str, own_cves: set[str], event_cves: set[str]) -> bool:
    """Does this report say THE EVENT's flaw is critical (unauthenticated RCE, or CVSS ≥ 9)? Attributed to the event the
    way exploited_about attributes 「exploited」 — a newsletter's sentence about another bug is not this event's."""
    return bool(_claim_about(_critical_sentence, title, text, own_cves, event_cves))


def exploited_about(title: str, text: str, own_cves: set[str], event_cves: set[str]) -> bool:
    """Does this report say that THE EVENT's vulnerability is being exploited? `exploited()` answers for a text; a text
    is often about several things. Live 2026-11-14, three P0s: a disclosure-policy post (its sentence about "actively
    exploited" bugs in general), a newsletter attached to the Apache event through one CVE (its exploited sentence was
    about another story), a weekly digest. The claim counts when its sentence
      - names a CVE of the event; or
      - is the headline; or
      - names no CVE, and the report is about this event only (every CVE it names is the event's); or
      - names no CVE in a report that names none at all, and the sentence shares a name with the headline
        ("SignDrop … exploited" under a SignDrop headline — not a remark in a policy essay)."""
    if (said := _claim_about(_exploited_sentence, title, text, own_cves, event_cves, decide=False)) is not None:
        return said
    # No sentence here says it, yet the report was judged "exploited": the sentence lies beyond the stored text (items
    # keep Limits.ITEM_TEXT_MAX characters), or the judgement predates a rule. Only the first is believed — a text that
    # was not cut is all there is unless today's rule reads the whole text as exploited (a headline 「Flaws Are Used to
    # Hack…」) — live 2026-11-18: Tenable's 3,470-character Oracle patch-day post, judged "exploited" by an older rule,
    # made Java4Shell 「有在野利用报道」 and posted a thread reply nobody's sentence supports.
    whole = exploited(f"{title or ''}\n{text or ''}")
    return (whole == "yes" or (whole != "no" and len(text or "") >= Limits.ITEM_TEXT_MAX)) and own_cves <= event_cves


def _claim_about(sentence: Callable[[str], str], title: str, text: str, own_cves: set[str], event_cves: set[str],
                 decide: bool = True) -> bool | None:
    """The attribution rule both claims share (see exploited_about). decide=False ⇒ None when no sentence makes the
    claim (the caller has a fallback)."""
    head = {t for t in re.findall(r"[A-Za-z][A-Za-z0-9]{3,}", title or "")}
    found = False
    for n, s in enumerate([title or "", *_SENTENCE.split(text or "")]):
        if sentence(s) != "yes":
            continue
        found = True
        named = {f"CVE-{y}-{m}" for y, m in _CVE.findall(s)}
        if named:
            # an event nobody gave a CVE yet (a media report whose CVE is not a key) has nothing to contradict the claim
            if named & event_cves or not event_cves:
                return True
            continue
        if n == 0 or (own_cves and own_cves <= event_cves):
            return True
        if not own_cves and head & set(re.findall(r"[A-Za-z][A-Za-z0-9]{3,}", s)) - _HEAD_COMMON:
            return True
    if found:
        return False
    return False if decide else None


_CVE = re.compile(r"(?<![A-Za-z0-9])CVE-(\d{4})-(\d{4,7})(?![A-Za-z0-9])", re.IGNORECASE)   # = keys.CVE_RE (keys imports nothing)
# words a headline and any sentence share without naming anything
_HEAD_COMMON = frozenset(["Vulnerability", "Vulnerabilities", "Security", "Exploit", "Exploited", "Exploits", "Attack",
                          "Attacks", "Attackers", "Zero", "Critical", "Update", "Updates", "Advisory", "Patch", "Flaw",
                          "With", "From", "That", "This", "Have", "Been", "Will", "Edition", "Policy"])


def exploited(text: str) -> Exploited:
    """Judged per sentence: a negation in one ("no evidence of exploitation for the other bugs") does not cancel "actively
    exploited" in another (07-code-quality B5: Patch Tuesday roundups read as not exploited). Within a sentence the
    negation still wins."""
    if not text:
        return "unclear"
    verdicts = {_exploited_sentence(s) for s in _SENTENCE.split(text)}
    return "yes" if "yes" in verdicts else "no" if "no" in verdicts else "unclear"


def poc(text: str) -> bool:
    return bool(_POC.search(text or ""))


# A loss that is not an incident: a company's result, a trader's position, a holding's mark-to-market. Live 2026-11-16
# the loss board's top three non-Binance rows were these — 「BitMine … $8.83 billion loss」 (unrealised), 「Whale … closing
# his long … at a $2.45M loss」, 「Dunamu Swings to $13.8 Million Q3 Net Loss」 — each became a "Web3 theft" because the
# word "loss" alone made one. Only a theft word makes such a text an incident.
_NOT_INCIDENT_LOSS = re.compile(
    r"\b(?:net|operating|quarterly|annual|Q[1-4]|unreali[sz]ed|paper|trading)\s+(?:\w+\s+)?loss(?:es)?\b"
    r"|\bfirst\s+operating\s+loss\b|\bswings?\s+to\b[^.]{0,40}\bloss\b"
    r"|\bclos(?:es|ed|ing)\s+(?:his|her|their|its|a|the)\s+(?:\w+\s+)?(?:long|short)\b|\bat\s+a\s+\$?[\d.,]+\s*[KMB]?\s+loss\b"
    r"|\bworst\s+asset\b|净亏损|经营亏损|营业亏损|季度亏损|财报|浮亏|账面亏损|平仓"
    # a market move: 「Nasdaq closes with 2.5% loss」 (CoinDesk live updates, 2026-11-16, in Dunamu's event)
    r"|\b\d+(?:\.\d+)?\s?%\s+(?:\w+\s+)?loss(?:es)?\b|跌幅"
    # a liquidated position: 「Machi … got liquidated again」, 「多头仓位…遭完全清算，损失1769万美元」 (live, 2026-11)
    r"|\bliquidat(?:ed|ion|ions)\b|爆仓|强平|遭(?:完全)?清算|仓位[^，。]{0,12}清算"
    r"|\b(?:leveraged\s+)?(?:long|short)\s+positions?\b|杠杆(?:多|空)单",   # 「Machi … to fund leveraged long positions」
    re.IGNORECASE)
# stole / steals / theft / heist: 「North Korean hackers stole $1.5 billion from Bybit」 was not an incident headline;
# 黑客: 「冻结币安黑客约3050万美元」
_THEFT = re.compile(
    r"\b(drained|exploit(?:ed)?|hack(?:ed)?|stolen|stole|steals?|theft|heist|attack(?:ed|er)?|compromis(?:e|ed)|rug ?pull"
    r"|drainer|(?<=[\dKMBkmb] )drains?|drains? (?:on|of|from)|draining|phishing|private key|flash ?loan|breach(?:ed)?|security incident|(?:key|api|credential)s? leak(?:ed|s)?"
    r"|leak(?:ed)? (?:api |private )?keys?)\b|被盗|被黑|攻击|漏洞|盗取|黑客|安全事件|泄露",
    re.IGNORECASE)   # breach / security incident: 「Lighter Halts Withdrawals After $15.5M Security Breach」 was no incident


def web3_incident(text: str) -> bool:
    """A theft word, or a loss word in a text that is not about a result, a position or a valuation."""
    t = text or ""
    if _THEFT.search(t):
        return True
    return bool(_LOSS_WORD_INCIDENT.search(t)) and not _NOT_INCIDENT_LOSS.search(t)


def security_event(text: str) -> bool:
    return bool(_SEC_EVENT.search(text or ""))


def _amount_spans(text: str):
    """(value, start, end) of every amount in text."""
    for m in _AMOUNT.finditer(text):
        num, unit = next(((m.group(i), m.group(i + 1)) for i in (1, 3, 5, 7) if m.group(i)), (None, None))
        if not num:
            continue
        try:
            v = float(num.replace(",", ""))
        except ValueError:
            continue
        yield v * _MULT.get((unit or "").lower(), 1.0), m.start(), m.end()


def _amounts_in(text: str):
    for v, _, _ in _amount_spans(text):
        yield v


def parse_amount(text: str | None) -> float | None:
    """'$ 90,500' → 90500; '~$90.5K' → 90500; '$387.5 million' → 3.875e8; '3.2 亿美元' → 3.2e8; '-' → None.
    Returns the largest amount mentioned (loss headlines put the total first, but tweets add sub-amounts)."""
    return max(_amounts_in(text), default=None) if text else None


# 「约63亿美元被盗」 is the loss; 「已冻结约30亿美元被盗资产」 is a freeze OF stolen assets — 被盗 there modifies the noun
_STOLEN_AFTER = re.compile(r"\s*(?:in\s+)?(?:stolen|lost|drained|theft|heist|hack(?:ed)?|exploit(?:ed)?)\b(?!\s+(?:funds|assets|tokens|coins))"
                           # 「the record $6.3 billion Binance hack」 / 「$6.43 billion Binance crypto heist」: a name or two between
                           r"|\s+(?:[A-Za-z][\w.'-]*\s+){1,3}(?:hack|heist|theft|exploit)\b"
                           r"|\s*(?:被盗|损失|失窃)(?!的?(?:资产|资金|代币|币|款))", re.IGNORECASE)


@_memo_text
def stated_losses(text: str | None) -> list[float]:
    """Body amounts whose own clause STATES a loss (被盗 / 损失 / stolen / drained …). A body sentence without any cue is
    not a loss by default — a headline is about the event, a body sentence often is not (live 2026-11-04, Binance:
    「币安托管资产约1440亿美元」, 「USDT 下降至341亿美元」, 「TVL…低于3000亿美元」, 「$171 billion in customer assets」)."""
    out = []
    for c in _CLAUSE.split(_NEGATED.sub("", text or "")):
        spans = list(_amount_spans(c))
        for i, (v, a, b) in enumerate(spans):
            lo = spans[i - 1][2] if i else 0
            hi = spans[i + 1][1] if i + 1 < len(spans) else len(c)
            # an amount the next words call stolen is the loss, whatever the rest of the clause says (live 2026-11-11:
            # 「$2.85 billion of the $6.43 billion stolen from Binance has been frozen」 and 「accounts tied to the $6.3 billion
            # theft」 made $6.43B / $6.3B freezes — Binance's frozen total exceeded its loss)
            own = "loss" if _STOLEN_AFTER.match(c, b) else _stretch_kind(c[lo:hi])   # stated_losses
            if own == "loss" or (own is None and (_LOSS_STATED.search(c) or _LOSS_WORD.search(c))
                                 and not _CONTEXT.search(c) and not _FROZEN.search(c)):
                out.append(v)
    return out


def loss_amount(title: str | None, text: str | None) -> float | None:
    """The amount a prose report states as the loss: the largest loss in its headline (a headline figure without a cue is
    the loss — that is what 快讯 headlines are), else the largest loss its body states (stated_losses); None when it
    states none. Live 2026-11-04: the largest number in 「损失超1.33亿美元的…银行…该行资产规模达2350亿美元」 is the bank's
    size, and the radar showed a $235B Web3 loss."""
    # the headline decides when it states a loss (the docstring's rule; the code took the max over headline AND body —
    # live 2026-11-16: Protos 「Abraxas may have lost $17M in Lighter API leak」 became $6B from its body, Unchained's
    # 「$15M Lost」 $388M, and the Lighter event's figure followed the latest report to $6.00B)
    head = [v for v, k in amount_mentions(title) if k == "loss"]
    body = stated_losses(text)
    if head:
        # … unless the body states the same figure more precisely ("$5.5 Billion" in the title, "$5.57 billion" below)
        close = [b for b in body if any(abs(b - h) <= Limits.AMOUNT_REFINE_RATIO * h for h in head)]
        return max(close or head)
    if body:
        return max(body)
    # no stated loss: the report's own figure still matters as another measure (「Tether冻结9.71亿美元」, 「用户资产约
    # 1651.2亿美元」) — pipeline._amounts decides which; a body figure no clause states as a loss is never one
    return max((v for v, _ in amount_mentions(title)), default=None) or parse_amount(text)


# Clause breaks for amount_mentions: CJK punctuation, ; ! ?, a comma not inside a number ("$5,800,000"), a full stop
# followed by a space (not a decimal point).
_CLAUSE = re.compile(r"[，；。！？;!?]|,(?!\d)|\.(?=\s)")


_LOSS_WORD = re.compile(r"\b(?:hack\w*|stolen|drain\w*|lost|loss(?:es)?|impact|exploit\w*|theft)\b|被盗|损失|盗走|黑客",
                        re.IGNORECASE)


_CONVERSION = re.compile(r"\s*(?:约合|折合|约值|价值约?|合计约?|相当于|约为|worth|valued at|≈|~)", re.IGNORECASE)


# the attacker LOSING funds is not the victim's loss (audit 02 Q1 #11: ZachXBT 「Binance hacker just lost $2.1M of the
# stolen ETH to an MEV bot」 replaced the $6.3B headline). It outranks "lost … $" and "… stolen" (both read as the loss).
# Order matters: 「users lost $5M to the hacker」 stays a loss — the attacker must be the one who lost.
_ATTACKER_LOSS = re.compile(r"\b(?:hacker|attacker|exploiter|thief|scammer)s?\b[^.,;:]{0,20}?\b(?:just\s+)?(?:lost|loses|losing)\b"
                            r"|(?:黑客|攻击者)[^，。,]{0,8}(?:亏损|损失了|亏掉)", re.IGNORECASE)
_HISTORIC = re.compile(r"(?:\d+|[一二三四五六七八九十两]+)\s*年前|\d+\s+years?\s+ago", re.IGNORECASE)


def _stretch_kind(span: str) -> str | None:
    """Measure stated in one amount's own stretch of text, None when it states none (amount_kind precedence)."""
    span = _NEGATED.sub("", span)
    if _FROZEN.search(span):
        return "frozen"
    if _ATTACKER_LOSS.search(span):
        return "context"
    if _HISTORIC.search(span):           # 「4 年前…被盗约2200万美元」: a past theft, even when stated as a loss
        return "context"
    if _LOSS_STATED.search(span):
        return "loss"
    if _CONTEXT.search(span):
        return "context"
    return "loss" if _LOSS_WORD.search(span) else None


@_memo_text
def amount_mentions(text: str | None) -> list[tuple[float, str]]:
    """Every amount in a report with its own measure. Live 2026-10-30: 「损失约63亿美元，已冻结约30亿美元资产」 judged as
    one text was "frozen", and its largest number — the $6.3B loss — became the frozen headline; The Defiant's "estimates
    the impact at $6.3 billion and says about $3 billion has been frozen" has both inside one clause. An amount reads the
    text between its neighbours in its clause; when that states no measure ("froze $500M and $200M"), the clause's."""
    out: list[tuple[float, str]] = []
    clauses = _CLAUSE.split(text or "")
    for n, c in enumerate(clauses):
        spans = list(_amount_spans(c))
        # 「买入7548枚ETH，约合1672万美元」: a clause that only converts another one into dollars states no measure of its
        # own — it inherits the previous clause's, or, leading a headline (「价值约922万美元，…通过Tornado转移」), the next
        # one's (live 2026-11-04, Pando Rings: the purchase and the laundering read as the loss)
        ref = clauses[n - 1] if n else (clauses[1] if len(clauses) > 1 else "")
        whole = (_stretch_kind(ref) or amount_kind(ref)) if ref and _CONVERSION.match(c) else amount_kind(c)
        for i, (v, a, b) in enumerate(spans):
            lo = spans[i - 1][2] if i else 0
            hi = spans[i + 1][1] if i + 1 < len(spans) else len(c)
            # an amount the next words call stolen is the loss, whatever the rest of the clause says (live 2026-11-11:
            # 「$2.85 billion of the $6.43 billion stolen from Binance has been frozen」 and 「accounts tied to the $6.3 billion
            # theft」 made $6.43B / $6.3B freezes — Binance's frozen total exceeded its loss)
            own = "loss" if _STOLEN_AFTER.match(c, b) else _stretch_kind(c[lo:hi])   # amount_mentions
            out.append((v, whole if _CONVERSION.match(c) else (own or whole)))
    return out


def loss_amounts(title: str | None, text: str | None) -> list[float]:
    """Every amount a report states as a loss: its headline's (cue-less headline figures included) and its body's stated
    ones (both its own and an earlier figure it repeats: 「总额已超1.33亿…此前损失超1.06亿」) — each is a clustering key
    (pipeline amt:), so a follow-up that cites the first figure joins its story."""
    return sorted({v for v, k in amount_mentions(title) if k == "loss"} | set(stated_losses(text)))
