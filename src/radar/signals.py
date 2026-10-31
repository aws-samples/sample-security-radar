"""Rule-based signals from free text. M2 adds an LLM extractor on top; these rules stay as the floor and
as the regression oracle for it."""

from __future__ import annotations

import re

from radar.model import Exploited

# negations are checked first: "no evidence of exploitation in the wild" must be "no", not "yes"
_NEG = re.compile(
    r"\b(no (?:evidence|indication|reports?|known)\b[^.]{0,60}\b(?:exploit|in the wild|attack)"
    r"|not aware of (?:any )?(?:active )?(?:exploit|attacks?|in[- ]the[- ]wild|malicious)"
    r"|not (?:been |being )?(?:actively )?exploited"
    r"|has not been exploited)"
    r"|未(?:发现|监测到|观察到)[^。]{0,10}在野|暂无在野",
    re.IGNORECASE,
)
_YES = re.compile(
    r"\b(exploited in the wild|actively exploited|active exploitation|under active attack"
    r"|exploits? (?:for [^.]{0,60} )?exists? in the wild|exploitation in the wild"
    r"|may have been exploited|limited,? (?:and )?targeted attacks?|observed (?:being )?exploited"
    r"|exploited as a zero-?day|zero-?day (?:attacks?|exploited)|known exploited)\b"
    r"|Exploited:Yes|在野利用|已被(?:黑客)?利用|已发现在野",
    re.IGNORECASE,
)
_POC = re.compile(r"\b(proof[- ]of[- ]concept|PoC (?:exploit|released|published|available)|exploit code (?:released|published))\b"
                  r"|PoC已公开|POC公开|公开了?(?:PoC|POC|利用代码)", re.IGNORECASE)

_WEB3_INCIDENT = re.compile(
    r"\b(drained|exploit(?:ed)?|hack(?:ed)?|stolen|attack(?:ed|er)?|compromis(?:e|ed)|rug ?pull|drainer"
    r"|phishing|private key|flash ?loan|loss)\b|被盗|被黑|攻击|漏洞|损失|盗取|黑客",   # 黑客: 「冻结币安黑客约3050万美元」
    re.IGNORECASE,
)
_SEC_EVENT = re.compile(
    r"\b(zero-?day|0-?day|ransomware|data breach|breach(?:ed)?|hack(?:ed)?|exploit(?:ed|ation)?|backdoor"
    r"|supply[- ]chain attack|malware|leak(?:ed)?|vulnerabilit(?:y|ies)|RCE|remote code execution|CVE-\d{4})\b"
    r"|漏洞|勒索|泄露|攻击|在野|被黑|入侵",
    re.IGNORECASE,
)

_AMOUNT = re.compile(
    r"(?:US)?\$\s?~?\s?([0-9][0-9,]*(?:\.[0-9]+)?)\s*(k|thousand|m|mn|million|b|bn|billion)?\b"
    r"|([0-9][0-9,]*(?:\.[0-9]+)?)\s*(万|亿)?\s*美元",
    re.IGNORECASE,
)
_MULT = {"k": 1e3, "thousand": 1e3, "m": 1e6, "mn": 1e6, "million": 1e6, "b": 1e9, "bn": 1e9, "billion": 1e9,
         "万": 1e4, "亿": 1e8}


# Which measure an amount in a report is (live 2026-10-30, the Binance theft: one headline number mixed the loss with
# freezes, borrows / sales inside the story and an estimate of user assets). Frozen wins over context, context over loss;
# a headline with neither cue is a loss figure. Decided on the report's title — that is where 快讯 / tweets state what the
# number is.
_FROZEN = re.compile(r"\b(?:froze|frozen|freez\w*|blacklist\w*|recover(?:ed|s)?|seiz(?:ed|ure)|returned)\b|冻结|追回|返还|归还|没收",
                     re.IGNORECASE)
_CONTEXT = re.compile(
    r"\b(?:liquidat\w*|short(?:ed|ing|s)?|long(?:ed|s)?|profit\w*|arbitrag\w*|reserves?|market cap|volume|borrow\w*"
    r"|sold|sell(?:s|ing)?|dump\w*|swap\w*|holds?|holding)\b"
    r"|爆仓|做空|做多|浮盈|获利|盈利|套利|用户资产|储备|市值|交易量|借出|抛售|售出|卖出|兑换|换成|持有", re.IGNORECASE)


# an amount stated *as* the loss beats a context word elsewhere in a tweet ("$NEM Loss: ~$821,920 … as sell volume")
_LOSS_STATED = re.compile(r"\bloss:?\s*~?\s*\$|\b(?:lost|stolen|drained|exploited for|hacked for)\b[^.]{0,24}\$"
                          r"|(?:被盗|损失|盗走|转走|流出)约?\s*[0-9]", re.IGNORECASE)


def amount_kind(text: str | None) -> str:
    """'frozen' | 'context' | 'loss' for the amount a report states: frozen > stated loss > context > loss."""
    t = text or ""
    if _FROZEN.search(t):
        return "frozen"
    if _LOSS_STATED.search(t) or not _CONTEXT.search(t):
        return "loss"
    return "context"


# Attack phases of an incident report, decided on its title (M4 D4). Order matters: a report about the hacker swapping
# stolen tokens is laundering, not the theft itself; an exchange's own statement is a statement even if it says "hack".
_A = r"(?<![A-Za-z0-9])"          # ASCII lookarounds: \b never fires next to CJK text
_Z = r"(?![A-Za-z0-9])"
_PH_ATTR = re.compile(_A + r"(?:North Korea\w*|DPRK|Lazarus|TraderTraitor|attribut\w*|same (?:attacker|hacker|group))" + _Z
                      + r"|朝鲜|同一攻击者|同一批|同一黑客|幕后", re.IGNORECASE)
_PH_RECOVER = re.compile(_A + r"(?:returned|bounty|recovered funds|refund\w*)" + _Z + r"|追回|返还|归还|赏金", re.IGNORECASE)
_PH_STATEMENT = re.compile(r"^(?:币安|Binance|何一|CZ|Tether|Circle|官方)\s*[：:]"
                           + "|" + _A + r"(?:statement|investigat\w*|confirm(?:s|ed)?|SAFU|cover all|post-?mortem"
                           + r"|withdrawals? (?:are |were )?(?:paused|suspended|resumed|halted))" + _Z
                           + r"|公告|声明|回应|暂停(?:充提|提币|充值)|恢复(?:充提|提币)|全额赔付|初步调查", re.IGNORECASE)
_PH_PREP = re.compile(_A + r"(?:rehears\w*|funded by|in advance|prepar\w*)" + _Z + r"|演练|彩排|提前|预先|资助|准备", re.IGNORECASE)
_PH_LAUNDER = re.compile(_A + r"(?:sold|sell\w*|dump\w*|swap\w*|bridge\w*|launder\w*|borrow\w*|moved (?:through|to|into)"
                         + r"|peel chain|consolidat\w*|mixer|Tornado Cash deposits?)" + _Z
                         + r"|抛售|售出|卖出|买入|兑换|换成|跨链|混币|洗钱|借出|转入|转移至|归集", re.IGNORECASE)
_PH_DRAIN = re.compile(_A + r"(?:drain\w*|stolen|steal\w*|hack(?:ed)?|outflows?|swept|sweep\w*|exploit\w*|compromis\w*"
                       + r"|hot wallets?|lost|poison\w*|phish\w*|drainer)" + _Z
                       + r"|转出|转走|被盗|盗走|流出|清扫|遭攻击|攻击|热钱包|遭窃|失窃|钓鱼", re.IGNORECASE)
_PH_IMPACT = re.compile(_A + r"(?:price|liquidat\w*|short(?:ed|s)?|exposure|unaffected|not affected|market)" + _Z
                        + r"|未受|影响|下跌|上涨|跌幅|涨幅|价格|爆仓|做空|敞口|市场", re.IGNORECASE)
PHASES = ("prep", "drain", "laundering", "freeze", "statement", "attribution", "recovery", "impact", "other")


def phase(title: str | None) -> str:
    """Attack phase of one report (PHASES): attribution > recovery > freeze > statement > prep > laundering > drain > impact."""
    t = title or ""
    for name, rx in (("attribution", _PH_ATTR), ("recovery", _PH_RECOVER), ("freeze", _FROZEN), ("statement", _PH_STATEMENT),
                     ("prep", _PH_PREP), ("laundering", _PH_LAUNDER), ("drain", _PH_DRAIN), ("impact", _PH_IMPACT)):
        if rx.search(t):
            return name
    return "other"


_ACTORS = ((re.compile(_A + r"(?:North Korea\w*|DPRK|Lazarus|TraderTraitor|BlueNoroff|APT38)" + _Z + r"|朝鲜", re.IGNORECASE),
            "North Korea (Lazarus / TraderTraitor)"),)


def attribution_actor(text: str | None) -> str | None:
    """A named threat actor the text attributes the incident to — a linkage ("same attacker as …") is not an actor."""
    return next((name for rx, name in _ACTORS if rx.search(text or "")), None)


def exploited(text: str) -> Exploited:
    if not text:
        return "unclear"
    if _NEG.search(text):
        return "no"
    return "yes" if _YES.search(text) else "unclear"


def poc(text: str) -> bool:
    return bool(_POC.search(text or ""))


def web3_incident(text: str) -> bool:
    return bool(_WEB3_INCIDENT.search(text or ""))


def security_event(text: str) -> bool:
    return bool(_SEC_EVENT.search(text or ""))


def _amount_spans(text: str):
    """(value, start, end) of every amount in text."""
    for m in _AMOUNT.finditer(text):
        num, unit = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
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


# Clause breaks for amount_mentions: CJK punctuation, ; ! ?, a comma not inside a number ("$5,800,000"), a full stop
# followed by a space (not a decimal point).
_CLAUSE = re.compile(r"[，；。！？;!?]|,(?!\d)|\.(?=\s)")


_LOSS_WORD = re.compile(r"\b(?:hack\w*|stolen|drain\w*|lost|loss(?:es)?|impact|exploit\w*|theft)\b|被盗|损失|盗走|黑客",
                        re.IGNORECASE)


def _stretch_kind(span: str) -> str | None:
    """Measure stated in one amount's own stretch of text, None when it states none (amount_kind precedence)."""
    if _FROZEN.search(span):
        return "frozen"
    if _LOSS_STATED.search(span):
        return "loss"
    if _CONTEXT.search(span):
        return "context"
    return "loss" if _LOSS_WORD.search(span) else None


def amount_mentions(text: str | None) -> list[tuple[float, str]]:
    """Every amount in a report with its own measure. Live 2026-10-30: 「损失约63亿美元，已冻结约30亿美元资产」 judged as
    one text was "frozen", and its largest number — the $6.3B loss — became the frozen headline; The Defiant's "estimates
    the impact at $6.3 billion and says about $3 billion has been frozen" has both inside one clause. An amount reads the
    text between its neighbours in its clause; when that states no measure ("froze $500M and $200M"), the clause's."""
    out: list[tuple[float, str]] = []
    for c in _CLAUSE.split(text or ""):
        spans = list(_amount_spans(c))
        for i, (v, a, b) in enumerate(spans):
            lo = spans[i - 1][2] if i else 0
            hi = spans[i + 1][1] if i + 1 < len(spans) else len(c)
            out.append((v, _stretch_kind(c[lo:hi]) or amount_kind(c)))
    return out
