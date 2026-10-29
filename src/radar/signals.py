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
    r"|phishing|private key|flash ?loan|loss)\b|被盗|被黑|攻击|漏洞|损失|盗取",
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


def parse_amount(text: str | None) -> float | None:
    """'$ 90,500' → 90500; '~$90.5K' → 90500; '$387.5 million' → 3.875e8; '3.2 亿美元' → 3.2e8; '-' → None.
    Returns the largest amount mentioned (loss headlines put the total first, but tweets add sub-amounts)."""
    if not text:
        return None
    best: float | None = None
    for m in _AMOUNT.finditer(text):
        num, unit = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
        if not num:
            continue
        try:
            v = float(num.replace(",", ""))
        except ValueError:
            continue
        v *= _MULT.get((unit or "").lower(), 1.0)
        best = v if best is None or v > best else best
    return best
