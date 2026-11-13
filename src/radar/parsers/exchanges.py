"""Exchange announcement endpoints — one table, one function.

Each exchange answers with "a list of notices, each with a title, a link and a time"; only the JSON paths differ.
A new exchange is a new row in SPECS (plus a fixture), not new code. Zendesk help centres (25 of the top-100
exchanges on CoinMarketCap, 2026-11-10) share one parser. Endpoints were found by docs/research (build/exchanges) and
admitted by scripts/source-onboard.py from the radar's AWS egress.

Every item carries extra.exchange and extra.ann_category (the exchange's own category, verbatim) for the
announcement board; whether it is a security event is decided downstream by the same signals as any report.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from bs4 import BeautifulSoup

from radar import timeutil
from radar.model import RawItem

KST = timezone(timedelta(hours=9))


@dataclass(frozen=True)
class Spec:
    exchange: str
    items: Callable[[Any], list[dict[str, Any]]]
    title: str
    time: str                                   # field holding the publication time
    time_unit: str = "ms"                        # "ms" epoch milliseconds | "iso" | "kst" ('YYYY-MM-DD HH:MM:SS' in KST)
    url: Callable[[dict[str, Any]], str] | None = None
    guid: str | None = None                      # field; default = the URL
    category: Callable[[dict[str, Any]], str | None] = lambda a: None
    text: str | None = None


def _okx(j):
    return [d for page in j.get("data") or [] for d in page.get("details") or []]


SPECS: dict[str, Spec] = {
    "ex_okx": Spec("OKX", _okx, "title", "pTime", url=lambda a: a["url"], category=lambda a: a.get("annType")),
    "ex_bybit": Spec("Bybit", lambda j: j["result"]["list"], "title", "publishTime", url=lambda a: a["url"],
                     category=lambda a: (a.get("type") or {}).get("key"), text="description"),
    "ex_bitget": Spec("Bitget", lambda j: j["data"], "annTitle", "cTime", url=lambda a: a["annUrl"], guid="annId",
                      category=lambda a: a.get("annType")),
    "ex_kucoin": Spec("KuCoin", lambda j: j["data"]["items"], "annTitle", "cTime", url=lambda a: a["annUrl"], guid="annId",
                      category=lambda a: ",".join(a.get("annType") or []) or None, text="annDesc"),
    "ex_mexc": Spec("MEXC", lambda j: j["data"]["results"], "title", "createdAt", "iso",
                    url=lambda a: f"https://www.mexc.com/support/articles/{a['id']}", guid="id"),
    "ex_ourbit": Spec("Ourbit", lambda j: j["data"]["results"], "title", "createdAt", "iso",
                      url=lambda a: f"https://www.ourbit.com/support/articles/{a['id']}", guid="id",
                      category=lambda a: ((a.get("parentSections") or [{}])[0]).get("name")),
    "ex_htx": Spec("HTX", lambda j: j["data"]["list"], "title", "showTime",
                   url=lambda a: f"https://www.htx.com/support/{a['id']}", guid="id"),
    "ex_crypto_com_exchange": Spec("Crypto.com Exchange", lambda j: j["result"]["data"], "title", "announced_at",
                                   url=lambda a: f"https://crypto.com/exchange/announcements#{a['id']}", guid="id",
                                   category=lambda a: a.get("category"), text="content"),
    "ex_bithumb": Spec("Bithumb", lambda j: j, "title", "published_at", "kst", url=lambda a: a["pc_url"],
                       category=lambda a: ",".join(a.get("categories") or []) or None),
}


def _when(v: Any, unit: str) -> datetime | None:
    if v in (None, ""):
        return None
    if unit == "ms":
        return timeutil.parse(int(v) / 1000)
    if unit == "kst":
        return datetime.strptime(str(v), "%Y-%m-%d %H:%M:%S").replace(tzinfo=KST).astimezone(UTC)
    return timeutil.parse(v)


def _plain(html: str | None, cap: int = 2000) -> str:
    return BeautifulSoup(html or "", "html.parser").get_text(" ", strip=True)[:cap]


def by_spec(parser_key: str) -> Callable[[str, str], list[RawItem]]:
    spec = SPECS[parser_key]

    def parse(body: str, source_id: str) -> list[RawItem]:
        out = []
        for a in spec.items(json.loads(body)) or []:
            title = (a.get(spec.title) or "").strip()
            url = spec.url(a) if spec.url else ""
            if not title or not url:
                continue          # a notice without a title or a link cannot be cited
            out.append(RawItem(source_id=source_id, url=url, title=title,
                               text=_plain(a.get(spec.text)) if spec.text else title,
                               published_at=_when(a.get(spec.time), spec.time_unit),
                               guid=str(a[spec.guid]) if spec.guid and a.get(spec.guid) is not None else url,
                               extra={"exchange": spec.exchange, "ann_category": spec.category(a)}))
        return out
    return parse


def zendesk(body: str, source_id: str) -> list[RawItem]:
    """Zendesk Help Center /api/v2/help_center/<locale>/…/articles.json (public, no key). The exchange name is
    filled by the registry (extra.exchange is set by the collector from the source); the section id is the category."""
    out = []
    for a in json.loads(body).get("articles") or []:
        title, url = (a.get("title") or "").strip(), a.get("html_url") or ""
        if not title or not url or a.get("draft"):
            continue
        out.append(RawItem(source_id=source_id, url=url, title=title, text=_plain(a.get("body")) or title,
                           published_at=timeutil.parse(a.get("created_at")), guid=str(a.get("id") or url),
                           extra={"ann_category": str(a["section_id"]) if a.get("section_id") else None}))
    return out
