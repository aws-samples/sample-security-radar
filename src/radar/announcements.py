"""Exchange announcement board: what kind of notice is this, decided by code.

Why: the board (#/announcements) shows every exchange notice, but an operator reads it for the few that matter —
a security incident, a deposit/withdrawal suspension (often the first public sign of a hack, e.g. Bithumb's
「입출금 일시 중지」), a delisting. KINDS are checked in priority order; the first match wins, so 「暂停提币：安全事件」
is a security notice, not a suspension. Titles come in English, Chinese, Korean, Japanese, Portuguese and Turkish
(top-100 exchanges on CoinMarketCap, 2026-11-10).
"""
from __future__ import annotations

import re
from typing import Any

KINDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("security", re.compile(
        r"hack|exploit|security (incident|breach|issue)|unauthori[sz]ed|stolen|compromis|phishing|attack|drain|"
        r"被盗|攻击|安全事件|盗币|해킹|보안 사고|不正アクセス|流出|ataque|invas", re.IGNORECASE)),
    ("suspension", re.compile(
        r"suspen|halt|pause|temporar(il)?y (clos|disabl|stop)|closed the (deposit|withdraw)|"
        r"暂停|停止充|停止提|일시 중지|중단|一時停止|停止|askıya|suspens", re.IGNORECASE)),
    ("delisting", re.compile(r"delist|de-list|terminat\w* (of )?trading|下架|上場廃止|상장 ?폐지|거래지원 종료|"
                             r"remov\w* .{0,30}(pair|token|trading)", re.IGNORECASE)),
    ("maintenance", re.compile(r"maintenance|upgrade|hard ?fork|network update|维护|升级|점검|업그레이드|メンテナンス|"
                               r"bakım|manuten", re.IGNORECASE)),
    ("listing", re.compile(r"will list|lists |listing|launch|new (spot|futures|perpetual)|open trading|上线|上新|"
                           r"\badds? |will add|상장|取扱開始|listagem|listeleniyor", re.IGNORECASE)),
)
PRIORITY = ("security", "suspension", "delisting", "maintenance", "listing", "other")
# help-centre guides share the words (Batonex 「How to Set Your Anti-Phishing Code」 read as a security notice, live
# 2026-11-10): a how-to is never an incident or a suspension
_GUIDE = re.compile(r"^\s*(how to|introduction to|guide|faq|what is|tutorial)\b|如何|教程|指南", re.IGNORECASE)


def kind(title: str) -> str:
    if _GUIDE.search(title or ""):
        return "other"
    for name, rx in KINDS:
        if rx.search(title or ""):
            return name
    return "other"


# ---------------------------------------------------------------- the board (Process appends, Publish renders)
BOARD_KEY = "__board__"     # one ledger item, single writer = Process (it sees every new notice exactly once)
BOARD_CAP = 600             # newest notices kept (≈ 150 KB, below DynamoDB's 400 KB item limit)
_HTTP_URL = re.compile(r"https?://", re.IGNORECASE)   # the only schemes a notice link may carry


def _exchange(raw: Any, source: Any) -> str:
    return (raw.extra or {}).get("exchange") or re.sub(r"\s*(公告|状态页)$", "", source.name)


def board_add(ledger: dict[str, Any], raws: list[Any], by_id: dict[str, Any], now_iso: str) -> dict[str, Any]:
    """Append this run's new notices from announcement boards (Source.board == "exchange"); newest first, deduped by
    (source, url), capped. Process hands over only new or edited entries (collect.incremental), so this is O(new)."""
    rows = list(ledger.get("notices") or [])
    have = {(r["source_id"], r["url"]) for r in rows}
    for raw in raws:
        s = by_id.get(raw.source_id)
        if s is None or s.board != "exchange" or (raw.source_id, raw.url) in have:
            continue
        # The URL is verbatim third-party JSON (parsers only check it is non-empty) and the UI renders it as a link:
        # a javascript:/data: URL from a poisoned feed would be stored XSS (research/action/05 #2). Dropped, not fixed.
        if not _HTTP_URL.match(raw.url or ""):
            continue
        have.add((raw.source_id, raw.url))
        rows.append({"source_id": raw.source_id, "exchange": _exchange(raw, s), "title": raw.title[:300], "url": raw.url,
                     "kind": kind(raw.title), "category": (raw.extra or {}).get("ann_category"),
                     "published_at": raw.published_at.isoformat().replace("+00:00", "Z") if raw.published_at else None,
                     "seen_at": now_iso})
    rows.sort(key=lambda r: r.get("published_at") or r["seen_at"], reverse=True)
    return {"notices": rows[:BOARD_CAP], "updated_at": now_iso}


def board_doc(ledger: dict[str, Any], by_id: dict[str, Any], now_iso: str) -> dict[str, Any]:
    """announcements.json: the notices, counts per kind, and every board source with its last notice — an exchange that
    went quiet shows as quiet, not as absent."""
    rows = ledger.get("notices") or []
    counts = {k: sum(1 for r in rows if r["kind"] == k) for k in PRIORITY}
    last = {}
    for r in rows:
        last.setdefault(r["source_id"], r.get("published_at") or r["seen_at"])
    boards = [{"source_id": s.source_id, "exchange": re.sub(r"\s*(公告|状态页)$", "", s.name), "url": s.url,
               "last_notice": last.get(s.source_id)} for s in by_id.values() if s.board == "exchange"]
    return {"kind": "announcements", "generated_at": now_iso, "counts": counts, "notices": rows,
            "boards": sorted(boards, key=lambda b: b["exchange"].lower())}
