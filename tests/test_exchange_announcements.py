"""Exchange announcement parsers (radar.parsers.exchanges) and the board's notice kind (radar.announcements).
Fixtures are the live responses fetched from the radar's AWS egress on 2026-11-10 (scripts/source-onboard.py),
trimmed to three notices each."""
import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from radar import announcements, parsers
from radar.parsers import exchanges

FX = Path(__file__).parent / "fixtures" / "snapshots" / "2026-11-10" / "exchanges"


@pytest.mark.parametrize("key", sorted([*exchanges.SPECS, "zendesk"]))
def test_every_exchange_parser_reads_its_live_response(key):
    raws = parsers.PARSERS[key]((FX / f"{key}.json").read_text(), "src")
    assert raws, key
    for r in raws:
        assert r.title and r.url.startswith("https://") and r.guid and r.published_at.tzinfo is not None
        assert r.published_at.year >= 2024
    if key != "zendesk":
        assert all(r.extra["exchange"] == exchanges.SPECS[key].exchange for r in raws)


def test_bithumb_times_are_korean_local_time():
    """「2026-11-09 22:55:57」 on Bithumb is KST: 13:55:57 UTC, not 22:55 UTC."""
    body = json.dumps([{"title": "인젝티브(INJ) 입출금 일시 중지 안내", "pc_url": "https://feed.bithumb.com/notice/1655568",
                        "published_at": "2026-11-09 22:55:57", "categories": ["입출금"]}])
    [r] = parsers.PARSERS["ex_bithumb"](body, "s")
    assert r.published_at == datetime(2026, 11, 9, 13, 55, 57, tzinfo=UTC)


def test_a_notice_without_a_link_or_title_is_dropped_and_a_draft_is_not_published():
    body = json.dumps({"articles": [{"id": 1, "title": "x", "html_url": "", "created_at": "2026-11-09T00:00:00Z"},
                                    {"id": 2, "title": "", "html_url": "https://h/2", "created_at": "2026-11-09T00:00:00Z"},
                                    {"id": 3, "title": "y", "html_url": "https://h/3", "created_at": "2026-11-09T00:00:00Z", "draft": True},
                                    {"id": 4, "title": "z", "html_url": "https://h/4", "created_at": "2026-11-09T00:00:00Z"}]})
    assert [r.guid for r in parsers.PARSERS["zendesk"](body, "s")] == ["4"]


@pytest.mark.parametrize(("title", "want"), [
    ("Security Incident | Recovery Update #7: 98% of Stolen Assets Replenished", "security"),
    ("業務委託先（アララ株式会社）への不正アクセスに伴う情報流出について（第2報）", "security"),
    ("暂停提币通知：安全事件调查中", "security"),                       # priority: security beats suspension
    ("인젝티브(INJ) 입출금 일시 중지 안내 (11/09 오후 11시 ~ )", "suspension"),
    ("KuCoin Has Temporarily Closed the Deposit Service of Ankr Network (ANKR)", "suspension"),
    ("Binance Will Delist EPIC, QUICK on 2026-10-28", "delisting"),
    ("Notice of Removal of Spot Trading Pairs - 2026-10-30", "delisting"),
    ("Wallet Maintenance for Ethereum Network (ETH) - 2026-10-28", "maintenance"),
    ("Binance Exchange Adds Applovin Corp (APPB)", "listing"),
    ("How to Set/Change Your Anti-Phishing Code", "other"),            # a help-centre guide, not an incident
    ("Introducing Sub-Affiliate: Flexible Commission Sharing", "other"),
])
def test_notice_kind(title, want):
    assert announcements.kind(title) == want


def test_every_json_endpoint_has_a_json_parser():
    """Live 2026-11-10: 31 exchange endpoints were registered with the RSS parser (the onboarding verdicts carried no
    parser for admitted rows) and failed parse_empty on the first cycle. The parser tests passed — they never looked
    at the registry."""
    from radar.registry import SOURCES
    wrong = [s.source_id for s in SOURCES if s.parser == "feed" and (re.search(r"/api/|\.json(\?|$)", s.url))
             and not re.search(r"rss|feed|atom", s.url.lower())]
    assert wrong == []


def test_the_board_keeps_each_notice_once_newest_first_and_only_from_boards():
    from radar.model import RawItem
    from radar.registry import BY_ID
    def raw(sid, title, at, url=None):
        return RawItem(source_id=sid, url=url or f"https://x/{title}", title=title, text=title,
                       published_at=datetime.fromisoformat(at), guid=title, author=None, links=[], extra={})
    led = announcements.board_add({}, [raw("ex_okx", "OKX to delist FOO", "2026-11-09T10:00:00+00:00"),
                                       raw("krebs", "Not an exchange", "2026-11-09T11:00:00+00:00"),
                                       raw("ex_bybit", "Suspension of TRX deposits", "2026-11-10T09:00:00+00:00")],
                                  BY_ID, "2026-11-10T12:00:00Z")
    assert [r["title"] for r in led["notices"]] == ["Suspension of TRX deposits", "OKX to delist FOO"]
    assert led["notices"][0]["kind"] == "suspension" and led["notices"][0]["exchange"] == "Bybit"
    again = announcements.board_add(led, [raw("ex_okx", "OKX to delist FOO", "2026-11-09T10:00:00+00:00")], BY_ID, "t")
    assert len(again["notices"]) == 2
    doc = announcements.board_doc(again, BY_ID, "2026-11-10T12:00:00Z")
    assert doc["counts"]["suspension"] == 1 and any(b["source_id"] == "ex_okx" and b["last_notice"] for b in doc["boards"])


def test_a_notice_url_that_is_not_http_never_reaches_the_board():
    """Board URLs come verbatim from third-party JSON (OKX a["url"], Bitget annUrl, Bithumb pc_url …) and are rendered
    as links on #/announcements: a poisoned feed's javascript: URL would be stored XSS on the radar's origin
    (research/action/05 #2, 06 B2). The UI filters too (safeHref); the board must not carry it at all."""
    from radar.model import RawItem
    from radar.registry import BY_ID
    def raw(title, url):
        return RawItem(source_id="ex_okx", url=url, title=title, text=title, guid=title, author=None, links=[], extra={},
                       published_at=datetime(2026, 11, 10, tzinfo=UTC))
    led = announcements.board_add({}, [raw("bad", "javascript:alert(document.domain)"), raw("data", "data:text/html,x"),
                                       raw("upper", "JavaScript:alert(1)"), raw("rel", "/notice/1"),
                                       raw("good", "https://www.okx.com/help/1"), raw("plain", "HTTP://example.com/n")],
                                  BY_ID, "2026-11-10T12:00:00Z")
    assert sorted(r["title"] for r in led["notices"]) == ["good", "plain"]


def test_two_defillama_hacks_with_one_name_and_date_are_two_items():
    """Gamma 2021-12-21 is listed twice ($4.5M, $8.2M): one guid made the item flip between the amounts every run
    (1,634 amount_change entries, event row 396 KB of 400 KB, live 2026-11-10)."""
    body = json.dumps([
        {"name": "Gamma", "date": 1640044800, "amount": 8200000, "technique": "Reentrancy", "chain": ["Ethereum"]},
        {"name": "Gamma", "date": 1640044800, "amount": 4500000, "technique": "Arithmetic Error", "chain": ["Ethereum"]},
        {"name": "Solo", "date": 1640044800, "amount": 1, "technique": "x", "chain": []}])
    a = parsers.PARSERS["defillama"](body, "defillama_hacks")
    b = parsers.PARSERS["defillama"](json.dumps(list(reversed(json.loads(body)))), "defillama_hacks")
    guid = {r.extra["technique"]: r.guid for r in a}
    assert len({r.guid for r in a}) == 3 and guid == {r.extra["technique"]: r.guid for r in b}   # stable across order
    assert guid["x"] == "Solo|1640044800" and "Gamma|1640044800" in guid.values()              # singles unchanged


SOCIAL = FX.parent / "social"


def test_a_telegram_channel_page_parses_to_posts_with_ids_and_utc_times():
    raws = parsers.PARSERS["telegram"]((SOCIAL / "tme-investigations.html").read_text(), "tg_zachxbt")
    assert raws and all(r.guid.startswith("investigations/") and r.url.startswith("https://t.me/investigations/") for r in raws)
    assert all(r.published_at.tzinfo is not None and r.title for r in raws)


def test_a_dead_channel_page_parses_to_nothing():
    """t.me/s of a dead channel falls back to the contact page with HTTP 200 — no posts, so parse_empty, not 'no news'."""
    assert parsers.PARSERS["telegram"]("<html><body><div class='tgme_page'>Contact</div></body></html>", "x") == []


def test_zone_less_china_times_are_utc_plus_8():
    raws = parsers.PARSERS["feed_cst"]((SOCIAL / "doonsec.xml").read_text(), "doonsec")
    plain = parsers.PARSERS["feed"]((SOCIAL / "doonsec.xml").read_text(), "doonsec")
    assert raws and all((p.published_at - r.published_at).total_seconds() == 8 * 3600 for r, p in zip(raws, plain, strict=True))


def test_a_photo_only_post_is_not_a_report():
    page = ('<div class="tgme_widget_message" data-post="ch/7"><a class="tgme_widget_message_date" href="https://t.me/ch/7">'
            '<time datetime="2026-11-09T14:44:49+00:00"></time></a><div class="tgme_widget_message_photo_wrap"></div></div>')
    assert parsers.PARSERS["telegram"](page, "x") == []


def test_a_telegram_title_skips_an_emoji_only_first_line():
    page = ('<div class="tgme_widget_message" data-post="ch/8"><div class="tgme_widget_message_text">🚨<br/>'
            'Exchange X hot wallet drained, $12M lost</div><a class="tgme_widget_message_date" href="https://t.me/ch/8">'
            '<time datetime="2026-11-09T14:44:49+00:00"></time></a></div>')
    [r] = parsers.PARSERS["telegram"](page, "x")
    assert r.title == "Exchange X hot wallet drained, $12M lost"
