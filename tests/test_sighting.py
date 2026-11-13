"""The event's clocks are kept apart (live 2026-11-03, CVE-2026-98432): CVE published 10-15 (cvemeta.disclosure),
first report published 10-29 15:57 by The Hacker News, radar captured it 16:28. The page had called 15:57 「雷达首见」."""
from datetime import UTC, datetime

from radar import pipeline, publish
from radar.model import RawItem
from radar.store import MemoryStore

NOW = datetime(2026, 11, 3, tzinfo=UTC)


def _raw(source_id, title, when, url):
    return RawItem(source_id=source_id, url=url, title=title, text="CVE-2026-98432 remote code execution",
                   published_at=when, guid=None, author=None, links=[], extra={})


def _store():
    store = MemoryStore()
    thn = _raw("thehackernews", "Linux Kernel TCP Flaw CVE-2026-98432", datetime(2026, 10, 29, 15, 57, 5, tzinfo=UTC),
               "https://thehackernews.com/2026/10/linux-tcp.html")
    pipeline.ingest([thn], store, datetime(2026, 10, 29, 16, 28, 30, tzinfo=UTC))
    aws = _raw("aws_bulletins", "CVE-2026-98432 - Linux kernel IPv4 TCP use-after-free Issue",
               datetime(2026, 10, 31, 5, 21, tzinfo=UTC), "https://aws.amazon.com/security/security-bulletins/2026-160-aws/")
    pipeline.ingest([aws], store, datetime(2026, 10, 31, 5, 40, tzinfo=UTC))
    return store


def test_first_report_and_first_capture_are_different_clocks():
    store = _store()
    [doc] = [d for k, d in publish.build(store, NOW).items() if k.startswith("events/")]
    s = doc["sighting"]
    assert s["first_report_at"] == "2026-10-29T15:57:05Z" and s["first_report_source"] == "The Hacker News"
    assert s["first_collected_at"] == "2026-10-29T16:28:30Z" and s["collect_lag_minutes"] == 31
    assert s["first_collected_source"] == "The Hacker News"
    by_src = {i["source_id"]: i for i in doc["items"]}
    assert by_src["thehackernews"]["collected_at"] == "2026-10-29T16:28:30Z"
    assert by_src["thehackernews"]["published_is_collected"] is False and by_src["thehackernews"]["date_only"] is False


def test_a_revision_keeps_the_first_capture_time():
    store = _store()
    rev = _raw("thehackernews", "Linux Kernel TCP Flaw CVE-2026-98432 (updated)", datetime(2026, 10, 29, 15, 57, 5, tzinfo=UTC),
               "https://thehackernews.com/2026/10/linux-tcp.html")
    pipeline.ingest([rev], store, datetime(2026, 10, 30, 8, 0, tzinfo=UTC))
    [doc] = [d for k, d in publish.build(store, NOW).items() if k.startswith("events/")]
    assert doc["sighting"]["first_collected_at"] == "2026-10-29T16:28:30Z"


def test_an_undated_report_says_its_time_is_the_capture_time():
    store = MemoryStore()
    raw = RawItem(source_id="thehackernews", url="https://thehackernews.com/x", title="CVE-2026-98432 flaw",
                  text="CVE-2026-98432", published_at=None, guid=None, author=None, links=[], extra={})
    pipeline.ingest([raw], store, datetime(2026, 10, 29, 16, 28, 30, tzinfo=UTC))
    [doc] = [d for k, d in publish.build(store, NOW).items() if k.startswith("events/")]
    assert doc["items"][0]["published_is_collected"] is True and doc["sighting"]["collect_lag_minutes"] == 0


def test_the_first_capture_names_the_report_it_came_from():
    """Live: the radar captured THN's tweet (16:28) before THN's article (17:08); the page must say which."""
    store = MemoryStore()
    art = _raw("thehackernews", "Linux Kernel TCP Flaw CVE-2026-98432", datetime(2026, 10, 29, 15, 57, 5, tzinfo=UTC),
               "https://thehackernews.com/2026/10/linux-tcp.html")
    tweet = _raw("x_security", "Linux kernel TCP flaw CVE-2026-98432 rated 9.8", datetime(2026, 10, 29, 15, 57, 37, tzinfo=UTC),
                 "https://x.com/TheHackersNews/status/2115835455661052022")
    pipeline.ingest([tweet], store, datetime(2026, 10, 29, 16, 28, 30, tzinfo=UTC))
    pipeline.ingest([art], store, datetime(2026, 10, 29, 17, 8, tzinfo=UTC))
    [doc] = [d for k, d in publish.build(store, NOW).items() if k.startswith("events/")]
    s = doc["sighting"]
    assert (s["first_report_source"], s["first_collected_source"]) == ("The Hacker News", "X @TheHackersNews")
    assert s["first_collected_at"] == "2026-10-29T16:28:30Z"


def test_a_date_only_first_report_is_flagged():
    store = MemoryStore()
    kev = RawItem(source_id="cisa_kev", url="https://www.cisa.gov/kev#CVE-2025-39682", title="CVE-2025-39682 Linux Kernel",
                  text="Known exploited", published_at=datetime(2026, 9, 18, tzinfo=UTC), guid=None, author=None, links=[],
                  extra={"cves": ["CVE-2025-39682"], "kev": True})
    pipeline.ingest([kev], store, datetime(2026, 10, 23, 5, 14, tzinfo=UTC))
    [doc] = [d for k, d in publish.build(store, NOW).items() if k.startswith("events/")]
    assert doc["sighting"]["first_report_date_only"] is True and doc["items"][0]["date_only"] is True
