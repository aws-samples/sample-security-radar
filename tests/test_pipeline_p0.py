"""P0 pipeline bugs (docs/research/action/07-code-quality.md B1 / B2 / B8): an event id that is already taken, X
accounts that share one source_id, and the hourly refresh that depended on the minute of the clock."""
from datetime import UTC, datetime, timedelta

from radar import pipeline
from radar.model import RawItem
from radar.store import MemoryStore


def _raw(src, title, text, when, url=None, author=None):
    return RawItem(source_id=src, url=url or f"https://{src}.example/{abs(hash(title))}", title=title, text=text,
                   published_at=when, guid=None, author=author, links=[], extra={})


# ---------------------------------------------------------------- B1: event_id seed collision

def test_a_new_event_never_reuses_an_existing_event_id():
    """A KEV roundup opens its event seeded by its first cve: key but does not index it (indexed_keys drops a roundup's
    CVEs); the next ordinary report of that CVE then finds nothing, derives the same id and overwrote the roundup's
    event — its report orphaned (research 07 §2.1 repro: after solo {'ev_3414…': ['it_14db…']})."""
    store = MemoryStore()
    t = datetime(2026, 11, 10, 9, tzinfo=UTC)
    pipeline.ingest([_raw("thehackernews", "CISA Adds Two Known Exploited Vulnerabilities to Catalog",
                          "CISA added CVE-2026-1111 and CVE-2026-2222 to its Known Exploited Vulnerabilities catalog.",
                          t)], store, t)
    assert len(store.events) == 1
    t2 = t + timedelta(hours=2)
    pipeline.ingest([_raw("thehackernews", "Zork Widget flaw exploited in the wild",
                          "Attackers are exploiting CVE-2026-1111 in Zork Widget.", t2)], store, t2)
    assert len(store.events) == 2, store.events.keys()
    owners: dict[str, list[str]] = {}
    for eid, ev in store.events.items():
        for i in ev["item_ids"]:
            owners.setdefault(i, []).append(eid)
    assert len(owners) == 2 and all(len(v) == 1 for v in owners.values()), owners


# ---------------------------------------------------------------- B2: X reporters share source_id x_security

def _tweet(handle, title, when):
    return _raw("x_security", title, title, when, url=f"https://x.com/{handle}/status/{abs(hash(title))}",
                author=handle)


def _items(store):
    return [pipeline.Item.from_dict(d) for d in store.items.values()]


def test_two_x_accounts_of_different_tiers_are_two_reporters():
    """ZachXBT (T1) 「$50.2M stolen」, Lookonchain (T2) 「drained $912.4M」: the T1 figure is the headline and an 18×
    gap between two reporters is a dispute — not one `x_security` source taking the last tweet's tier and its max."""
    store = MemoryStore()
    t = datetime(2026, 11, 10, 11, tzinfo=UTC)
    for h, title, when in (("zachxbt", "Acme Finance exploited, $50.2M stolen from its bridge", t),
                           ("lookonchain", "Acme Finance bridge drained $912.4M", t + timedelta(hours=1))):
        pipeline.ingest([_tweet(h, title, when)], store, when)
    items = _items(store)
    assert {i.tier for i in items} == {"T1", "T2"}
    _, headline, disputed, _, _ = pipeline._amounts(items)
    assert headline == 50_200_000
    assert disputed is True


def test_two_x_accounts_back_each_others_figure():
    """Two different X accounts stating the same huge figure back it: it is not a lone outlier."""
    store = MemoryStore()
    t = datetime(2026, 11, 10, 11, tzinfo=UTC)
    for h, when in (("zachxbt", t), ("peckshieldalert", t + timedelta(minutes=20))):
        pipeline.ingest([_tweet(h, f"Zorkchain bridge exploited, $60B stolen ({h})", when)], store, when)
    hist, headline, _, _, _ = pipeline._amounts(_items(store))
    assert [p["kind"] for p in hist] == ["loss", "loss"]
    assert headline == 60e9
    assert all(set(p) == {"value", "source_id", "observed_at", "kind"} for p in hist)   # stored shape unchanged


def test_one_x_account_tweeting_twice_is_still_one_reporter():
    """The same handle stating the same implausible figure twice does not back itself."""
    store = MemoryStore()
    t = datetime(2026, 11, 10, 11, tzinfo=UTC)
    for n, when in ((1, t), (2, t + timedelta(minutes=20))):
        pipeline.ingest([_tweet("zachxbt", f"Zorkchain bridge exploited, $60B stolen (update {n})", when)], store, when)
    hist, _, _, _, _ = pipeline._amounts(_items(store))
    assert [p["kind"] for p in hist] == ["outlier", "outlier"]


def test_an_x_account_never_shares_a_reporter_with_an_rss_source_of_its_org():
    """watchtowrcyber's org is `watchtowr`, the watchTowr Labs RSS source_id is `watchtowr` too: one reporter key made the
    T1 blog take the later T2 tweet's tier (tier_of is last-wins) and the two stop backing each other — headline
    $10M (ZachXBT) instead of $40M (the T1 blog, which 668ae18 picked). X reporters live in their own namespace."""
    store = MemoryStore()
    t = datetime(2026, 11, 10, 11, tzinfo=UTC)
    pipeline.ingest([_tweet("zachxbt", "Acme Finance exploited, $10M stolen", t)], store, t)
    t2 = t + timedelta(minutes=5)
    pipeline.ingest([_raw("watchtowr", "Acme Finance exploited, $40M stolen", "Acme Finance exploited, $40M stolen", t2)],
                    store, t2)
    t3 = t + timedelta(minutes=9)
    pipeline.ingest([_tweet("watchtowrcyber", "Acme Finance exploited, $41M stolen", t3)], store, t3)
    items = _items(store)
    assert [i.source_id for i in items] == ["x_security", "watchtowr", "x_security"]
    # a vuln-domain report keeps no amount history; give each report the figure its title states (the review's repro)
    for it, v, when in zip(items, (10e6, 40e6, 41e6), (t, t2, t3), strict=True):
        it.extra["amount_history"] = [{"value": v, "observed_at": when.isoformat()}]
    hist, headline, _, _, _ = pipeline._amounts(items)
    assert headline == 40_000_000
    assert [p["kind"] for p in hist] == ["loss", "loss", "loss"]
