"""Cost harness: the publish station's work must not grow cubically with an event's report count.

Live 2026-11-02: the Binance page (186 reports) took 133 s — insights.progress replays every prefix and each replay
compared every pair of titles (1.4 M SequenceMatcher.ratio calls); publish runs crept 89 s → 256 s over two days and
then hit the 300 s timeout. These tests pin the work in calls (not seconds, so they are not flaky)."""
from datetime import UTC, datetime
from difflib import SequenceMatcher

from radar import insights, pipeline
from radar.model import Event, Item


def _item(k: int) -> Item:
    when = f"2026-10-29T{(k // 60) % 24:02d}:{k % 60:02d}:00Z"
    return Item(item_id=f"it_{k:04d}", source_id="odaily", tier="T3", org=f"org{k % 40}", domain="web3",
                url=f"https://x.example/{k}", canonical_url=f"https://x.example/{k}",
                title=f"Binance hot wallet theft update {k} — report number {k * 7919 % 1000}", text="", published_at=when,
                fetched_at=when, content_hash=str(k), keys=[], links=[], entity="Binance CEX", eventful=True,
                signals={"exploited": "none", "kev": False, "poc": False, "amount_usd": None}, extra={})


def _reference_groups(items):
    """The pre-optimisation algorithm, verbatim in effect: ratio() on every pair."""
    n = len(items)
    dsu = pipeline._DSU(n)
    by_org = {}
    for i, it in enumerate(items):
        if it.org in by_org:
            dsu.union(i, by_org[it.org])
        by_org.setdefault(it.org, i)
    t = [pipeline._norm_title(it.title) for it in items]
    for i in range(n):
        for j in range(i + 1, n):
            if t[i] and t[j] and SequenceMatcher(None, t[i], t[j]).ratio() >= pipeline.Limits.ECHO_TITLE_SIMILARITY:
                dsu.union(i, j)
    roots = {}
    return [roots.setdefault(dsu.find(i), len(roots)) for i in range(n)]


def test_memoised_grouping_gives_the_same_groups():
    items = [_item(k) for k in range(80)]
    pipeline._similar_titles.cache_clear()
    assert pipeline.independent_groups(items) == _reference_groups(items)


def test_progress_compares_each_title_pair_at_most_once(monkeypatch):
    n = 150
    items = [_item(k) for k in range(n)]
    ev = Event(event_id="ev_0a4e5c3e0fce8be9", domain="web3", title="Binance CEX — x", first_seen=items[0].published_at,
               last_updated=items[-1].published_at, item_ids=[i.item_id for i in items], keys=[])
    calls = {"n": 0}
    real = SequenceMatcher.ratio

    def counted(self):
        calls["n"] += 1
        return real(self)
    monkeypatch.setattr(SequenceMatcher, "ratio", counted)
    pipeline._similar_titles.cache_clear()
    insights.progress(ev, items, datetime(2026, 11, 2, tzinfo=UTC))
    assert calls["n"] <= n * (n - 1) // 2          # was ~n³/6 ≈ 560 k for n = 150
