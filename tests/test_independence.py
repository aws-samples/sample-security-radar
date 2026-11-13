"""One test per independence guard (each guard gets its own mutation; see mutations.txt M02/M14/M15)."""

from radar.model import Item
from radar.pipeline import independent_groups


def _it(n, org, title, links=(), x_status=None, url=None):
    return Item(item_id=f"it_{n:016x}", source_id=f"s{n}", tier="T2", org=org, domain="vuln",
                url=url or f"https://e{n}.example/a", canonical_url=url or f"https://e{n}.example/a", title=title,
                text="", published_at="2026-10-20T00:00:00Z", fetched_at="2026-10-20T00:00:00Z", content_hash="h",
                keys=[], links=list(links), entity=None, eventful=True,
                signals={"exploited": "unclear", "kev": False, "poc": False, "amount_usd": None},
                extra={"x_status": x_status} if x_status else {})


def test_same_org_is_one_source_even_without_links():
    g = independent_groups([_it(1, "thn", "Alpha zero-day exploited"), _it(2, "thn", "Unrelated wording entirely")])
    assert len(set(g)) == 1


def test_citing_a_tweet_joins_its_author_group():
    tweet = _it(1, "peckshield", "alert", x_status="2113290086808990182")
    db = _it(2, "someaggregator", "different title here",
             links=["https://x.com/PeckShieldAlert/status/2113290086808990182"])
    assert len(set(independent_groups([tweet, db]))) == 1


def test_citing_an_article_url_joins_its_group():
    a = _it(1, "vendor", "Vendor advisory", url="https://vendor.example/adv/1")
    b = _it(2, "media", "Media writeup with other words", links=["https://vendor.example/adv/1"])
    assert len(set(independent_groups([a, b]))) == 1


def test_unrelated_orgs_and_titles_stay_independent():
    assert len(set(independent_groups([_it(1, "a", "Acme VPN flaw"), _it(2, "b", "Ransomware hits hospital")]))) == 2


def _partition(groups):
    by: dict[int, set[int]] = {}
    for i, g in enumerate(groups):
        by.setdefault(g, set()).add(i)
    return sorted(sorted(v) for v in by.values())


def test_title_pair_skips_never_change_the_grouping():
    """The pair loop skips joined pairs and length-hopeless pairs; the partition must equal the all-pairs one."""
    import random

    from radar import pipeline
    rnd = random.Random(7)
    words = ["binance", "hack", "exploit", "bridge", "drained", "million", "wallet", "hot", "attack", "funds"]
    for _ in range(40):
        its = [_it(k, f"o{k}", " ".join(rnd.choice(words) for _ in range(rnd.randint(1, 7)))) for k in range(30)]
        n, titles = len(its), [pipeline._norm_title(i.title) for i in its]
        dsu = pipeline._DSU(n)
        for i in range(n):
            for j in range(i + 1, n):
                if titles[i] and titles[j] and pipeline._similar_titles(titles[i], titles[j]):
                    dsu.union(i, j)
        assert _partition(independent_groups(its)) == _partition([dsu.find(i) for i in range(n)])


def test_syndicated_copies_are_compared_once_not_pairwise():
    """Live 2026-11-11: the now-board ran this per listed event and Publish spent minutes in SequenceMatcher."""
    from radar import pipeline
    pipeline._similar_titles.cache_clear()
    its = [_it(k, f"o{k}", f"Binance hot wallet drained in exploit copy {k}") for k in range(300)]
    assert len(set(independent_groups(its))) == 1
    assert pipeline._similar_titles.cache_info().misses < 2_000        # all-pairs would be 44,850


def test_precomputed_title_pairs_group_every_subset_exactly_like_comparing_titles():
    """insights.progress hands recompute the full event's title pairs; every prefix must group as if compared."""
    import random

    from radar import pipeline
    rnd = random.Random(11)
    words = ["binance", "hack", "exploit", "bridge", "drained", "million", "wallet", "hot", "attack", "funds"]
    for _ in range(25):
        its = [_it(k, f"o{k % 9}", " ".join(rnd.choice(words) for _ in range(rnd.randint(1, 6)))) for k in range(24)]
        for it in its:
            it.published_at = f"2026-10-{rnd.randint(10, 20)}T00:00:00Z"
        pairs = pipeline.title_edges(its)
        order = pipeline._recompute_order(its)
        for k in range(1, len(order) + 1):
            sub = rnd.sample(order, k)
            sub = pipeline._recompute_order(sub)
            assert _partition(independent_groups(sub, pairs)) == _partition(independent_groups(sub))
