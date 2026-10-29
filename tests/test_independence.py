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
