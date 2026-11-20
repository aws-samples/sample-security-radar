"""A feed that prints the entry's age into its text must not make every fetch a revision (live 2026-11-19, cvefeed)."""
from datetime import UTC, datetime

from radar import pipeline
from radar.model import RawItem
from radar.store import MemoryStore

TEXT = ("CVE ID : CVE-2026-2307 Published : Nov. 19, 2026, 3:17 a.m. | {age} ago Description : The Elementor Website "
        "Builder plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and "
        "including, 4.0.5 via `/wp-json/elementor/v1/user` REST endpoint.")


def raw(age: str) -> RawItem:
    return RawItem(source_id="cvefeed", url="https://cvefeed.io/vuln/detail/CVE-2026-2307", title="CVE-2026-2307",
                   text=TEXT.format(age=age), published_at=datetime(2026, 11, 19, 3, 17, tzinfo=UTC), guid="CVE-2026-2307")


def test_the_age_is_not_part_of_the_text_or_its_hash():
    src = pipeline.BY_ID["cvefeed"]
    a = pipeline.normalize(raw("42 minutes"), src, datetime(2026, 11, 19, 4, tzinfo=UTC))
    b = pipeline.normalize(raw("1 hour, 52 minutes"), src, datetime(2026, 11, 19, 5, tzinfo=UTC))
    assert a.content_hash == b.content_hash
    assert "ago" not in a.text and "3:17 a.m. | Description :" in a.text


def test_a_refetch_with_only_a_new_age_is_unchanged():
    store, src = MemoryStore(), "cvefeed"
    pipeline.ingest([raw("42 minutes")], store, datetime(2026, 11, 19, 4, tzinfo=UTC))
    res = pipeline.ingest([raw("2 days")], store, datetime(2026, 11, 21, 4, tzinfo=UTC))
    assert (res.unchanged_items, res.updated_items) == (1, 0)
    assert "revised_at" not in store.get_item(pipeline.normalize(raw("1 day"), pipeline.BY_ID[src],
                                                                 datetime(2026, 11, 19, tzinfo=UTC)).item_id).extra


def test_an_age_in_prose_is_left_alone():
    """Only the feed's `| N unit ago` stamp: "patched 3 days ago" in an article is the article's words."""
    src = pipeline.BY_ID["cvefeed"]
    r = RawItem(source_id="cvefeed", url="https://x.example/a", title="t", text="The vendor patched it 3 days ago.",
                published_at=datetime(2026, 11, 19, tzinfo=UTC), guid="g")
    assert pipeline.normalize(r, src, datetime(2026, 11, 19, tzinfo=UTC)).text == "The vendor patched it 3 days ago."


def test_a_pack_built_before_the_strip_still_reads_back_against_text_with_another_age():
    """Live 2026-11-19: the pack quoted "| 42 minutes ago …", the stored item read "| 1 hour, 52 minutes ago …"."""
    from radar import rulepack
    old = "Title. " + TEXT.format(age="42 minutes")
    now = "Title. " + TEXT.format(age="1 hour, 52 minutes")
    tok = "/wp-json/elementor/v1/user"
    q = {"token": tok, "span": [old.index(tok), old.index(tok) + len(tok)], "sentence": old[old.index("| 42"):]}
    assert rulepack.verify_quote(q, now)
    assert not rulepack.verify_quote(q, now.replace("4.0.5", "4.0.6"))   # anything but the age still has to match


def test_the_age_pattern_is_bounded_on_hostile_text():
    """semgrep regex_dos: a long run of near-stamps with no "ago" must not backtrack (it is third-party text)."""
    import time

    from radar import timeutil
    hostile = "| " + "1 hour, " * 20000 + "x"
    t = time.perf_counter()
    assert timeutil.strip_relative_age(hostile) == hostile
    assert time.perf_counter() - t < 0.5
    assert timeutil.strip_relative_age("a | 1 year, 2 months, 3 days ago b") == "a | b"
