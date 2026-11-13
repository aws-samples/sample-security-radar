"""Feeds whose AWS egress stopped working go through firecrawl; the generated table is left as onboarding made it."""
from radar import registry
from radar.registry_feeds import FEEDS


def test_an_overridden_feed_is_fetched_through_firecrawl_and_says_why():
    by = {s.source_id: s for s in registry.SOURCES}
    for sid, (via, cadence, why) in registry.FEED_EGRESS_OVERRIDES.items():
        assert by[sid].via == via == "firecrawl" and by[sid].cadence_min == cadence and why in by[sid].notes
        assert any(r[0] == sid for r in FEEDS), f"{sid}: an override must name an admitted feed"


def test_feeds_without_an_override_stay_direct():
    over = set(registry.FEED_EGRESS_OVERRIDES)
    assert all(s.via == "direct" for s in registry.SOURCES if s.source_id in {r[0] for r in FEEDS} - over)
