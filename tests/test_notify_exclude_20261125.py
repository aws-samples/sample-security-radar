"""A channel that takes every P0 (Neo 2026-11-25), no cloud_stack prefilter; WordPress P0s still never reach a
company channel (Neo 2026-11-23) — the exclusion filter `not_p0_products` keeps them out."""
from __future__ import annotations

from radar import notify


def _view(title):
    return notify.view({"event_id": "ev_1", "title": title, "severity": "P0", "domain": "vuln", "entities": []}, has_waf_pack=False)


SUB = {"severity": ["P0"], "domain": ["vuln", "incident"], "not_p0_products": ["wordpress"]}


def test_a_wordpress_plugin_p0_is_kept_out():
    assert not notify.matches(SUB, _view("CVE-2026-124990 Masteriyo LMS <= 3.5.1 WordPress plugin unauthenticated RCE"))


def test_every_other_p0_passes_without_the_cloud_prefilter():
    assert notify.matches(SUB, _view("CVE-2026-6460 PostgreSQL type confusion executes arbitrary code"))
    assert notify.matches(SUB, _view("ICSA-26-237-03 Siemens SIMATIC IoT2050 Advanced"))      # not cloud_stack, still sent


def test_the_filter_is_validated_against_the_tile_registry():
    _, err = notify._filters({"not_p0_products": ["wordpres"]}, "team")
    assert err and err["error"] == "filter_value"
    ok, err = notify._filters({"not_p0_products": ["wordpress"]}, "team")
    assert err is None and ok == {"not_p0_products": ["wordpress"]}
