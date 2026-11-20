"""Live 11-19: Ruby2Shell was reported as GHSA-34m4-m9fh-gqp5 with "CVE pending"; the radar read no identifier, G10
held the P0 ~1 h 50 min until a source revised its title to CVE-2026-132825. A GHSA id is an identifier."""
from datetime import UTC, datetime

from radar import keys, notify, pipeline
from radar.model import RawItem

SITE = "https://site"
ROW = {"event_id": "ev_00000000000000d1", "severity": "P0", "domain": "vuln", "level": "V2", "exploitation": "none",
       "title": "Ruby2Shell: critical Ruby RCE, affected versions and how to fix it (GHSA-34m4-m9fh-gqp5)",
       "first_seen": "2026-11-19T09:42:00Z", "cves": [], "ghsas": ["GHSA-34m4-m9fh-gqp5"], "summary": "s",
       "entities": [], "chains": []}


def test_ghsa_ids_are_read_with_githubs_alphabet_and_become_strong_keys():
    assert keys.ghsas("fix it (GHSA-34m4-m9fh-gqp5), also ghsa-2C3W-xyz1-aaaa") == ["GHSA-34m4-m9fh-gqp5"]
    raw = RawItem(source_id="aikido", url="https://x/r", title=ROW["title"], text="", published_at=datetime(2026, 11, 19, tzinfo=UTC), guid="g")
    it = pipeline.normalize(raw, pipeline.BY_ID["aikido"], datetime(2026, 11, 19, tzinfo=UTC))
    assert "ghsa:GHSA-34m4-m9fh-gqp5" in it.keys and "ghsa:" in pipeline._STRONG


def test_a_p0_with_a_ghsa_and_no_cve_is_sent_and_names_the_advisory():
    v = notify.view(ROW, False)
    (m,) = notify.plan(v, {}, SITE)
    assert "no_cve" not in {p["error"] for p in notify.gate(m, v, SITE, [])}
    assert "🧩 GHSA-34m4-m9fh-gqp5（CVE 待分配）" in m["text"]       # the cut headline no longer shows the id
    v2 = notify.view({**ROW, "ghsas": []}, False)
    (m2,) = notify.plan(v2, {}, SITE)
    assert "no_cve" in {p["error"] for p in notify.gate(m2, v2, SITE, [])}


def test_when_the_cve_arrives_the_rendered_notice_changes_so_the_sent_one_is_edited():
    (before,) = notify.plan(notify.view(ROW, False), {}, SITE)
    (after,) = notify.plan(notify.view({**ROW, "cves": ["CVE-2026-132825"]}, False), {}, SITE)
    assert notify.rendered(before) != notify.rendered(after)
    assert "🧩 CVE-2026-132825" in after["text"]            # the headline names the GHSA, not the CVE


def test_the_identifier_line_appears_only_when_the_headline_does_not_name_it():
    plain = {**ROW, "title": "Ruby2Shell: critical Ruby RCE in case conversion"}
    assert notify.id_line(notify.view(plain, False), "Ruby2Shell: critical Ruby RCE") == "🧩 GHSA-34m4-m9fh-gqp5（CVE 待分配）"
    named = {**ROW, "title": "CVE-2026-132825 - Ruby heap overflow", "cves": ["CVE-2026-132825"], "ghsas": []}
    assert notify.id_line(notify.view(named, False), "CVE-2026-132825 - Ruby heap overflow") is None
    assert notify.id_line({**notify.view(plain, False), "domain": "web3"}, "x") is None
