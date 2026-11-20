"""Neo 2026-11-19: 「检查一下当前是不是所有发布的 P0 都会有 WAF 规则包保护…能用 WAF 解决的，先用 WAF 挡一下」. Live: of 8
vulnerability P0s only 3 had a deployable rule; REDCap and TYPO3 (PHP applications) got nothing because products.match
knows neither, REDCap's CWE-73 had no mapping, and the empty packs said nothing about why."""
from radar import mitigate, rulepack


def _plans(title, entities=(), cves=("CVE-2026-90817",), cwes=None):
    ev = {"event_id": "ev_0000000000000001", "title": title, "entities": list(entities), "cves": list(cves)}
    return rulepack.managed(ev, {}, cwes or {})


def test_a_php_application_gets_the_php_group_as_generic_cover():
    for title in ("CVE-2026-90817 Vanderbilt University Research Electronic Data Capture (REDCap): code injection",
                  "CVE-2026-125160 TYPO3 CMS - Information Disclosure in Form Framework"):
        groups = {p["group"]: p for p in _plans(title)}
        assert "AWSManagedRulesPHPRuleSet" in groups, title
        assert "不针对这个 CVE" in groups["AWSManagedRulesPHPRuleSet"]["reason"]
    assert mitigate.php_app({"title": "Apache Roller deserialization"}) is None
    assert mitigate.php_app({"title": "x", "entities": ["Drupal"]}) == "Drupal"


def test_cwe_73_maps_to_the_path_traversal_signatures():
    groups = {p["group"] for p in _plans("Some Java app flaw", cwes={"CVE-2026-90817": ["CWE-73"]})}
    assert {"AWSManagedRulesCommonRuleSet", "AWSManagedRulesLinuxRuleSet"} <= groups


def test_an_empty_pack_says_why_naming_the_weakness():
    ev = {"event_id": "ev_0000000000000002", "title": "Synology DiskStation Manager improper encoding", "entities": [],
          "cves": ["CVE-2024-10441"]}
    pack = rulepack.build(ev, [], {}, {}, {"CVE-2024-10441": ["CWE-116"]}, {}).to_dict()
    assert pack["managed"] == [] and pack["custom"] == [] and "CWE-116" in pack["no_rule"]
    bare = rulepack.build({**ev, "title": "NGINX HTTP/2 memory corruption"}, [], {}, {}, {}, {}).to_dict()
    assert "没有弱点类型" in bare["no_rule"]
    php = rulepack.build({**ev, "title": "TYPO3 CMS flaw"}, [], {}, {}, {}, {}).to_dict()
    assert php["managed"] and php["no_rule"] is None


def test_the_station_passes_title_and_entities_to_the_pack():
    """The live miss: mitigate_station built packs from {event_id, cves, product} — php_app never saw 「TYPO3」."""
    from pathlib import Path
    src = Path(__file__).resolve().parents[1].joinpath("src/radar/mitigate_station.py").read_text()
    assert '"product": resp.get("product"), "title": ev.title,' in src and '"entities": list(ev.entities)}' in src


def test_a_quote_moved_by_a_revised_source_still_verifies_when_its_sentence_is_verbatim():
    """Live 2026-11-19: the deploy check failed on one of 5,292 packs — cvefeed revised CVE-2026-132560 and the token
    moved 7 characters; the sentence and the token were still there, verbatim."""
    s = "This impacts an unknown function of the file /api/v1/memory/logs of the component Memory HTTP Service."
    q = {"token": "/api/v1/memory/logs", "span": [288, 307], "sentence": s}
    revised = "x" * 250 + "A new line. " + s
    assert rulepack.verify_quote(q, revised)
    assert not rulepack.verify_quote(q, revised.replace("/api/v1/memory/logs", "/api/v1/memory/log"))   # the token changed
    assert not rulepack.verify_quote({**q, "sentence": s.replace("Memory", "Mem")}, revised)          # the sentence is gone
    assert not rulepack.verify_quote({**q, "token": "/admin"}, revised)                               # not in its sentence
