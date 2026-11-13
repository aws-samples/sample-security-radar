"""P2 rule pack (radar.rulepack): the five worked examples of research/08 §3 as tests, the counter-examples, and the
hard rules a PackRule refuses to break."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from radar import mitigate, pocs, rulepack
from radar.limits import Limits
from radar.rulepack import ORIGIN_SECRET_PLACEHOLDER, PackRule, Quote
from radar.wafmatch import Request, match

FIX = Path(__file__).parent / "fixtures" / "nuclei"
SHA = "0123456789abcdef0123456789abcdef01234567"


def _poc(*cves: str) -> dict:
    return {c: {"state": "found", "path": f"http/cves/2026/{c}.yaml", "sha": SHA, "text": (FIX / f"{c}.yaml").read_text()}
            for c in cves}


def _pack(*cves: str, items=(), catalog=None, cwes=None):
    return rulepack.build({"event_id": "ev_40bbda4fb2090dde", "cves": list(cves)}, list(items), _poc(*cves), catalog or {}, cwes or {})


def _only(cve: str):
    p = _pack(cve)
    assert len(p.custom) == 1, (p.custom, p.rejected)
    return p.custom[0], p


def _verbatim(rule, cve: str) -> None:
    text = (FIX / f"{cve}.yaml").read_text()
    for q in rule.source_quotes:
        assert q.sha == SHA and q.repo == pocs.REPO
        assert rulepack.verify_quote(q.as_dict(), text), q


def test_87902_double_encoded_traversal_in_pagename():
    r, _ = _only("CVE-2026-87902")
    s = r.statement["ByteMatchStatement"]
    assert s["FieldToMatch"] == {"SingleQueryArgument": {"Name": "pagename"}}
    assert (s["SearchString"], s["PositionalConstraint"]) == ("../", "CONTAINS")
    assert [t["Type"] for t in s["TextTransformations"]] == ["URL_DECODE", "URL_DECODE"]   # no NORMALIZE_PATH (it eats ../)
    assert r.confidence == "exact" and r.verified["offline"]["state"] == "pass"
    _verbatim(r, "CVE-2026-87902")
    assert match(r.statement, Request(uri="/?pagename=parent/child")) is False


def test_9586_sqli_is_heuristic_and_offline_unchecked():
    r, _ = _only("CVE-2026-9586")
    parts = r.statement["AndStatement"]["Statements"]
    assert parts[0]["ByteMatchStatement"]["SearchString"] == "/pa"
    assert parts[1]["ByteMatchStatement"]["SearchString"] == "<phoneip>"
    assert "SqliMatchStatement" in parts[2]
    # the injected string has {{interactsh-url}} in it: element name + endpoint only, never the payload
    assert not any("interactsh" in str(p) for p in parts)
    assert r.confidence == "heuristic" and r.verified["offline"]["state"] == "unchecked"
    _verbatim(r, "CVE-2026-9586")


def test_104935_named_header_presence():
    r, _ = _only("CVE-2026-104935")
    s = r.statement["SizeConstraintStatement"]
    assert s["FieldToMatch"] == {"SingleHeader": {"Name": "x-dscgi-path"}} and (s["ComparisonOperator"], s["Size"]) == ("GT", 0)
    assert r.confidence == "exact" and r.verified["offline"]["state"] == "pass"
    _verbatim(r, "CVE-2026-104935")
    # the template's own name singles the header out — that line is quoted too
    assert any("via X-DSCGI-PATH Header" in (FIX / "CVE-2026-104935.yaml").read_text().split("\n")[q.line - 1]
               for q in r.source_quotes)


def test_42018_trailing_slash_with_the_templates_own_negative():
    r, _ = _only("CVE-2026-42018")
    s = r.statement["ByteMatchStatement"]
    assert (s["FieldToMatch"], s["SearchString"], s["PositionalConstraint"]) == ({"UriPath": {}}, "/access/api/v1/aws/token/", "EXACTLY")
    assert any(n.uri == "/access/api/v1/aws/token" for n in r.negatives)
    assert any(p.uri.endswith("%2F") for p in r.positives)
    assert r.verified["offline"]["state"] == "pass"
    _verbatim(r, "CVE-2026-42018")


def test_96655_ssrf_url_parameter_and_plex_headers_are_not_rules():
    r, _ = _only("CVE-2026-96655")
    parts = r.statement["AndStatement"]["Statements"]
    assert parts[0]["ByteMatchStatement"]["SearchString"] == "/video/:/transcode/universal/start.m3u8"
    rx = parts[1]["RegexMatchStatement"]
    assert rx["FieldToMatch"] == {"SingleQueryArgument": {"Name": "path"}} and rx["RegexString"] == rulepack.URL_SCHEME_RE
    assert r.confidence == "exact" and r.verified["offline"]["state"] == "pass"
    assert "X-Plex" not in str(r.statement)          # product headers every client sends, not named by the template
    _verbatim(r, "CVE-2026-96655")


@pytest.mark.parametrize("cve,reason", [("CVE-2026-109619", "fingerprint_only"), ("CVE-2026-71362", "no_verbatim_feature"),
                                        ("CVE-2026-35273", "payload_by_helper"), ("CVE-2026-0257", "not_http")])
def test_counter_examples_are_rejected_with_their_reason(cve, reason):
    p = _pack(cve)
    assert not p.custom
    assert [x["reason"] for x in p.rejected] == [reason] and p.rejected[0]["cve"] == cve and p.rejected[0]["detail"]


def test_probe_requests_never_become_rules():
    """A request in a block whose extractors are internal fetches a target value — it is not the attack, even when it
    looks like one. Without the probe exclusion this fixture yields a traversal rule from the probe."""
    text = """id: CVE-2026-1
info:
  name: X - probe only
  severity: high
http:
  - raw:
      - |
        GET /?file=..%2f..%2fsecret HTTP/1.1
        Host: {{Hostname}}

    extractors:
      - type: regex
        name: v
        internal: true
        regex:
          - 'v=([0-9]+)'
"""
    p = rulepack.build({"event_id": "ev_x", "cves": ["CVE-2026-1"]}, [],
                       {"CVE-2026-1": {"state": "found", "path": "p.yaml", "sha": SHA, "text": text}}, {}, {})
    assert not p.custom and p.rejected[0]["reason"] == "fingerprint_only"


# review of p1/rulepack: a wrong-typed node of a third-party template reached .get / .line / .items and crashed the run
_HTTP = "http:\n  - raw:\n      - |\n        GET /a HTTP/1.1\n"
MALFORMED = {
    "info_scalar": "id: x\ninfo: oops\n" + _HTTP,
    "raw_int": "id: x\ninfo:\n  name: n\nhttp:\n  - raw: [123]\n",
    "raw_scalar": "id: x\ninfo:\n  name: n\nhttp:\n  - raw: oops\n",
    "headers_list": "id: x\ninfo:\n  name: n\nhttp:\n  - method: GET\n    path:\n      - '{{BaseURL}}/a'\n    headers:\n      - x\n",
    "matchers_int": "id: x\ninfo:\n  name: n\nhttp:\n  - matchers: 5\n    raw:\n      - |\n        GET /a HTTP/1.1\n",
    "http_mapping": "id: x\ninfo:\n  name: n\nhttp:\n  raw: x\n",
}


@pytest.mark.parametrize("shape", sorted(MALFORMED))
def test_a_wrong_typed_template_node_is_unsupported_yaml_and_a_rejected_unparseable_row(shape):
    with pytest.raises(pocs.UnsupportedYaml):
        pocs.parse_template(MALFORMED[shape])
    poc = {"CVE-2026-1": {"state": "found", "text": MALFORMED[shape], "sha": SHA, "path": "x.yaml"}}
    p = rulepack.build({"event_id": "ev_x", "cves": ["CVE-2026-1"]}, [], poc, {}, {})
    assert [(r["cve"], r["reason"]) for r in p.rejected] == [("CVE-2026-1", "unparseable")] and not p.custom


def test_a_parser_bug_on_feed_bytes_is_a_rejection_named_by_its_type_not_a_crash(monkeypatch):
    def boom(text):
        raise AttributeError("'Located' object has no attribute 'get'")
    monkeypatch.setattr(pocs, "parse_template", boom)
    p = _pack("CVE-2026-87902")
    assert [r["reason"] for r in p.rejected] == ["unparseable"] and "AttributeError" in p.rejected[0]["detail"]


def test_a_rule_cannot_exist_without_a_verbatim_pinned_quote_or_with_a_variable_or_a_generic_header():
    q = Quote("/a/b", pocs.REPO, SHA, "p.yaml", 3)
    ok = rulepack.byte({"UriPath": {}}, "/a/b", "EXACTLY", "URL_DECODE")
    kw = {"confidence": "exact", "false_positive_note": "fp", "positives": (Request(),), "negatives": (Request(),)}
    PackRule("radar-x-1", "byte", "t", ok, (q,), **kw)
    with pytest.raises(ValueError):          # no quote
        PackRule("radar-x-1", "byte", "t", ok, (), **kw)
    with pytest.raises(ValueError):          # a template variable as match string
        PackRule("radar-x-1", "byte", "t", rulepack.byte({"UriPath": {}}, "{{BaseURL}}/a", "STARTS_WITH"), (q,), **kw)
    with pytest.raises(ValueError):          # a generic header as field
        PackRule("radar-x-1", "byte", "t", rulepack.byte({"SingleHeader": {"Name": "User-Agent"}}, "curl/8", "CONTAINS"), (q,), **kw)
    with pytest.raises(ValueError):          # Block is the reader's decision
        PackRule("radar-x-1", "byte", "t", ok, (q,), action="Block", **kw)
    with pytest.raises(ValueError):          # a template quote must be pinned to a commit, not a branch
        Quote("/a/b", pocs.REPO, "main", "p.yaml", 3)
    with pytest.raises(ValueError):          # an evidence quote's token must be in its sentence
        Quote("X-A: b", url="https://e.x/a", sentence="no such header here")
    # the one placeholder allowed is the origin secret, and only in the origin template
    PackRule("radar-x-2", "origin_lockdown", "t", rulepack.byte({"SingleHeader": {"Name": "x-origin-verify"}},
                                                                 ORIGIN_SECRET_PLACEHOLDER, "EXACTLY"), (q,), **kw)
    with pytest.raises(ValueError):
        PackRule("radar-x-2", "byte", "t", rulepack.byte({"SingleHeader": {"Name": "x-origin-verify"}},
                                                          ORIGIN_SECRET_PLACEHOLDER, "EXACTLY"), (q,), **kw)


def test_a_candidate_that_fails_its_samples_is_rejected_with_the_sample():
    rej: list = []
    c = rulepack.Candidate("byte", rulepack.byte({"UriPath": {}}, "/api", "STARTS_WITH"),
                           (Quote("/api", pocs.REPO, SHA, "p.yaml", 1),), (Request(uri="/api/x"),), (Request(uri="/api/y"),),
                           "exact", "fp")
    assert rulepack._admit(c, "radar-x-1", "t", "CVE-1", rej, "nuclei") is None
    assert rej[0]["reason"] == "negative_matched" and "/api/y" in rej[0]["detail"]


def test_a_candidate_that_hits_common_traffic_is_rejected_even_if_its_own_negatives_pass():
    rej: list = []
    c = rulepack.Candidate("byte", rulepack.byte({"UriPath": {}}, "/static", "STARTS_WITH"),
                           (Quote("/static", pocs.REPO, SHA, "p.yaml", 1),), (Request(uri="/static/x"),), (Request(uri="/x"),),
                           "exact", "fp")
    assert rulepack._admit(c, "radar-x-1", "t", "CVE-1", rej, "nuclei") is None
    assert rej[0]["reason"] == "negative_matched" and "/static/app.js" in rej[0]["detail"]


def test_every_custom_rule_misses_the_benign_corpus():
    p = _pack("CVE-2026-87902", "CVE-2026-104935", "CVE-2026-42018", "CVE-2026-96655")
    assert len(p.custom) == 4
    for r in p.custom:
        assert all(match(r.statement, b) is False for b in rulepack.BENIGN), r.rule_id


def test_managed_candidates_need_no_located_target():
    """W5: PHP2Shell — no target at all, the pack still names the PHP group from the changelog (≥ Version_2.4)."""
    cat = {"CVE-2026-109618": [mitigate.CveRules("AWSManagedRulesPHPRuleSet", ("PHP2Shell_BODY",), "Version_2.4", "2026-10-21")]}
    p = rulepack.build({"event_id": "ev_php", "cves": ["CVE-2026-109618"]}, [], {}, cat, {})
    assert [(m["tier"], m["group"], m["min_version"]) for m in p.managed] == [("cve", "AWSManagedRulesPHPRuleSet", "Version_2.4")]
    assert p.managed[0]["rule"]["OverrideAction"] == {"Count": {}}
    assert p.poc[0]["state"] == "unavailable"      # no PoC data ≠ "no template"


def test_templates_trigger_only_on_registered_wording_and_ips_only_when_defanged():
    items = [SimpleNamespace(item_id="it_1", url="https://e.x/a", title="Credential stuffing wave",
                             text="The origin server was exposed to the internet. Sources: 8.8.8[.]8, 9.9.9.9 and 10.0.0[.]1.")]
    p = _pack(items=items)
    kinds = {r.kind: r for r in p.templates}
    assert set(kinds) == {"rate", "origin_lockdown", "ipset"}
    assert all(r.confidence == "heuristic" for k, r in kinds.items() if k != "ipset")
    assert kinds["ipset"].ip_set["addresses"] == ["8.8.8.8/32"]           # plain 9.9.9.9 is not an IOC; 10/8 is private
    assert kinds["origin_lockdown"].verified["offline"]["state"] == "pass"
    secret = kinds["origin_lockdown"].statement["NotStatement"]["Statement"]["ByteMatchStatement"]["SearchString"]
    assert secret == ORIGIN_SECRET_PLACEHOLDER
    assert all(q.url == "https://e.x/a" and q.token in q.sentence for r in p.templates for q in r.source_quotes)
    assert not _pack(items=[SimpleNamespace(item_id="it_1", url="u", title="A patch", text="Upgrade to 2.4.1 now.")]).templates


def test_evidence_header_is_quoted_by_url_and_sentence():
    items = [SimpleNamespace(item_id="it_1", url="https://e.x/n", title="Next.js bypass",
                             text="Requests carrying X-Middleware-Subrequest: middleware skip the check.")]
    p = _pack(items=items)
    [r] = p.custom
    assert r.statement["ByteMatchStatement"]["FieldToMatch"] == {"SingleHeader": {"Name": "x-middleware-subrequest"}}
    assert r.source_quotes[0].url == "https://e.x/n" and "X-Middleware-Subrequest: middleware" in r.source_quotes[0].sentence


@pytest.mark.parametrize("header", sorted(rulepack.PROXY_HEADERS))
def test_a_proxy_header_named_in_evidence_never_becomes_a_rule_and_is_listed_as_rejected(header):
    """Review of p1/rulepack: 「X-Forwarded-Proto: https」 in an article became an `exact` rule that matches every
    request behind CloudFront → ALB. Every proxy header is refused by PackRule, and the refusal is shown."""
    name = "-".join(w.capitalize() for w in header.split("-"))
    stmt = rulepack.byte({"SingleHeader": {"Name": header}}, "https", "CONTAINS")
    kw = {"confidence": "exact", "false_positive_note": "fp", "positives": (Request(),), "negatives": (Request(),)}
    with pytest.raises(ValueError, match="generic header"):
        PackRule("radar-x-1", "byte", "t", stmt, (Quote("/a/b", pocs.REPO, SHA, "p.yaml", 3),), **kw)
    if name.startswith("X-"):        # the evidence extractor only reads X-* names
        p = _pack(items=[SimpleNamespace(item_id="it_1", url="https://e.x/a", title="t",
                                         text=f"The exploit sends {name}: https to reach the admin route.")])
        assert not p.custom and [(r["extractor"], r["reason"]) for r in p.rejected] == [("evidence_header", "constraint")]


def test_the_benign_corpus_carries_every_proxy_header():
    seen = {n.lower() for r in rulepack.BENIGN for n, _ in r.headers}
    assert rulepack.PROXY_HEADERS <= seen


def test_rules_over_the_cap_are_listed_not_dropped(monkeypatch):
    monkeypatch.setattr(Limits, "RULEPACK_MAX_RULES", 2)
    p = _pack("CVE-2026-87902", "CVE-2026-104935", "CVE-2026-42018")
    assert len(p.custom) + len(p.templates) == 2
    assert [x["reason"] for x in p.rejected] == ["over_rule_cap"]


def test_pack_dict_hash_is_stable_and_follows_the_rules():
    a = _pack("CVE-2026-87902").to_dict()
    b = _pack("CVE-2026-87902").to_dict()
    assert a["hash"] == b["hash"] and a["license"] == pocs.LICENSE
    assert _pack("CVE-2026-42018").to_dict()["hash"] != a["hash"]
    assert a["capacity"] == {"state": "unchecked", "wcu": None, "detail": "尚未调用 CheckCapacity"}


def test_check_reads_every_quote_back_at_its_pinned_sha():
    d = _pack("CVE-2026-87902", "CVE-2026-42018").to_dict()
    texts = {c: (FIX / f"{c}.yaml").read_text() for c in ("CVE-2026-87902", "CVE-2026-42018")}
    asked: list = []

    def get(url):
        asked.append(url)
        return texts[url.rsplit("/", 1)[-1].removesuffix(".yaml")]
    assert rulepack.check_quotes(d, get, {}.get) == []
    assert all(f"/{SHA}/" in u for u in asked)
    # the template moved under the same line number ⇒ the check fails, naming the rule
    texts["CVE-2026-42018"] = texts["CVE-2026-42018"].replace("aws/token/", "aws/token2/")
    bad = rulepack.check_quotes(d, get, {}.get)
    assert [b["reason"] for b in bad] == ["not_verbatim"] and "trailing-slash" in bad[0]["rule_id"]

    def down(url):
        raise OSError("unreachable")
    assert {b["reason"] for b in rulepack.check_quotes(d, down, {}.get)} == {"fetch_failed"}


EV_ITEM = SimpleNamespace(item_id="it_9", url="https://e.x/n", title="Next.js bypass",
                          text="Patch now. Requests carrying X-Middleware-Subrequest: middleware skip the check. Also 8.8.8[.]8.")


def test_an_evidence_quote_carries_the_span_of_its_token_in_the_item():
    """01-waf §4: 「逐字」 = evidence_text(item)[span[0]:span[1]] == token — for every evidence / template-trigger quote."""
    p = _pack(items=[EV_ITEM])
    qs = [q for r in p.custom + p.templates for q in r.source_quotes]
    assert qs and all(q.item_id == "it_9" for q in qs)
    src = rulepack.evidence_text(EV_ITEM)
    assert sorted(src[q.span[0]:q.span[1]] for q in qs) == ["8.8.8[.]8", "X-Middleware-Subrequest: middleware"]
    with pytest.raises(ValueError):          # an evidence quote without a source position cannot exist
        Quote("X-A: b", url="https://e.x/a", sentence="X-A: b here")


def test_check_reads_an_evidence_quote_back_from_the_item_not_from_its_own_sentence():
    """Review of p1/rulepack: the evidence branch re-tested token-in-sentence (what Quote already enforces) and never
    read the source. Now the item is re-read: edited / missing ⇒ a failure; a quote without a span ⇒ a failure."""
    d = _pack(items=[EV_ITEM]).to_dict()
    assert rulepack.check_quotes(d, lambda u: "", {"it_9": EV_ITEM}.get) == []
    edited = SimpleNamespace(**{**EV_ITEM.__dict__, "text": "Patch now. Requests carrying X-Other: thing skip the check. Also 8.8.8[.]8."})
    assert "not_verbatim" in {b["reason"] for b in rulepack.check_quotes(d, lambda u: "", {"it_9": edited}.get)}
    assert {b["reason"] for b in rulepack.check_quotes(d, lambda u: "", {}.get)} == {"source_missing"}
    d["custom"][0]["source_quotes"][0].pop("span")
    assert "no_span" in {b["reason"] for b in rulepack.check_quotes(d, lambda u: "", {"it_9": EV_ITEM}.get)}


def test_a_feed_path_with_dot_segments_never_reaches_a_url_or_a_quote():
    """Review of p1/rulepack: cves.json file_path went unvalidated into RAW_URL + sha + path and the markdown link."""
    for bad in ("../../other/repo/x.yaml", "http/../x.yaml", "/etc/x.yaml", "a//b.yaml", "a/b c.yaml", "a/(x).yaml",
                "a/.hidden.yaml", "a/b.yaml\n"):
        assert not pocs.safe_path(bad), bad
        with pytest.raises(ValueError):
            pocs.raw_url(SHA, bad)
        with pytest.raises(ValueError):
            pocs.template_url(SHA, bad)
        with pytest.raises(ValueError):
            Quote("/a/b", pocs.REPO, SHA, bad, 3)
    assert pocs.safe_path("http/cves/2026/CVE-2026-87902.yaml") and pocs.safe_path("network/cves/2021/CVE-2021-44228.yml")
    unsafe: list = []
    idx = pocs.parse_index('{"ID":"CVE-2026-1001","file_path":"../../x.yaml"}\n{"ID":"CVE-2026-2002","file_path":"http/a.yaml"}\n', unsafe)
    assert idx == {"CVE-2026-2002": "http/a.yaml"} and unsafe == ["CVE-2026-1001: ../../x.yaml"]


def test_quote_links_are_built_once_and_only_for_http():
    tq = Quote("/a/b", pocs.REPO, SHA, "http/a.yaml", 3).as_dict()
    assert rulepack.quote_href(tq) == f"https://github.com/{pocs.REPO}/blob/{SHA}/http/a.yaml#L3"
    ev = {"token": "X-A: bb", "url": "javascript:alert(1)", "sentence": "X-A: bb", "item_id": "i", "span": [0, 7]}
    assert rulepack.quote_href(ev) is None and rulepack.quote_href({**ev, "url": "https://e.x/a"}) == "https://e.x/a"
