"""Respond station criteria (radar → AWS Security Agent + AWS Continuum). Evidence = real live event docs
(2026-10-23: PHP2Shell P0, Node2Shell P1/poc); target = the demo-shop repo shipped for the PoC."""

import copy
import json
import re
from pathlib import Path

import jsonschema
import pytest

from radar import coverage, products, respond

ROOT = Path(__file__).resolve().parents[1]
FX = ROOT / "tests" / "fixtures" / "events"
SCHEMA = json.loads((ROOT / "schemas" / "site-data.schema.json").read_text())
NOW = "2026-10-23T18:00:00Z"
NAMES = {"demo-shop": "demo-shop", "security-radar": "security-radar"}


def _doc(name):
    d = json.loads((FX / f"{name}.json").read_text())
    return d["event"], d["items"], d.get("analysis")


def _target_dir(tid, root):
    return {f"{tid}/{p.relative_to(root)}": p.read_text() for p in sorted(root.rglob("*")) if p.is_file()}


DEMO = ROOT / "integrations/continuum/targets"


@pytest.fixture
def targets():
    demo = respond.Target("demo-shop", "demo-shop", "demo", _target_dir("demo-shop", DEMO / "demo-shop"))
    radar_files = {"security-radar/.gitlab-ci.yml": "lint:\n  image: python:3.12-bookworm\nui:\n  image: node:24-bookworm\n",
                   **{f"security-radar/{p}": (ROOT / p).read_text() for p in ("infra/stack.py", "pyproject.toml")}}
    return [demo, respond.Target("security-radar", "security-radar", "self", radar_files)]


@pytest.fixture
def fleet(targets):
    """Every shipped demo target + this repo — what production scans."""
    return targets + [respond.Target(t, t, t, _target_dir(t, DEMO / t)) for t in ("node-gateway", "wp-storefront", "alps-vault")]


def _validate(defname, obj):
    v = jsonschema.Draft202012Validator({"$defs": SCHEMA["$defs"], "$ref": f"#/$defs/{defname}"})
    errs = sorted(v.iter_errors(obj), key=str)
    assert not errs, errs[:3]


# ---------------------------------------------------------------- products (D-class extraction)

def test_fixed_versions_are_extracted_verbatim_from_php2shell_evidence():
    ev, items, _ = _doc("php2shell")
    p = products.match(ev["title"], ev["entities"])
    assert p and p.product_id == "php"
    assert products.versions(p, respond.texts(items)) == (["8.5.12", "8.4.27", "8.3.36", "8.2.35"], [])


def test_node2shell_demonstrated_version_is_affected_not_fixed():
    ev, items, _ = _doc("node2shell")
    p = products.match(ev["title"], ev["entities"])
    assert p and p.product_id == "nodejs"
    assert products.versions(p, respond.texts(items)) == ([], ["24.22.0"])


def test_inventory_locates_every_php_pin_in_demo_shop_by_line(targets):
    pins = [(p.file, p.line, p.version) for p in targets[0].pins() if p.product_id == "php"]
    assert pins == [("demo-shop/.gitlab-ci.yml", 2, "8.3.30"), ("demo-shop/Dockerfile", 1, "8.3.30"),
                    ("demo-shop/composer.json", 8, "8.3.30")]


@pytest.mark.parametrize("pin,expect", [
    ("8.3.30", ("affected", "8.3.36")), ("8.3.36", ("fixed", "8.3.36")), ("8.4.30", ("fixed", "8.4.27")),
    ("8.3", ("unknown", None)), ("8.1.2", ("unknown", None)),
])
def test_version_verdict_compares_within_branch_only(pin, expect):
    assert products.verdict(pin, ["8.5.12", "8.4.27", "8.3.36", "8.2.35"], []) == expect


def test_exact_affected_version_without_fix_is_affected():
    assert products.verdict("24.22.0", [], ["24.22.0"]) == ("affected", None)
    assert products.verdict("24.21.0", [], ["24.22.0"]) == ("unknown", None)


# ---------------------------------------------------------------- eligibility

@pytest.mark.parametrize("patch,ok,why", [
    ({}, True, "PHP"),
    ({"severity": "P2"}, False, "只对 P0"),
    ({"domain": "incident"}, False, "不涉及代码"),
    ({"title": "Arista patches new VeloCloud Orchestrator zero-day", "entities": []}, False, "登记表"),
])
def test_eligibility_says_why(patch, ok, why):
    ev, items, _ = _doc("php2shell")
    e = respond.eligibility({**ev, **patch}, items)
    assert e["eligible"] is ok and why in e["reason"]


def test_requirement_name_is_api_safe():
    ev, _, _ = _doc("php2shell")
    n = respond.requirement_name(ev)
    assert n == "radar-cve-2026-109618-cve-2026-109619-cve-2026-115560"
    for e in ({**ev, "cves": [f"CVE-2026-{i}" for i in range(30)]}, {**ev, "cves": [], "event_id": "ev_7875c36932b3dc41"}):
        assert re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", respond.requirement_name(e)) and not respond.requirement_name(e).endswith("-")


# ---------------------------------------------------------------- decide / apply (idempotency, budget)

def _ok(op):
    return {"sync_requirement": {"ok": True}, "write_context": {"ok": True},
            "submit_finding": {"finding_id": f"cf-{op.payload.get('uid', '')[-6:]}", "status": "SUBMITTED", "title": "t"},
            "request_scan": {"scan_run_id": "scan-1", "status": "SUBMITTED"},
            "start_review": {"code_review_id": "cr-1", "job_id": "cj-1"},
            "poll_review": {"status": "IN_PROGRESS", "findings": None},
            "poll_continuum": {"findings": [], "issues": [], "issues_complete": True}}[op.kind]


def _run(ev, items, an, st, targets, budget, results=_ok):
    st, ops = respond.decide(ev, items, an, st, targets, budget)
    for op in ops:
        st = respond.apply(st, op, results(op), NOW)
    return st, ops


def test_first_cycle_on_p0_pushes_rule_context_findings_scan_and_one_review(targets):
    ev, items, an = _doc("php2shell")
    b = respond.Budget(reviews_left=4, scan_allowed=True, today=NOW[:10])
    _, ops = _run(ev, items, an, None, targets, b)
    kinds = [(o.kind, o.target_id) for o in ops]
    assert kinds.count(("submit_finding", "demo-shop")) == 3
    assert ("start_review", "demo-shop") in kinds and ("start_review", "security-radar") not in kinds  # no PHP there
    assert {"sync_requirement", "write_context"} <= {k for k, _ in kinds}
    assert "request_scan" not in {k for k, _ in kinds}   # cost: no scan until a finding is actually submitted


def test_second_cycle_scans_the_submitted_findings_once_then_only_polls(targets):
    """Cost rule (2026-10-28): the scan is bought by findings that were submitted (cycle 2), exactly once."""
    ev, items, an = _doc("php2shell")
    st, _ = _run(ev, items, an, None, targets, respond.Budget(4, True, today=NOW[:10]))
    st, ops = _run(ev, items, an, st, targets, respond.Budget(4, True, today=NOW[:10]))
    assert {o.kind for o in ops} == {"poll_review", "poll_continuum", "request_scan"}
    _, ops = respond.decide(ev, items, an, st, targets, respond.Budget(4, True, today=NOW[:10]))
    assert {o.kind for o in ops} == {"poll_review", "poll_continuum"}


def test_escalation_reruns_review_only_after_previous_finished(targets):
    ev, items, an = _doc("php2shell")
    st, _ = _run(ev, items, an, None, targets, respond.Budget(4, True, today=NOW[:10]))
    hot = {**ev, "exploitation": "confirmed" if ev["exploitation"] != "confirmed" else "poc"}
    _, ops = respond.decide(hot, items, an, st, targets, respond.Budget(4, False, today=NOW[:10]))
    assert "start_review" not in {o.kind for o in ops}             # still running
    st["targets"]["demo-shop"]["review"]["status"] = "COMPLETED"
    st["targets"]["demo-shop"]["review"]["findings_fetched"] = True
    _, ops = respond.decide(hot, items, an, st, targets, respond.Budget(4, False, today=NOW[:10]))
    assert ("start_review", "demo-shop") in [(o.kind, o.target_id) for o in ops]


def test_reviews_are_batched_per_target_and_budget_is_per_review():
    req = lambda e, t: (e, respond.Op("start_review", t, {}))
    b = respond.Budget(2, True, today=NOW[:10])
    start, blocked = respond.plan_reviews([req("a", "demo-shop"), req("b", "demo-shop"), req("b", "alps-vault"),
                                           req("c", "wp-storefront")], b)
    assert start == {"demo-shop": ["a", "b"], "alps-vault": ["b"]} and blocked == [("c", "wp-storefront")]
    assert b.reviews_left == 0


def test_exhausted_budget_blocks_review_visibly(targets):
    st = respond.block_review({}, "demo-shop")
    assert "额度" in st["targets"]["demo-shop"]["review_blocked"]


def test_failed_operation_is_recorded_and_retried_next_cycle(targets):
    ev, items, an = _doc("php2shell")
    fail = lambda op: {"error": "AccessDenied: x"} if op.kind == "sync_requirement" else _ok(op)
    st, _ = _run(ev, items, an, None, targets, respond.Budget(4, True, today=NOW[:10]), fail)
    assert st["actions"]["requirement"]["status"] == "failed" and "AccessDenied" in st["actions"]["requirement"]["detail"]
    _, ops = respond.decide(ev, items, an, st, targets, respond.Budget(4, True, today=NOW[:10]))
    assert "sync_requirement" in {o.kind for o in ops}


def test_p1_poc_with_partial_pins_checks_inventory_but_spends_nothing(targets):
    ev, items, an = _doc("node2shell")
    st, ops = _run(ev, items, an, None, targets, respond.Budget(4, True, today=NOW[:10]))
    assert not {"start_review", "submit_finding"} & {o.kind for o in ops}
    r = respond.to_response(st, NAMES, NOW)
    by = {t["target_id"]: t for t in r["targets"]}
    assert by["security-radar"]["relevant"] and by["security-radar"]["verdict"] == "unknown"   # node:24 ≠ comparable
    assert by["demo-shop"]["verdict"] == "skipped"


# ---------------------------------------------------------------- rendering + schema

def _completed_state(targets):
    ev, items, an = _doc("php2shell")
    st, _ = _run(ev, items, an, None, targets, respond.Budget(4, True, today=NOW[:10]))
    done = {"status": "COMPLETED", "findings": [
        {"finding_id": "f-1", "title": "[Requirement: radar-cve-2026-109618-…] PHP pinned to 8.3.30", "severity": "HIGH",
         "status": "ACTIVE", "file": "Dockerfile", "line": 1, "requirement_hit": True},
        {"finding_id": "f-0", "title": "Container runs as root", "severity": "HIGH", "status": "ACTIVE",
         "file": None, "line": None, "requirement_hit": False}],
        "patches": [{"path": "continuum/patches/x.diff", "files_changed": ["Dockerfile"], "source": "security_agent", "summary": "bump"}]}
    st = respond.apply(st, respond.Op("poll_review", "demo-shop", {"job_id": "cj-1"}), done, NOW)
    return ev, st


def test_completed_review_renders_affected_with_requirement_hits_first(targets):
    _, st = _completed_state(targets)
    r = respond.to_response(st, NAMES, NOW)
    _validate("Response", r)
    assert r["findings"][0]["requirement_hit"] and r["targets"][0]["verdict"] == "affected"
    assert r["patches"] and r["patches"][0]["target_id"] == "demo-shop"
    assert respond.impact(r) == {"status": "affected", "affected": 1, "checked": 2}
    _validate("ImpactSummary", respond.impact(r))


def test_not_eligible_renders_reason_and_chip():
    ev, items, an = _doc("php2shell")
    st, _ = respond.decide({**ev, "severity": "P2"}, items, an, None, [], respond.Budget(4, True, today=NOW[:10]))
    r = respond.to_response(st, NAMES, NOW)
    _validate("Response", r)
    assert r["status"] == "not_eligible" and respond.impact(r)["status"] == "not_eligible"


def test_ocsf_document_carries_continuum_overlay_fields(targets):
    ev, items, _ = _doc("php2shell")
    loc = respond.locations(targets[0], respond.eligibility(ev, items))[0]
    d = respond.ocsf(ev, items, loc, "us-east-1", 1)
    assert d["class_uid"] == 2002 and d["metadata"]["version"] == "1.9.0"
    assert d["finding_info"]["uid"] == respond.finding_uid(ev, loc)
    assert d["vulnerabilities"][0]["affected_code"][0]["file"]["path"].startswith("demo-shop/")  # repo-prefixed
    assert d["cloud"]["region"] == "us-east-1" and d["osint"] and all(o["value"].startswith("http") for o in d["osint"])


def test_context_doc_contains_only_grounded_sentences():
    ev, items, an = _doc("php2shell")
    an = {**an, "bluf": [*an["bluf"], {"text": "UNGROUNDED CLAIM", "cite": [], "grounded": False, "issues": []}]}
    doc = respond.context_doc(ev, an, items)
    assert "UNGROUNDED CLAIM" not in doc and an["bluf"][0]["text"] in doc


def test_coverage_counts_only_applicable_capabilities():
    rows = coverage.rows({"counters": {c.counter: 1 for c in coverage.CAPABILITIES if c.counter and c.key != "github"}})
    assert coverage.percent(rows) == 100.0
    assert {r["status"] for r in rows} == {"live", "needs_user", "not_applicable"}
    half = coverage.rows({"counters": {"events_considered": 1}})
    assert 0 < coverage.percent(half) < 100
    for r in rows:
        _validate("Capability", r)


def test_requirement_is_reasserted_on_a_new_day(targets):
    """The pack is a CloudFormation resource; a stack update could drop API-added rules ⇒ re-sync daily."""
    ev, items, an = _doc("php2shell")
    st, _ = _run(ev, items, an, None, targets, respond.Budget(4, True, today=NOW[:10]))
    _, ops = respond.decide(ev, items, an, st, targets, respond.Budget(4, False, today="2026-10-24"))
    assert "sync_requirement" in {o.kind for o in ops}


# ---------------------------------------------------------------- the demo fleet (real incidents × shipped targets)

def _ops(ev, items, an, fleet, budget=None):
    _, ops = respond.decide(ev, items, an, None, fleet, budget or respond.Budget(6, True, today=NOW[:10]))
    return [(o.kind, o.target_id) for o in ops]


def test_alpscon_iocs_and_attack_class_come_from_evidence():
    from radar import patterns
    ev, items, _ = _doc("alpscon")
    e = respond.eligibility(ev, items)
    assert e["eligible"] and e["kind"] == "web3"
    assert patterns.HARDHAT_ACCOUNT0 in e["iocs"] and "public-dev-key" in e["classes"]


def test_alps_vault_exact_hits_are_the_whitelisted_dev_account_and_its_public_key(fleet):
    ev, items, _ = _doc("alpscon")
    vault = next(t for t in fleet if t.target_id == "alps-vault")
    locs = respond.locations(vault, respond.eligibility(ev, items))
    exact = {(loc["file"], loc["match"]) for loc in locs if loc["match"] == "exact"}
    assert ("alps-vault/contracts/RewardVault.sol", "exact") in exact and ("alps-vault/hardhat.config.ts", "exact") in exact
    src = (DEMO / "alps-vault/contracts/RewardVault.sol").read_text().splitlines()
    reserves = next(n for n, line in enumerate(src, 1) if "getReserves()" in line and "pricePair" in line)
    # a code *shape* is only a candidate: Security Agent / Continuum decide, the radar never claims it
    assert {loc["match"] for loc in locs if loc["line"] == reserves} <= {"heuristic"}


def test_alpscon_reviews_only_the_contract_repo(fleet):
    ev, items, an = _doc("alpscon")
    ops = _ops(ev, items, an, fleet)
    assert [t for k, t in ops if k == "start_review"] == ["alps-vault"]
    assert {t for k, t in ops if k == "submit_finding"} == {"alps-vault"}


def test_node2shell_pins_exact_affected_runtime_in_node_gateway_without_paid_review(fleet):
    ev, items, an = _doc("node2shell")
    ops = _ops(ev, items, an, fleet)
    assert {t for k, t in ops if k == "submit_finding"} == {"node-gateway"} and not [k for k, _ in ops if k == "start_review"]
    gw = next(t for t in fleet if t.target_id == "node-gateway")
    assert {loc["file"] for loc in respond.locations(gw, respond.eligibility(ev, items))} >= {
        "node-gateway/.nvmrc", "node-gateway/Dockerfile"}


def test_php2shell_reviews_every_php_target_including_wordpress_image(fleet):
    ev, items, an = _doc("php2shell")
    ops = _ops(ev, items, an, fleet)
    assert sorted(t for k, t in ops if k == "start_review") == ["demo-shop", "wp-storefront"]


def test_ioc_hit_ignores_address_checksum_casing():
    from radar import patterns
    hits = patterns.scan({"x/Config.sol": f"address constant A = {patterns.HARDHAT_ACCOUNT0.lower()};"}, [],
                         [patterns.HARDHAT_ACCOUNT0])
    assert hits and hits[0]["match"] == "exact" and hits[0]["what"].endswith(patterns.HARDHAT_ACCOUNT0)


def test_web3_ocsf_carries_a_cwe_since_there_is_no_cve(fleet):
    """Live validator: OCSF vulnerability must have cve | cwe | advisory (2026-10-23 rejection)."""
    ev, items, _ = _doc("alpscon")
    vault = next(t for t in fleet if t.target_id == "alps-vault")
    loc = respond.locations(vault, respond.eligibility(ev, items))[0]
    v = respond.ocsf(ev, items, loc, "us-east-1", 1)["vulnerabilities"][0]
    assert "cve" in v or v["cwe"]["uid"] == "798"


def test_decide_never_mutates_the_previous_state(targets):
    """The handler persists only when new != old; a shared nested dict made every change invisible (live bug)."""
    import copy
    ev, items, an = _doc("php2shell")
    st, _ = _run(ev, items, an, None, targets, respond.Budget(4, True, today=NOW[:10]))
    st["targets"]["demo-shop"]["locations"] = []
    before = copy.deepcopy(st)
    new, _ = respond.decide(ev, items, an, st, targets, respond.Budget(4, True, today=NOW[:10]))
    assert st == before and new != before            # recomputed locations differ and are visible as a change


def test_detector_source_does_not_match_itself():
    from radar import patterns
    src = (ROOT / "src/radar/patterns.py").read_text()
    assert not patterns.scan({"security-radar/src/radar/patterns.py": src}, ["public-dev-key"], [patterns.HARDHAT_ACCOUNT0])


def test_client_token_is_stable_across_retries_and_changes_with_content(targets):
    ev, items, _ = _doc("php2shell")
    loc = respond.locations(targets[0], respond.eligibility(ev, items))[0]
    uid = respond.finding_uid(ev, loc)
    a, b = respond.ocsf(ev, items, loc, "us-east-1", 1), respond.ocsf(ev, items, loc, "us-east-1", 2)
    assert respond.client_token(uid, a) == respond.client_token(uid, b)          # only the clock differs
    c = respond.ocsf({**ev, "independent_sources": 99}, items, loc, "us-east-1", 1)
    assert respond.client_token(uid, a) != respond.client_token(uid, c)
    assert len(respond.client_token(uid, a)) <= 64


@pytest.mark.parametrize("name,hit", [
    ("[Requirement: security-radar/radar-cve-2026-109618-cve-2026-109619-cve-2026-115560] PHP runtime pinned", True),
    ("[Requirement: radar-cve-2026-109618-cve-2026-109619-cve-2026-115560] PHP runtime pinned", True),   # PoC pack
    ("[Requirement: ASA Base Pack/secure-by-default-best-practices] Container runs as root", False),
    ("Unauthenticated LFI/RFI via $_GET['tpl']", False),
])
def test_requirement_hit_matches_live_security_agent_titles(name, hit):
    assert respond.requirement_hit(name) is hit


def test_skipped_targets_contribute_no_actions_or_findings(targets):
    _, st = _completed_state(targets)
    st["targets"]["security-radar"]["review"] = {"job_id": "cj-x", "status": "COMPLETED", "findings_fetched": True,
        "findings": [{"finding_id": "x", "title": "t", "severity": "HIGH", "status": "ACTIVE", "requirement_hit": True}]}
    st["actions"]["code_review:security-radar"] = {"kind": "code_review", "service": "security_agent",
        "target_id": "security-radar", "status": "done", "detail": "d", "external_id": None, "console_url": None,
        "started_at": NOW, "updated_at": NOW}
    r = respond.to_response(st, NAMES, NOW)
    assert all(f["target_id"] != "security-radar" for f in r["findings"])
    assert all(a["target_id"] != "security-radar" for a in r["actions"])



def test_github_capability_moves_needs_user_to_wired_to_live():
    gh = lambda led: next(r for r in coverage.rows(led) if "GitHub PR" in r["capability"])["status"]
    assert gh({}) == "needs_user"                                                    # no OAuth integration yet
    assert gh({"env": {"github_environment_id": "e"}}) == "wired"                     # integrated, no PR seen
    assert gh({"env": {"github_environment_id": "e"}, "counters": {"github_prs": 1}}) == "live"


def test_github_mirror_submits_located_findings_once_and_scans(fleet):
    ev, items, an = _doc("php2shell")
    b = respond.Budget(6, True, today=NOW[:10], github_targets=("demo-shop",), github_scan_allowed=True)
    st, ops = respond.decide(ev, items, an, None, fleet, b)
    gh = [o for o in ops if o.kind == "submit_finding_gh"]
    assert {o.target_id for o in gh} == {"demo-shop"} and len(gh) == 3 and "request_scan_gh" not in {o.kind for o in ops}
    # one environment per target: the mirrored repo is not also submitted to the S3 environment (cost x2)
    assert not [o for o in ops if o.kind == "submit_finding" and o.target_id == "demo-shop"]
    for op in ops:
        if op.kind == "submit_finding_gh":
            st = respond.apply(st, op, {"finding_id": f"g-{op.payload['uid'][-4:]}", "status": "SUBMITTED"}, NOW)
    b2 = respond.Budget(6, False, today=NOW[:10], github_targets=("demo-shop",), github_scan_allowed=True)
    _, ops2 = respond.decide(ev, items, an, st, fleet, b2)
    kinds2 = {o.kind for o in ops2}
    assert "submit_finding_gh" not in kinds2 and "poll_continuum_gh" in kinds2 and "request_scan_gh" in kinds2


def test_gitlab_channel_runs_the_same_chain_as_github(fleet):
    """One repository channel abstraction (REPO_CHANNELS): GitLab gets submit → scan → poll with its own op kinds,
    its own state and its own 24 h debounce, and never touches the GitHub or S3 environments."""
    ev, items, an = _doc("php2shell")
    b = respond.Budget(6, True, today=NOW[:10], s3_targets=(), gitlab_targets=("demo-shop",), gitlab_scan_allowed=True)
    st, ops = respond.decide(ev, items, an, None, fleet, b)
    kinds = {o.kind for o in ops}
    assert {o.target_id for o in ops if o.kind == "submit_finding_gl"} == {"demo-shop"}
    assert not kinds & {"submit_finding", "submit_finding_gh", "request_scan_gl"}
    for op in ops:
        if op.kind == "submit_finding_gl":
            st = respond.apply(st, op, {"finding_id": f"l-{op.payload['uid'][-4:]}", "status": "SUBMITTED"}, NOW)
    assert st["gitlab"]["findings"] and not (st.get("github") or {}).get("findings")
    _, ops2 = respond.decide(ev, items, an, st, fleet, b)
    assert {"poll_continuum_gl", "request_scan_gl"} <= {o.kind for o in ops2}
    b3 = respond.Budget(6, True, today=NOW[:10], s3_targets=(), gitlab_targets=("demo-shop",), gitlab_scan_allowed=False)
    _, ops3 = respond.decide(ev, items, an, st, fleet, b3)
    assert "request_scan_gl" not in {o.kind for o in ops3}                            # 24 h debounce per channel


def test_a_gitlab_target_is_never_also_submitted_to_the_s3_environment(fleet):
    """Even when the S3 channel would accept it (s3_targets unset = legacy all), a GitLab target lives in one env only."""
    ev, items, an = _doc("php2shell")
    _, ops = respond.decide(ev, items, an, None, fleet, respond.Budget(6, True, today=NOW[:10], gitlab_targets=("demo-shop",)))
    assert not [o for o in ops if o.kind == "submit_finding" and o.target_id == "demo-shop"]
    assert [o for o in ops if o.kind == "submit_finding_gl" and o.target_id == "demo-shop"]


def test_merge_request_surfaces_in_response(fleet):
    ev, items, an = _doc("php2shell")
    st, _ = respond.decide(ev, items, an, None, fleet, respond.Budget(0, False, today=NOW[:10]))
    mr = "https://gitlab.com/u/security-radar-demo-fleet/-/merge_requests/3"
    issue = {"issue_id": "i9", "name": "PHP 8.3.30", "severity": "CRITICAL", "phase": "REMEDIATION", "status": "COMPLETED",
             "exploitable": "EXPLOITABLE", "patch_status": "SUCCEEDED", "patch_path": "continuum/patches/y.patch",
             "patch_files": ["alps-vault/Dockerfile"], "synopsis": None, "effect": None, "evidence_summary": None, "pr_url": mr}
    st = respond.apply(st, respond.Op("poll_continuum_gl"), {"findings": [], "issues": [issue], "issues_complete": True}, NOW)
    r = respond.to_response(st, NAMES, NOW)
    _validate("Response", r)
    assert any(p.get("pr_url") == mr for p in r["patches"])


def test_gitlab_capability_moves_needs_user_to_wired_to_live():
    gl = lambda led: next(r for r in coverage.rows(led) if "GitLab MR" in r["capability"])
    assert gl({})["status"] == "needs_user"
    assert gl({"env": {"gitlab_environment_id": "e"}})["status"] == "wired"
    assert gl({"env": {"gitlab_environment_id": "e"}, "counters": {"gitlab_mrs": 1}})["status"] == "live"
    assert gl({"gitlab_error": "AccessDenied"})["evidence"].startswith("blocked:")
    # the GitHub row reads only its own channel
    assert next(r for r in coverage.rows({"env": {"gitlab_environment_id": "e"}}) if "GitHub PR" in r["capability"])["status"] == "needs_user"


def test_gitlab_mr_url_from_delivery_target():
    from radar import continuum_aws as A
    assert A._gitlab_mr_url({"mergeRequestUrl": "https://gitlab.com/a/b/-/merge_requests/2"}) == "https://gitlab.com/a/b/-/merge_requests/2"
    assert A._gitlab_mr_url({"projectPath": "a/b", "mergeRequestIid": 5}) == "https://gitlab.com/a/b/-/merge_requests/5"
    assert A._gitlab_mr_url({"instanceUrl": "https://gl.example/", "projectPath": "a/b", "mergeRequestIid": 5}) == "https://gl.example/a/b/-/merge_requests/5"
    assert A._gitlab_mr_url({}) is None and A._gitlab_mr_url({"url": "https://gitlab.com/a/b"}) is None


def test_pull_request_surfaces_in_response(fleet):
    ev, items, an = _doc("php2shell")
    st, _ = respond.decide(ev, items, an, None, fleet, respond.Budget(0, False, today=NOW[:10]))
    issue = {"issue_id": "i1", "name": "PHP 8.3.30", "severity": "CRITICAL", "phase": "REMEDIATION", "status": "COMPLETED",
             "exploitable": "EXPLOITABLE", "patch_status": "SUCCEEDED", "patch_path": "continuum/patches/x.patch",
             "patch_files": ["demo-shop/Dockerfile"], "synopsis": None, "effect": None, "evidence_summary": None,
             "pr_url": "https://github.com/o/r/pull/7"}
    st = respond.apply(st, respond.Op("poll_continuum_gh"), {"findings": [], "issues": [issue], "issues_complete": True}, NOW)
    r = respond.to_response(st, NAMES, NOW)
    _validate("Response", r)
    assert any(p.get("pr_url") == "https://github.com/o/r/pull/7" for p in r["patches"])
    assert any(a["console_url"] == "https://github.com/o/r/pull/7" for a in r["actions"])


def test_submitted_findings_trigger_a_rescan_once_the_last_scan_finished(targets):
    """Continuum validates a submitted finding only at the next successful build (live: stuck SUBMITTED 2 days)."""
    ev, items, an = _doc("node2shell")
    ev = {**ev, "severity": "P1"}
    st = {"targets": {"node-gateway": {"cn_findings": {"u": {"finding_id": "f", "status": "SUBMITTED",
                                                              "submitted_at": "2026-10-23T12:00:00Z"}}}},
          "scan": {"scan_run_id": "s", "status": "SUCCEEDED", "requested_at": "2026-10-23T10:00:00Z"}}
    _, ops = respond.decide(ev, items, an, st, targets, respond.Budget(6, True, today=NOW[:10]))
    assert "request_scan" in {o.kind for o in ops}
    st["scan"]["status"] = "SCANNING"
    _, ops = respond.decide(ev, items, an, st, targets, respond.Budget(6, True, today=NOW[:10]))
    assert "request_scan" not in {o.kind for o in ops}


def test_github_block_is_visible_in_coverage():
    row = next(r for r in coverage.rows({"github_error": "InternalServerException"}) if "GitHub PR" in r["capability"])
    assert row["status"] == "needs_user" and row["evidence"].startswith("blocked:")


def test_cooled_down_event_keeps_and_shows_its_results(targets):
    """P0 → P1 after 72 h must not erase reviews/issues/patches (live 2026-10-25, PHP2Shell)."""
    ev, st = _completed_state(targets)
    cooled = {**ev, "severity": "P1", "exploitation": "reported"}
    items = _doc("php2shell")[1]
    st2, ops = respond.decide(cooled, items, None, st, targets, respond.Budget(6, True, today=NOW[:10]))
    assert not {"start_review", "submit_finding", "sync_requirement"} & {o.kind for o in ops}
    r = respond.to_response(st2, NAMES, NOW)
    _validate("Response", r)
    assert r["status"] != "not_eligible" and r["patches"] and "已退出触发条件" in r["reason"]



def test_a_finding_stuck_after_its_rescan_does_not_rescan_again(targets):
    """Cost guard: each scan spends Continuum inference units; a stuck finding gets one rescan, not one per 6 h."""
    ev, items, an = _doc("node2shell")
    st = {"targets": {"node-gateway": {"cn_findings": {"u": {"finding_id": "f", "status": "SUBMITTED",
                                                              "submitted_at": "2026-10-23T12:00:00Z"}}}},
          "scan": {"scan_run_id": "s", "status": "SUCCEEDED", "requested_at": "2026-10-24T10:00:00Z"}}
    _, ops = respond.decide({**ev, "severity": "P1"}, items, an, st, targets, respond.Budget(6, True, today=NOW[:10]))
    assert "request_scan" not in {o.kind for o in ops}


def test_rescan_token_follows_the_finding_set(targets):
    """A per-event token made the rescan replay the event's first, finished scan — nothing ran (live 2026-10-25)."""
    ev, items, an = _doc("node2shell")
    ev = {**ev, "severity": "P1"}
    base = {"targets": {"node-gateway": {"cn_findings": {"u": {"finding_id": "f", "status": "SUBMITTED",
                                                                "submitted_at": "2026-10-23T12:00:00Z"}}}},
            "scan": {"scan_run_id": "s", "status": "SUCCEEDED", "requested_at": "2026-10-23T10:00:00Z"}}
    tok = lambda st: next(o.payload["token"] for o in respond.decide(
        ev, items, an, st, targets, respond.Budget(6, True, today=NOW[:10]))[1] if o.kind == "request_scan")
    more = copy.deepcopy(base)
    more["targets"]["node-gateway"]["cn_findings"]["v"] = dict(base["targets"]["node-gateway"]["cn_findings"]["u"])
    assert tok(base) == tok(copy.deepcopy(base)) and tok(base) != tok(more) and len(tok(more)) <= 64


def test_a_scan_already_finished_when_requested_is_not_left_running():
    """Idempotent replay returns a SUCCEEDED run; poll never revisits it, so 'running' would stick forever."""
    st = respond.apply({}, respond.Op("request_scan", payload={"token": "t"}), {"scan_run_id": "s", "status": "SUCCEEDED"}, NOW)
    assert st["actions"]["code_scan"]["status"] == "done"
    st = respond.apply({}, respond.Op("request_scan", payload={"token": "t"}), {"scan_run_id": "s", "status": "SUBMITTED"}, NOW)
    assert st["actions"]["code_scan"]["status"] == "running"


def test_merge_states_rekeys_findings_and_keeps_survivor_records():
    """R2: absorbed findings are re-keyed to the survivor's uid (else decide() drops and resubmits them ⇒ paid scan)."""
    loc = {"file": "Dockerfile", "line": 3, "found_version": "8.3.30", "kind": "docker"}
    absorbed = {"targets": {"demo-shop": {"locations": [loc], "review": {"job_id": "old"},
                                          "cn_findings": {"radar-ev_a-x": {"finding_id": "f1", "file": "Dockerfile", "line": 3}}}},
                "actions": {"code_scan": {"status": "done"}, "requirement": {"status": "done"}},
                "issues": [{"issue_id": "i1"}, {"issue_id": "i2"}], "delivered_prs": {"i1": "u1"},
                "scan": {"scan_run_id": "s-new", "requested_at": "2026-10-24T00:00:00Z"}}
    survivor = {"targets": {"demo-shop": {"review": {"job_id": "mine"}}}, "actions": {"code_scan": {"status": "running"}},
                "issues": [{"issue_id": "i1", "mine": True}], "scan": {"scan_run_id": "s-old", "requested_at": "2026-10-23T00:00:00Z"}}
    out = respond.merge_states("ev_b", survivor, "ev_a", absorbed)
    uid = respond.finding_uid({"event_id": "ev_b"}, loc)
    assert list(out["targets"]["demo-shop"]["cn_findings"]) == [uid]
    assert out["targets"]["demo-shop"]["review"] == {"job_id": "mine"} and out["actions"]["code_scan"]["status"] == "running"
    assert out["issues"] == [{"issue_id": "i1", "mine": True}, {"issue_id": "i2"}] and out["delivered_prs"] == {"i1": "u1"}
    assert out["scan"]["scan_run_id"] == "s-new" and out["merged_from"] == ["ev_a"]
    alone = respond.merge_states("ev_b", None, "ev_a", absorbed)
    assert alone["targets"]["demo-shop"]["review"] == {"job_id": "old"} and alone["issues"] == absorbed["issues"]


def test_finding_whose_location_disappeared_is_kept_as_resolved(targets):
    """R3: a fixed pin used to make the finding vanish from the page; now it shows as removed from code."""
    ev, items, an = _doc("php2shell")
    st = {"targets": {"demo-shop": {"cn_findings": {"radar-gone": {"finding_id": "f9", "status": "CONFIRMED",
                                                                       "file": "old/Dockerfile", "line": 1}}}}}
    st2, _ = respond.decide(ev, items, an, st, targets, respond.Budget(6, True, today="2026-10-27"))
    ts = st2["targets"]["demo-shop"]
    assert "radar-gone" not in (ts.get("cn_findings") or {})
    assert ts["resolved_findings"]["radar-gone"]["resolved_on"] == "2026-10-27"
    r = respond.to_response(st2, NAMES, NOW)
    _validate("Response", r)
    assert any(f["finding_id"] == "f9" and "代码中已移除" in f["status"] for f in r["findings"])


def test_findings_keyed_by_continuum_id_are_rekeyed_not_resolved_or_resubmitted(targets):
    """Live 2026-10-26: rehydrated findings keyed by findingId looked 'gone' when PHP2Shell turned eligible again —
    moved to resolved, resubmitted, and the new finding set started a paid scan."""
    ev, items, an = _doc("php2shell")
    st0, _ = respond.decide(ev, items, an, None, targets, respond.Budget(6, True, today="2026-10-27"))
    locs = st0["targets"]["demo-shop"]["locations"]
    legacy = {f"01a169fd{k}": {"finding_id": f"01a169fd{k}", "status": "CONFIRMED", "file": loc["file"], "line": loc["line"]}
              for k, loc in enumerate(locs)}
    first, *rest = list(legacy.items())
    st = {"targets": {"demo-shop": {"cn_findings": dict(rest), "resolved_findings": {first[0]: {**first[1], "resolved_on": "2026-10-26"}}}},
          "scan": {"scan_run_id": "s", "status": "SUCCEEDED", "requested_at": "2026-10-23T10:00:00Z"}}
    st2, ops = respond.decide(ev, items, an, st, targets, respond.Budget(6, True, today="2026-10-27"))
    ts = st2["targets"]["demo-shop"]
    assert set(ts["cn_findings"]) == {respond.finding_uid(ev, loc) for loc in locs}
    assert "resolved_findings" not in ts and all("resolved_on" not in f for f in ts["cn_findings"].values())
    assert not {"submit_finding", "request_scan"} & {o.kind for o in ops}


def test_a_poll_without_issues_does_not_erase_known_issues():
    st = {"issues": [{"issue_id": "i1", "status": "OLD"}, {"issue_id": "i2"}]}
    st = respond.apply(st, respond.Op("poll_continuum"), {"findings": [], "issues": [{"issue_id": "i1", "status": "NEW"}, {"issue_id": "i3"}],
                                                          "issues_complete": True}, NOW)
    assert st["issues"] == [{"issue_id": "i1", "status": "NEW"}, {"issue_id": "i2"}, {"issue_id": "i3"}]
    st = respond.apply(st, respond.Op("poll_continuum"), {"findings": [], "issues": [], "issues_complete": True}, NOW)
    assert [i["issue_id"] for i in st["issues"]] == ["i1", "i2", "i3"]


def test_a_failing_submit_never_buys_a_scan(targets):
    """Live 2026-10-26/27: CreateCodeFinding was disabled, every cycle re-issued the submit, each counted as a "new
    finding" and a full paid scan ran every 6 h (~$1.4k/day). Only findings that WERE submitted may trigger one."""
    ev, items, an = _doc("php2shell")
    # P0 with an existing scan record: the "P0 without any scan" trigger (one-off) is not in play
    st = {"scan": {"scan_run_id": "s", "status": "SUCCEEDED", "requested_at": "2026-10-23T10:00:00Z"}}
    st2, ops = respond.decide(ev, items, an, st, targets, respond.Budget(6, True, today=NOW[:10]))
    assert "submit_finding" in {o.kind for o in ops} and "request_scan" not in {o.kind for o in ops}
    op = next(o for o in ops if o.kind == "submit_finding")
    st3 = respond.apply(st2, op, {"error": "ValidationException: CreateCodeFinding is temporarily disabled."}, NOW)
    _, ops = respond.decide(ev, items, an, st3, targets, respond.Budget(6, True, today=NOW[:10]))
    assert "request_scan" not in {o.kind for o in ops}             # still failing ⇒ still no scan
    st4 = respond.apply(st3, op, {"finding_id": "f1", "status": "SUBMITTED", "title": "t"}, NOW)
    _, ops = respond.decide(ev, items, an, st4, targets, respond.Budget(6, True, today=NOW[:10]))
    assert "request_scan" in {o.kind for o in ops}                 # a real submission ⇒ one scan


def test_a_p0_event_with_nothing_located_in_our_code_never_buys_a_scan(targets):
    """Live 2026-10-28 01:11Z: the restored Adobe Commerce event (P0, no location in any target) requested a full
    environment scan (≈ $450) because "P0 without a scan yet" was a trigger of its own."""
    ev, items, an = _doc("php2shell")
    nothing = [respond.Target(t.target_id, t.name, t.description, {}) for t in targets]   # no code ⇒ no locations
    st, ops = _run(ev, items, an, None, nothing, respond.Budget(4, True, today=NOW[:10]))
    st, ops2 = _run(ev, items, an, st, nothing, respond.Budget(4, True, today=NOW[:10]))
    assert "request_scan" not in {o.kind for o in ops + ops2}


def test_only_s3_channel_targets_go_to_the_s3_environment(targets):
    """Cost 2026-10-28: every zip in the S3 environment is scanned and paid for; a target whose channel is not s3
    (the radar's own repo, or a GitHub/GitLab one) must not be submitted there."""
    ev, items, an = _doc("php2shell")
    _, ops = respond.decide(ev, items, an, None, targets, respond.Budget(4, True, today=NOW[:10], s3_targets=("wp-storefront",)))
    assert not [o for o in ops if o.kind == "submit_finding"]
    _, ops = respond.decide(ev, items, an, None, targets, respond.Budget(4, True, today=NOW[:10], s3_targets=("demo-shop",)))
    assert {o.target_id for o in ops if o.kind == "submit_finding"} == {"demo-shop"}


def test_every_target_has_exactly_one_channel():
    from radar import targets as T
    assert set(T.CHANNEL) == set(T.NAMES) and T.CHANNEL["security-radar"] == "none"
    assert sum(len(T.on(c)) for c in T.CHANNELS) == len(T.NAMES)


def _gl_submitted(fleet):
    """php2shell on demo-shop, routed to the GitLab channel; every located finding submitted and later CONFIRMED."""
    ev, items, an = _doc("php2shell")
    b = respond.Budget(6, False, today=NOW[:10], s3_targets=(), gitlab_targets=("demo-shop",))
    st, ops = respond.decide(ev, items, an, None, fleet, b)
    for op in ops:
        if op.kind == "submit_finding_gl":
            st = respond.apply(st, op, {"finding_id": f"l-{op.payload['uid'][-4:]}", "status": "SUBMITTED"}, NOW)
    for f in st["gitlab"]["findings"].values():
        f["status"] = "CONFIRMED"
    return ev, items, an, st, b


def test_a_repository_channel_finding_whose_line_is_gone_is_resolved_not_resubmitted(fleet):
    """R12: the S3 path recorded "removed from the code"; GitHub / GitLab findings just stayed open forever."""
    ev, items, an, st, b = _gl_submitted(fleet)
    n = len(st["gitlab"]["findings"])
    fixed = [respond.Target(t.target_id, t.name, t.description, {k: v.replace("8.3.30", "8.3.36") for k, v in t.files.items()})
             if t.target_id == "demo-shop" else t for t in fleet]   # the real fix: every pin bumped to the fixed release
    st2, ops = respond.decide(ev, items, an, st, fixed, b)
    assert not st2["gitlab"].get("findings") and len(st2["gitlab"]["resolved_findings"]) == n
    assert not [o for o in ops if o.kind.startswith(("submit_finding", "request_scan"))]
    r = respond.to_response(st2, NAMES, NOW)
    _validate("Response", r)
    assert sum("代码中已移除" in f["status"] and f["status"].endswith("GitLab") for f in r["findings"]) == n
    # the line comes back ⇒ the same findings return, nothing is resubmitted (a new set would buy a paid scan)
    st3, ops3 = respond.decide(ev, items, an, st2, fleet, b)
    assert len(st3["gitlab"]["findings"]) == n and not st3["gitlab"].get("resolved_findings")
    assert "submit_finding_gl" not in {o.kind for o in ops3}


def test_a_target_that_moved_to_another_channel_keeps_its_old_findings_open(fleet):
    """Leaving a channel is not a fix: findings of a target now validated elsewhere are not marked removed."""
    ev, items, an, st, _ = _gl_submitted(fleet)
    elsewhere = respond.Budget(6, False, today=NOW[:10], s3_targets=(), github_targets=("demo-shop",))
    st2, _ = respond.decide(ev, items, an, st, fleet, elsewhere)
    assert st2["gitlab"]["findings"] and not st2["gitlab"].get("resolved_findings")
    # the channel still has another target (node-gateway, nothing located for PHP2Shell): demo-shop's findings are not its own
    shared = respond.Budget(6, False, today=NOW[:10], s3_targets=(), github_targets=("demo-shop",), gitlab_targets=("node-gateway",))
    st3, _ = respond.decide(ev, items, an, st, fleet, shared)
    assert st3["gitlab"]["findings"] and not st3["gitlab"].get("resolved_findings")


def test_repository_channel_findings_reach_the_event_page_and_the_verdict(fleet):
    """The event page listed only S3 findings; a CONFIRMED GitLab finding did not count toward 'affected'."""
    _ev, _items, _an, st, _ = _gl_submitted(fleet)
    st["targets"]["demo-shop"]["locations"] = []          # isolate the verdict from the radar's own locations
    r = respond.to_response(st, NAMES, NOW)
    gl = [f for f in r["findings"] if f["status"].endswith("· GitLab")]
    assert gl and all(f["target_id"] == "demo-shop" and f["status"].startswith("CONFIRMED") for f in gl)
    assert all(f["title"] for f in gl)                     # no blank rows (repo findings stored without a title)
    assert next(t for t in r["targets"] if t["target_id"] == "demo-shop")["verdict"] == "affected"


def test_a_merge_keeps_the_absorbed_events_repository_channel_findings_and_mrs(fleet):
    ev, _items, _an, st, _ = _gl_submitted(fleet)
    st["gitlab"]["issues"] = [{"issue_id": "i-mr", "name": "x", "pr_url": "https://gitlab.com/a/b/-/merge_requests/1"}]
    out = respond.merge_states("ev_survivor", {}, ev["event_id"], st)
    assert len(out["gitlab"]["findings"]) == len(st["gitlab"]["findings"])
    assert all(u.startswith("radar-ev_survivor-") for u in out["gitlab"]["findings"])   # re-keyed: no resubmission
    assert out["gitlab"]["issues"][0]["pr_url"].endswith("/merge_requests/1")


def _shift(fleet, tid, path_end):
    """A comment line inserted at the top of one file of one target: every pin in it moves down by one."""
    return [respond.Target(t.target_id, t.name, t.description,
                           {k: ("# edited\n" + v if k.endswith(path_end) else v) for k, v in t.files.items()})
            if t.target_id == tid else t for t in fleet]


def test_a_pin_that_only_moved_lines_keeps_its_finding_and_buys_no_scan(fleet):
    """R9: Dockerfile:1 → :2 after an unrelated edit was 'resolved + new finding' ⇒ a new finding set ⇒ a paid scan."""
    ev, items, an, st, b = _gl_submitted(fleet)
    before = {f["finding_id"] for f in st["gitlab"]["findings"].values()}
    st2, ops = respond.decide(ev, items, an, st, _shift(fleet, "demo-shop", "Dockerfile"), b)
    assert not [o for o in ops if o.kind.startswith(("submit_finding", "request_scan"))]
    assert {f["finding_id"] for f in st2["gitlab"]["findings"].values()} == before and not st2["gitlab"].get("resolved_findings")
    moved = [f for f in st2["gitlab"]["findings"].values() if f.get("moved_from")]
    assert len(moved) == 1 and moved[0]["file"].endswith("Dockerfile") and (moved[0]["moved_from"], moved[0]["line"]) == (1, 2)


def test_line_drift_on_the_s3_path_too(targets):
    ev, items, an = _doc("php2shell")
    b = respond.Budget(4, False, today=NOW[:10], s3_targets=("demo-shop",))
    st, ops = respond.decide(ev, items, an, None, targets, b)
    for op in ops:
        if op.kind == "submit_finding":
            st = respond.apply(st, op, {"finding_id": f"f-{op.payload['uid'][-4:]}", "status": "CONFIRMED"}, NOW)
    st2, ops2 = respond.decide(ev, items, an, st, _shift(targets, "demo-shop", "Dockerfile"), b)
    assert "submit_finding" not in {o.kind for o in ops2}
    assert not st2["targets"]["demo-shop"].get("resolved_findings")


def test_an_ambiguous_drift_is_not_guessed(fleet):
    """Two live candidates in the same file with the same version ⇒ no re-pointing (old behaviour: retire + resubmit)."""
    ev, items, an, st, b = _gl_submitted(fleet)
    dup = [respond.Target(t.target_id, t.name, t.description,
                          {k: ("# edited\n" + v + "\n" + v if k.endswith("Dockerfile") else v) for k, v in t.files.items()})
           if t.target_id == "demo-shop" else t for t in fleet]
    st2, _ = respond.decide(ev, items, an, st, dup, b)
    assert not any(f.get("moved_from") for f in st2["gitlab"]["findings"].values())


def test_stale_radar_rules_leave_the_pack_after_the_ttl_and_nothing_else_does():
    """R6: rules of merged-away / no-longer-eligible events stayed in the Security Agent pack forever."""
    pack = ["radar-cve-2026-109618-cve-2026-109619-cve-2026-115560", "radar-cve-2026-111497-old-merge", "radar-ev-new", "team-rule"]
    seen = {"radar-cve-2026-109618-cve-2026-109619-cve-2026-115560": "2026-10-28",   # re-asserted today
            "radar-cve-2026-111497-old-merge": "2026-10-10", "radar-gone-from-pack": "2026-09-01"}
    gone, after = respond.prune_plan(pack, seen, "2026-10-28", 14)
    assert gone == ["radar-cve-2026-111497-old-merge"]                      # 18 days > 14
    assert after["radar-ev-new"] == "2026-10-28"                            # first observed ⇒ full grace, not deleted
    assert "team-rule" not in after and "radar-gone-from-pack" not in after  # not ours / no longer in the pack
    assert respond.prune_plan(pack, {}, "2026-10-28", 14)[0] == []           # the deploy that adds pruning deletes nothing
