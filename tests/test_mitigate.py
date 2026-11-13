"""M3 mitigation criteria (B1, B8 and the registry). Evidence = the AWS Managed Rules changelog and
DescribeManagedRuleGroup answers recorded 2026-10-29; the PHP2Shell event is the live 10-23 P0."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from radar import mitigate as M

ROOT = Path(__file__).resolve().parents[1]
SNAP = ROOT / "tests" / "fixtures" / "snapshots" / "2026-10-29"
GROUPS = {g["name"]: g for g in map(json.loads, (SNAP / "waf-groups.jsonl").read_text().splitlines())}
LABELS = {n: g["labels"] for n, g in GROUPS.items()}
ROWS = M.parse_waf_changelog((SNAP / "waf-changelog.html").read_text())
CATALOG = M.waf_catalog(ROWS)
PHP2SHELL = {"event_id": "ev_bb65db3b8694e5f4", "product": "php",
             "cves": ["CVE-2026-109618", "CVE-2026-109619", "CVE-2026-115560", "CVE-2026-46300"]}
TARGETS = [{"target_id": "demo-shop", "verdict": "affected"}, {"target_id": "wp-storefront", "verdict": "affected"},
           {"target_id": "alps-vault", "verdict": "unaffected"}, {"target_id": "security-radar", "verdict": "not_applicable"}]


# ---------------------------------------------------------------- registry ↔ what AWS says the groups contain
def test_every_registered_group_and_rule_exists_in_aws():
    assert set(M.WAF_GROUPS) == set(GROUPS)
    for cwe, entries in M.CWE_RULES.items():
        for group, rules in entries:
            assert set(rules) <= set(GROUPS[group]["rules"]), (cwe, group, set(rules) - set(GROUPS[group]["rules"]))
    assert set(M.PRODUCT_GROUPS.values()) <= set(GROUPS)


def test_label_prefix_matches_the_labels_aws_emits():
    for name, g in M.WAF_GROUPS.items():
        assert all(lb.startswith(g.label_prefix + ":") for lb in LABELS[name]), name


# ---------------------------------------------------------------- catalog
def test_changelog_rows_carry_group_from_the_first_cell_only():
    php = [r for r in ROWS if r.group == "AWSManagedRulesPHPRuleSet" and r.cves]
    assert {r.version for r in php} >= {"Version_2.3", "Version_2.4", "Version_2.5"}
    # the 2.3 row links the Core rule set in its description — that must not become a CRS mapping
    assert all(c.group != "AWSManagedRulesCommonRuleSet" for c in CATALOG["CVE-2026-109618"])


def test_b1_php2shell_maps_to_php_rule_set_at_least_2_4_with_both_rules():
    for cve in ("CVE-2026-109618", "CVE-2026-109619"):
        (cr,) = CATALOG[cve]
        assert cr.group == "AWSManagedRulesPHPRuleSet"
        assert M.version_key(cr.min_version) >= (2, 4)
        # newest static version that names the CVE, whatever order the page lists rows in (it lists newest first today)
        assert [r.min_version for r in M.waf_catalog(list(reversed(ROWS)))[cve]] == [cr.min_version] == ["Version_2.5"]
    (plan,) = [p for p in M.waf_plans(PHP2SHELL, TARGETS, CATALOG, {}, LABELS) if p.target_id == "demo-shop"]
    assert plan.tier == "cve" and plan.appliable
    assert {"PHP2Shell_BODY", "PHP2Shell_BODY_Extended"} <= set(plan.rules)
    assert set(plan.labels) == {"awswaf:managed:aws:php-app:PHP2Shell_Body", "awswaf:managed:aws:php-app:PHP2Shell_Body_Extended"}
    rule = M.waf_rule(plan, 0)
    assert rule["OverrideAction"] == {"Count": {}}   # staged: the whole group counts (W1), not just the named rules
    assert "Version" not in rule["Statement"]["ManagedRuleGroupStatement"]   # default version (AWS recommendation)


def test_older_cves_in_the_changelog_are_cataloged_too():
    (cr,) = CATALOG["CVE-2023-22518"]
    assert cr.group == "AWSManagedRulesKnownBadInputsRuleSet" and "ExploitablePaths_URIPATH" in cr.rules


# ---------------------------------------------------------------- plans
def test_only_affected_targets_get_a_plan_and_the_specific_tier_wins():
    plans = M.waf_plans(PHP2SHELL, TARGETS, CATALOG, {}, LABELS)
    assert {p.target_id for p in plans} == {"demo-shop", "wp-storefront"}
    # php is also a product-tier group — the cve tier replaces it, one plan per target × group
    assert [p.tier for p in plans if p.group == "AWSManagedRulesPHPRuleSet"] == ["cve", "cve"]


def test_product_tier_without_a_changelog_entry_counts_the_whole_group():
    ev = {"event_id": "e", "product": "wordpress", "cves": ["CVE-2099-0001"]}
    (p,) = M.waf_plans(ev, [{"target_id": "wp-storefront", "verdict": "affected"}], CATALOG, {}, LABELS)
    assert (p.tier, p.group, p.rules) == ("product", "AWSManagedRulesWordPressRuleSet", ())
    assert M.waf_rule(p, 3)["OverrideAction"] == {"Count": {}}


def test_cwe_tier_is_advisory_never_applied():
    ev = {"event_id": "e", "cves": ["CVE-2099-0002"]}
    plans = M.waf_plans(ev, [{"target_id": "t", "verdict": "affected"}], CATALOG, {"CVE-2099-0002": ["CWE-89"]}, LABELS)
    assert [(p.tier, p.group, p.appliable) for p in plans] == [("cwe", "AWSManagedRulesSQLiRuleSet", False)]
    assert "通用" in plans[0].reason


def _effective(rule, group_rules):
    """Rule name → the action AWS WAF takes for it under this web ACL rule. OverrideAction Count turns every rule of the
    group into Count; with OverrideAction None each rule acts at its own action (Block for these groups) unless a
    RuleActionOverrides entry names it."""
    if "Count" in rule["OverrideAction"]:
        return {r: "Count" for r in group_rules}
    stmt = rule["Statement"]["ManagedRuleGroupStatement"]
    ov = {o["Name"]: next(iter(o["ActionToUse"])) for o in stmt.get("RuleActionOverrides") or []}
    return {r: ov.get(r, "Block") for r in group_rules}


# every appliable plan shape the registry produces: cve tier (PHP2Shell names 2 of the PHP rules, CVE-2023-22518 names 1
# of the 12 Known bad inputs rules) and product tier (WordPress, whole group)
W1_EVENTS = [PHP2SHELL, {"event_id": "kbi", "cves": ["CVE-2023-22518"]},
             {"event_id": "wp", "product": "wordpress", "cves": ["CVE-2099-0001"]}]


def test_w1_staged_counts_every_rule_of_the_group_and_promotion_blocks_only_the_named_rules():
    """Live bug (docs/research/action/01-waf.md Bug-1): staging rendered OverrideAction None + Count on the named rules,
    so the group's OTHER rules blocked with nobody's confirmation — PHP2Shell staging blocked the 4
    PHPHighRiskMethodsVariables_* rules, CVE-2023-22518 staging blocked 11 Known bad inputs rules."""
    plans = [p for ev in W1_EVENTS for p in M.waf_plans(ev, TARGETS[:1], CATALOG, {}, LABELS) if p.appliable]
    assert {(p.tier, p.group) for p in plans} == {("cve", "AWSManagedRulesPHPRuleSet"),
                                                  ("cve", "AWSManagedRulesKnownBadInputsRuleSet"),
                                                  ("product", "AWSManagedRulesWordPressRuleSet")}
    for plan in plans:
        every = GROUPS[plan.group]["rules"]
        staged = _effective(M.waf_rule(plan, 0), every)
        assert set(staged.values()) == {"Count"}, (plan.group, sorted(r for r, a in staged.items() if a != "Count"))
        promoted = _effective(M.waf_rule(plan, 0, block=True, group_rules=every), every)
        blocks = {r for r, a in promoted.items() if a == "Block"}
        assert blocks == (set(plan.rules) & set(every) if plan.rules else set(every)), plan.group
        assert blocks, plan.group


def test_w1_promoting_a_named_rule_plan_without_the_group_rule_list_is_refused():
    (plan,) = M.waf_plans(PHP2SHELL, TARGETS[:1], CATALOG, {}, LABELS)
    with pytest.raises(ValueError):
        M.waf_rule(plan, 0, block=True)   # cannot tell which rules to keep at Count ⇒ never render a blind Block


# ---------------------------------------------------------------- check (read-only state of a web ACL)
def _acl(*rules):
    return {"Name": "x", "Rules": list(rules)}


PHP_RULES = GROUPS["AWSManagedRulesPHPRuleSet"]["rules"]


def test_check_states():
    (plan,) = M.waf_plans(PHP2SHELL, TARGETS[:1], CATALOG, {}, LABELS)
    staged = M.waf_rule(plan, 0)
    blocking = M.waf_rule(plan, 0, block=True, group_rules=PHP_RULES)
    assert M.waf_check(plan, _acl(), "Version_2.5")["state"] == "absent"
    assert M.waf_check(plan, _acl(staged), "Version_2.5")["state"] == "staged"
    assert M.waf_check(plan, _acl(blocking), "Version_2.5")["state"] == "blocking"
    pinned = json.loads(json.dumps(staged))
    pinned["Statement"]["ManagedRuleGroupStatement"]["Version"] = "Version_2.3"
    assert M.waf_check(plan, _acl(pinned), "Version_2.5")["state"] == "too_old"
    assert M.waf_check(plan, _acl(blocking), "Version_2.2")["state"] == "too_old"   # stale default
    # someone else's rule counting the whole group: nothing blocks, and it is not the radar's stage (nobody promotes it)
    counted = {**blocking, "Name": "ops-php", "OverrideAction": {"Count": {}}}
    assert M.waf_check(plan, _acl(counted), "Version_2.5")["state"] == "group_counted"
    # the pre-W1 staged shape: named rules Count, the group's other rules at their own action ⇒ never reported as staged
    old = {**blocking, "OverrideAction": {"None": {}},
           "Statement": {"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": plan.group, "RuleActionOverrides":
                                                       [{"Name": r, "ActionToUse": {"Count": {}}} for r in plan.rules]}}}
    assert M.waf_check(plan, _acl(old), "Version_2.5")["state"] == "rules_counted"
    schema = json.loads((ROOT / "schemas" / "site-data.schema.json").read_text())
    enum = schema["$defs"]["MitigationPlan"]["properties"]["state"]["enum"]
    assert set(enum) == set(M.CHECK_STATES) | {"no_web_acl", "unchecked"}   # the page can render every state check says


def test_w2_plans_on_one_group_merge_into_one_rule():
    """Live bug (01-waf.md Bug-2): plans of two events on the same web ACL × group were deduplicated by group, the later
    one replacing the earlier — the rule was rendered for the later plan's rules only."""
    (a,) = M.waf_plans({"event_id": "a", "cves": ["CVE-2022-42889"]}, TARGETS[:1], CATALOG, {}, LABELS)
    (b,) = M.waf_plans({"event_id": "b", "cves": ["CVE-2023-22515"]}, TARGETS[1:2], CATALOG, {}, LABELS)
    assert a.group == b.group == "AWSManagedRulesKnownBadInputsRuleSet" and not set(a.rules) & set(b.rules)
    for m in (M.merge_plans([a, b]), M.merge_plans([b, a])):
        assert (m.group, set(m.rules), set(m.cves)) == (a.group, set(a.rules) | set(b.rules), set(a.cves) | set(b.cves))
        assert set(m.labels) == set(a.labels) | set(b.labels)
    # a whole-group plan in the mix ⇒ the merged plan is the whole group, named after the most specific tier
    (w,) = M.waf_plans({"event_id": "w", "product": "php", "cves": []}, TARGETS[:1], CATALOG, {}, LABELS)
    (p,) = M.waf_plans(PHP2SHELL, TARGETS[:1], CATALOG, {}, LABELS)
    for m in (M.merge_plans([p, w]), M.merge_plans([w, p])):
        assert (m.rules, m.tier) == ((), "cve")


def test_w4_rule_json_for_pasting_has_a_distinct_priority_per_group():
    """A rule copied into the user's own web ACL cannot know their priorities (Bug-5: a fixed 0 collides with the rule most
    hand-built ACLs start at). The placeholder is distinct per group, so radar rules pasted together never collide."""
    prios = [M.paste_priority(g) for g in M.WAF_GROUPS]
    assert len(set(prios)) == len(prios) and min(prios) >= M.PASTE_PRIORITY_BASE > 0


def test_b8_every_plan_surface_says_mitigation_is_not_a_fix():
    assert "唯一完整的修复" in M.MITIGATION_NOTE and "缓解 ≠ 修复" in M.MITIGATION_NOTE


# ---------------------------------------------------------------- B1 against the real API (read-only, skipped offline)
@pytest.mark.skipif(not os.environ.get("RADAR_LIVE") or not shutil.which("aws"), reason="live AWS check: set RADAR_LIVE=1")
def test_b1_live_check_capacity_accepts_the_rendered_rule():
    (plan,) = M.waf_plans(PHP2SHELL, TARGETS[:1], CATALOG, {}, LABELS)
    out = subprocess.run(["aws", "wafv2", "check-capacity", "--scope", "CLOUDFRONT", "--region", "us-east-1",
                          "--rules", json.dumps([M.waf_rule(plan, 0)]), "--output", "json"],
                         capture_output=True, text=True, check=True)
    assert json.loads(out.stdout)["Capacity"] == GROUPS[plan.group]["capacity"]


# ---------------------------------------------------------------- apply: only radar-* rules are ever written
FOREIGN = {"Name": "someone-elses-rule", "Priority": 5, "Action": {"Block": {}},
           "Statement": {"RateBasedStatement": {"Limit": 100, "AggregateKeyType": "IP"}},
           "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "x"}}


def test_merge_adds_staged_rule_after_existing_priorities_and_keeps_foreign_rules():
    (plan,) = M.waf_plans(PHP2SHELL, TARGETS[:1], CATALOG, {}, LABELS)
    out = M.merge_acl_rules([FOREIGN], [(plan, False)])
    assert out[0] == FOREIGN
    assert out[1]["Name"] == "radar-AWSManagedRulesPHPRuleSet" and out[1]["Priority"] == 6
    assert M.waf_check(plan, {"Rules": out}, "Version_2.5")["state"] == "staged"
    assert M.merge_acl_rules(out, [(plan, False)]) is None          # idempotent: nothing to write


def test_merge_promotes_in_place_and_never_touches_foreign_rules():
    (plan,) = M.waf_plans(PHP2SHELL, TARGETS[:1], CATALOG, {}, LABELS)
    staged = M.merge_acl_rules([FOREIGN], [(plan, False)])
    out = M.merge_acl_rules(staged, [(plan, True)], {plan.group: PHP_RULES})
    assert out[0] == FOREIGN and out[1]["Priority"] == staged[1]["Priority"]
    assert M.waf_check(plan, {"Rules": out}, "Version_2.5")["state"] == "blocking"
    # a foreign rule that happens to use the same managed group is left alone (the radar only writes radar-*)
    theirs = {**M.waf_rule(plan, 1, block=True, group_rules=PHP_RULES), "Name": "their-php-rules"}
    out2 = M.merge_acl_rules([theirs], [(plan, False)])
    assert out2[0] == theirs and out2[1]["Name"].startswith(M.RADAR_RULE_PREFIX)


# ---------------------------------------------------------------- DNS Firewall (pure)
from radar import patterns


def test_only_defanged_domains_become_iocs_and_critical_services_never_do():
    texts = ["C2 at evil-cdn[.]top and hxxps://wallet-drain[.]xyz/login — reported by bleepingcomputer.com",
             "exfil to api[.]github[.]com and s3[.]amazonaws[.]com", "ns1(dot)bad(.)ru", "PHP 8.3.30 and index.php"]
    assert patterns.indicators(texts).domains == ["evil-cdn.top", "ns1.bad.ru", "wallet-drain.xyz"]


def test_dns_rules_alert_until_promoted_and_skip_unknown_managed_lists():
    managed = {"AWSManagedDomainsMalwareDomainList": "m1", "AWSManagedDomainsBotnetCommandandControl": "m2"}
    rules = M.dns_rules("radar-list", managed, set())
    assert [r["Name"] for r in rules] == ["radar-ioc-domains", "radar-AWSManagedDomainsBotnetCommandandControl",
                                          "radar-AWSManagedDomainsMalwareDomainList"]
    assert {r["Action"] for r in rules} == {"ALERT"}
    blocked = M.dns_rules("radar-list", managed, {"radar-ioc-domains"})
    assert blocked[0]["Action"] == "BLOCK" and blocked[0]["BlockResponse"] == "NXDOMAIN" and blocked[1]["Action"] == "ALERT"


def test_dns_diff_creates_updates_and_never_touches_foreign_rules():
    wanted = M.dns_rules("radar-list", {"AWSManagedDomainsMalwareDomainList": "m1"}, set())
    create, update = M.dns_diff([], wanted)
    assert len(create) == 2 and update == []
    existing = [{**wanted[0]}, {"Name": "theirs", "FirewallDomainListId": "m1", "Action": "BLOCK", "Priority": 1}]
    create, update = M.dns_diff(existing, M.dns_rules("radar-list", {"AWSManagedDomainsMalwareDomainList": "m1"}, {"radar-ioc-domains"}))
    assert create == [] and [u["Name"] for u in update] == ["radar-ioc-domains"]   # theirs (same list) left alone
    assert M.dns_diff(wanted, wanted) == ([], [])


def test_dns_domain_list_always_carries_the_canary():
    assert M.dns_domains({}) == [M.DNS_CANARY]
    assert M.dns_domains({"e1": ["b.top", "a.xyz"], "e2": ["a.xyz"]}) == ["a.xyz", "b.top", M.DNS_CANARY]


# --- R4.1: a promotion covers what the human approved, not what the plan becomes later -------------------------------

def _plan(rules, tier="cve"):
    return M.WafPlan("demo-shop", tier, "AWSManagedRulesPHPRuleSet", tuple(rules), None, "r")


def test_a_promotion_is_pinned_to_the_rules_approved_and_a_later_whole_group_plan_does_not_widen_it():
    """Audit 04 §6.1 (reproduced), and live on the demo ACL since 2026-11: the ledger kept {by, at} per rule name. Neo
    promoted the PHP rule for the two PHP2Shell rules; a later event added a whole-group plan for the same group, the
    plans merged to "whole group", and the promoted rule blocked every rule of the group — a decision nobody made."""
    approved = {"by": "ops", "at": "2026-11-01T07:48:57Z", "rules": ["PHP2Shell_BODY", "PHP2Shell_BODY_Extended"]}
    grown = M.merge_plans([_plan(approved["rules"]), _plan((), "product")])
    assert grown.rules == ()                                                  # the merged plan now asks for the whole group
    plan, beyond = M.pinned(grown, approved, named=tuple(approved["rules"]))
    assert plan.rules == ("PHP2Shell_BODY", "PHP2Shell_BODY_Extended") and beyond == "whole group"
    rule = M.waf_rule(plan, 1, block=True, group_rules=["PHP2Shell_BODY", "PHP2Shell_BODY_Extended", "PHPHighRisk_A", "PHPHighRisk_B"])
    counted = {o["Name"] for o in rule["Statement"]["ManagedRuleGroupStatement"]["RuleActionOverrides"]}
    assert counted == {"PHPHighRisk_A", "PHPHighRisk_B"}                      # everything not approved still only counts


def test_pinned_reports_new_rules_and_leaves_an_unchanged_or_whole_group_approval_alone():
    two = {"by": "n", "at": "t", "rules": ["A", "B"]}
    plan, beyond = M.pinned(_plan(["A", "B", "C"]), two, named=("A", "B", "C"))
    assert plan.rules == ("A", "B") and beyond == "C"
    assert M.pinned(_plan(["A", "B"]), two, named=("A", "B")) == (_plan(["A", "B"]), None)
    assert M.pinned(_plan(["A"]), two, named=("A",))[0].rules == ("A", "B")          # never demoted on its own
    whole = {"by": "n", "at": "t", "rules": []}
    assert M.pinned(_plan(()), whole, named=()) == (_plan(()), None)                   # the whole group was approved


def test_a_promotion_from_before_pinning_covers_the_named_rules_not_a_whole_group_that_came_later():
    """The live row: {"by": "ops", "at": …} and no "rules". What was approved is unknown; the narrow reading is taken —
    the rules the plans name today — and the whole-group part is reported as waiting for a decision."""
    old = {"by": "ops", "at": "2026-11-01T07:48:57Z"}
    plan, beyond = M.pinned(_plan(()), old, named=("PHP2Shell_BODY", "PHP2Shell_BODY_Extended"))
    assert plan.rules == ("PHP2Shell_BODY", "PHP2Shell_BODY_Extended") and beyond == "whole group"
    assert M.pinned(_plan(()), old, named=()) == (_plan(()), None)      # only ever a whole-group plan: that was it


def test_what_a_promotion_records_is_what_the_plans_ask_for_at_that_moment():
    rows = [{"web_acl": "acl", "group": "G", "appliable": True, "rules": ["A"]},
            {"web_acl": "acl", "group": "G", "appliable": True, "rules": ["B", "A"]},
            {"web_acl": "acl", "group": "G", "appliable": False, "rules": []},          # advice only: not what is applied
            {"web_acl": "other", "group": "G", "appliable": True, "rules": []}]
    assert M.promotion_scope(rows, "acl", "G") == ["A", "B"]
    assert M.promotion_scope([*rows, {"web_acl": "acl", "group": "G", "appliable": True, "rules": []}], "acl", "G") == []
    assert M.promotion_scope(rows, "acl", "H") is None                             # nothing to approve
