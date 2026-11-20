"""M3 · mitigation channels — the fast path next to the patch (D-class: deterministic, no LLM).

The respond station's path (located finding → AWS Security Agent / AWS Continuum → patch → a human merges) is the cure,
and it takes hours to days. A mitigation covers that window: a virtual patch at the edge (AWS WAF), a DNS block
(Route 53 Resolver DNS Firewall). It is NEVER a fix — every plan carries MITIGATION_NOTE, and the page and the PR say so.

One channel = one row of CHANNELS; each answers, by code:
  plan   which mitigation fits this event on this located target (and why: the tier says how specific it is)
  check  is it already in place (read-only, from the resource's own description)
  apply  put it in place on a radar-owned resource, in the non-blocking mode (WAF Count / DNS ALERT)
Promotion to blocking is a human step (scripts/promote.py) — never automatic.

WAF tiers, most specific first (one plan per target × rule group; the most specific tier wins):
  cve      the AWS Managed Rules changelog names the CVE (parse_waf_changelog) — rules + minimum static version
  product  the located product has its own rule group (PHP → PHP application, WordPress → WordPress application)
  cwe      the CVE's weakness class has a generic rule family (SQLi, path traversal, SSRF, OS command injection …) —
           advisory only, never applied: generic signatures on a specific CVE are a hint, not a virtual patch
Adding a group / product / CWE = one registry row (checked against DescribeManagedRuleGroup by tests), never a code path.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from typing import Any

MITIGATION_NOTE = "缓解 ≠ 修复：边缘规则只在打补丁之前降低风险，升级到修复版本才是唯一完整的修复。"
WAF_CHANGELOG_URL = "https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-changelog.html"
TIERS = ("cve", "product", "cwe")
APPLY_TIERS = ("cve", "product")   # cwe stays advisory (see module doc)


@dataclass(frozen=True)
class WafGroup:
    name: str            # ManagedRuleGroupStatement.Name (vendor AWS)
    anchor: str          # fragment of the group's section in the WAF developer guide — how the changelog links it
    label: str           # display name
    label_prefix: str    # rule labels: <label_prefix>:<rule name as labelled> (case differs from rule names)


# Free AWS managed rule groups the radar may plan (paid groups — Bot Control, ATP, ACFP, Anti-DDoS — are out of scope).
WAF_GROUPS: dict[str, WafGroup] = {g.name: g for g in (
    WafGroup("AWSManagedRulesCommonRuleSet", "aws-managed-rule-groups-baseline-crs", "Core rule set", "awswaf:managed:aws:core-rule-set"),
    WafGroup("AWSManagedRulesKnownBadInputsRuleSet", "aws-managed-rule-groups-baseline-known-bad-inputs", "Known bad inputs",
             "awswaf:managed:aws:known-bad-inputs"),
    WafGroup("AWSManagedRulesSQLiRuleSet", "aws-managed-rule-groups-use-case-sql-db", "SQL database", "awswaf:managed:aws:sql-database"),
    WafGroup("AWSManagedRulesLinuxRuleSet", "aws-managed-rule-groups-use-case-linux-os", "Linux operating system",
             "awswaf:managed:aws:linux-os"),
    WafGroup("AWSManagedRulesUnixRuleSet", "aws-managed-rule-groups-use-case-posix-os", "POSIX operating system",
             "awswaf:managed:aws:posix-os"),
    WafGroup("AWSManagedRulesWindowsRuleSet", "aws-managed-rule-groups-use-case-windows-os", "Windows operating system",
             "awswaf:managed:aws:windows-os"),
    WafGroup("AWSManagedRulesPHPRuleSet", "aws-managed-rule-groups-use-case-php-app", "PHP application", "awswaf:managed:aws:php-app"),
    WafGroup("AWSManagedRulesWordPressRuleSet", "aws-managed-rule-groups-use-case-wordpress-app", "WordPress application",
             "awswaf:managed:aws:wordpress-app"),
)}
_BY_ANCHOR = {g.anchor: g for g in WAF_GROUPS.values()}

# product tier: radar.products ids → the group written for that runtime/application (whole group, its own rules)
PRODUCT_GROUPS: dict[str, str] = {"php": "AWSManagedRulesPHPRuleSet", "wordpress": "AWSManagedRulesWordPressRuleSet"}
# Applications that ARE PHP, named in an event's title / entities (Neo 2026-11-19: 「能用 WAF 解决的，先用 WAF 挡一下」 —
# a live check found REDCap and TYPO3 P0s with empty packs: products.match knows neither, so the PHP group was never
# offered). The PHP group's rules are generic for PHP apps — the plan's reason says so; it is not a CVE signature.
PHP_APPS = re.compile(r"\b(?:typo3|redcap|drupal|joomla|magento|moodle|phpmyadmin|laravel|prestashop|opencart|"
                      r"mediawiki|nextcloud|owncloud|roundcube|glpi|suitecrm|vtiger|php)\b", re.IGNORECASE)


def php_app(event: dict[str, Any]) -> str | None:
    """The PHP application an event names, or None (title and entities only — a summary may name another product)."""
    m = PHP_APPS.search(" ".join([str(event.get("title") or ""), *map(str, event.get("entities") or [])]))
    return m.group(0) if m else None


# cwe tier: weakness → (group, the rule family in it). Only classes whose exploit travels in an HTTP request.
CWE_RULES: dict[str, tuple[tuple[str, tuple[str, ...]], ...]] = {
    "CWE-89": (("AWSManagedRulesSQLiRuleSet", ("SQLi_QUERYARGUMENTS", "SQLi_BODY", "SQLi_COOKIE", "SQLi_URIPATH")),),
    "CWE-22": (("AWSManagedRulesCommonRuleSet", ("GenericLFI_QUERYARGUMENTS", "GenericLFI_URIPATH", "GenericLFI_BODY")),
               ("AWSManagedRulesLinuxRuleSet", ("LFI_URIPATH", "LFI_QUERYSTRING", "LFI_HEADER"))),
    "CWE-918": (("AWSManagedRulesCommonRuleSet", ("EC2MetaDataSSRF_BODY", "EC2MetaDataSSRF_COOKIE", "EC2MetaDataSSRF_URIPATH",
                                                  "EC2MetaDataSSRF_QUERYARGUMENTS")),),
    "CWE-78": (("AWSManagedRulesUnixRuleSet", ("UNIXShellCommandsVariables_QUERYSTRING", "UNIXShellCommandsVariables_BODY",
                                               "UNIXShellCommandsVariables_HEADER")),
               ("AWSManagedRulesWindowsRuleSet", ("WindowsShellCommands_QUERYARGUMENTS", "WindowsShellCommands_BODY",
                                                  "WindowsShellCommands_HEADER"))),
    "CWE-502": (("AWSManagedRulesKnownBadInputsRuleSet", ("JavaDeserializationRCE_BODY", "JavaDeserializationRCE_URIPATH",
                                                          "JavaDeserializationRCE_QUERYSTRING", "JavaDeserializationRCE_HEADER")),),
    "CWE-917": (("AWSManagedRulesKnownBadInputsRuleSet", ("Log4JRCE_QUERYSTRING", "Log4JRCE_BODY", "Log4JRCE_URIPATH",
                                                          "Log4JRCE_HEADER")),),
}
CWE_RULES["CWE-23"] = CWE_RULES["CWE-22"]     # relative path traversal: same signatures
CWE_RULES["CWE-73"] = CWE_RULES["CWE-22"]     # external control of a file name / path (REDCap CVE-2026-90817): LFI signatures
CWE_RULES["CWE-77"] = CWE_RULES["CWE-78"]     # command injection (generic parent of OS command injection)


# ---------------------------------------------------------------- catalog: the AWS Managed Rules changelog
@dataclass(frozen=True)
class ChangelogRow:
    group: str                   # rule group API name
    rules: tuple[str, ...]       # rules the row says it adds/updates (may be empty: whole-group release)
    version: str                 # "Version_2.4"
    cves: tuple[str, ...]
    date: str                    # YYYY-MM-DD


_ROW = re.compile(r"<tr>(.*?)</tr>", re.DOTALL)
_CELL = re.compile(r"<td\b[^>]*>(.*?)</td>", re.DOTALL)
_CODE = re.compile(r"<code\b[^>]*>([A-Za-z0-9_]+)</code>")
_STATIC = re.compile(r"static version\s+(\d+)\.(\d+)", re.IGNORECASE)
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}")
_DATE = re.compile(r"\b(\d{4}-\d{2}-\d{2})\b")


def _plain(fragment: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", fragment))).strip()


def parse_waf_changelog(page: str) -> list[ChangelogRow]:
    """Rows of the changelog tables whose first cell links a group in WAF_GROUPS and whose text names a static version.
    The group comes from the FIRST cell's link only — the description cell may link other groups in passing
    (live 2026-10-21: the PHP 2.3 row points CVE-2026-109618 at the Core rule set)."""
    out = []
    for row in _ROW.findall(page):
        cells = _CELL.findall(row)
        if len(cells) < 3:
            continue
        m = re.search(r'href="[^"]*#([a-z0-9-]+)"', cells[0])
        group = _BY_ANCHOR.get(m.group(1)) if m else None
        ver = _STATIC.search(_plain(cells[1]))
        date = _DATE.search(_plain(cells[2]))
        if not group or not ver or not date:
            continue
        out.append(ChangelogRow(group.name, tuple(dict.fromkeys(_CODE.findall(cells[0]))),
                                f"Version_{ver.group(1)}.{ver.group(2)}",
                                tuple(dict.fromkeys(_CVE.findall(_plain(cells[1])))), date.group(1)))
    return out


def version_key(v: str | None) -> tuple[int, ...]:
    """'Version_2.4' → (2, 4); None / unparseable → () (sorts first: unknown is never 'new enough')."""
    m = re.fullmatch(r"Version_(\d+)\.(\d+)", v or "")
    return (int(m.group(1)), int(m.group(2))) if m else ()


@dataclass(frozen=True)
class CveRules:
    group: str
    rules: tuple[str, ...]
    min_version: str
    since: str                   # date of the row that set min_version


def waf_catalog(rows: list[ChangelogRow]) -> dict[str, list[CveRules]]:
    """CVE → what to deploy, per group. rules = every rule any row about the CVE names; min_version = the NEWEST
    static version whose row names the CVE. Newest, not first: later rows refine detection, and the first row to
    mention a CVE may only mention it (PHP 2.3 names CVE-2026-109618 but detects it only from 2.4 / improved in 2.5)."""
    acc: dict[tuple[str, str], dict[str, Any]] = {}
    for r in rows:
        for cve in r.cves:
            a = acc.setdefault((cve, r.group), {"rules": [], "version": "", "since": ""})
            a["rules"] += [x for x in r.rules if x not in a["rules"]]
            if version_key(r.version) > version_key(a["version"]):
                a["version"], a["since"] = r.version, r.date
    out: dict[str, list[CveRules]] = {}
    for (cve, group), a in sorted(acc.items()):
        out.setdefault(cve, []).append(CveRules(group, tuple(a["rules"]), a["version"], a["since"]))
    return out


# ---------------------------------------------------------------- WAF plan
@dataclass(frozen=True)
class WafPlan:
    target_id: str
    tier: str                    # cve | product | cwe
    group: str
    rules: tuple[str, ...]       # rules that block once a human promotes; () ⇒ the whole group (staged = whole group Count either way)
    min_version: str | None      # None ⇒ any version (product / cwe tiers)
    reason: str
    cves: tuple[str, ...] = ()
    labels: tuple[str, ...] = field(default=())

    @property
    def key(self) -> str:
        return f"waf:{self.target_id}:{self.group}"

    @property
    def appliable(self) -> bool:
        return self.tier in APPLY_TIERS


def rule_name(group: str) -> str:
    """Web ACL rule name the radar uses for a group — one per group, so re-applying is idempotent."""
    return f"radar-{group}"


def waf_plans(event: dict[str, Any], targets: list[dict[str, Any]], catalog: dict[str, list[CveRules]],
              cwes: dict[str, list[str]], labels: dict[str, list[str]] | None = None) -> list[WafPlan]:
    """Plans for one event. `targets` = published response targets ({target_id, verdict, …}); only targets the radar
    (or the AWS agents) found affected get a plan — a mitigation for code that does not run the product is noise.
    `cwes` = CVE → CWE ids (KEV); `labels` = group → AvailableLabels (DescribeManagedRuleGroup), for verification."""
    labels = labels or {}
    cves = [c for c in event.get("cves") or [] if c]
    product = event.get("product")
    best: dict[tuple[str, str], WafPlan] = {}

    def offer(p: WafPlan) -> None:
        k = (p.target_id, p.group)
        if k not in best or TIERS.index(p.tier) < TIERS.index(best[k].tier):
            best[k] = p

    for t in targets:
        if t.get("verdict") != "affected":
            continue
        tid = t["target_id"]
        for cve in cves:
            for cr in catalog.get(cve, []):
                # merge every CVE of the event that maps to the same group (PHP2Shell: two CVEs, one group)
                same = [(c, r) for c in cves for r in catalog.get(c, []) if r.group == cr.group]
                rules = tuple(dict.fromkeys(x for _, r in same for x in r.rules))
                minv = max((r.min_version for _, r in same), key=version_key)
                hit = tuple(dict.fromkeys(c for c, _ in same))
                offer(WafPlan(tid, "cve", cr.group, rules, minv,
                              f"AWS 托管规则 changelog 写明 {'、'.join(hit)} 由 {WAF_GROUPS[cr.group].label} "
                              f"{minv} 起的 {'、'.join(rules) or '整组规则'} 覆盖", hit,
                              labels_for(cr.group, rules, labels)))
        if product in PRODUCT_GROUPS:
            g = PRODUCT_GROUPS[product]
            offer(WafPlan(tid, "product", g, (), None, f"受影响的产品是 {product}，{WAF_GROUPS[g].label} 规则组专门防护它",
                          tuple(cves), labels_for(g, (), labels)))
        elif (app := php_app(event)):
            g = PRODUCT_GROUPS["php"]
            offer(WafPlan(tid, "product", g, (), None, f"{app} 是 PHP 应用，{WAF_GROUPS[g].label} 规则组的通用防护"
                          "（PHP 注入、高危函数调用；不针对这个 CVE）", tuple(cves), labels_for(g, (), labels)))
        for cve in cves:
            for cwe in cwes.get(cve, []):
                for g, rules in CWE_RULES.get(cwe, ()):
                    offer(WafPlan(tid, "cwe", g, rules, None,
                                  f"{cve} 的弱点类型是 {cwe}，{WAF_GROUPS[g].label} 有对应的通用规则（通用防护，不针对这个 CVE）",
                                  (cve,), labels_for(g, rules, labels)))
    return sorted(best.values(), key=lambda p: (p.target_id, TIERS.index(p.tier), p.group))


def labels_for(group: str, rules: tuple[str, ...], available: dict[str, list[str]]) -> tuple[str, ...]:
    """Labels the staged rules emit — matched case-insensitively, because label case differs from rule names
    (PHP2Shell_BODY → awswaf:managed:aws:php-app:PHP2Shell_Body)."""
    avail = available.get(group) or []
    if not rules:
        return tuple(avail)
    want = {r.lower() for r in rules}
    return tuple(lb for lb in avail if lb.rsplit(":", 1)[-1].lower() in want)


def merge_plans(plans: list[WafPlan]) -> WafPlan:
    """One web ACL carries ONE radar rule per group, so every appliable plan for that ACL × group (other events, other
    targets behind the same ACL) is rendered as one: rules = union, unless any plan is whole-group ⇒ whole group;
    cves / labels = union; tier = the most specific. Each original plan is still checked on its own (waf_check).
    Live bug 2026-11-11 (docs/research/action/01-waf.md Bug-2): the station kept the last plan per group instead."""
    tiers = sorted(plans, key=lambda p: TIERS.index(p.tier))
    rules = () if any(not p.rules for p in plans) else tuple(dict.fromkeys(r for p in tiers for r in p.rules))
    return WafPlan(",".join(sorted({p.target_id for p in plans})), tiers[0].tier, plans[0].group, rules,
                   max((p.min_version for p in plans if p.min_version), key=version_key, default=None),
                   "；".join(dict.fromkeys(p.reason for p in tiers)),
                   tuple(dict.fromkeys(c for p in tiers for c in p.cves)), tuple(dict.fromkeys(lb for p in tiers for lb in p.labels)))


def pinned(plan: WafPlan, promotion: dict[str, Any], named: tuple[str, ...]) -> tuple[WafPlan, str | None]:
    """What a promoted rule may block: what the human approved — `promotion["rules"]`, recorded by scripts/promote.py
    ([] = the whole group). Returns (the plan to render as blocking, what today's plan asks for beyond it, or None).
    The plan a rule renders is the union over the events in the window (merge_plans), so it changes without anyone
    deciding: a later whole-group plan for the group turned a promotion of two rules into a whole-group Block (audit 04
    §6.1; live on the demo ACL). What lies beyond the approval keeps counting and is reported, never blocked.
    A promotion from before pinning has no "rules": the narrow reading is taken — `named`, the rules today's plans name;
    with none named it was a whole-group plan all along."""
    ok = tuple(promotion["rules"]) if "rules" in promotion else named
    if not ok:
        return plan, None
    beyond = "whole group" if not plan.rules else ", ".join(r for r in plan.rules if r not in ok) or None
    return WafPlan(plan.target_id, plan.tier, plan.group, ok, plan.min_version, plan.reason, plan.cves, plan.labels), beyond


def promotion_scope(plan_rows: list[dict[str, Any]], web_acl: str, group: str) -> list[str] | None:
    """What promoting <group> on <web_acl> approves right now, from the station's plan rows: the union of the rules
    the appliable plans name, [] when any of them is whole-group, None when there is no appliable plan."""
    rows = [r for r in plan_rows if r.get("web_acl") == web_acl and r.get("group") == group and r.get("appliable")]
    if not rows:
        return None
    if any(not r.get("rules") for r in rows):
        return []
    return sorted({x for r in rows for x in r["rules"]})


# rule_json handed to a user to paste into THEIR web ACL cannot know which priorities that ACL already uses
# (UpdateWebACL rejects a duplicate). Bug-5: the fixed 0 collided with the rule most hand-built ACLs start at. The
# placeholder is high and distinct per group (several radar rules pasted together never collide with each other); the
# page tells the user to change it if their ACL already uses it. On a radar ACL the real priority is shown instead.
PASTE_PRIORITY_BASE = 10000


def paste_priority(group: str) -> int:
    return PASTE_PRIORITY_BASE + list(WAF_GROUPS).index(group)


def waf_rule(plan: WafPlan, priority: int, block: bool = False, group_rules: list[str] | tuple[str, ...] = (),
             default_version: str | None = None) -> dict[str, Any]:
    """The web ACL rule for a plan — the ONLY renderer (the page, the PR text and apply all use this one).
    Staged (block=False): OverrideAction Count — EVERY rule of the group counts, the named ones included; nothing the
      radar stages ever blocks. Live bug 2026-11-11 (01-waf.md Bug-1): staging was OverrideAction None + Count on the
      named rules only, so the group's other rules acted at their own action — PHP2Shell staging blocked the 4
      PHPHighRiskMethodsVariables_* rules without anyone promoting them.
    Promoted (block=True, a human's step): OverrideAction None. A plan naming rules lets ONLY those block: every other
      rule of the group (`group_rules`, from DescribeManagedRuleGroup) is overridden to Count — without that list the
      render is refused (ValueError), never a blind whole-group Block. A whole-group plan blocks at the group's own actions.
    Default version on purpose (AWS: 'we recommend the default version') — unless the group's default is known to be
    older than the plan's minimum: then the rule pins Version = min_version, since the default would not contain the
    CVE's rules (audit 04 2.5: the write went out unpinned and check() could only report too_old). Once the default
    catches up, the next render drops the pin by itself. Unknown default (DescribeManagedRuleGroup failed) ⇒ no pin."""
    stmt: dict[str, Any] = {"VendorName": "AWS", "Name": plan.group}
    if plan.min_version and default_version and version_key(default_version) < version_key(plan.min_version):
        stmt["Version"] = plan.min_version
    name = rule_name(plan.group)
    if not block:
        return _acl_rule(name, priority, stmt, {"Count": {}})   # staged: the whole group counts
    if plan.rules:
        if not group_rules:
            raise ValueError(f"cannot render a promoted {plan.group} rule without the group's rule list")
        others = [r for r in group_rules if r not in plan.rules]
        if others:
            stmt["RuleActionOverrides"] = [{"Name": r, "ActionToUse": {"Count": {}}} for r in others]
    return _acl_rule(name, priority, stmt, {"None": {}})


def _acl_rule(name: str, priority: int, stmt: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    return {"Name": name, "Priority": priority, "Statement": {"ManagedRuleGroupStatement": stmt},
            "OverrideAction": override,
            "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                                 "MetricName": re.sub(r"[^A-Za-z0-9]", "", name)[:128]}}


# ---------------------------------------------------------------- WAF check (read-only)
CHECK_STATES = ("absent", "too_old", "group_counted", "rules_counted", "staged", "blocking")


def waf_check(plan: WafPlan, web_acl: dict[str, Any], default_version: str | None) -> dict[str, Any]:
    """Where a plan stands on one web ACL (the GetWebACL `WebACL` object), from the rule's own description:
      absent         the group is not in the web ACL
      too_old        pinned (or default) version below the plan's minimum — the CVE rules are not in it
      staged         the radar's rule, whole group overridden to Count (the non-blocking stage — waits for a human)
      group_counted  someone else's rule counts the whole group (nothing blocks — AWS: 'confirm you haven't overridden…')
      rules_counted  the plan's rules are overridden to Count one by one while the group's OTHER rules act at their own
                     action — not a non-blocking stage (the pre-2026-11-11 staged shape, 01-waf.md Bug-1)
      blocking       present and the plan's rules act (Block)"""
    rule = next((r for r in web_acl.get("Rules") or []
                 if (r.get("Statement") or {}).get("ManagedRuleGroupStatement", {}).get("Name") == plan.group), None)
    if rule is None:
        return {"state": "absent", "detail": f"web ACL 里没有 {plan.group}"}
    stmt = rule["Statement"]["ManagedRuleGroupStatement"]
    version = stmt.get("Version") or default_version
    if plan.min_version and version_key(version) < version_key(plan.min_version):
        return {"state": "too_old", "rule": rule["Name"], "version": version,
                "detail": f"{plan.group} 用的是 {version or '未知版本'}，低于 {plan.min_version}"}
    if "Count" in (rule.get("OverrideAction") or {}):
        if rule["Name"].startswith(RADAR_RULE_PREFIX):   # every plan stages exactly like this (waf_rule)
            return {"state": "staged", "rule": rule["Name"], "version": version, "counting": ["*"],
                    "detail": "整组在 Count（观察期，组内规则都不拦截），等人确认后切 Block"}
        return {"state": "group_counted", "rule": rule["Name"], "version": version, "detail": "整组被设为 Count，不拦截"}
    counted = {o["Name"] for o in stmt.get("RuleActionOverrides") or [] if "Count" in (o.get("ActionToUse") or {})}
    if plan.rules and counted & set(plan.rules):
        return {"state": "rules_counted", "rule": rule["Name"], "version": version, "counting": sorted(counted & set(plan.rules)),
                "detail": "这些规则单独设为 Count，但组内其余规则按自身动作生效（可能拦截）—— 不是观察期"}
    return {"state": "blocking", "rule": rule["Name"], "version": version, "detail": "规则生效（Block）"}


# ---------------------------------------------------------------- WAF apply (pure part)
RADAR_RULE_PREFIX = "radar-"
RADAR_ACL_PREFIX = "security-radar-"   # web ACLs the radar may write (IAM scopes UpdateWebACL to this prefix too)
# UpdateWebACL resets every optional field it is not given ⇒ carried over from GetWebACL on every write — by the
# station (mitigate_aws.put_rules) and by the rule pack's CLI steps for a reader (packrender.cli): one list for both
ACL_CARRY_FIELDS = ("Description", "CustomResponseBodies", "CaptchaConfig", "ChallengeConfig", "TokenDomains", "AssociationConfig")


def merge_acl_rules(rules: list[dict[str, Any]], wanted: list[tuple[WafPlan, bool]],
                    group_rules: dict[str, list[str]] | None = None,
                    default_versions: dict[str, str | None] | None = None) -> list[dict[str, Any]] | None:
    """The web ACL's new rule list, or None when nothing changes. Only rules named radar-* are ever written —
    every other rule is kept byte-for-byte (a web ACL may be shared). A radar rule keeps its priority; a new one goes
    after the highest priority in use. `wanted` = (plan, block) — block=True only after a human promoted the plan, one
    plan per group (merge_plans); `group_rules` = group → its rule names (needed to render a promoted plan, waf_rule).
    Rules are never removed here: a mitigation outlives the patch as a supporting control until a human removes it."""
    group_rules = group_rules or {}
    out = [dict(r) for r in rules]
    by_name = {r["Name"]: i for i, r in enumerate(out)}
    nxt = max((r["Priority"] for r in out), default=-1) + 1
    changed = False
    for plan, block in wanted:
        name = rule_name(plan.group)
        i = by_name.get(name)
        new = waf_rule(plan, out[i]["Priority"] if i is not None else nxt, block=block,
                       group_rules=group_rules.get(plan.group) or (),
                       default_version=(default_versions or {}).get(plan.group))
        if i is None:
            out.append(new)
            by_name[name] = len(out) - 1
            nxt += 1
            changed = True
        elif out[i] != new:
            out[i] = new
            changed = True
    return out if changed else None


# ---------------------------------------------------------------- DNS Firewall (Route 53 Resolver)
# The radar owns ONE domain list (CFN-created, contents = runtime state) and ONE rule group associated with the VPCs it
# protects. Rules: the radar list (IOC domains from evidence, defanged spelling only — radar.patterns.indicators)
# and the AWS-managed threat lists, all ALERT until a human promotes them to BLOCK (scripts/promote.py dns …).
DNS_CANARY = "radar-canary.security-radar.invalid"   # always listed: the end-to-end check resolves it from the demo VPC
DNS_MANAGED_LISTS = ("AWSManagedDomainsAggregateThreatList", "AWSManagedDomainsAmazonGuardDutyThreatList",
                     "AWSManagedDomainsBotnetCommandandControl", "AWSManagedDomainsGlobalThreatList", "AWSManagedDomainsMalwareDomainList")
DNS_RADAR_RULE = "radar-ioc-domains"


def dns_domains(by_event: dict[str, list[str]]) -> list[str]:
    """Desired contents of the radar domain list: every event's domain IOCs + the canary (sorted, unique)."""
    return sorted({d for ds in by_event.values() for d in ds} | {DNS_CANARY})


def dns_rules(radar_list_id: str, managed: dict[str, str], promoted: set[str]) -> list[dict[str, Any]]:
    """Desired rules of the radar rule group: radar list first (priority 100), then the managed lists (200, 210 …).
    `managed` = list name → id in this Region (looked up by name: ids differ per Region). Missing managed lists are
    skipped — the caller records them."""
    rows = [{"Name": DNS_RADAR_RULE, "FirewallDomainListId": radar_list_id, "Priority": 100}]
    rows += [{"Name": f"radar-{n}", "FirewallDomainListId": managed[n], "Priority": 200 + 10 * i}
             for i, n in enumerate(DNS_MANAGED_LISTS) if n in managed]
    for r in rows:
        r["Action"] = "BLOCK" if r["Name"] in promoted else "ALERT"
        if r["Action"] == "BLOCK":
            r["BlockResponse"] = "NXDOMAIN"
    return rows


def dns_diff(existing: list[dict[str, Any]], wanted: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(create, update) to make the rule group match `wanted`, keyed by domain list id. Rules the radar did not name
    are never touched; nothing is deleted (a removed managed list stays until a human removes it)."""
    have = {r["FirewallDomainListId"]: r for r in existing}
    create, update = [], []
    for w in wanted:
        h = have.get(w["FirewallDomainListId"])
        if h is None:
            create.append(w)
        elif not str(h.get("Name", "")).startswith(RADAR_RULE_PREFIX):
            continue
        elif (h.get("Action"), h.get("Priority"), h.get("BlockResponse")) != (w["Action"], w["Priority"], w.get("BlockResponse")):
            update.append(w)
    return create, update
