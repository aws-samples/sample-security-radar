"""AWS adapter for the mitigate station: AWS WAF (CLOUDFRONT scope lives in us-east-1).

Read calls (changelog over HTTP, DescribeManagedRuleGroup, ListAvailableManagedRuleGroupVersions, GetWebACL) need no
write permission. The one write — UpdateWebACL — is granted by IAM only on web ACLs whose name starts with the radar
prefix (infra/stack.py), so a mistake here cannot reach a web ACL that belongs to someone else (B3). Failures come back
as {"error": …}; the station records them and never raises on a downstream outage."""

from __future__ import annotations

import hashlib
import os
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from radar import fetch, mitigate

WAF_REGION = "us-east-1"
_clients: dict[str, Any] = {}


def _waf() -> Any:
    if "waf" not in _clients:
        _clients["waf"] = boto3.client("wafv2", region_name=WAF_REGION)
    return _clients["waf"]


def web_acls() -> dict[str, dict[str, str]]:
    """target_id → {name, id, scope} of the radar-owned web ACL in front of it (stack env, JSON). Empty ⇒ plan + advise only."""
    import json
    return json.loads(os.environ.get("MITIGATE_WEB_ACLS") or "{}")


def load_targets() -> list[Any]:
    """The target zips the respond station reads (s3://SA_CODE_BUCKET/code/<id>.zip) — the same code, no new copy."""
    from radar import continuum_aws
    from radar.targets import TARGETS
    return continuum_aws.load_targets(list(TARGETS))


def scan_sbom(doc: dict[str, Any]) -> dict[str, Any]:
    """Amazon Inspector ScanSbom (stateless: nothing is enabled in the account; $0.03 per call)."""
    import json
    try:
        if "inspector-scan" not in _clients:
            _clients["inspector-scan"] = boto3.client("inspector-scan", region_name=os.environ.get("AWS_REGION", "ap-northeast-1"))
        r = _clients["inspector-scan"].scan_sbom(sbom=doc, outputFormat="CYCLONE_DX_1_5")
        return {"sbom": r["sbom"] if isinstance(r["sbom"], dict) else json.loads(r["sbom"])}
    except (ClientError, BotoCoreError) as e:
        return {"error": str(e)[:300]}


def changelog_rows() -> list[mitigate.ChangelogRow] | dict[str, str]:
    try:
        return mitigate.parse_waf_changelog(fetch.http_get(mitigate.WAF_CHANGELOG_URL).body)
    except fetch.FetchError as e:
        return {"error": f"changelog: {e}"}


def group_meta(group: str, scope: str = "CLOUDFRONT") -> dict[str, Any]:
    """{labels, default_version} for an AWS managed group — {"error"} if either call fails."""
    try:
        d = _waf().describe_managed_rule_group(VendorName="AWS", Name=group, Scope=scope)
        v = _waf().list_available_managed_rule_group_versions(VendorName="AWS", Name=group, Scope=scope)
        return {"labels": [lb["Name"] for lb in d.get("AvailableLabels") or []], "default_version": v.get("CurrentDefaultVersion")}
    except (ClientError, BotoCoreError) as e:
        return {"error": str(e)[:300]}


def _acl_id(ref: dict[str, str]) -> str:
    """Web ACL ids are assigned by AWS ⇒ the stack passes names; the id is looked up (and cached) by name."""
    key = f"id:{ref['name']}"
    if key not in _clients:
        scope, marker = ref.get("scope", "CLOUDFRONT"), None
        while key not in _clients:
            page = _waf().list_web_acls(Scope=scope, Limit=100, **({"NextMarker": marker} if marker else {}))
            for a in page.get("WebACLs") or []:
                if a["Name"] == ref["name"]:
                    _clients[key] = a["Id"]
            marker = page.get("NextMarker")
            if not marker or not page.get("WebACLs"):
                break
        if key not in _clients:
            raise KeyError(f"web ACL {ref['name']} not found in scope {scope}")
    return _clients[key]


def get_acl(ref: dict[str, str]) -> dict[str, Any]:
    try:
        r = _waf().get_web_acl(Name=ref["name"], Scope=ref.get("scope", "CLOUDFRONT"), Id=ref.get("id") or _acl_id(ref))
        return {"acl": r["WebACL"], "lock": r["LockToken"]}
    except (ClientError, BotoCoreError, KeyError) as e:
        return {"error": str(e)[:300]}


def put_rules(ref: dict[str, str], acl: dict[str, Any], lock: str, rules: list[dict[str, Any]]) -> dict[str, Any]:
    """UpdateWebACL with every field the API requires carried over from GetWebACL (an omitted field is reset)."""
    if not ref["name"].startswith(mitigate.RADAR_ACL_PREFIX):   # belt and braces next to the IAM scope
        return {"error": f"refusing to write {ref['name']}: not a radar-owned web ACL"}
    kw: dict[str, Any] = {"Name": acl["Name"], "Scope": ref.get("scope", "CLOUDFRONT"), "Id": acl["Id"],
                          "DefaultAction": acl["DefaultAction"], "Rules": rules, "VisibilityConfig": acl["VisibilityConfig"],
                          "LockToken": lock}
    for k in ("Description", "CustomResponseBodies", "CaptchaConfig", "ChallengeConfig", "TokenDomains",
              "AssociationConfig"):
        if acl.get(k):
            kw[k] = acl[k]
    try:
        r = _waf().update_web_acl(**kw)
        return {"lock": r.get("NextLockToken")}
    except (ClientError, BotoCoreError) as e:
        return {"error": str(e)[:300]}


# ---------------------------------------------------------------- Route 53 Resolver DNS Firewall (radar Region)
def _r53r() -> Any:
    if "r53r" not in _clients:
        _clients["r53r"] = boto3.client("route53resolver", region_name=os.environ.get("AWS_REGION", "ap-northeast-1"))
    return _clients["r53r"]


def dns_config() -> dict[str, str] | None:
    """{rule_group_id, domain_list_id} of the radar-owned DNS Firewall objects (stack env); None ⇒ plan only."""
    g, d = os.environ.get("DNS_RULE_GROUP_ID"), os.environ.get("DNS_DOMAIN_LIST_ID")
    return {"rule_group_id": g, "domain_list_id": d} if g and d else None


def dns_state(cfg: dict[str, str]) -> dict[str, Any]:
    """Current radar list contents, rules of the radar rule group, and managed list name → id (this Region)."""
    try:
        c = _r53r()
        domains, tok = [], None
        while True:
            r = c.list_firewall_domains(FirewallDomainListId=cfg["domain_list_id"], MaxResults=1000, **({"NextToken": tok} if tok else {}))
            domains += r.get("Domains") or []
            tok = r.get("NextToken")
            if not tok:
                break
        rules = c.list_firewall_rules(FirewallRuleGroupId=cfg["rule_group_id"], MaxResults=100).get("FirewallRules") or []
        managed, tok = {}, None
        while True:
            r = c.list_firewall_domain_lists(MaxResults=100, **({"NextToken": tok} if tok else {}))
            managed.update({x["Name"]: x["Id"] for x in r.get("FirewallDomainLists") or [] if x.get("ManagedOwnerName")})
            tok = r.get("NextToken")
            if not tok:
                break
        return {"domains": sorted(d.rstrip(".") for d in domains), "rules": rules, "managed": managed}
    except (ClientError, BotoCoreError) as e:
        return {"error": str(e)[:300]}


def dns_put(cfg: dict[str, str], domains: list[str] | None, create: list[dict[str, Any]],
            update: list[dict[str, Any]]) -> dict[str, Any]:
    try:
        c = _r53r()
        if domains is not None:
            c.update_firewall_domains(FirewallDomainListId=cfg["domain_list_id"], Operation="REPLACE", Domains=domains)
        for r in create:
            # ≤ 64 chars (RSLVR-02006, live 2026-10-29); deterministic ⇒ a retried create is idempotent
            rid = "radar-" + hashlib.sha256(f"{cfg['rule_group_id']}/{r['FirewallDomainListId']}".encode()).hexdigest()[:40]
            c.create_firewall_rule(CreatorRequestId=rid,
                                   FirewallRuleGroupId=cfg["rule_group_id"], **r)
        for r in update:
            c.update_firewall_rule(FirewallRuleGroupId=cfg["rule_group_id"], **r)
        return {}
    except (ClientError, BotoCoreError) as e:
        return {"error": str(e)[:300]}


# ---------------------------------------------------------------- AWS Security Hub (radar Region)
def security_hub() -> dict[str, str] | None:
    """{account, region, site_url} when the stack turned the export on (SECURITY_HUB=on); None ⇒ not configured."""
    if os.environ.get("SECURITY_HUB") != "on":
        return None
    if "account" not in _clients:
        _clients["account"] = boto3.client("sts").get_caller_identity()["Account"]
    return {"account": _clients["account"], "region": os.environ.get("AWS_REGION", "ap-northeast-1"),
            "site_url": os.environ.get("SITE_URL", "")}


def security_hub_import(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """BatchImportFindings in chunks of 100; returns the ids Security Hub rejected."""
    try:
        if "securityhub" not in _clients:
            _clients["securityhub"] = boto3.client("securityhub", region_name=os.environ.get("AWS_REGION", "ap-northeast-1"))
        failed = []
        for i in range(0, len(findings), 100):
            r = _clients["securityhub"].batch_import_findings(Findings=findings[i:i + 100])
            failed += [x["Id"] for x in r.get("FailedFindings") or []]
        return {"failed": failed}
    except (ClientError, BotoCoreError) as e:
        return {"error": str(e)[:300]}
