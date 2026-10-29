"""M3.5 · AWS Security Hub: one ASFF finding per (event × affected target), next to GuardDuty / Inspector findings
(D-class). The finding carries the radar's verdict, the patch version, and the live state of every mitigation channel,
so an operator who lives in Security Hub sees the whole chain without opening the radar.

Imported with BatchImportFindings (product = this account's `default` product); re-imported only when its content
changes (hash in the ledger — ingestion beyond 10k/month is billed); a pair that is no longer affected is ARCHIVED."""

from __future__ import annotations

import hashlib
import json
from typing import Any

SCHEMA = "2018-10-08"
SEVERITY = {"P0": "CRITICAL", "P1": "HIGH", "P2": "MEDIUM"}
GENERATOR = "security-radar/mitigate"


def finding_id(event_id: str, target_id: str) -> str:
    return f"security-radar/{event_id}/{target_id}"


def asff(ev: dict[str, Any], target: dict[str, Any], mitigation: dict[str, Any] | None, account: str, region: str,
         now: str, site_url: str = "") -> dict[str, Any]:
    """ev = {event_id, title, severity, cves, first_seen}; target = a published response target (verdict affected)."""
    plans = [p for p in (mitigation or {}).get("plans") or [] if p["target_id"] == target["target_id"]]
    waf = "; ".join(f"WAF {p['group_label']} ({p['tier']}): {p['state']}" for p in plans) or "WAF: no plan"
    dns = (mitigation or {}).get("dns")
    dns_txt = f"DNS Firewall: {len(dns['domains'])} IOC domain(s), {dns['action'] or dns['state']}" if dns else "DNS Firewall: no IOC domains"
    locs = target.get("locations") or []
    fixed = sorted({loc["fixed_version"] for loc in locs if loc.get("fixed_version")})
    rec = (f"Upgrade to a fixed version ({', '.join(fixed)}). " if fixed else "Apply the vendor fix. ") + \
          "Mitigation is not a fix: edge rules only reduce exposure until the patch is deployed."
    resources = [{"Type": "Other", "Id": f"{target['target_id']}:{loc['file']}:{loc['line']}", "Partition": "aws", "Region": region,
                  "Details": {"Other": {"file": loc["file"][:1024], "line": str(loc["line"]),
                                        "found_version": str(loc.get("found_version") or ""), "match": str(loc.get("match") or "")}}}
                 for loc in locs[:10]] or [{"Type": "Other", "Id": target["target_id"], "Partition": "aws", "Region": region}]
    f = {"SchemaVersion": SCHEMA, "Id": finding_id(ev["event_id"], target["target_id"]),
         "ProductArn": f"arn:aws:securityhub:{region}:{account}:product/{account}/default", "GeneratorId": GENERATOR,
         "AwsAccountId": account, "Types": ["Software and Configuration Checks/Vulnerabilities/CVE"],
         "CreatedAt": ev.get("first_seen") or now, "UpdatedAt": now,
         "Severity": {"Label": SEVERITY.get(ev.get("severity") or "", "MEDIUM")},
         "Title": f"[Security Radar] {ev['title']}"[:256],
         "Description": (f"{target['target_id']}: {target.get('detail') or 'affected'}. {waf}. {dns_txt}.")[:1024],
         "Remediation": {"Recommendation": {"Text": rec[:512], **({"Url": f"{site_url}/#/events/{ev['event_id']}"} if site_url else {})}},
         "Resources": resources, "RecordState": "ACTIVE", "Workflow": {"Status": "NEW"},
         "ProductFields": {"radar/event_id": ev["event_id"], "radar/target_id": target["target_id"],
                           "radar/mitigation": waf[:2000]}}
    if ev.get("cves"):
        f["Vulnerabilities"] = [{"Id": c} for c in ev["cves"][:10]]
    return f


def content_hash(f: dict[str, Any]) -> str:
    """Hash without the timestamps: an unchanged finding is not re-imported every cycle."""
    body = {k: v for k, v in f.items() if k not in ("UpdatedAt",)}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:16]


def archived(f_id: str, account: str, region: str, now: str, title: str) -> dict[str, Any]:
    """Minimal re-import that archives a finding whose pair is no longer affected (BatchImportFindings needs the
    required fields again)."""
    return {"SchemaVersion": SCHEMA, "Id": f_id, "ProductArn": f"arn:aws:securityhub:{region}:{account}:product/{account}/default",
            "GeneratorId": GENERATOR, "AwsAccountId": account, "Types": ["Software and Configuration Checks/Vulnerabilities/CVE"],
            "CreatedAt": now, "UpdatedAt": now, "Severity": {"Label": "INFORMATIONAL"}, "Title": title[:256],
            "Description": "No longer affected according to Security Radar.", "RecordState": "ARCHIVED",
            "Resources": [{"Type": "Other", "Id": f_id.rsplit("/", 1)[-1]}]}


def plan(current: dict[str, dict[str, Any]], exported: dict[str, dict[str, str]], account: str, region: str,
         now: str) -> tuple[list[dict[str, Any]], dict[str, dict[str, str]]]:
    """(findings to import, new export ledger). current = finding id → ASFF; exported = id → {hash, title, state}."""
    out, led = [], {}
    for fid, f in sorted(current.items()):
        h = content_hash(f)
        led[fid] = {"hash": h, "title": f["Title"], "state": "ACTIVE"}
        if (exported.get(fid) or {}).get("hash") != h or (exported.get(fid) or {}).get("state") != "ACTIVE":
            out.append(f)
    for fid, row in sorted(exported.items()):
        if fid in current:
            continue
        if row.get("state") == "ACTIVE":
            out.append(archived(fid, account, region, now, row.get("title") or fid))
        led[fid] = {**row, "state": "ARCHIVED"}
    return out, led
