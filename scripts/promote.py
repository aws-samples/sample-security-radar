"""The human step of a mitigation: promote a staged (counting) rule to blocking — or take the promotion back.

  STAGE= uv run python scripts/promote.py waf                                   # list staged / promoted rules
  STAGE= uv run python scripts/promote.py waf <web-acl> <group> --by <name>     # promote (Count → Block)
  STAGE= uv run python scripts/promote.py waf <web-acl> <group> --revoke        # back to Count
  STAGE= uv run python scripts/promote.py dns <rule> --by <name>                # DNS Firewall rule ALERT → BLOCK

Before promoting, look at what the rule matched while counting (AWS: start in Count, confirm it does not match
legitimate traffic, then Block — and measure that review in hours, not days). This script only records the decision
(DynamoDB, key __mitigate_promotions__, written by nobody else); the mitigate station applies it within one cycle and
never demotes a promoted rule on its own."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from radar import mitigate, mitigate_station
from radar.dynamo import DynamoStore


def _store() -> DynamoStore:
    stage = os.environ.get("STAGE", "")
    outputs = json.loads((ROOT / "build" / f"outputs{'-' + stage if stage else ''}.json").read_text())
    table = boto3.resource("dynamodb", region_name="ap-northeast-1").Table(outputs[f"SecurityRadar{stage.capitalize()}"]["TableName"])
    return DynamoStore(table)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("channel", choices=["waf", "dns"])
    ap.add_argument("web_acl", nargs="?")
    ap.add_argument("group", nargs="?", help="managed rule group, e.g. AWSManagedRulesPHPRuleSet")
    ap.add_argument("--by", help="who decided (kept with the promotion)")
    ap.add_argument("--revoke", action="store_true")
    a = ap.parse_args()
    store = _store()
    led = store.get_source_state(mitigate_station.MITIGATE_KEY)
    promo = store.get_source_state(mitigate_station.PROMOTE_KEY)
    if a.channel == "dns":
        rules = [mitigate.DNS_RADAR_RULE, *(f"radar-{n}" for n in mitigate.DNS_MANAGED_LISTS)]
        if a.web_acl not in rules:
            print(f"[promote] DNS rule must be one of: {', '.join(rules)}", file=sys.stderr)
            return 2
        dns = promo.setdefault("dns", {})
        if a.revoke:
            dns.pop(a.web_acl, None)
        elif not a.by:
            print("[promote] --by <name> is required", file=sys.stderr)
            return 2
        else:
            dns[a.web_acl] = {"by": a.by, "at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")}
        store.put_source_state(mitigate_station.PROMOTE_KEY, promo)
        print(f"[promote] {'revoked' if a.revoke else 'promoted'} DNS rule {a.web_acl}; applied next cycle")
        return 0
    if not a.web_acl:
        for eid, m in sorted((led.get("events") or {}).items()):
            for p in m.get("plans") or []:
                if p.get("web_acl"):
                    print(f"{p['state']:<10} {p['web_acl']}  {p['group']}  ({eid}, {p['target_id']}, tier {p['tier']})")
        return 0
    if a.group not in mitigate.WAF_GROUPS:
        print(f"[promote] unknown group {a.group!r}; one of: {', '.join(mitigate.WAF_GROUPS)}", file=sys.stderr)
        return 2
    staged = {(p["web_acl"], p["group"]) for m in (led.get("events") or {}).values() for p in m.get("plans") or []
              if p.get("appliable")}
    if (a.web_acl, a.group) not in staged and not a.revoke:
        print(f"[promote] no appliable plan for {a.group} on {a.web_acl} — nothing the station would apply", file=sys.stderr)
        return 2
    acl = promo.setdefault("waf", {}).setdefault(a.web_acl, {})
    rule = mitigate.rule_name(a.group)
    if a.revoke:
        acl.pop(rule, None)
    else:
        if not a.by:
            print("[promote] --by <name> is required: a promotion is a human decision and keeps who made it", file=sys.stderr)
            return 2
        acl[rule] = {"by": a.by, "at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")}
    store.put_source_state(mitigate_station.PROMOTE_KEY, promo)
    print(f"[promote] {'revoked' if a.revoke else 'promoted'} {rule} on {a.web_acl}; the mitigate station applies it next cycle")
    return 0


if __name__ == "__main__":
    sys.exit(main())
