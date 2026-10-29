"""B5 end to end (M3.4): the radar's DNS Firewall rule sees a query from the demo VPC.

  STAGE= uv run python scripts/dns-e2e.py [--expect alert|block] [--wait-min 15]

1. the radar domain list contains the canary and the radar rule group has the radar rule + AWS-managed lists
2. the probe Lambda (inside the demo VPC, no internet path) resolves the canary — .invalid ⇒ NXDOMAIN either way
3. the Resolver query log shows that query with firewall_rule_action = ALERT (or BLOCK after promotion)
Exit 0 = PASS."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from radar import mitigate

REGION = "ap-northeast-1"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--expect", choices=["alert", "block"], default="alert")
    ap.add_argument("--wait-min", type=int, default=15)
    a = ap.parse_args()
    stage = os.environ.get("STAGE", "")
    out = json.loads((ROOT / "build" / f"outputs{'-' + stage if stage else ''}.json").read_text())[f"SecurityRadar{stage.capitalize()}"]
    r53r = boto3.client("route53resolver", region_name=REGION)
    ok = True

    rules = r53r.list_firewall_rules(FirewallRuleGroupId=out["DnsRuleGroupId"], MaxResults=100)["FirewallRules"]
    radar = next((r for r in rules if r["Name"] == mitigate.DNS_RADAR_RULE), None)
    domains = r53r.list_firewall_domains(FirewallDomainListId=radar["FirewallDomainListId"], MaxResults=1000)["Domains"] if radar else []
    have = radar is not None and any(d.rstrip(".") == mitigate.DNS_CANARY for d in domains)
    print(f"{'PASS' if have else 'FAIL'} 1 radar rule {radar and radar['Action']} with {len(domains)} domain(s), "
          f"{len(rules)} rule(s) in the group (canary listed: {have})")
    if not have:
        return 1

    lam = boto3.client("lambda", region_name=REGION)
    t0 = int(time.time() * 1000)
    resp = json.loads(lam.invoke(FunctionName=out["DnsProbeFunction"], Payload=json.dumps({"name": mitigate.DNS_CANARY}))["Payload"].read())
    probed = "errorMessage" not in resp
    print(f"{'PASS' if probed else 'FAIL'} 2 probe resolved {mitigate.DNS_CANARY}: "
          f"{resp.get('answers') or resp.get('error') or resp.get('errorMessage')}")
    ok &= probed

    logs = boto3.client("logs", region_name=REGION)
    want = a.expect.upper()
    deadline, rec = time.time() + a.wait_min * 60, None
    while time.time() < deadline and not rec:
        ev = logs.filter_log_events(logGroupName=out["DnsQueryLogGroup"], startTime=t0 - 60_000,
                                    filterPattern=f'"{mitigate.DNS_CANARY}"').get("events") or []
        for e in ev:
            m = json.loads(e["message"])
            if m.get("query_name", "").rstrip(".") == mitigate.DNS_CANARY and m.get("firewall_rule_action"):
                rec = m
        if not rec:
            # semgrep arbitrary-sleep: polling interval while Resolver query logs arrive (bounded by --wait-min)
            time.sleep(20)  # nosemgrep
    act = (rec or {}).get("firewall_rule_action")
    hit = act == want
    print(f"{'PASS' if hit else 'FAIL'} 3 query log: action={act} (expected {want}) rcode={(rec or {}).get('rcode')}")
    ok &= hit
    print("ALL CHECKS PASSED" if ok else "CHECKS FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
