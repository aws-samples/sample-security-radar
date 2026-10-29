"""B2 end to end (M3): the virtual patch the mitigate station staged really sees a PHP2Shell-shaped request.

  STAGE= uv run python scripts/waf-e2e.py [--expect count|block] [--wait-min 30]

1. anonymous GET on the demo distribution → 401 + WWW-Authenticate (the deny-all gate; nothing is behind it)
2. the radar's rule for AWSManagedRulesPHPRuleSet is in the demo web ACL (GetWebACL)
3. one POST carrying a PHP session id and the session-upload-progress field — the shape AWS documents for
   PHP2Shell_BODY (CVE-2026-109619) — tagged with a unique path, harmless by construction (no PHP behind it)
   count ⇒ WAF lets it through to the gate (401);  block ⇒ WAF stops it (403)
4. GetSampledRequests shows that request with the label awswaf:managed:aws:php-app:PHP2Shell_Body
Exit 0 = PASS. Veto (M3-PLAN §4): no label within --wait-min ⇒ FAIL."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from radar import mitigate

GROUP = "AWSManagedRulesPHPRuleSet"
LABEL = "awswaf:managed:aws:php-app:PHP2Shell_Body"


def _status(req: urllib.request.Request) -> tuple[int, dict[str, str]]:
    try:
        with urllib.request.urlopen(req, timeout=20) as r:   # nosemgrep
            return r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--expect", choices=["count", "block"], default="count")
    ap.add_argument("--wait-min", type=int, default=30)
    a = ap.parse_args()
    stage = os.environ.get("STAGE", "")
    outs = json.loads((ROOT / "build" / f"outputs{'-' + stage if stage else ''}.json").read_text())
    demo = outs[f"SecurityRadarMitigateDemo{stage.capitalize()}"]
    url, acl_name = demo["DemoUrl"], demo["DemoWebAclName"]
    waf = boto3.client("wafv2", region_name="us-east-1")
    ok = True

    code, hdr = _status(urllib.request.Request(url + "/"))
    gate = code == 401 and "basic" in {k.lower(): v for k, v in hdr.items()}.get("www-authenticate", "").lower()
    print(f"{'PASS' if gate else 'FAIL'} 1 anonymous GET → {code} (gate {'seen' if gate else 'NOT seen'})")
    ok &= gate

    acl_id = next(x["Id"] for x in waf.list_web_acls(Scope="CLOUDFRONT", Limit=100)["WebACLs"] if x["Name"] == acl_name)
    acl = waf.get_web_acl(Name=acl_name, Scope="CLOUDFRONT", Id=acl_id)["WebACL"]
    rule = next((r for r in acl["Rules"] if r["Name"] == mitigate.rule_name(GROUP)), None)
    print(f"{'PASS' if rule else 'FAIL'} 2 radar rule {mitigate.rule_name(GROUP)} in {acl_name}"
          + (f" (overrides: {[o['Name'] for o in rule['Statement']['ManagedRuleGroupStatement'].get('RuleActionOverrides') or []]})" if rule else ""))
    if not rule:
        return 1

    nonce = uuid.uuid4().hex[:12]
    boundary = "radar" + nonce
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nradar-e2e\r\n"
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n"
            f"Content-Type: text/plain\r\n\r\nx\r\n--{boundary}--\r\n").encode()
    req = urllib.request.Request(f"{url}/radar-e2e/{nonce}", data=body, method="POST", headers={
        "Content-Type": f"multipart/form-data; boundary={boundary}", "Cookie": f"PHPSESSID=radar{nonce}"})
    sent = datetime.now(UTC)
    code, _ = _status(req)
    want = 401 if a.expect == "count" else 403
    print(f"{'PASS' if code == want else 'FAIL'} 3 PHP2Shell-shaped POST → {code} (expected {want} for {a.expect})")
    ok &= code == want

    metric = rule["VisibilityConfig"]["MetricName"]
    deadline = time.time() + a.wait_min * 60
    seen = None
    while time.time() < deadline and not seen:
        r = waf.get_sampled_requests(WebAclArn=acl["ARN"], RuleMetricName=metric, Scope="CLOUDFRONT", MaxItems=100,
                                     TimeWindow={"StartTime": sent - timedelta(minutes=5), "EndTime": datetime.now(UTC)})
        for s in r.get("SampledRequests") or []:
            if nonce in s["Request"].get("URI", ""):
                seen = s
        if not seen:
            time.sleep(30)
    # evidence that THE rule matched: the sample names the rule inside the group (COUNT samples carry no Labels),
    # or — when present — the rule's label
    labels = [lb["Name"] for lb in (seen or {}).get("Labels") or []]
    inner = (seen or {}).get("RuleNameWithinRuleGroup") or ""
    hit = inner.endswith(f"#{GROUP}#PHP2Shell_BODY") or LABEL in labels
    print(f"{'PASS' if hit else 'FAIL'} 4 sampled request {'found' if seen else 'NOT found'}: action={seen and seen.get('Action')}"
          f" rule={inner or None} labels={labels}")
    ok &= hit

    # B3: the mitigate role can update the demo web ACL and no other web ACL in the account
    lam = boto3.client("lambda", region_name="ap-northeast-1")
    fn = next(f for page in lam.get_paginator("list_functions").paginate() for f in page["Functions"]
              if f["FunctionName"].startswith(f"SecurityRadar{stage.capitalize()}-MitigateFn"))
    iam = boto3.client("iam")
    others = [x["ARN"] for x in waf.list_web_acls(Scope="CLOUDFRONT", Limit=100)["WebACLs"] if x["Name"] != acl_name]
    others += [x["ARN"] for reg in ("ap-northeast-1", "us-east-1")
               for x in boto3.client("wafv2", region_name=reg).list_web_acls(Scope="REGIONAL", Limit=100)["WebACLs"]]
    # one ARN per call: with several ResourceArns the per-resource verdicts move into ResourceSpecificResults
    by = {arn: iam.simulate_principal_policy(PolicySourceArn=fn["Role"], ActionNames=["wafv2:UpdateWebACL"],
                                             ResourceArns=[arn])["EvaluationResults"][0]["EvalDecision"]
          for arn in [acl["ARN"], *others]}
    scope_ok = by.get(acl["ARN"]) == "allowed" and all(by.get(o) != "allowed" for o in others)
    print(f"{'PASS' if scope_ok else 'FAIL'} 5 UpdateWebACL: demo={by.get(acl['ARN'])}, "
          f"{sum(1 for o in others if by.get(o) != 'allowed')}/{len(others)} other web ACLs denied")
    ok &= scope_ok
    print("ALL CHECKS PASSED" if ok else "CHECKS FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
