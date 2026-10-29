"""PoC phase 2: Security Radar → AWS Continuum (code vulnerabilities, us-east-1).

  uv run --with boto3 python -m integrations.continuum.cn_poc setup     # bucket, integration role, S3 integration, environment
  uv run --with boto3 python -m integrations.continuum.cn_poc context   # radar briefs → context/ (knowledge documents)
  uv run --with boto3 python -m integrations.continuum.cn_poc scan      # CreateCodeScan (radar-triggered scan)
  uv run --with boto3 python -m integrations.continuum.cn_poc finding   # CreateCodeFinding: radar CVE pinned to a code location
  uv run --with boto3 python -m integrations.continuum.cn_poc status    # scans, findings, issues, artifacts
  uv run --with boto3 python -m integrations.continuum.cn_poc teardown

Continuum has no endpoint in ap-northeast-1, so this runs in us-east-1 (bucket must share its Region).
State: build/continuum-cn-poc.json."""

from __future__ import annotations

import io
import json
import sys
import time
import uuid
import zipfile

import boto3
from botocore.exceptions import ClientError

from integrations.continuum.poc import DEMO, ROOT, TAGS, _event_doc

REGION = "us-east-1"
STATE = ROOT / "build" / "continuum-cn-poc.json"
NAME = "sr-continuum"


def _state() -> dict:
    return json.loads(STATE.read_text()) if STATE.exists() else {}


def _save(s: dict) -> None:
    STATE.parent.mkdir(exist_ok=True)
    STATE.write_text(json.dumps(s, indent=2, default=str))


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for path, body in files.items():
            z.writestr(path, body)
    return buf.getvalue()


def setup() -> None:
    s = _state()
    acct = boto3.client("sts").get_caller_identity()["Account"]
    s3, iam, cn = boto3.client("s3", region_name=REGION), boto3.client("iam"), boto3.client("continuum", region_name=REGION)
    bucket = s.get("bucket") or f"{NAME}-{acct}-{REGION}"
    if "bucket" not in s:
        s3.create_bucket(Bucket=bucket)
        s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={k: True for k in (
            "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")})
        s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
        s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in TAGS.items()]})
        s["bucket"] = bucket
        _save(s)
    s3.put_object(Bucket=bucket, Key="code/demo-shop.zip", Body=_zip(DEMO))
    if "role_arn" not in s:
        s["external_id"] = str(uuid.uuid4())
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "continuum.amazonaws.com"},
                 "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"sts:ExternalId": s["external_id"]}}}]}
        role = iam.create_role(RoleName=f"{NAME}-integration", Path="/continuum/integrations/",
                               AssumeRolePolicyDocument=json.dumps(trust),
                               Tags=[{"Key": k, "Value": v} for k, v in TAGS.items()])["Role"]
        iam.put_role_policy(RoleName=f"{NAME}-integration", PolicyName="ContinuumIntegrationAccess", PolicyDocument=json.dumps({
            "Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket}"},
                {"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion"],
                 "Resource": [f"arn:aws:s3:::{bucket}/code/*", f"arn:aws:s3:::{bucket}/context/*"]},
                {"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion"],
                 "Resource": f"arn:aws:s3:::{bucket}/continuum-patches/*"}]}))
        s["role_arn"] = role["Arn"]
        _save(s)
        # semgrep arbitrary-sleep: IAM is eventually consistent and no waiter covers propagation to another service
        time.sleep(15)  # nosemgrep
    if "integration_id" not in s:
        r = cn.create_integration(name=NAME, clientToken=f"{NAME}-int-1",
                                  providerConfiguration={"s3": {"bucket": bucket, "roleArn": s["role_arn"], "externalId": s["external_id"]}})
        s["integration_id"] = r["integrationId"]
        _save(s)
    if "environment_id" not in s:
        r = cn.create_environment(name=NAME, configuration={
            "codeConfiguration": {"sourceConfiguration": {"s3Sources": [
                {"integrationId": s["integration_id"], "codePrefix": "code/", "contextPrefix": "context/"}]},
                "environmentConfiguration": {"scanFrequency": "P7D", "patchCreationPolicy": "ENABLED"}}})
        s["environment_id"] = r["environmentId"]
        s["environment_arn"] = r["environmentArn"]
    _save(s)
    print(json.dumps({k: s.get(k) for k in ("bucket", "role_arn", "integration_id", "environment_id")}, indent=2))


def context() -> None:
    """Radar → Continuum context: the event and its analyst brief as a knowledge document."""
    s = _state()
    doc = _event_doc()
    ev, an = doc["event"], doc.get("analysis") or {}
    lines = [f"# Security Radar threat intel: {ev['title']}", "",
             f"- Severity {ev['severity']} / verification {ev['level']} / exploitation {ev['exploitation']}",
             f"- CVEs: {', '.join(ev['cves'])}", f"- Independent sources: {ev['independent_sources']}",
             f"- First seen: {ev['first_seen']}", ""]
    for sec in (an.get("sections") or []):
        lines.append(f"## {sec.get('title') or sec.get('key')}")
        lines += [f"- {x.get('text', x) if isinstance(x, dict) else x}" for x in sec.get("sentences", sec.get("items", []))]
    lines += ["", "## Evidence"] + [f"- {it.get('source')}: {it.get('title')} {it.get('url')}" for it in doc["items"][:20]]
    boto3.client("s3", region_name=REGION).put_object(Bucket=s["bucket"], Key=f"context/radar-{ev['event_id']}.md",
                                                     Body="\n".join(lines).encode(), ContentType="text/markdown")
    print(f"context/radar-{ev['event_id']}.md", len("\n".join(lines)))


def scan() -> None:
    s = _state()
    cn = boto3.client("continuum", region_name=REGION)
    r = cn.create_code_scan(environmentId=s["environment_id"], clientToken=f"radar-scan-{int(time.time())}")
    s.setdefault("scans", []).append(r)
    _save(s)
    print(json.dumps(r, indent=2, default=str))


def finding() -> None:
    """Radar event → OCSF 2002 Vulnerability Finding pinned to the Dockerfile line that uses an affected PHP."""
    s = _state()
    doc = _event_doc()
    ev = doc["event"]
    now = int(time.time() * 1000)
    ocsf = {
        "class_uid": 2002, "category_uid": 2, "type_uid": 200201, "activity_id": 1, "severity_id": 4, "status_id": 1,
        "time": now, "cloud": {"provider": "AWS", "region": REGION},
        "osint": [{"type_id": 5, "value": it["url"], "src_url": it["url"], "name": it.get("source", "")} for it in doc["items"][:10] if it.get("url")],
        "metadata": {"version": "1.9.0", "product": {"name": "Security Radar", "vendor_name": "aws-gcr-web3"}},
        "finding_info": {"uid": f"radar-{ev['event_id']}-demo-shop-dockerfile", "title": f"Affected PHP runtime: {ev['title']}"[:240],
                         "desc": f"Security Radar {ev['severity']}/{ev['level']} ({ev['exploitation']}); CVEs {', '.join(ev['cves'])}.",
                         "first_seen_time": now},
        "vulnerabilities": [{
            "title": f"PHP 8.3.30 is affected by {', '.join(ev['cves'])}", "desc": "Base image pinned below fixed release 8.3.36.",
            "cve": {"uid": ev["cves"][0]}, "severity": "High",
            "affected_code": [{"file": {"name": "Dockerfile", "path": "demo-shop/Dockerfile", "type_id": 1}, "start_line": 1, "end_line": 1}],
            "affected_packages": [{"name": "php", "version": "8.3.30", "fixed_in_version": "8.3.36"}],
            "remediation": {"desc": "Upgrade the base image to php:8.3.36-apache."},
        }],
    }
    cn = boto3.client("continuum", region_name=REGION)
    r = cn.create_code_finding(environmentId=s["environment_id"], ocsfDocument=ocsf, clientToken=f"radar-{ev['event_id']}-1")
    s.setdefault("findings", []).append(r)
    _save(s)
    print(json.dumps(r, indent=2, default=str))


def status() -> None:
    s = _state()
    cn = boto3.client("continuum", region_name=REGION)
    env = s["environment_id"]
    out = {"environment": cn.get_environment(environmentId=env), "scans": cn.list_code_scans(environmentId=env),
           "findings": cn.list_code_findings(environmentId=env), "issues": cn.list_code_issues(environmentId=env)}
    for o in (out["environment"], out["scans"], out["findings"], out["issues"]):
        o.pop("ResponseMetadata", None)
    print(json.dumps(out, indent=2, default=str)[:8000])


def teardown() -> None:
    s = _state()
    cn, s3, iam = boto3.client("continuum", region_name=REGION), boto3.client("s3", region_name=REGION), boto3.client("iam")
    def empty() -> None:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=s["bucket"]):
            for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=s["bucket"], Key=v["Key"], VersionId=v["VersionId"])
    steps = [("environment", lambda: cn.delete_environment(environmentId=s["environment_id"])),
             ("integration", lambda: cn.delete_integration(integrationId=s["integration_id"])),
             ("bucket objects", empty), ("bucket", lambda: s3.delete_bucket(Bucket=s["bucket"])),
             ("role policy", lambda: iam.delete_role_policy(RoleName=f"{NAME}-integration", PolicyName="ContinuumIntegrationAccess")),
             ("role", lambda: iam.delete_role(RoleName=f"{NAME}-integration"))]
    for label, fn in steps:
        try:
            fn()
            print(f"deleted {label}")
        except (ClientError, KeyError) as e:
            print(f"skip {label}: {e}")  # visible, not silent
    STATE.unlink(missing_ok=True)


if __name__ == "__main__":
    {"setup": setup, "context": context, "scan": scan, "finding": finding, "status": status, "teardown": teardown}[sys.argv[1]]()
