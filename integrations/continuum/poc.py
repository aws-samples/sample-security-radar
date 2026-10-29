"""PoC: Security Radar event → AWS Security Agent (part of AWS Continuum) code review + automatic remediation.

  uv run python -m integrations.continuum.poc setup     # bucket, role, agent space, requirement pack
  uv run python -m integrations.continuum.poc run       # upload demo repo, create + start code review
  uv run python -m integrations.continuum.poc status    # job status + findings
  uv run python -m integrations.continuum.poc teardown  # delete everything this PoC created

Account/profile: any non-production profile, region ap-northeast-1. State: build/continuum-poc.json.
Every step is code; the only "judgement" happens inside the AWS agent we are evaluating."""

from __future__ import annotations

import io
import json
import sys
import time
import zipfile
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

from radar import respond

REGION = "ap-northeast-1"
ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / "build" / "continuum-poc.json"
TAGS = {"project": "security-radar", "purpose": "continuum-poc"}
NAME = "sr-continuum-poc"

DEMO = {
    "Dockerfile": "FROM php:8.3.30-apache\nCOPY src/ /var/www/html/\nRUN docker-php-ext-install pdo_mysql\n",
    "composer.json": json.dumps({"name": "demo/shop", "require": {"php": "^8.3"}, "config": {"platform": {"php": "8.3.30"}}}, indent=2),
    ".gitlab-ci.yml": "test:\n  image: php:8.3.30-cli\n  script: [php -v]\n",
    "src/index.php": "<?php\n// demo storefront (intentionally on an affected PHP 8.3 release)\n"
                     "$q = $_GET['q'] ?? '';\necho '<h1>Search: ' . htmlspecialchars($q) . '</h1>';\n",
}


def _state() -> dict:
    return json.loads(STATE.read_text()) if STATE.exists() else {}


def _save(s: dict) -> None:
    STATE.parent.mkdir(exist_ok=True)
    STATE.write_text(json.dumps(s, indent=2, default=str))


def _event_doc() -> dict:
    """Live radar event: the PHP2Shell event from the published site data."""
    out = json.loads((ROOT / "build" / "outputs.json").read_text())["SecurityRadar"]
    s3 = boto3.client("s3", region_name=REGION)
    listing = json.loads(s3.get_object(Bucket=out["SiteBucketName"], Key="data/events.json")["Body"].read())
    ev = next(e for e in listing["events"] if "CVE-2026-109618" in e["cves"])
    return json.loads(s3.get_object(Bucket=out["SiteBucketName"], Key=f"data/events/{ev['event_id']}.json")["Body"].read())


def setup() -> None:
    s = _state()
    acct = boto3.client("sts").get_caller_identity()["Account"]
    s3, iam, sa = boto3.client("s3", region_name=REGION), boto3.client("iam"), boto3.client("securityagent", region_name=REGION)
    bucket = s.get("bucket") or f"{NAME}-{acct}-{REGION}"
    if "bucket" not in s:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": REGION})
        s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={k: True for k in (
            "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")})
        s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in TAGS.items()]})
        s["bucket"] = bucket
    if "role_arn" not in s:
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "securityagent.amazonaws.com"},
                 "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"aws:SourceAccount": acct}}}]}
        role = iam.create_role(RoleName=NAME, AssumeRolePolicyDocument=json.dumps(trust),
                               Tags=[{"Key": k, "Value": v} for k, v in TAGS.items()])["Role"]
        iam.put_role_policy(RoleName=NAME, PolicyName="read-poc-sources-write-logs", PolicyDocument=json.dumps({
            "Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"],
                 "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]},
                {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                 "Resource": f"arn:aws:logs:{REGION}:{acct}:log-group:/aws/securityagent/*"}]}))
        s["role_arn"] = role["Arn"]
        _save(s)
        # semgrep arbitrary-sleep: IAM is eventually consistent and no waiter covers propagation to another service
        time.sleep(12)  # nosemgrep
    if "agent_space_id" not in s:
        r = sa.create_agent_space(name=NAME, description="Security Radar → Security Agent PoC",
                                  awsResources={"s3Buckets": [f"arn:aws:s3:::{bucket}"], "iamRoles": [s["role_arn"]]},
                                  codeReviewSettings={"controlsScanning": True, "generalPurposeScanning": True}, tags=TAGS)
        s["agent_space_id"] = r.get("agentSpaceId") or r.get("id") or r
    if "pack_id" not in s:
        r = sa.create_security_requirement_pack(name=NAME, description="Requirements generated from Security Radar P0/P1 events",
                                                status="ENABLED", tags=TAGS)
        s["pack_id"] = r.get("packId") or r.get("id") or r
        doc = _event_doc()
        req = respond.requirement(doc["event"], respond.eligibility(doc["event"], doc["items"]))
        s["requirement"] = req
        s["requirements_created"] = sa.batch_create_security_requirements(packId=s["pack_id"], securityRequirements=[req])
    _save(s)
    print(json.dumps({k: s[k] for k in ("bucket", "role_arn", "agent_space_id", "pack_id")}, indent=2, default=str))


def run() -> None:
    s = _state()
    sa, s3 = boto3.client("securityagent", region_name=REGION), boto3.client("s3", region_name=REGION)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for path, body in DEMO.items():
            z.writestr(f"demo-shop/{path}", body)
    key = "sources/demo-shop.zip"
    s3.put_object(Bucket=s["bucket"], Key=key, Body=buf.getvalue())
    cr = sa.create_code_review(title="radar-php2shell-cve-2026-109618", agentSpaceId=s["agent_space_id"],
                               assets={"sourceCode": [{"s3Location": f"s3://{s['bucket']}/{key}"}]},
                               serviceRole=s["role_arn"], codeRemediationStrategy="AUTOMATIC", maxTaskHours=20.0)  # API minimum; billing is per CIU used
    s["code_review"] = cr
    cr_id = cr.get("codeReviewId") or cr.get("id")
    job = sa.start_code_review_job(agentSpaceId=s["agent_space_id"], codeReviewId=cr_id)
    s["code_review_id"], s["job"] = cr_id, job
    s["started_at"] = time.time()
    _save(s)
    print(json.dumps({"code_review_id": cr_id, "job": job}, indent=2, default=str))


def status() -> None:
    s = _state()
    sa = boto3.client("securityagent", region_name=REGION)
    job_id = (s.get("job") or {}).get("codeReviewJobId") or (s.get("job") or {}).get("jobId")
    jobs = sa.batch_get_code_review_jobs(agentSpaceId=s["agent_space_id"], codeReviewJobIds=[job_id]) if job_id else {}
    findings = sa.list_findings(agentSpaceId=s["agent_space_id"], codeReviewJobId=job_id) if job_id else {}
    out = {"elapsed_min": round((time.time() - s.get("started_at", time.time())) / 60, 1), "jobs": jobs, "findings": findings}
    print(json.dumps(out, indent=2, default=str)[:6000])


def teardown() -> None:
    s = _state()
    sa, s3, iam = boto3.client("securityagent", region_name=REGION), boto3.client("s3", region_name=REGION), boto3.client("iam")
    steps = [
        ("code review", lambda: sa.batch_delete_code_reviews(agentSpaceId=s["agent_space_id"], codeReviewIds=[s["code_review_id"]])),
        ("requirements", lambda: sa.batch_delete_security_requirements(packId=s["pack_id"], securityRequirementNames=[
            r["name"] for r in sa.list_security_requirements(packId=s["pack_id"])["securityRequirementSummaries"]])),
        ("requirement pack", lambda: sa.delete_security_requirement_pack(packId=s["pack_id"])),  # must be empty first
        ("agent space", lambda: sa.delete_agent_space(agentSpaceId=s["agent_space_id"])),
        ("bucket objects", lambda: [s3.delete_object(Bucket=s["bucket"], Key=o["Key"]) for o in
                                    s3.list_objects_v2(Bucket=s["bucket"]).get("Contents", [])]),
        ("bucket", lambda: s3.delete_bucket(Bucket=s["bucket"])),
        ("role policy", lambda: iam.delete_role_policy(RoleName=NAME, PolicyName="read-poc-sources-write-logs")),
        ("role", lambda: iam.delete_role(RoleName=NAME)),
    ]
    for label, fn in steps:
        try:
            fn()
            print(f"deleted {label}")
        except (ClientError, KeyError) as e:
            print(f"skip {label}: {e}")  # visible, not silent: a skipped step is reported
    STATE.unlink(missing_ok=True)


if __name__ == "__main__":
    {"setup": setup, "run": run, "status": status, "teardown": teardown}[sys.argv[1]]()
