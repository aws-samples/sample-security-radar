"""AWS adapter for the respond station: executes radar.respond operations against AWS Security Agent
(ap-northeast-1) and AWS Continuum (us-east-1; no endpoint in Tokyo). Every call's failure is returned as
`{"error": ...}` and recorded by respond.apply — the station never raises on a downstream outage.

Config comes from the stack (env): SA_AGENT_SPACE_ID, SA_PACK_ID, SA_SERVICE_ROLE_ARN, SA_CODE_BUCKET,
CN_REGION, CN_BUCKET, CN_INTEGRATION_ROLE_ARN, CN_EXTERNAL_ID, SITE_BUCKET."""

from __future__ import annotations

import io
import json
import logging
import os
import re
import time
import urllib.request
import zipfile
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from radar import respond
from radar.limits import Limits

log = logging.getLogger()
ENV_NAME = os.environ.get("CN_ENV_NAME", "security-radar")  # per stage (infra/app.py)
PATCH_MAX_BYTES = 1_000_000
_clients: dict[str, Any] = {}


def _c(service: str, region: str | None = None) -> Any:
    key = f"{service}@{region}"
    if key not in _clients:
        _clients[key] = boto3.client(service, region_name=region) if region else boto3.client(service)
    return _clients[key]


_RAW: dict[str, bytes] = {}  # last raw GetCodeIssueArtifact response (single-threaded Lambda)


def _keep_raw_artifact(http_response: Any, **_: Any) -> None:
    _RAW["artifact"] = http_response.content


def _cn() -> Any:
    cn = _c("continuum", os.environ.get("CN_REGION", "us-east-1"))
    # botocore 1.43.118 has no `gitlab` member in the patch delivery target union: the parser returns
    # {"SDK_UNKNOWN_MEMBER": {"name": "gitlab"}} and drops projectPath / mergeRequestNumber (live, MR !1 2026-10-28).
    # Keep the raw body so _delivery_target can read it; unique_id ⇒ registered once per cached client.
    cn.meta.events.register("after-call.continuum.GetCodeIssueArtifact", _keep_raw_artifact, unique_id="radar-raw-artifact")
    return cn


def _delivery_target(body: dict[str, Any]) -> dict[str, Any]:
    """Patch delivery target of the artifact just read; falls back to the raw JSON for members the SDK model lacks."""
    tgt = ((body.get("patch") or {}).get("delivery") or {}).get("target") or {}
    if "SDK_UNKNOWN_MEMBER" not in tgt:
        return tgt
    try:
        raw = json.loads(_RAW.get("artifact") or b"{}")
    except ValueError:
        return tgt   # unreadable raw body ⇒ no link (the MR still exists; the event page just cannot point at it)
    return ((((raw.get("body") or {}).get("patch") or {}).get("delivery") or {}).get("target")) or tgt


def _sa() -> Any:
    return _c("securityagent")


def _err(e: Exception) -> dict[str, Any]:
    code = e.response.get("Error", {}).get("Code") if isinstance(e, ClientError) else type(e).__name__
    return {"error": f"{code}: {str(e)[:240]}"}


# ---------------------------------------------------------------- targets

def load_targets(target_ids: list[tuple[str, str, str]]) -> list[respond.Target]:
    """(target_id, name, description) → Target with files read from s3://SA_CODE_BUCKET/code/<id>.zip (every target;
    the Continuum bucket now holds only the S3-channel targets, targets.CHANNEL). A missing zip yields a target with
    no files (it simply has no pins) and a logged warning."""
    out = []
    s3 = _c("s3")
    for tid, name, desc in target_ids:
        try:
            obj = s3.get_object(Bucket=os.environ["SA_CODE_BUCKET"], Key=f"code/{tid}.zip")
            z = zipfile.ZipFile(io.BytesIO(obj["Body"].read()))
            files = {f"{name}/{n}": z.read(n).decode("utf-8", "ignore") for n in z.namelist()
                     if not n.endswith("/") and z.getinfo(n).file_size < 2_000_000}
            out.append(respond.Target(tid, name, desc, files, obj["LastModified"].strftime("%Y-%m-%dT%H:%M:%SZ")))
        except (ClientError, BotoCoreError, zipfile.BadZipFile) as e:
            log.warning(json.dumps({"station": "respond", "degraded": "target_unavailable", "target": tid, "error": str(e)[:200]}))
            out.append(respond.Target(tid, name, desc, {}, None))
    return out


# ---------------------------------------------------------------- Continuum environment (no CFN type ⇒ reconcile)

def ensure_environment(target_ids: list[str], github_retry: bool = True) -> dict[str, Any]:
    """Find-or-create the S3 integration and the environment (one S3 source = code/, every target zip under it)."""
    cn = _cn()
    ints = [i for i in cn.list_integrations().get("items", []) if i.get("name") == ENV_NAME]
    if ints:
        integ = ints[0]["integrationId"]
    else:
        ext = os.environ["CN_EXTERNAL_ID"]
        integ = cn.create_integration(name=ENV_NAME, clientToken=f"{ENV_NAME}-integration",
                                      providerConfiguration={"s3": {"bucket": os.environ["CN_BUCKET"],
                                                                    "roleArn": os.environ["CN_INTEGRATION_ROLE_ARN"],
                                                                    "externalId": ext}})["integrationId"]
    envs = [e for e in cn.list_environments().get("items", []) if e.get("name") == ENV_NAME]
    # live constraint (2026-10-23): exactly ONE s3Source per environment ⇒ one prefix holding every target zip;
    # each zip under it is one repository (quota 10 per environment)
    if len(target_ids) > 10:
        raise ValueError(f"too_many_targets: {len(target_ids)} > 10 repositories per Continuum environment")
    sources = [{"integrationId": integ, "codePrefix": "code/", "contextPrefix": "context/"}]
    if envs:
        env = envs[0]["environmentId"]
        code = cn.get_environment(environmentId=env)["configuration"]["codeConfiguration"]
        cur = code["sourceConfiguration"]
        sched = (code.get("environmentConfiguration") or {}).get("scanFrequency")
        # reconcile the schedule too: environments created with P7D kept a weekly paid scan (cost, 2026-10-28)
        if sorted(s["codePrefix"] for s in cur.get("s3Sources", [])) != sorted(s["codePrefix"] for s in sources) \
                or sched != Limits.CONTINUUM_SCHEDULED_SCAN:
            cn.update_environment(environmentId=env, configuration={"codeConfiguration": {
                "sourceConfiguration": {"s3Sources": sources},
                "environmentConfiguration": {"scanFrequency": Limits.CONTINUUM_SCHEDULED_SCAN, "patchCreationPolicy": "ENABLED"}}})
    else:
        env = cn.create_environment(name=ENV_NAME, configuration={"codeConfiguration": {
            "sourceConfiguration": {"s3Sources": sources},
            "environmentConfiguration": {"scanFrequency": Limits.CONTINUUM_SCHEDULED_SCAN, "patchCreationPolicy": "ENABLED"}}})["environmentId"]
    out = {"integration_id": integ, "environment_id": env}
    if not github_retry:  # backing off after a failure (the caller keeps the clock in the ledger)
        return out
    for ch in respond.REPO_CHANNELS:
        try:  # a repository channel never takes the S3 path (or another channel) down with it
            out.update(_ensure_repo_environment(cn, ch))   # (live: GitHub CreateEnvironment InternalServerException)
        except (ClientError, BotoCoreError) as e:
            log.warning(json.dumps({"station": "respond", "degraded": f"{ch}_environment_unavailable", "error": str(e)[:300]}))
            out[f"{ch}_error"] = str(e)[:200]
    return out


# Repository channels (respond.REPO_CHANNELS): the integration `<env>-<channel>` is created once, out of band — GitHub by
# a browser App authorization, GitLab by scripts/sync-fleet.py --channel gitlab with an access token (write-only in Continuum,
# never in this Lambda). Here: find it by name and keep one PT0H environment on the configured repository.
REPO_SOURCE_ENV = {"github": "CN_GITHUB_REPO", "gitlab": "CN_GITLAB_PROJECT"}


def repo_web(ch: str) -> str:
    """Web root of a repository channel's host: CN_<CHANNEL>_URL (cdk.json `gitlab_url` for a self-managed GitLab),
    else the SaaS default in respond.REPO_CHANNELS. The GitLab delivery target carries no instanceUrl (live 10-28),
    so MR links are built from this too (R14)."""
    return (os.environ.get(f"CN_{ch.upper()}_URL") or respond.REPO_CHANNELS[ch]["web"]).rstrip("/")


def _ensure_repo_environment(cn: Any, ch: str) -> dict[str, Any]:
    """Absent repository config or integration ⇒ {} (channel not wired). Same schedule reconcile as the S3 env."""
    repo = os.environ.get(REPO_SOURCE_ENV[ch])
    name = f"{ENV_NAME}-{ch}"
    integ = [i for i in cn.list_integrations().get("items", []) if i.get("name") == name]
    if not repo or not integ:
        return {}
    src = [{"integrationId": integ[0]["integrationId"], "repository": repo, "defaultBranch": "main"}]
    cfg = {"codeConfiguration": {"sourceConfiguration": {"repositorySources": src},
                                 "environmentConfiguration": {"scanFrequency": Limits.CONTINUUM_SCHEDULED_SCAN,
                                                              "patchCreationPolicy": "ENABLED"}}}
    envs = [e for e in cn.list_environments().get("items", []) if e.get("name") == name]
    env = envs[0]["environmentId"] if envs else cn.create_environment(name=name, configuration=cfg)["environmentId"]
    if envs and (cn.get_environment(environmentId=env)["configuration"]["codeConfiguration"].get("environmentConfiguration")
                 or {}).get("scanFrequency") != Limits.CONTINUUM_SCHEDULED_SCAN:
        cn.update_environment(environmentId=env, configuration=cfg)    # environments created with P7D kept a weekly paid scan
    return {f"{ch}_integration_id": integ[0]["integrationId"], f"{ch}_environment_id": env, f"{ch}_repo": repo}


# ---------------------------------------------------------------- operations

def execute(op: respond.Op, ev: dict[str, Any], items: list[dict[str, Any]], st: dict[str, Any], env: dict[str, Any]) -> dict[str, Any]:
    try:
        return _EXEC[op.kind](op, ev, items, st, env)
    except (ClientError, BotoCoreError, OSError, KeyError, ValueError) as e:
        log.warning(json.dumps({"station": "respond", "op": op.kind, "event": ev["event_id"], "error": str(e)[:300]}))
        return _err(e)


def _sync_requirement(op: respond.Op, *_: Any) -> dict[str, Any]:
    sa, pack, req = _sa(), os.environ["SA_PACK_ID"], op.payload["requirement"]
    names, token = set(), None
    while True:
        page = sa.list_security_requirements(packId=pack, **({"nextToken": token} if token else {}))
        names |= {r["name"] for r in page.get("securityRequirementSummaries", [])}
        token = page.get("nextToken")
        if not token:
            break
    fn = sa.batch_update_security_requirements if req["name"] in names else sa.batch_create_security_requirements
    r = fn(packId=pack, securityRequirements=[req])
    if r.get("errors"):
        return {"error": f"{r['errors'][0].get('code')}: {r['errors'][0].get('message', '')[:200]}"}
    return {"ok": True}


def requirement_names() -> list[str]:
    sa, pack, names, token = _sa(), os.environ["SA_PACK_ID"], [], None
    while True:
        page = sa.list_security_requirements(packId=pack, **({"nextToken": token} if token else {}))
        names += [r["name"] for r in page.get("securityRequirementSummaries", [])]
        token = page.get("nextToken")
        if not token:
            return names


def delete_requirements(names: list[str]) -> list[str]:
    """Returns the names Security Agent refused (reported, retried tomorrow)."""
    sa, pack, failed = _sa(), os.environ["SA_PACK_ID"], []
    for i in range(0, len(names), 10):
        r = sa.batch_delete_security_requirements(packId=pack, securityRequirementNames=names[i:i + 10])
        failed += [e.get("name") or e.get("securityRequirementName") or "?" for e in r.get("errors") or []]
    return failed


def _write_context(op: respond.Op, *_: Any) -> dict[str, Any]:
    _c("s3", os.environ.get("CN_REGION", "us-east-1")).put_object(
        Bucket=os.environ["CN_BUCKET"], Key=op.payload["key"], Body=op.payload["body"].encode(), ContentType="text/markdown")
    return {"ok": True}


def _submit_finding(op: respond.Op, ev: dict[str, Any], items: list[dict[str, Any]], _st: Any, env: dict[str, Any]) -> dict[str, Any]:
    doc = respond.ocsf(ev, items, op.payload["location"], os.environ.get("CN_REGION", "us-east-1"), int(time.time() * 1000))
    try:
        r = _cn().create_code_finding(environmentId=env["environment_id"], ocsfDocument=doc,
                                      clientToken=respond.client_token(op.payload["uid"], doc))
    except ClientError as e:
        fl = e.response.get("fieldList")
        return {"error": f"{e.response['Error']['Code']}: {fl or str(e)[:200]}"}
    return {"finding_id": r["findingId"], "status": r["status"], "title": r["title"]}


def _request_scan(op: respond.Op, _ev: Any, _items: Any, _st: Any, env: dict[str, Any]) -> dict[str, Any]:
    try:
        r = _cn().create_code_scan(environmentId=env["environment_id"], clientToken=op.payload["token"][:64])
    except ClientError as e:
        if e.response["Error"]["Code"] != "ServiceQuotaExceededException":
            raise
        # live constraint: one scan in flight per environment ⇒ the running scan already covers this request
        running = [s for s in _cn().list_code_scans(environmentId=env["environment_id"]).get("scans", [])
                   if s["status"] not in respond.TERMINAL_SCAN]
        if not running:
            raise
        return {"scan_run_id": running[0]["scanRunId"], "status": running[0]["status"]}
    scan = r.get("scan") or r
    return {"scan_run_id": scan["scanRunId"], "status": scan.get("status", "SUBMITTED")}


def _start_review(op: respond.Op, ev: dict[str, Any], *_: Any) -> dict[str, Any]:
    sa, space, tid = _sa(), os.environ["SA_AGENT_SPACE_ID"], op.target_id
    title = re.sub(r"[^A-Za-z0-9_-]", "-", f"radar-{ev['event_id']}-{tid}")[:100]
    cr = sa.create_code_review(title=title, agentSpaceId=space,
                               assets={"sourceCode": [{"s3Location": f"s3://{os.environ['SA_CODE_BUCKET']}/code/{tid}.zip"}]},
                               serviceRole=os.environ["SA_SERVICE_ROLE_ARN"], codeRemediationStrategy="AUTOMATIC",
                               maxTaskHours=20.0)  # API minimum (an upper bound, not the billed amount)
    cr_id = cr.get("codeReviewId") or cr["id"]
    job = sa.start_code_review_job(agentSpaceId=space, codeReviewId=cr_id)
    return {"code_review_id": cr_id, "job_id": job.get("codeReviewJobId") or job["jobId"]}


def _poll_review(op: respond.Op, ev: dict[str, Any], *_: Any) -> dict[str, Any]:
    sa, space, job_id = _sa(), os.environ["SA_AGENT_SPACE_ID"], op.payload["job_id"]
    jobs = sa.batch_get_code_review_jobs(agentSpaceId=space, codeReviewJobIds=[job_id]).get("codeReviewJobs", [])
    status = (jobs[0].get("status") if jobs else None) or "UNKNOWN"
    if status not in respond.TERMINAL_JOB:
        return {"status": status, "findings": None}
    ids, token = [], None
    while True:
        page = sa.list_findings(agentSpaceId=space, codeReviewJobId=job_id, **({"nextToken": token} if token else {}))
        ids += [f["findingId"] for f in page.get("findingsSummaries", [])]
        token = page.get("nextToken")
        if not token:
            break
    findings, patches = [], []
    for i in range(0, len(ids), 20):
        for f in sa.batch_get_findings(agentSpaceId=space, findingIds=ids[i:i + 20]).get("findings", []):
            loc = re.search(r"([\w./-]+\.\w+|Dockerfile):(\d+)", f.get("attackScript") or "")
            findings.append({"finding_id": f["findingId"], "title": f.get("name", ""), "severity": f.get("riskLevel", "UNKNOWN"),
                             "status": f.get("status", ""), "file": loc.group(1) if loc else None,
                             "line": int(loc.group(2)) if loc else None,
                             "requirement_hit": respond.requirement_hit(f.get("name") or "")})
            for k, task in enumerate((f.get("codeRemediationTask") or {}).get("taskDetails") or []):
                if task.get("codeDiffLink"):  # presigned, 180 s ⇒ capture now or lose it
                    p = _capture_diff(task["codeDiffLink"], f"continuum/patches/{ev['event_id']}-{f['findingId']}-{k}.diff")
                    if p and p["path"] not in {x["path"] for x in patches}:
                        patches.append({**p, "source": respond.SA, "summary": f.get("name", "")[:200]})
    return {"status": status, "findings": findings, "patches": patches}


def _capture_diff(url: str, rel: str) -> dict[str, Any] | None:
    if not url.startswith("https://") or ".amazonaws.com/" not in url:
        return None  # only AWS-hosted presigned links
    with urllib.request.urlopen(url, timeout=20) as r:
        body = r.read(PATCH_MAX_BYTES + 1)[:PATCH_MAX_BYTES]
    files = sorted(set(re.findall(r"^\+\+\+ b/(.+)$", body.decode("utf-8", "ignore"), re.MULTILINE)))
    _c("s3").put_object(Bucket=os.environ["SITE_BUCKET"], Key=f"data/{rel}", Body=body,
                        ContentType="text/plain; charset=utf-8", CacheControl="max-age=300")
    return {"path": rel, "files_changed": files}


def _read_env(eid: str, finding_ids: set[str], scan_run_id: str | None, event_id: str, tag: str) -> dict[str, Any]:
    """Findings (ours), their issues, validation evidence, patches and PR delivery for one environment."""
    cn = _cn()
    out: dict[str, Any] = {}
    if scan_run_id:
        out["scan"] = cn.get_code_scan(environmentId=eid, scanRunId=scan_run_id)["scan"]
    rows = [f for f in _all(cn.list_code_findings, environmentId=eid) if f["findingId"] in finding_ids]
    findings, issue_ids = [], []
    for f in rows:
        verdict = None
        if f["status"] in ("CONFIRMED", "DISCARDED"):
            g = cn.get_code_finding(environmentId=eid, findingId=f["findingId"])
            # customer findings carry no validation block (live); the terminal status is the verdict, and the
            # issue's VALIDATION_EVIDENCE adds exploitability below
            verdict = (g.get("validation") or {}).get("verdict") or f.get("discardReason") or f["status"]
        findings.append({"finding_id": f["findingId"], "status": f["status"], "verdict": verdict})
        if f.get("createdIssueId") or f.get("duplicateOfIssueId"):
            issue_ids.append(f.get("createdIssueId") or f["duplicateOfIssueId"])
    issues = []
    for iid in dict.fromkeys(issue_ids):
        i = cn.get_code_issue(environmentId=eid, issueId=iid)
        pd = i.get("patchDelivery") or {}
        row = {"issue_id": iid, "name": i.get("name", ""), "severity": i.get("severity", ""), "phase": i.get("phase", ""),
               "status": i.get("status", ""), "synopsis": (i.get("synopsis") or "")[:600] or None,
               "patch_status": pd.get("status"), "exploitable": None, "patch_path": None,
               "effect": None, "evidence_summary": None, "pr_url": None}
        for a in _all(cn.list_code_issue_artifacts, environmentId=eid, issueId=iid):
            if a["artifactType"] not in ("PATCH", "VALIDATION_EVIDENCE"):
                continue
            body = cn.get_code_issue_artifact(environmentId=eid, issueId=iid, artifactId=a["artifactId"]).get("body") or {}
            if a["artifactType"] == "VALIDATION_EVIDENCE":
                ve = body.get("validationEvidence") or {}
                sa_ = ve.get("sourceAnalysis") or {}
                proof = ve.get("executedProof") or {}
                row["exploitable"] = ve.get("exploitable")
                row["effect"] = proof.get("observedEffect") or sa_.get("inferredEffect")
                row["evidence_summary"] = (sa_.get("summary") or "")[:4000] or None
                continue
            tgt = _delivery_target(body)
            gh = tgt.get("github") or {}
            if gh.get("pullRequestNumber"):  # GitHub delivery ⇒ the patch is a pull request in the customer repo
                row["pr_url"] = f"https://github.com/{gh['owner']}/{gh['repository']}/pull/{gh['pullRequestNumber']}"
            row["pr_url"] = row["pr_url"] or _gitlab_mr_url(tgt.get("gitlab") or {})
            text = _patch_text(body)
            if text:
                rel = f"continuum/patches/{event_id}-{tag}{iid}.patch"
                _c("s3").put_object(Bucket=os.environ["SITE_BUCKET"], Key=f"data/{rel}", Body=text.encode()[:PATCH_MAX_BYTES],
                                    ContentType="text/plain; charset=utf-8", CacheControl="max-age=300")
                row["patch_path"] = rel
                row["patch_files"] = sorted(set(re.findall(r"^\+\+\+ b/(.+)$", text, re.MULTILINE)))
        issues.append(row)
    out.update(findings=findings, issues=issues,
               issues_complete=all(i["status"] in ("COMPLETED", "FAILED") for i in issues))
    return out


def _poll_continuum(op: respond.Op, ev: dict[str, Any], _items: Any, st: dict[str, Any], env: dict[str, Any]) -> dict[str, Any]:
    mine = {f["finding_id"] for t in (st.get("targets") or {}).values() for f in (t.get("cn_findings") or {}).values()}
    return _read_env(env["environment_id"], mine, (st.get("scan") or {}).get("scan_run_id"), ev["event_id"], "")


def _gitlab_mr_url(gl: dict[str, Any]) -> str | None:
    """GitLab delivery target → merge request URL. Field names are not documented (gitlab shape seen only on a live
    artifact); accept an explicit URL, else build it from instance + project path + MR iid."""
    for k in ("mergeRequestUrl", "webUrl", "url"):
        if isinstance(gl.get(k), str) and "/merge_requests/" in gl[k]:
            return gl[k]
    iid = gl.get("mergeRequestIid") or gl.get("mergeRequestNumber") or gl.get("mergeRequestId")
    path = gl.get("projectPath") or gl.get("project") or gl.get("repository")
    if iid and path:
        base = (gl.get("instanceUrl") or repo_web("gitlab")).rstrip("/")
        return f"{base}/{path}/-/merge_requests/{iid}"
    return None


def _repo_ops(ch: str) -> dict[str, Any]:
    """submit / scan / poll for one repository channel = the S3 operations pointed at that channel's environment and
    reading that channel's state (respond keeps it under st[<channel>])."""
    op_tag = respond.REPO_CHANNELS[ch]["op"]

    def env_of(env: dict[str, Any]) -> dict[str, Any]:
        return {"environment_id": env[f"{ch}_environment_id"]}

    def poll(op: respond.Op, ev: dict[str, Any], _items: Any, st: dict[str, Any], env: dict[str, Any]) -> dict[str, Any]:
        cs = st.get(ch) or {}
        mine = {f["finding_id"] for f in (cs.get("findings") or {}).values()}
        return _read_env(env[f"{ch}_environment_id"], mine, (cs.get("scan") or {}).get("scan_run_id"), ev["event_id"], f"{op_tag}-")

    return {f"submit_finding_{op_tag}": lambda op, ev, items, st, env: _submit_finding(op, ev, items, st, env_of(env)),
            f"request_scan_{op_tag}": lambda op, ev, items, st, env: _request_scan(op, ev, items, st, env_of(env)),
            f"poll_continuum_{op_tag}": poll}


def _patch_text(body: dict[str, Any]) -> str | None:
    """The PATCH artifact body shape is not documented beyond 'content'; take the first string that looks
    like a unified diff, anywhere in the body (searched, not guessed)."""
    stack: list[Any] = [body]
    while stack:
        x = stack.pop()
        if isinstance(x, str) and ("\n+++ " in x or x.startswith(("--- ", "diff --git"))):
            return x
        if isinstance(x, dict):
            stack += list(x.values())
        elif isinstance(x, list):
            stack += x
    return None


def _all(fn: Any, **kw: Any) -> list[dict[str, Any]]:
    out, token = [], None
    while True:
        page = fn(**kw, **({"nextToken": token} if token else {}))
        out += page.get("items", [])
        token = page.get("nextToken")
        if not token:
            return out


_EXEC = {"sync_requirement": _sync_requirement, "write_context": _write_context, "submit_finding": _submit_finding,
         "request_scan": _request_scan, "start_review": _start_review, "poll_review": _poll_review,
         "poll_continuum": _poll_continuum, **{k: f for ch in respond.REPO_CHANNELS for k, f in _repo_ops(ch).items()}}


# ---------------------------------------------------------------- overview (continuum.json)

def fetch_costs(start: str, end: str) -> list[dict[str, Any]]:
    """Daily spend of the AWS services the radar drives (Cost Explorer is global, served from us-east-1)."""
    ce = _c("ce", "us-east-1")
    kw: dict[str, Any] = {"TimePeriod": {"Start": start, "End": end}, "Granularity": "DAILY",
                          "Metrics": ["UnblendedCost", "UsageQuantity"],
                          "Filter": {"Dimensions": {"Key": "SERVICE", "Values": ["AWS Continuum", "AWS Security Agent"]}},
                          "GroupBy": [{"Type": "DIMENSION", "Key": "SERVICE"}, {"Type": "DIMENSION", "Key": "USAGE_TYPE"}]}
    out: list[dict[str, Any]] = []
    while True:
        r = ce.get_cost_and_usage(**kw)
        out += r["ResultsByTime"]
        if not r.get("NextPageToken"):
            return out
        kw["NextPageToken"] = r["NextPageToken"]


def target_location(target_id: str, channel: str, env: dict[str, Any] | None) -> tuple[str, str | None]:
    """(where the code is, repository URL) for the target's ONE channel. s3 / none: the bucket key (none = only the
    Security Agent bucket); repository channels: <repo>/<target>/ in the mirror the environment scans."""
    meta = respond.REPO_CHANNELS.get(channel)
    repo = ((env or {}).get(f"{channel}_repo") or os.environ.get(REPO_SOURCE_ENV.get(channel, ""), "")) if meta else ""
    if not meta or not repo:
        return f"code/{target_id}.zip", None
    return f"{repo}/{target_id}/", f"{repo_web(channel)}/{repo}/{meta['tree']}/main/{target_id}"


def resources(env: dict[str, Any]) -> list[dict[str, Any]]:
    cnr = os.environ.get("CN_REGION", "us-east-1")
    rows = [{"kind": "agent_space", "id": os.environ.get("SA_AGENT_SPACE_ID", ""), "name": "security-radar",
             "region": os.environ.get("AWS_REGION", ""), "status": "ACTIVE", "console_url": None},
            {"kind": "requirement_pack", "id": os.environ.get("SA_PACK_ID", ""), "name": "security-radar",
             "region": os.environ.get("AWS_REGION", ""), "status": "ENABLED", "console_url": None}]
    try:
        e = _cn().get_environment(environmentId=env["environment_id"])
        rows += [{"kind": "integration", "id": env["integration_id"], "name": f"{ENV_NAME} (S3)", "region": cnr,
                  "status": "ACTIVE", "console_url": None},
                 {"kind": "environment", "id": env["environment_id"], "name": e.get("name", ENV_NAME), "region": cnr,
                  "status": e.get("status", ""), "console_url": None}]
        for ch, meta in respond.REPO_CHANNELS.items():   # every wired repository channel is a resource too
            if not env.get(f"{ch}_environment_id"):
                continue
            ge = _cn().get_environment(environmentId=env[f"{ch}_environment_id"])
            repo = env.get(f"{ch}_repo", "")
            rows += [{"kind": "integration", "id": env[f"{ch}_integration_id"], "name": f"{ENV_NAME}-{ch} ({meta['label']})",
                      "region": cnr, "status": "ACTIVE", "console_url": None},
                     {"kind": "environment", "id": env[f"{ch}_environment_id"], "name": ge.get("name", f"{ENV_NAME}-{ch}"),
                      "region": cnr, "status": ge.get("status", ""),
                      "console_url": f"{repo_web(ch)}/{repo}" if repo else None}]
    except (ClientError, BotoCoreError, KeyError) as ex:
        rows.append({"kind": "environment", "id": env.get("environment_id", ""), "name": ENV_NAME, "region": cnr,
                     "status": f"unavailable: {str(ex)[:80]}", "console_url": None})
    return rows
