"""Rebuild an event's respond-station state from what AWS still holds (repair tool).

Needed once on 2026-10-25: a cooled-down event (P0 → P1) had its state overwritten by a since-fixed bug. AWS keeps the
work, so we reconstruct the job references and let the next Respond cycle re-read results, diffs, issues and patches:
  · Security Agent code reviews titled radar-<event_id>-<target>  → targets[<target>].review (re-read on next poll)
  · Continuum findings whose title contains the event title        → targets[<target>].cn_findings
  STAGE= uv run python scripts/rehydrate_response.py <event_id> [--write]
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from radar import respond
from radar.targets import NAMES


def main() -> None:
    event_id, write = sys.argv[1], "--write" in sys.argv
    stage = os.environ.get("STAGE", "")
    outputs = json.loads((ROOT / "build" / f"outputs{'-' + stage if stage else ''}.json").read_text())
    out = outputs[f"SecurityRadar{stage.capitalize()}"]
    table = boto3.resource("dynamodb", region_name="ap-northeast-1").Table(out["TableName"])
    ev = json.loads(table.get_item(Key={"pk": f"EVENT#{event_id}", "sk": "META"})["Item"]["d"])
    items = [json.loads(i["d"]) for i in (table.get_item(Key={"pk": f"ITEM#{x}", "sk": "META"}).get("Item")
                                           for x in ev["item_ids"]) if i]
    refs = [{"title": i["title"], "excerpt": i.get("text", "")[:2000], "url": i.get("url", ""), "source_name": i["source_id"]}
            for i in items]
    view = {**{k: ev[k] for k in ("event_id", "domain", "title", "level", "exploitation", "cves", "entities",
                                  "independent_sources", "first_seen")}, "severity": "P0"}  # as it was when it acted
    hist = respond.eligibility(view, refs)
    st: dict = {"eligibility": respond.eligibility({**view, "severity": ev["severity"]}, refs),
                "last_eligibility": hist, "targets": {}, "actions": {}}
    sa = boto3.client("securityagent", region_name="ap-northeast-1")
    for c in sa.list_code_reviews(agentSpaceId=out["AgentSpaceId"]).get("codeReviewSummaries", []):
        prefix = f"radar-{event_id}-"
        if not c["title"].startswith(prefix):
            continue
        tid = c["title"][len(prefix):]
        jobs = sa.list_code_review_jobs_for_code_review(agentSpaceId=out["AgentSpaceId"], codeReviewId=c["codeReviewId"])
        job = (jobs.get("codeReviewJobSummaries") or jobs.get("codeReviewJobs") or [{}])[0]
        jid = job.get("codeReviewJobId")
        if jid:
            st["targets"].setdefault(tid, {})["review"] = {"code_review_id": c["codeReviewId"], "job_id": jid,
                                                           "status": "RUNNING", "trigger": respond.trigger_key(view)}
    cn = boto3.client("continuum", region_name=os.environ.get("CN_REGION", "us-east-1"))
    env = next(e["environmentId"] for e in cn.list_environments()["items"] if e["name"] == ("security-radar" if not stage else f"security-radar-{stage}"))
    token = None
    while True:
        page = cn.list_code_findings(environmentId=env, **({"nextToken": token} if token else {}))
        for f in page["items"]:
            if ev["title"][:60] in (f.get("title") or "") and f.get("type") == "CUSTOMER_CODE_VULN":
                g = cn.get_code_finding(environmentId=env, findingId=f["findingId"])
                path = g.get("filePath") or ""
                tid = path.split("/", 1)[0] if "/" in path else None
                if tid in NAMES:
                    # keyed by findingId, not the radar uid: respond.decide re-keys by (file, line) on its next run
                    # (before that fix, these keys made the findings look 'gone' — live 2026-10-26, PHP2Shell)
                    st["targets"].setdefault(tid, {}).setdefault("cn_findings", {})[f["findingId"]] = {
                        "finding_id": f["findingId"], "status": f["status"], "title": f.get("title", ""),
                        "file": path, "line": g.get("lineNumber") or 1}
        token = page.get("nextToken")
        if not token:
            break
    st["targets"].pop("security-radar", None)  # its 10-23 work came from an archive that wrongly nested the demos
    demo = ROOT / "integrations" / "continuum" / "targets"
    for tid in NAMES:
        ts = st["targets"].setdefault(tid, {})
        if (demo / tid).is_dir():  # same deterministic locator the station uses
            files = {f"{tid}/{p.relative_to(demo / tid)}": p.read_text(errors="ignore")
                     for p in (demo / tid).rglob("*") if p.is_file()}
            tgt = respond.Target(tid, tid, "", files)
            ts["relevant"] = respond.relevant(tgt, hist)
            ts["locations"] = respond.locations(tgt, hist)
    print(json.dumps({t: {k: (v if k != "cn_findings" else len(v)) for k, v in s.items()} for t, s in st["targets"].items()},
                     indent=1, default=str))
    if write:
        table.put_item(Item={"pk": f"EVENT#{event_id}", "sk": "RESPONSE", "d": json.dumps(st)})
        print("written; the next Respond cycle re-reads reviews, findings, issues and patches")


if __name__ == "__main__":
    main()
