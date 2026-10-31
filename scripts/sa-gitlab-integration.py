"""C2d · AWS Security Agent ⇄ gitlab.com: one GitLab integration (personal access token) and the demo-fleet project as an
integrated repository with code remediation, so a code review of a gitlab-channel target runs on the repository itself
and Security Agent's automatic fix opens a merge request there.

  AWS_PROFILE=<non-production-profile> uv run python scripts/sa-gitlab-integration.py           # dry run: what exists
  AWS_PROFILE=<non-production-profile> uv run python scripts/sa-gitlab-integration.py --apply   # create / associate

The token comes from ~/.env `GITLAB_COM_SA_TOKEN` (its own token: the Continuum integration rotates the other one) and
goes only into the CreateIntegration request — never printed. Idempotent: an integration with the same display name is
reused; an already-associated repository is left as it is. Prints the two ids to put in infra/cdk.json
(`sa_gitlab_integration_id`, `sa_gitlab_repo_id`).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[1]
NAME = "security-radar-gitlab"
REGION = "ap-northeast-1"            # where the radar's agent space lives (infra: the SecurityRadar stack)


def _env_token() -> str:
    for line in (Path.home() / ".env").read_text().splitlines():
        if line.startswith("export GITLAB_COM_SA_TOKEN="):
            return line.split("=", 1)[1].strip().strip('"')
    raise SystemExit(json.dumps({"error": "missing_token", "message": "GITLAB_COM_SA_TOKEN not in ~/.env",
                                 "actual": None, "limit": "a gitlab.com PAT with api / read_repository / write_repository"}))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    out = json.loads((ROOT / "build" / "outputs.json").read_text())["SecurityRadar"]
    space = out["AgentSpaceId"]
    project = json.loads((ROOT / "infra" / "cdk.json").read_text())["context"]["gitlab_project"]
    namespace, name = project.rsplit("/", 1)
    # the agent space's region, pinned: an ambient AWS_REGION (e.g. a Bedrock region in the shell) created the
    # integration in the wrong region on 2026-11-01
    sa = boto3.Session(region_name=REGION).client("securityagent")

    found = [i for i in sa.list_integrations().get("integrationSummaries", []) if i.get("displayName") == NAME]
    if found:
        iid = found[0].get("integrationId") or found[0]["id"]
        print(f"integration exists: {iid}")
    elif not args.apply:
        print(f"dry run: would create GitLab integration {NAME!r} (PERSONAL token from ~/.env)"); iid = None
    else:
        r = sa.create_integration(provider="GITLAB", integrationDisplayName=NAME,
                                  input={"gitlab": {"accessToken": _env_token(), "tokenType": "PERSONAL"}})
        iid = r.get("integrationId") or r["id"]
        print(f"integration created: {iid}")
    if not iid:
        return 0

    def repo_id() -> str | None:
        page = sa.list_integrated_resources(agentSpaceId=space, integrationId=iid, resourceType="CODE_REPOSITORY")
        for it in next((v for k, v in page.items() if isinstance(v, list)), []):
            res = (it.get("resource") or {}).get("gitlabRepository") or {}
            if res.get("name") == name and res.get("namespace") == namespace:
                return res.get("providerResourceId")
        return None

    rid = repo_id()
    if rid:
        print(f"repository associated: {project} → {rid}")
    elif not args.apply:
        print(f"dry run: would associate {project} with remediateCode"); return 0
    else:
        sa.update_integrated_resources(agentSpaceId=space, integrationId=iid, items=[{
            "resource": {"gitlabRepository": {"name": name, "namespace": namespace}},
            "capabilities": {"gitlab": {"remediateCode": True, "leaveComments": False}}}])
        rid = repo_id()
        print(f"repository associated: {project} → {rid}")
    print(json.dumps({"sa_gitlab_integration_id": iid, "sa_gitlab_repo_id": rid}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
