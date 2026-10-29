#!/usr/bin/env bash
# Remove an independent copy created with `STAGE=<name> ./scripts/deploy-all.sh`. Refuses the live deployment.
# Also deletes that stage's Continuum environment + integration (they are reconciled by the Lambda, not CFN).
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib.sh
[ -z "$STAGE" ] && { echo "refusing: STAGE is empty (that is the live deployment)" >&2; exit 1; }
name="security-radar-$STAGE"
pack=$(out RequirementPackId 2>/dev/null || true); space=$(out AgentSpaceId 2>/dev/null || true)
uv run -q python -I -   # boto3 from the locked project environment "$name" "$pack" "$space" <<'PY'
import sys, boto3
name, pack, space = sys.argv[1], sys.argv[2], sys.argv[3]
if space:  # code reviews created by the Lambda live inside the CFN agent space
    sa = boto3.client("securityagent", region_name="ap-northeast-1")
    ids = [c["codeReviewId"] for c in sa.list_code_reviews(agentSpaceId=space).get("codeReviewSummaries", [])]
    if ids:
        sa.batch_delete_code_reviews(agentSpaceId=space, codeReviewIds=ids)
        print(f"deleted {len(ids)} code reviews")
if pack:  # the pack is a CFN resource but its rules were added by the Lambda; CFN cannot delete a non-empty pack
    sa = boto3.client("securityagent", region_name="ap-northeast-1")
    names = [r["name"] for r in sa.list_security_requirements(packId=pack).get("securityRequirementSummaries", [])]
    if names:
        sa.batch_delete_security_requirements(packId=pack, securityRequirementNames=names)
        print(f"emptied requirement pack ({len(names)} rules)")
cn = boto3.client("continuum", region_name="us-east-1")
for e in cn.list_environments().get("items", []):
    if e.get("name") == name:
        cn.delete_environment(environmentId=e["environmentId"]); print("deleted environment", e["environmentId"])
for i in cn.list_integrations().get("items", []):
    if i.get("name") == name:
        try:
            cn.delete_integration(integrationId=i["integrationId"]); print("deleted integration", i["integrationId"])
        except cn.exceptions.ClientError as ex:  # environment deletion may still be propagating
            print("integration not deleted yet:", ex)
PY
(cd infra && JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION=1 npx -y aws-cdk@2.1146.1 destroy \
  "SecurityRadar$SUFFIX" "SecurityRadarMitigateDemo$SUFFIX" "SecurityRadarContinuum$SUFFIX" -c "stage=$STAGE" --force)
