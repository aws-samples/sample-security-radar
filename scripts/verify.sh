#!/usr/bin/env bash
# Acceptance checks for a deployment (STAGE selects which). Every check prints PASS/FAIL; exit 1 if any fail.
#   ./scripts/verify.sh          # check the current state
#   ./scripts/verify.sh --run    # start one Step Functions cycle first and wait for it
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib.sh
fails=0
check() { if eval "$2" >/dev/null 2>&1; then echo "PASS  $1"; else echo "FAIL  $1"; fails=$((fails + 1)); fi; }

sm=$(out StateMachineArn); site=$(out SiteUrl); bucket=$(out SiteBucketName)
if [ "${1:-}" = "--run" ]; then
  arn=$(aws stepfunctions start-execution --region ap-northeast-1 --state-machine-arn "$sm" --input '{"full": true}' \
        --query executionArn --output text)
  echo "cycle started: ${arn##*:}"
  for _ in $(seq 1 90); do
    st=$(aws stepfunctions describe-execution --region ap-northeast-1 --execution-arn "$arn" --query status --output text)
    [ "$st" != RUNNING ] && break
    sleep 10
  done
  check "cycle succeeded ($st)" "[ '$st' = SUCCEEDED ]"
fi

creds=$(aws secretsmanager get-secret-value --region ap-northeast-1 --secret-id "$(out UiSecretArn)" --query SecretString --output text)
hf=$(mktemp); chmod 600 "$hf"; trap 'rm -f "$hf"' EXIT   # credential header via file, never argv
printf '%s' "$creds" | uv run -q python -I -c 'import json,sys,base64;d=json.load(sys.stdin);print("Authorization: Basic "+base64.b64encode((d["username"]+":"+d["password"]).encode()).decode())' > "$hf"
unset creds
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
check "anonymous request denied by the gate (401)" "[ \$(code '$site/') = 401 ]"
check "wrong credential denied (401)" "[ \$(code -H 'Authorization: Basic d3Jvbmc6d3Jvbmc=' '$site/') = 401 ]"
check "authorised UI loads (200)" "[ \$(code -H @'$hf' '$site/') = 200 ]"
for doc in events.json sources.json continuum.json; do
  check "data/$doc published" "aws s3api head-object --region ap-northeast-1 --bucket '$bucket' --key data/$doc"
done
check "site bucket blocks public access" \
  "[ \"\$(aws s3api get-public-access-block --region ap-northeast-1 --bucket '$bucket' --query 'PublicAccessBlockConfiguration.RestrictPublicBuckets' --output text)\" = True ]"
check "Security Agent agent space exists" \
  "[ \"\$(aws securityagent batch-get-agent-spaces --region ap-northeast-1 --agent-space-ids '$(out AgentSpaceId)' --query 'agentSpaces[0].agentSpaceId' --output text)\" = '$(out AgentSpaceId)' ]"
cn_bucket=$(out ContinuumBucketName continuum)
# head-object per target: a pipe into an early-exiting grep SIGPIPEs aws under pipefail (false FAIL, observed)
# channel-aware (src/radar/targets.py CHANNEL): S3-channel zips must be there; every other target must NOT be — each zip
# in the S3 environment is scanned and paid for, and a target lives in exactly one environment (cost, 2026-10-28)
read -r -a s3_ids <<< "$(uv run -q python -I -c "import sys;sys.path.insert(0,'src');from radar import targets;print(' '.join(targets.on('s3')))")"
read -r -a other_ids <<< "$(uv run -q python -I -c "import sys;sys.path.insert(0,'src');from radar import targets;print(' '.join(t for t in targets.NAMES if targets.CHANNEL[t] != 's3'))")"
for id in "${s3_ids[@]}"; do
  check "Continuum S3 target $id uploaded" "aws s3api head-object --region us-east-1 --bucket '$cn_bucket' --key code/$id.zip"
done
for id in "${other_ids[@]}"; do
  check "non-S3 target $id not in the S3 environment" "! aws s3api head-object --region us-east-1 --bucket '$cn_bucket' --key code/$id.zip >/dev/null 2>&1"
done
aws s3 cp --quiet --region ap-northeast-1 "s3://$bucket/data/continuum.json" build/verify-continuum.json || true
check "Continuum environment reconciled (resources in continuum.json)" \
  "uv run -q python -I -c \"import json;d=json.load(open('build/verify-continuum.json'));assert any(r['kind']=='environment' and r['status']=='ACTIVE' for r in d['resources'])\""
check "respond station considered events" \
  "uv run -q python -I -c \"import json;d=json.load(open('build/verify-continuum.json'));assert d['coverage'] and any(r['status']=='live' for r in d['coverage'])\""
uv run -q python -I -c "
import json
d=json.load(open('build/verify-continuum.json'))
rs=[r for r in d['coverage'] if r['status'] in ('live','wired')]
print(f\"coverage: {sum(r['status']=='live' for r in rs)}/{len(rs)} applicable capabilities live\")
for r in d['coverage']: print(f\"  {r['status']:<15} {r['capability']}\")" || true
echo
[ "$fails" = 0 ] && echo "ALL CHECKS PASSED" || { echo "$fails CHECK(S) FAILED"; exit 1; }
