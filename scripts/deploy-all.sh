#!/usr/bin/env bash
# One command from an empty account to a running, verified Security Radar + AWS Continuum/Security Agent loop.
#
#   ./scripts/deploy-all.sh                 # the live deployment
#   STAGE=repro ./scripts/deploy-all.sh     # an independent full copy (reproducibility check)
#   STAGE=repro ./scripts/destroy-stage.sh  # remove that copy again
#
# Order is the builder-security deploy order: infrastructure with an EMPTY site → auth gate armed →
# anonymous request must be denied by the gate (401 + WWW-Authenticate) → only then upload the UI.
# Prerequisites: AWS profile with admin on a non-prod account, CDK bootstrapped in ap-northeast-1 and us-east-1,
# uv, node ≥ 22, zip. Optional: ~/.env with X_API_KEY / FIRECRAWL_API_KEY* (collectors degrade visibly without).
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib.sh
step() { printf '\n\033[1;36m▸ %s\033[0m\n' "$*"; }

step "build Lambda asset and target code bases"
./scripts/build-lambda.sh
./scripts/build-targets.sh

step "cdk deploy (us-east-1 Continuum side, then ap-northeast-1 radar + Security Agent)"
ctx=(-c "schedule=${SCHEDULE:-on}")
[ -n "$STAGE" ] && ctx+=(-c "stage=$STAGE")
[ -n "${REVIEW_BUDGET:-}" ] && ctx+=(-c "review_budget=$REVIEW_BUDGET")   # paid Security Agent reviews per day
(cd infra && JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION=1 npx -y aws-cdk@latest deploy \
  "SecurityRadarContinuum$SUFFIX" "SecurityRadar$SUFFIX" "${ctx[@]}" \
  --require-approval never --outputs-file "../$OUTPUTS" > "../build/deploy${STAGE:+-$STAGE}.log" 2>&1) \
  || { tail -30 "build/deploy${STAGE:+-$STAGE}.log"; exit 1; }

step "arm the UI gate (hash of the generated credential → CloudFront KeyValueStore)"
./scripts/set-ui-auth.sh

step "verify anonymous access is denied by the gate BEFORE any content is uploaded"
site=$(out SiteUrl)
for i in $(seq 1 30); do
  hdr=$(curl -s -o /dev/null -D - "$site/" || true)
  if printf '%s' "$hdr" | grep -qi '^www-authenticate: Basic'; then echo "anonymous → 401 (gate)"; break; fi
  [ "$i" = 30 ] && { echo "gate not observed — refusing to upload content" >&2; exit 1; }
  sleep 10
done

if [ -f ~/.env ]; then step "collector credentials (stdin only)"; ./scripts/sync-collector-keys.sh; fi

step "upload UI"
./scripts/deploy-ui.sh

step "run one cycle now and verify end to end"
./scripts/verify.sh --run
