# Shared by every deploy script. STAGE (env) selects the deployment: empty = live, anything else = an independent
# copy deployed with `cdk -c stage=$STAGE` (stacks SecurityRadar<Stage>, SecurityRadarContinuum<Stage>).
export AWS_PROFILE=${AWS_PROFILE:?set AWS_PROFILE to a non-production profile}
STAGE=${STAGE:-}
SUFFIX=$(printf '%s' "$STAGE" | uv run -q python -I -c 'import sys;print(sys.stdin.read().capitalize())')
OUTPUTS=build/outputs${STAGE:+-$STAGE}.json
# out <Key> [continuum] — a CloudFormation output of this stage's Tokyo (default) or us-east-1 stack
out() {
  local stack="SecurityRadar$SUFFIX"; [ "${2:-}" = continuum ] && stack="SecurityRadarContinuum$SUFFIX"
  uv run -q python -I -c "import json,sys;print(json.load(open('$OUTPUTS'))['$stack']['$1'])"
}
