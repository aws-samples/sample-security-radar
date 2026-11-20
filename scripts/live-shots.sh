#!/usr/bin/env bash
# Screenshot the deployed UI (real data). Reads the UI credential from Secrets Manager into env only.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib.sh
arn=$(out UiSecretArn)
creds=$(aws secretsmanager get-secret-value --region ap-northeast-1 --secret-id "$arn" --query SecretString --output text)
U=$(printf '%s' "$creds" | uv run -q python -I -c 'import json,sys;print(json.load(sys.stdin)["username"])')
P=$(printf '%s' "$creds" | uv run -q python -I -c 'import json,sys;print(json.load(sys.stdin)["password"])')
unset creds
mkdir -p docs/screenshots
(cd ui && U="$U" P="$P" OUT="$(pwd)/../docs/screenshots" ONLY="${ONLY:-}" node scripts/live-screenshots.mjs)
# deck v9: announcements / search / 响应决策 / WAF rule pack shots + the event documents its numbers are checked against
# section shots end where their section ends: trim the flat background a capped element shot can carry
uv run -q python scripts/trim_shots.py docs/screenshots/live-env-*.png docs/screenshots/live-incident-*.png
if [ -z "${ONLY:-}" ]; then     # ONLY=<name,…> re-shoots a few README shots, nothing else
  (cd ui && U="$U" P="$P" OUT="$(pwd)/../docs/screenshots" UI_DIR="$(pwd)" DUMP="${DUMP:-/tmp}" \
    node ../docs/deck/v9/tools/live-shots-v9.mjs)
fi
echo "screenshots in docs/screenshots"
