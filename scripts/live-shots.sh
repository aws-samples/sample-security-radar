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
(cd ui && U="$U" P="$P" OUT="$(pwd)/../docs/screenshots" node scripts/live-screenshots.mjs)
echo "screenshots in docs/screenshots"
