#!/usr/bin/env bash
# Copy collector credentials from ~/.env into the stack's Secrets Manager secret.
# Values travel via stdin only (never argv, never echoed). Do NOT run with `bash -x`.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib.sh
export AWS_REGION=ap-northeast-1
arn=$(out SecretArn)
set +x; set -a; source ~/.env >/dev/null 2>&1; set +a
uv run -q python -I -c '
import json, os
fc = [os.environ[k] for k in sorted(os.environ) if k.startswith("FIRECRAWL_API_KEY") and os.environ[k]]
print(json.dumps({"X_API_KEY": os.environ.get("X_API_KEY", ""), "FIRECRAWL_API_KEYS": fc}))' \
  | aws secretsmanager put-secret-value --secret-id "$arn" --secret-string file:///dev/stdin --query VersionId --output text >/dev/null
echo "collector secret updated"
