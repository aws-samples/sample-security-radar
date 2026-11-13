#!/usr/bin/env bash
# Copy collector credentials from ~/.env into the stack's Secrets Manager secret.
# Values travel via stdin only (never argv, never echoed). Do NOT run with `bash -x`.
# ~/.env is PARSED for the collector keys only, never sourced: sourcing exported every key in it to uv / python / aws,
# and an AWS_PROFILE or AWS_ACCESS_KEY_ID there would silently send this write to another account.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib.sh
export AWS_REGION=ap-northeast-1
arn=$(out SecretArn)
uv run -q python -I -c '
import json, pathlib, re
want = re.compile(r"\s*(?:export\s+)?(X_API_KEY|FIRECRAWL_API_KEY\w*)=(.*)")
keys = {}
for line in (pathlib.Path.home() / ".env").read_text(encoding="utf-8").splitlines():
    m = want.fullmatch(line)
    if not m:
        continue
    v = m.group(2).strip()
    if v[:1] in ("\"", "\x27") and v.find(v[0], 1) > 0:
        v = v[1:v.find(v[0], 1)]                       # quoted, as the shell reads it
    else:
        v = re.split(r"\s+#", v, maxsplit=1)[0]          # unquoted: a trailing ` # comment` is not part of the value
    keys[m.group(1)] = v                                 # the last assignment wins, as with `source`
fc = [keys[k] for k in sorted(keys) if k.startswith("FIRECRAWL_API_KEY") and keys[k]]
print(json.dumps({"X_API_KEY": keys.get("X_API_KEY", ""), "FIRECRAWL_API_KEYS": fc}))' \
  | aws secretsmanager put-secret-value --secret-id "$arn" --secret-string file:///dev/stdin --query VersionId --output text >/dev/null
echo "collector secret updated"
