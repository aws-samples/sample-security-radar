#!/usr/bin/env bash
# Put sha256("Basic " + base64(user:pass)) of the generated UI credential — and of every alias user in the
# secret's optional "aliases" list (same password) — into CloudFront KeyValueStore, comma-separated.
# The plaintext stays in Secrets Manager; read it with:
#   aws secretsmanager get-secret-value --secret-id <UiSecretArn> --query SecretString --output text
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib.sh
ui_arn=$(out UiSecretArn); kvs_arn=$(out AuthStoreArn)
hash=$(aws secretsmanager get-secret-value --region ap-northeast-1 --secret-id "$ui_arn" --query SecretString --output text \
  | uv run -q python -I -c '
import base64, hashlib, json, sys
d = json.load(sys.stdin)
users = [d["username"], *d.get("aliases", [])]  # aliases share the password (demo access for colleagues)
print(",".join(hashlib.sha256(("Basic " + base64.b64encode((u + ":" + d["password"]).encode()).decode()).encode()).hexdigest()
               for u in dict.fromkeys(users)))')
etag=$(aws cloudfront-keyvaluestore describe-key-value-store --kvs-arn "$kvs_arn" --query ETag --output text)
aws cloudfront-keyvaluestore put-key --kvs-arn "$kvs_arn" --key basic_auth_sha256 --value "$hash" --if-match "$etag" >/dev/null
echo "basic auth hash(es) stored in KeyValueStore"
