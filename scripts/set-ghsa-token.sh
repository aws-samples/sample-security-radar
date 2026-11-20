#!/usr/bin/env bash
# R12: put the read-only GitHub token for the GHSA → CVE lookup where the Analyze Lambda reads it — without echoing it.
#   GITHUB_ADVISORY_TOKEN (~/.env, a fine-grained token: public repositories, no permissions) → Secrets Manager
#   (stack output GhsaTokenSecretArn). The value travels through a 0600 temp file, never argv or the terminal.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib.sh
# shellcheck source=/dev/null
val() { (set +x; source ~/.env >/dev/null 2>&1; printf '%s' "${!1:-}"); }
tok=$(val GITHUB_ADVISORY_TOKEN)
[ -n "$tok" ] || { echo "GITHUB_ADVISORY_TOKEN missing in ~/.env" >&2; exit 1; }
case "$tok" in github_pat_*) ;; *) echo "GITHUB_ADVISORY_TOKEN is not a fine-grained token (github_pat_…)" >&2; exit 1;; esac
tmp=$(mktemp); chmod 600 "$tmp"
trap 'rm -f "$tmp"' EXIT   # a secret-holding temp file: deleted, never moved to the Trash
printf '%s' "$tok" > "$tmp"
aws secretsmanager put-secret-value --region ap-northeast-1 --secret-id "$(out GhsaTokenSecretArn)" \
  --secret-string "file://$tmp" --query VersionId --output text >/dev/null
echo "GHSA lookup token → Secrets Manager"
