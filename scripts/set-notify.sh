#!/usr/bin/env bash
# C3: copy the Slack / Lark push credentials from ~/.env into the NotifyConfig secret (one JSON), never echoing them.
# Either channel may be absent; the station then reports that channel as not_configured.
#   SLACK_BOT_TOKEN SLACK_CHANNEL_ID · LARK_APP_ID LARK_APP_SECRET LARK_CHAT_ID [LARK_DOMAIN=open.larksuite.com]
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib.sh
tmp=$(mktemp); chmod 600 "$tmp"; trap 'trash "$tmp" 2>/dev/null || true' EXIT
(set +x; source ~/.env >/dev/null 2>&1
 jq -n --arg st "${SLACK_BOT_TOKEN:-}" --arg sc "${SLACK_CHANNEL_ID:-}" --arg la "${LARK_APP_ID:-}" \
       --arg ls "${LARK_APP_SECRET:-}" --arg lc "${LARK_CHAT_ID:-}" --arg ld "${LARK_DOMAIN:-open.larksuite.com}" \
   '{slack_bot_token:$st, slack_channel_id:$sc, lark_app_id:$la, lark_app_secret:$ls, lark_chat_id:$lc, lark_domain:$ld}
    | with_entries(select(.value != ""))' > "$tmp")
echo "channels configured: $(jq -r '[(if .slack_bot_token and .slack_channel_id then "slack" else empty end),
  (if .lark_app_id and .lark_app_secret and .lark_chat_id then "lark" else empty end)] | join(", ") | if . == "" then "none" else . end' "$tmp")"
aws secretsmanager put-secret-value --region ap-northeast-1 --secret-id "$(out NotifySecretArn)" \
  --secret-string "file://$tmp" --query VersionId --output text >/dev/null
echo "NotifyConfig updated — the next cycle records a baseline (no replay of old events), then pushes new ones"
