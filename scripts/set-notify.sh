#!/usr/bin/env bash
# P3: write the NotifyConfig secret — bot credentials + the subscription table, one JSON — from ~/.env and a private
# subscriptions file, never echoing a value. Shape and filters: src/radar/notify.py (`python -m radar.notify` prints
# the filter table). Invalid subscriptions are reported on #/ops by the notify station (code / actual / allowed).
#   ~/.env: SLACK_BOT_TOKEN · LARK_APP_ID LARK_APP_SECRET [LARK_DOMAIN=open.larksuite.com] · [NOTIFY_ROLLOUT=owner_only|all]
#   Subscriptions: the JSON array in $NOTIFY_SUBSCRIPTIONS_FILE (default ~/.config/security-radar/subscriptions.json,
#   private — never in the repo). Without that file, SLACK_CHANNEL_ID / LARK_CHAT_ID become the owner's subscriptions
#   `slack` / `lark` (P0 + P1 — what the single-channel push used to cover).
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib.sh
tmp=$(mktemp); chmod 600 "$tmp"; trap 'trash "$tmp" 2>/dev/null || true' EXIT
# jq reads the values from its environment ($ENV) and the subscription file by path, not from `--arg` (argv is visible
# to `ps`). `set -a` exports what ~/.env assigns, but only inside this subshell — jq is the one child that sees them.
# shellcheck source=/dev/null
(set +x; set -a; source ~/.env >/dev/null 2>&1; set +a
 subs="${NOTIFY_SUBSCRIPTIONS_FILE:-$HOME/.config/security-radar/subscriptions.json}"
 if [ -f "$subs" ]; then from=(--slurpfile own "$subs"); else from=(--argjson own '[]'); fi
 jq -n "${from[@]}" '
   def legacy($id; $channel; $target):
     if ($target // "") != "" then {id: $id, owner: true, channel: $channel, target: $target,
                                     filters: {severity: ["P0", "P1"]}} else empty end;
   {rollout: ($ENV.NOTIFY_ROLLOUT // "owner_only"),
    slack_bot_token: ($ENV.SLACK_BOT_TOKEN // ""), lark_app_id: ($ENV.LARK_APP_ID // ""),
    lark_app_secret: ($ENV.LARK_APP_SECRET // ""),
    lark_domain: (($ENV.LARK_DOMAIN // "") | if . == "" then "open.larksuite.com" else . end),
    subscriptions: ($own[0] // [legacy("slack"; "slack_channel"; $ENV.SLACK_CHANNEL_ID),
                                 legacy("lark"; "lark_chat"; $ENV.LARK_CHAT_ID)])}
   | if (.subscriptions | type) != "array" then error("the subscriptions file must hold a JSON array") else . end
   | with_entries(select(.value != ""))' > "$tmp")
# ids and channels only — targets and secrets stay out of the terminal
echo "subscriptions: $(jq -r '[.subscriptions[] | "\(.id) (\(.channel))"] | join(", ") | if . == "" then "none" else . end' "$tmp")" \
     "· rollout $(jq -r .rollout "$tmp")"
aws secretsmanager put-secret-value --region ap-northeast-1 --secret-id "$(out NotifySecretArn)" \
  --secret-string "file://$tmp" --query VersionId --output text >/dev/null
echo "NotifyConfig updated — a new subscription's first cycle records a baseline (no replay of old events), then pushes"
