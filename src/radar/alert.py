"""CloudWatch alarm → SNS → the owner's chat (roadmap R0.2).

Why: the stack's one alarm had no action. An alarm nobody hears is not a control. This is the last hop: an SNS record
becomes one line of text and goes to every `owner: true` chat subscription of the notify secret — the channels that
already work, no new credential. It does not go through the Notify station (that station may be what is broken) and
keeps no state: CloudWatch sends one message per state change.

Not sent to: non-owner subscriptions (ops noise is the operator's) and webhooks (their body is an event; there is none).
"""
from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from radar import fetch, notify

CHAT_CHANNELS = ("slack_dm", "slack_channel", "lark_chat", "lark_dm")
REASON_MAX = 600


class AlertError(Exception):
    def __init__(self, detail: dict[str, Any]):
        super().__init__(detail.get("message", detail.get("error", "alert error")))
        self.detail = detail


def messages(event: dict[str, Any]) -> list[str]:
    """One text per SNS record. A CloudWatch alarm message is JSON; anything else is passed on as it is."""
    out = []
    for rec in event.get("Records") or []:
        sns = rec.get("Sns") or {}
        body = sns.get("Message") or ""
        try:
            a = json.loads(body)
        except ValueError:
            a = None
        if isinstance(a, dict) and a.get("AlarmName"):
            out.append(f"[雷达告警] {a['AlarmName']}：{a.get('NewStateValue')}\n{a.get('AlarmDescription') or ''}\n"
                       f"{str(a.get('NewStateReason') or '')[:REASON_MAX]}")
        else:
            out.append(f"[雷达告警] {sns.get('Subject') or ''}\n{body[:REASON_MAX]}")
    return out


def deliver(cfg: dict[str, Any], texts: list[str], site_url: str,
            senders: dict[str, Callable[..., str]] | None = None) -> dict[str, Any]:
    """Send each text to every owner chat subscription. Raises AlertError when there were recipients and none got
    anything (the invocation fails ⇒ Lambda retries it and its Errors metric shows it); with no owner chat subscription
    it returns a `degraded` marker instead — a retry cannot create one."""
    senders = senders if senders is not None else notify.SENDERS
    owners = [s for s in notify.parse_config(cfg).subscriptions if s.owner and s.channel in CHAT_CHANNELS]
    out: dict[str, Any] = {"messages": len(texts), "sent": 0, "errors": []}
    if not owners:
        return {**out, "degraded": "no_owner_chat_subscription"}
    link = f"\n{site_url.rstrip('/')}/#/ops" if site_url else ""
    cache: dict[str, Any] = {}
    for text in texts:
        for s in owners:
            try:
                senders[s.channel](cfg, s, {"key": "alert", "text": text + link, "link": link.strip()}, None, cache)
                out["sent"] += 1
            except (OSError, ValueError, KeyError, fetch.FetchError) as e:     # same set the Notify station catches
                out["errors"].append({"subscription": s.id, "error": type(e).__name__})   # never the target (a secret)
    if texts and not out["sent"]:
        raise AlertError({"error": "alert_not_delivered", "message": "no owner subscription accepted the alert",
                          "attempted": len(texts) * len(owners), "delivered": 0})
    return out
