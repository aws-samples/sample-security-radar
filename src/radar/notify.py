"""Push to Slack and Lark (C3): P0 events, "your code is affected" verdicts and delivered PR links — one thread per
event and channel, every message sent at most once.

plan() is pure: (event row, response, NOTIFY state) → messages not yet sent, each with an idempotency key.
Keys are facts, not times — `p0`, `affected:<n>`, `pr:<url>` — so a re-run, a retry or a cold start never repeats one.
The first message of an event opens its thread; later ones reply in it (Slack thread_ts / Lark reply).
send_slack / send_lark are the only network code; the Respond handler drives them (handlers._notify).
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any

from radar import fetch
from radar.limits import Limits

CHANNELS = ("slack", "lark")


def plan(ev: dict[str, Any], resp: dict[str, Any] | None, impact: dict[str, Any] | None, sent: dict[str, Any],
         site_url: str) -> list[dict[str, str]]:
    """Messages for one event this channel has not sent yet. ev = event_id/title/severity/level_reason;
    resp = respond.to_response(...) (issues carry pr_url); impact = respond.impact(resp); sent = state[channel]."""
    done = set(sent.get("keys") or [])
    link = f"{site_url.rstrip('/')}/#/events/{ev['event_id']}"
    out = []
    if ev["severity"] == "P0":
        out.append({"key": "p0", "text": f"[P0] {ev['title']}\n{ev.get('level_reason') or ''}\n{link}"})
    imp = impact or {}
    if imp.get("status") == "affected" and imp.get("affected"):
        out.append({"key": f"affected:{imp['affected']}",
                    "text": f"受影响：{imp['affected']}/{imp.get('checked', '?')} 个代码目标命中 · {ev['title']}\n{link}?section=env"})
    for i in (resp or {}).get("issues") or []:
        if i.get("pr_url"):
            out.append({"key": f"pr:{i['pr_url']}",
                        "text": f"补丁 PR（{i.get('severity', '')} · {i.get('exploitable', '')}）待人审核合并：{i['pr_url']}"})
    seen: set[str] = set()  # several issues can share one PR
    return [m for m in out if m["key"] not in done and not (m["key"] in seen or seen.add(m["key"]))]


def record(sent: dict[str, Any], key: str, thread: str | None) -> dict[str, Any]:
    keys = list(dict.fromkeys([*(sent.get("keys") or []), key]))
    return {**sent, "keys": keys, "thread": sent.get("thread") or thread}


# ---------------------------------------------------------------- adapters (network)

def _post(url: str, body: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json; charset=utf-8", **headers})
    with fetch.urlopen(req, timeout=Limits.HTTP_TIMEOUT_S) as r:
        return json.loads(r.read())


def send_slack(cfg: dict[str, str], text: str, thread: str | None) -> str:
    """chat.postMessage; returns the message ts (the thread id for replies). Slack reports errors in-band."""
    r = _post("https://slack.com/api/chat.postMessage",
              {"channel": cfg["slack_channel_id"], "text": text, **({"thread_ts": thread} if thread else {})},
              {"Authorization": f"Bearer {cfg['slack_bot_token']}"})
    if not r.get("ok"):
        raise ValueError(f"slack: {r.get('error')}")
    return thread or r["ts"]


def send_lark(cfg: dict[str, str], text: str, thread: str | None) -> str:
    """Tenant token → send to the chat, or reply to the thread's root message; returns the root message_id."""
    base = f"https://{cfg.get('lark_domain') or 'open.larksuite.com'}/open-apis"
    tok = _post(f"{base}/auth/v3/tenant_access_token/internal",
                {"app_id": cfg["lark_app_id"], "app_secret": cfg["lark_app_secret"]}, {})
    if tok.get("code") != 0:
        raise ValueError(f"lark auth: {tok.get('msg')}")
    auth = {"Authorization": f"Bearer {tok['tenant_access_token']}"}
    content = json.dumps({"text": text}, ensure_ascii=False)
    if thread:
        r = _post(f"{base}/im/v1/messages/{thread}/reply", {"msg_type": "text", "content": content}, auth)
    else:
        r = _post(f"{base}/im/v1/messages?receive_id_type=chat_id",
                  {"receive_id": cfg["lark_chat_id"], "msg_type": "text", "content": content}, auth)
    if r.get("code") != 0:
        raise ValueError(f"lark: {r.get('msg')}")
    return thread or r["data"]["message_id"]


SENDERS = {"slack": send_slack, "lark": send_lark}
REQUIRED = {"slack": ("slack_bot_token", "slack_channel_id"), "lark": ("lark_app_id", "lark_app_secret", "lark_chat_id")}


def configured(cfg: dict[str, str]) -> list[str]:
    return [c for c in CHANNELS if all(cfg.get(k) for k in REQUIRED[c])]
