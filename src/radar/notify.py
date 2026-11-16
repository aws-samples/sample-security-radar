"""Push (C3 → P3): subscriptions, a pure matcher, message planning and the four channel adapters.

Subscriptions live in the NotifyConfig secret (Secrets Manager), never in the repo — their targets are private ids
(tests/test_no_private_config.py). The secret is one JSON object:

    {"rollout": "owner_only" | "all",                         # default owner_only: only `owner: true` subscriptions get mail
     "slack_bot_token": "…", "lark_app_id": "…", "lark_app_secret": "…", "lark_domain": "open.larksuite.com",
     "subscriptions": [{"id": "neo-p0", "owner": true, "enabled": true,
                        "channel": "slack_channel" | "slack_dm" | "lark_chat" | "lark_dm" | "webhook",
                        "target": "<channel id | user id | chat id | https URL>",
                        "secret": "<webhook HMAC key — webhook only>",
                        "filters": {"severity": ["P0"], "domain": ["web3"], …}}]}

The filter fields and their meaning are FILTER_FIELDS (one table; `python -m radar.notify --explain` prints it).
A subscription that does not parse is reported `invalid` with code / message / actual / allowed — never dropped quietly.

plan() is pure: (event view, sent state) → messages not yet sent, each with an idempotency key. Keys are facts, not
times — `p0`, `affected:<n>`, `pr:<url>` — so a re-run, a retry or a cold start never repeats one. The first message of
an event opens its thread; later ones reply in it (Slack thread_ts / Lark reply). The adapters are the only network
code; radar.notify_station drives them.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from radar import fetch, products, wallets
from radar.limits import Limits

CHANNELS = ("slack_channel", "slack_dm", "lark_chat", "lark_dm", "webhook")
ROLLOUTS = ("owner_only", "all")
# secret fields a channel needs besides the subscription's own target (webhook: the subscription carries its key)
CREDENTIALS = {"slack_channel": ("slack_bot_token",), "slack_dm": ("slack_bot_token",),
               "lark_chat": ("lark_app_id", "lark_app_secret"), "lark_dm": ("lark_app_id", "lark_app_secret"), "webhook": ()}
NOTIFY_SEVERITIES = ("P0", "P1")   # the push window: what the station considers at all (a P2 is a page, not a push)
EXCHANGES = tuple(sorted({w.exchange for w in wallets.ENTRIES}))
_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")   # the state key: fullmatch, so "abc\n" is refused (pathguard rule)

LEVELS = ("V0", "V1", "V2", "V3", "V4")              # verification, weakest first (X = disputed: below every minimum)
EXPLOITATION = ("none", "poc", "reported", "confirmed")
# One table: field → (type, allowed values or None for free text, meaning). Lists match when ANY value matches
# (OR inside a field); fields combine with AND; an absent field does not constrain. "atleast" = one value of an ordered
# scale, matched by rank; "number" = a lower bound on a number the event may not have (no figure ⇒ no match).
FILTER_FIELDS: dict[str, tuple[str, tuple[str, ...] | None, str]] = {
    "severity": ("list", NOTIFY_SEVERITIES, "event severity"),
    "domain": ("list", ("vuln", "incident", "web3"), "event domain"),
    "products": ("list", tuple(p.product_id for p in products.PRODUCTS), "radar.products registry product the event names"),
    "vendors": ("list", None, "an event entity, case-insensitive (vendor / project name as reported)"),
    "chains": ("list", None, "a chain the event names (Event.chains), case-insensitive"),
    "exchanges": ("list", EXCHANGES, "an exchange of the radar.wallets registry the event names"),
    "has_waf_pack": ("bool", None, "the mitigate station planned WAF rules for the event"),
    "has_verdict": ("bool", None, "a code-impact verdict exists (affected / not_affected)"),
    "cves": ("list", None, "a CVE id the event names, case-insensitive"),
    "exploitation": ("list", EXPLOITATION, "exploitation status of the event"),
    "min_level": ("atleast", LEVELS, "verification level at least this (a disputed event, level X, never matches)"),
    "min_loss_usd": ("number", None, "headline loss in USD at least this; an event without a loss figure never matches"),
    # R4.4: a filter on the MESSAGE, not the event (matches() skips it; wanted() applies it per message)
    "kinds": ("list", ("p0", "update", "waf", "verdict", "pr", "digest"),
              ("message kinds to receive (absent: every event kind). `digest` — the daily digest, one message a day, "
              "event filters not applied — only when listed")),
}


def explain() -> str:
    rows = ["| filter | type | allowed | meaning |", "|---|---|---|---|"]
    for k, (t, allowed, what) in FILTER_FIELDS.items():
        say = ", ".join(allowed) if allowed else {"bool": "true / false", "number": "a number ≥ 0"}.get(t, "free text")
        rows.append(f"| `{k}` | {t} | {say} | {what} |")
    return "\n".join(rows)


@dataclass(frozen=True)
class Subscription:
    id: str
    channel: str
    target: str
    owner: bool = False
    filters: dict[str, Any] = field(default_factory=dict)
    secret: str = field(default="", repr=False)    # webhook HMAC key; never logged, never in a message


def _bad(code: str, message: str, actual: Any, allowed: Any, sub_id: str | None = None) -> dict[str, Any]:
    """Error rule 5: machine code, human message, actual value, allowed value."""
    return {"error": code, "message": message, "actual": actual, "allowed": allowed, **({"id": sub_id} if sub_id else {})}


def _filters(raw: Any, sid: str) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if raw is None:
        return {}, None
    if not isinstance(raw, dict):
        return {}, _bad("filters_not_object", "filters must be an object", type(raw).__name__, "object", sid)
    out: dict[str, Any] = {}
    for k, v in raw.items():
        if k not in FILTER_FIELDS:
            return {}, _bad("unknown_filter", f"unknown filter field {k!r}", k, sorted(FILTER_FIELDS), sid)
        kind, allowed, _ = FILTER_FIELDS[k]
        if kind == "bool":
            if not isinstance(v, bool):
                return {}, _bad("filter_not_bool", f"{k} must be true or false", v, [True, False], sid)
            out[k] = v
            continue
        if kind == "atleast":
            if v not in (allowed or ()):
                return {}, _bad("filter_value", f"{k} must be one of the scale", v, list(allowed or ()), sid)
            out[k] = v
            continue
        if kind == "number":
            # bool is an int in Python: `true` is not a threshold
            if isinstance(v, bool) or not isinstance(v, int | float) or not 0 <= v < float("inf"):
                return {}, _bad("filter_not_number", f"{k} must be a number ≥ 0", v, "number ≥ 0", sid)
            out[k] = v
            continue
        if not isinstance(v, list) or not v or not all(isinstance(x, str) and x for x in v):
            # an empty list would match nothing — almost surely a typo, not a wish to receive nothing
            return {}, _bad("filter_not_list", f"{k} must be a non-empty list of strings", v, "list[str]", sid)
        if allowed is not None and (extra := sorted(set(v) - set(allowed))):
            return {}, _bad("filter_value", f"{k} has values outside the allowed set", extra, list(allowed), sid)
        out[k] = list(v)
    return out, None


def parse_subscription(raw: Any, cfg: dict[str, Any]) -> tuple[Subscription | None, dict[str, Any] | None]:
    if not isinstance(raw, dict):
        return None, _bad("subscription_not_object", "a subscription must be an object", type(raw).__name__, "object")
    sid = raw.get("id")
    if not isinstance(sid, str) or not _ID.fullmatch(sid):
        return None, _bad("bad_id", "id must match [a-z0-9][a-z0-9-]{0,31}", sid, _ID.pattern)
    ch = raw.get("channel")
    if ch not in CHANNELS:
        return None, _bad("unknown_channel", f"channel {ch!r} is not supported", ch, list(CHANNELS), sid)
    target = raw.get("target")
    if not isinstance(target, str) or not target.strip():
        return None, _bad("no_target", "target is required", target, "non-empty string", sid)
    missing = [k for k in CREDENTIALS[ch] if not cfg.get(k)]
    if missing:
        return None, _bad("missing_credentials", f"{ch} needs {', '.join(missing)} in the secret", missing, list(CREDENTIALS[ch]), sid)
    secret = raw.get("secret") or ""
    if ch == "lark_dm" and lark_receive_type(ch, target.strip()) is None:
        return None, _bad("lark_dm_target", "a lark_dm target is the user's open_id (ou_…) or email", target[:40],
                          "ou_… | name@domain", sid)
    if ch == "webhook":
        u = urllib.parse.urlsplit(target)
        if u.scheme != "https" or not u.hostname:
            return None, _bad("webhook_not_https", "a webhook target must be an https URL", u.scheme or target[:40], "https", sid)
        if not isinstance(secret, str) or len(secret) < Limits.WEBHOOK_SECRET_MIN_CHARS:
            return None, _bad("webhook_secret_short", "a webhook needs its own HMAC secret",
                              len(secret) if isinstance(secret, str) else None, f">= {Limits.WEBHOOK_SECRET_MIN_CHARS} chars", sid)
    filters, err = _filters(raw.get("filters"), sid)
    if err:
        return None, err
    return Subscription(id=sid, channel=ch, target=target.strip(), owner=raw.get("owner") is True, filters=filters,
                        secret=secret if ch == "webhook" else ""), None


@dataclass
class Config:
    rollout: str
    subscriptions: list[Subscription]
    disabled: list[str]
    invalid: list[dict[str, Any]]
    legacy: bool = False    # the pre-subscription single-channel shape: reported, not translated (see parse_config)


def parse_config(cfg: dict[str, Any]) -> Config:
    """The secret → subscriptions. The old single-channel keys (slack_channel_id / lark_chat_id) are NOT translated
    into a subscription: that hard-coded path is gone, and a secret still in the old shape is reported as `legacy`
    (rerun scripts/set-notify.sh) instead of pushing to a channel nobody declared as a subscription."""
    invalid: list[dict[str, Any]] = []
    rollout = cfg.get("rollout", "owner_only")
    if rollout not in ROLLOUTS:
        invalid.append(_bad("bad_rollout", "rollout is owner_only or all; owner_only is used", rollout, list(ROLLOUTS)))
        rollout = "owner_only"     # fail toward fewer recipients, never more
    if cfg.get("self_service_error"):
        invalid.append(_bad("self_subscriptions_unreadable", "self-service subscriptions could not be read this run; "
                            "none of them was sent to", str(cfg["self_service_error"])[:120], "a readable secret"))
    raw = cfg.get("subscriptions")
    legacy = raw is None and any(cfg.get(k) for k in ("slack_channel_id", "lark_chat_id"))
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        invalid.append(_bad("subscriptions_not_list", "subscriptions must be a list", type(raw).__name__, "list"))
        raw = []
    if len(raw) > Limits.NOTIFY_SUBSCRIPTIONS_MAX:
        invalid.append(_bad("too_many_subscriptions", "only the first subscriptions are used", len(raw),
                            Limits.NOTIFY_SUBSCRIPTIONS_MAX))
        raw = raw[: Limits.NOTIFY_SUBSCRIPTIONS_MAX]
    subs, disabled, seen = [], [], set()
    for r in raw:
        s, err = parse_subscription(r, cfg)
        if s is None:
            invalid.append(err or _bad("unparsed", "subscription did not parse", None, "a subscription object"))
            continue
        if s.id in seen:
            invalid.append(_bad("duplicate_id", "two subscriptions share an id (it is their state key)", s.id, "unique ids", s.id))
            continue
        seen.add(s.id)
        (disabled.append(s.id) if isinstance(r, dict) and r.get("enabled") is False else subs.append(s))
    return Config(rollout=rollout, subscriptions=subs, disabled=disabled, invalid=invalid, legacy=legacy)


def gated(sub: Subscription, rollout: str) -> bool:
    """The rollout gate: owner_only (the default) holds back every subscription that is not the owner's."""
    return rollout != "all" and not sub.owner


# ---------------------------------------------------------------- the event view (the only input of messages and feeds)

def view(row: dict[str, Any], has_waf_pack: bool, prs: list[str] | None = None) -> dict[str, Any]:
    """One event as subscribers may see it, from the PUBLIC summary row (publish._summary: retitled title, grounded
    summary, impact). Nothing else reaches a message, a webhook body or a feed — internal state (analysis cache keys,
    triage notes, raw responses, secrets) cannot leak because it is never an input."""
    imp = row.get("impact") or {}
    text = " ".join([row.get("title") or "", *(row.get("entities") or [])]).lower()
    prod = products.match(row.get("title") or "", list(row.get("entities") or []))
    return {"event_id": row["event_id"], "title": row["title"], "severity": row["severity"], "domain": row["domain"],
            "level": row.get("level"), "level_reason": row.get("level_reason") or "", "summary": row.get("summary") or "",
            "first_seen": row.get("first_seen"), "last_updated": row.get("last_updated"),
            "cves": list(row.get("cves") or []), "chains": list(row.get("chains") or []),
            "entities": list(row.get("entities") or []), "vendors": list(row.get("entities") or []), "products": [prod.product_id] if prod else [],
            "exchanges": [x for x in EXCHANGES if re.search(rf"\b{re.escape(x.lower())}\b", text)],
            "exploitation": row.get("exploitation") or "none", "amount_usd": row.get("amount_usd_latest"),
            "tx_confirmed": int(row.get("tx_confirmed") or 0),
            "has_waf_pack": bool(has_waf_pack), "has_verdict": imp.get("status") in ("affected", "not_affected"),
            "impact": {"status": imp.get("status"), "affected": imp.get("affected", 0), "checked": imp.get("checked", 0)}
            if imp else None, "prs": sorted(set(prs or []))}


# a threshold filter reads the view field it bounds (the view keeps the event's own names: it is what subscribers get)
_BOUNDS = {"min_level": "level", "min_loss_usd": "amount_usd"}


def matches(filters: dict[str, Any], v: dict[str, Any]) -> bool:
    """Pure: does the event view pass every filter field?"""
    for k, want in filters.items():
        if k == "kinds":                      # a message filter (wanted), not an event filter
            continue
        if FILTER_FIELDS[k][0] == "bool":
            if bool(v.get(k)) != want:
                return False
            continue
        if FILTER_FIELDS[k][0] == "atleast":
            scale = FILTER_FIELDS[k][1] or ()
            if v.get(_BOUNDS[k]) not in scale or scale.index(v[_BOUNDS[k]]) < scale.index(want):
                return False
            continue
        if FILTER_FIELDS[k][0] == "number":
            if not isinstance(v.get(_BOUNDS[k]), int | float) or v[_BOUNDS[k]] < want:
                return False
            continue
        have = v.get(k)
        have = [have] if isinstance(have, str) else list(have or [])
        if not {x.lower() for x in have} & {x.lower() for x in want}:
            return False
    return True


def wanted(filters: dict[str, Any], msg: dict[str, Any]) -> bool:
    """R4.4: does the subscription want this kind of message? No `kinds` filter ⇒ every kind."""
    kinds = filters.get("kinds")
    return not kinds or msg.get("kind") in kinds


def wants_digest(filters: dict[str, Any]) -> bool:
    """Opt-in (R4.4): a subscription without `kinds` keeps exactly the messages it had before the digest existed."""
    return "digest" in (filters.get("kinds") or [])


DIGEST_SHOWN = 6     # sentences of the digest a message carries (summary first, then highlights); the page has all


def digest_message(d: dict[str, Any], day: str, site_url: str) -> dict[str, Any] | None:
    """The daily digest (radar.digest) as one message, or None: not today's, or failed. Only sentences that passed the
    grounding check are sent — an ungrounded one is never stated as fact (radar.digest); how many were left out is said.
    Every number outside the prose is the digest's code-made header."""
    if d.get("day") != day or d.get("status") not in ("ok", "partial"):
        return None
    h, link = d.get("header") or {}, site_url.rstrip("/") + "/"
    said = [x for k in ("summary", "highlights") for x in d.get(k) or []]
    good = [x["text"] for x in said if x.get("grounded")]
    lines = [f"安全雷达日报 {day}（截至 08:00 HKT）"]
    if not h.get("events"):
        lines.append("过去 24 小时没有 P0 / P1 事件，也没有级别变化。")
    else:
        lines.append(f"{h['events']} 个事件 · P0 {h.get('p0', 0)} · P1 {h.get('p1', 0)} · 新增 {h.get('new', 0)} · "
                     f"升级 {h.get('escalated', 0)}")
        lines += [f"· {t}" for t in good[:DIGEST_SHOWN]]
        if len(said) > len(good):
            lines.append(f"（{len(said) - len(good)} 句未通过核对，未列出）")
    return {"key": f"digest:{day}", "kind": "digest", "text": "\n".join([*lines, link]), "link": link}


def loss_rung(amount: Any) -> str | None:
    """The doubling step a loss figure stands on: $1M, $2M, $4M, … (None below $1M or without a figure). A message key
    is a fact, not a time — "the loss reached the $64M step" is said once however often the figure is restated."""
    if isinstance(amount, bool) or not isinstance(amount, int | float) or amount < 1_000_000:
        return None
    return f"loss:{1 << (int(amount) // 1_000_000).bit_length() - 1}M"


def _usd(amount: float) -> str:
    return f"${amount / 1e9:.2f}B" if amount >= 1e9 else f"${amount / 1e6:.1f}M"


def standing(v: dict[str, Any]) -> list[str]:
    """What the P0 notice itself already says about the event's state: recorded with it, so only a later CHANGE is an
    update (roadmap R4.3) — the loss step and the verification level at that moment."""
    return [STANDING, *(k for k in (loss_rung(v.get("amount_usd")),
                                    f"level:{v['level']}" if v.get("level") in CONFIRMED else None,
                                    f"tx:{v['tx_confirmed']}" if v.get("tx_confirmed") else None,
                                    "waf" if v.get("has_waf_pack") else None,
                                    "verdict:not_affected" if (v.get("impact") or {}).get("status") == "not_affected" else None)
                         if k)]


CONFIRMED = ("V3", "V4")     # confirmed / finalized: worth telling a thread that started on a weaker level
# marks a notice whose standing was recorded. A thread opened before updates existed has no such mark and gets none:
# without it, the first run after the deployment would have "updated" every open P0 thread with its current state.
STANDING = "standing"


def plan(v: dict[str, Any], sent: dict[str, Any], site_url: str) -> list[dict[str, Any]]:
    """Messages for one event this subscription has not sent yet."""
    done = set(sent.get("keys") or [])
    link = f"{site_url.rstrip('/')}/#/events/{v['event_id']}"
    out: list[dict[str, Any]] = []
    if v["severity"] == "P0":
        out.append({"key": "p0", "kind": "p0", "text": f"[P0] {v['title']}\n{v.get('level_reason') or ''}\n{link}", "also": standing(v)})
        if STANDING in done:   # updates belong to a thread whose notice recorded where the event stood
            rung = loss_rung(v.get("amount_usd"))
            if rung:
                out.append({"key": rung, "kind": "update", "text": f"更新：损失数字升至 {_usd(v['amount_usd'])} · {v['title']}\n{link}"})
            if v.get("tx_confirmed"):        # R4.3: the attack transaction read back on chain, in the same thread
                n = v["tx_confirmed"]
                out.append({"key": f"tx:{n}", "kind": "update", "text": f"更新：攻击交易已在链上证实（{n} 笔）· {v['title']}\n{link}"})
            if v.get("has_waf_pack"):         # R4.4: the mitigate station planned WAF rules (Count, waits for a human)
                out.append({"key": "waf", "kind": "waf", "text": f"WAF 规则包已生成（Count 观察中，需人确认后拦截）· {v['title']}\n{link}?section=env"})
            if (v.get("impact") or {}).get("status") == "not_affected":
                imp0 = v["impact"]
                out.append({"key": "verdict:not_affected", "kind": "verdict",
                            "text": f"代码目标均未受影响（已查 {imp0.get('checked', '?')} 个）· {v['title']}\n{link}?section=env"})
            if v.get("level") in CONFIRMED:
                out.append({"key": f"level:{v['level']}", "kind": "update", "text": f"更新：已{'定论' if v['level'] == 'V4' else '证实'}"
                                                                    f"（{v['level']}）· {v.get('level_reason') or v['title']}\n{link}"})
    imp = v.get("impact") or {}
    if imp.get("status") == "affected" and imp.get("affected"):
        out.append({"key": f"affected:{imp['affected']}", "kind": "verdict",
                    "text": f"受影响：{imp['affected']}/{imp.get('checked', '?')} 个代码目标命中 · {v['title']}\n{link}?section=env"})
    for url in v.get("prs") or []:
        out.append({"key": f"pr:{url}", "kind": "pr", "text": f"补丁 PR 待人审核合并：{url} · {v['title']}"})
    return [{**m, "link": link} for m in out if m["key"] not in done]


def record(sent: dict[str, Any], key: str, thread: str | None, also: list[str] | None = None) -> dict[str, Any]:
    """`also`: facts the message itself states (notify.standing) — recorded with it, never sent on their own."""
    keys = list(dict.fromkeys([*(sent.get("keys") or []), key, *(also or [])]))
    return {**sent, "keys": keys, "thread": sent.get("thread") or thread}


# ---------------------------------------------------------------- adapters (network)

def _post(url: str, body: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",  # noqa: S310 — fixed https chat API endpoints
                                 headers={"Content-Type": "application/json; charset=utf-8", **headers})
    with fetch.urlopen(req, timeout=Limits.HTTP_TIMEOUT_S) as r:
        return json.loads(r.read())


def slack_escape(text: str) -> str:
    """Slack's three control characters (api.slack.com formatting: & < > must be sent as entities). Message text carries
    third-party feed / X / Telegram titles (docs/research/action/05 §3.6): unescaped, `<!channel>` pings the whole
    channel and `<https://phish|官方补丁>` shows as a trusted-looking link."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# Lark text messages turn <at user_id="all"></at> into @所有人 (and <at user_id="ou_…"> into a personal ping) — a title
# carrying the tag would page the chat. The tag's "<" becomes a full-width "＜": readable, never parsed; other "<" stay.
_LARK_AT = re.compile(r"<(?=\s*/?\s*at\b)", re.IGNORECASE)


def lark_escape(text: str) -> str:
    return _LARK_AT.sub("＜", text)


def send_slack(cfg: dict[str, Any], sub: Subscription, msg: dict[str, Any], thread: str | None,
               cache: dict[str, Any]) -> str:
    """chat.postMessage to a channel id or (slack_dm) a user id; returns the message ts (the thread id)."""
    r = _post("https://slack.com/api/chat.postMessage",
              {"channel": sub.target, "text": slack_escape(msg["text"]), **({"thread_ts": thread} if thread else {})},
              {"Authorization": f"Bearer {cfg['slack_bot_token']}"})
    if not r.get("ok"):
        raise ValueError(f"slack: {r.get('error')}")
    return thread or r["ts"]


def _lark_token(cfg: dict[str, Any], base: str, cache: dict[str, Any]) -> str:
    """One tenant token per station run (it lives two hours), not one per message (research/03 §2)."""
    if "lark_token" not in cache:
        tok = _post(f"{base}/auth/v3/tenant_access_token/internal",
                    {"app_id": cfg["lark_app_id"], "app_secret": cfg["lark_app_secret"]}, {})
        if tok.get("code") != 0:
            raise ValueError(f"lark auth: {tok.get('msg')}")
        cache["lark_token"] = tok["tenant_access_token"]
    return cache["lark_token"]


def lark_receive_type(channel: str, target: str) -> str | None:
    """Lark's receive_id_type for a target (im/v1/messages): a group chat id, or — R4.4 lark_dm — a person by open_id
    or email. None ⇒ a lark_dm target that is neither (refused when the subscription is parsed)."""
    if channel == "lark_chat":
        return "chat_id"
    if target.startswith("ou_"):
        return "open_id"
    return "email" if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", target) else None


def send_lark(cfg: dict[str, Any], sub: Subscription, msg: dict[str, Any], thread: str | None,
              cache: dict[str, Any]) -> str:
    """Send to the chat, or reply to the thread's root message; returns the root message_id."""
    base = f"https://{cfg.get('lark_domain') or 'open.larksuite.com'}/open-apis"
    auth = {"Authorization": f"Bearer {_lark_token(cfg, base, cache)}"}
    content = json.dumps({"text": lark_escape(msg["text"])}, ensure_ascii=False)
    if thread:
        r = _post(f"{base}/im/v1/messages/{thread}/reply", {"msg_type": "text", "content": content}, auth)
    else:
        r = _post(f"{base}/im/v1/messages?receive_id_type={lark_receive_type(sub.channel, sub.target)}",
                  {"receive_id": sub.target, "msg_type": "text", "content": content}, auth)
    if r.get("code") != 0:
        raise ValueError(f"lark: {r.get('msg')}")
    return thread or r["data"]["message_id"]


SIGNATURE_HEADER = "X-Radar-Signature"
TIMESTAMP_HEADER = "X-Radar-Timestamp"
DELIVERY_HEADER = "X-Radar-Delivery"


def sign(secret: str, timestamp: str, body: bytes) -> str:
    """HMAC-SHA256 over `<timestamp>.<body>` — the timestamp is signed so a captured delivery cannot be replayed later
    with a fresh header (the receiver rejects old timestamps)."""
    return "sha256=" + hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()


def webhook_body(sub: Subscription, msg: dict[str, Any], v: dict[str, Any]) -> bytes:
    return json.dumps({"subscription": sub.id, "key": msg["key"], "text": msg["text"], "url": msg["link"], "event": v},
                      ensure_ascii=False, sort_keys=True).encode()


def send_webhook(cfg: dict[str, Any], sub: Subscription, msg: dict[str, Any], thread: str | None,
                 cache: dict[str, Any]) -> str:
    """POST the JSON body, signed; 2xx = delivered. Every other answer raises: a 3xx is a refused redirect
    (fetch.FetchError — empty allowlist: it could carry the signed body to another host), 4xx / 5xx urllib's
    HTTPError (its HTTPErrorProcessor passes only 2xx through). The response body is not read into logs.
    No thread: returns the delivery id."""
    body = webhook_body(sub, msg, msg["view"])
    ts = str(int(time.time()))
    delivery = f"{msg['view']['event_id']}:{msg['key']}"
    req = urllib.request.Request(sub.target, data=body, method="POST", headers={  # noqa: S310 — webhook targets are validated https at load (webhook_not_https)
        "Content-Type": "application/json; charset=utf-8", TIMESTAMP_HEADER: ts,
        SIGNATURE_HEADER: sign(sub.secret, ts, body), DELIVERY_HEADER: delivery})
    # resolved again at send time: a name accepted at registration can be pointed at an internal address later
    host = urllib.parse.urlsplit(sub.target).hostname or ""
    if fetch._internal_host(host):
        raise fetch.FetchError("webhook_internal", "the webhook host resolves to a non-public address")
    with fetch.urlopen(req, timeout=Limits.HTTP_TIMEOUT_S, allow_hosts=frozenset()):
        pass
    return thread or delivery


SENDERS = {"slack_channel": send_slack, "slack_dm": send_slack, "lark_chat": send_lark, "lark_dm": send_lark,
           "webhook": send_webhook}


if __name__ == "__main__":   # python -m radar.notify --explain
    print(explain())
