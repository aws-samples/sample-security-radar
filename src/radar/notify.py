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

from radar import cloudstack, fetch, p0class, products, timeutil, wallets
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
    "cloud_stack": ("bool", None, ("the affected product is a mainstream cloud component (radar.cloudstack) — nginx, "
                                   "Java, PHP, Linux, MySQL …; not mobile / desktop apps, SAP, appliances, ICS")),
    "team_send": ("bool", None, "the send arbitration (radar.send_judge) said send; unasked or failed = false"),
    "cves": ("list", None, "a CVE id the event names, case-insensitive"),
    # Neo 2026-11-23: WordPress plugin P0s stay on the site, never in a company channel — when the channel takes every
    # P0 (no cloud_stack prefilter, 2026-11-25: a channel that takes every P0), this is what keeps them out
    "not_p0_products": ("notlist", tuple(p.id for p in p0class.PRODUCTS), "P0-wall tile (radar.p0class) the event must NOT be on"),
    "exploitation": ("list", EXPLOITATION, "exploitation status of the event"),
    "min_level": ("atleast", LEVELS, "verification level at least this (a disputed event, level X, never matches)"),
    "min_loss_usd": ("number", None, "headline loss in USD at least this; an event without a loss figure never matches"),
    # R4.4: a filter on the MESSAGE, not the event (matches() skips it; wanted() applies it per message)
    "kinds": ("list", ("p0", "update", "waf", "verdict", "pr", "digest", "alarm", "withdrawn", "merged", "exploited"),
              ("message kinds to receive (absent: every event kind). `digest` — the daily digest, one message a day, "
              "event filters not applied — only when listed. `withdrawn` / `merged` — the one correction in the thread "
              "of a notified event that was withdrawn / merged into another")),
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
        if fetch.has_control(target.strip()):
            return None, _bad("webhook_control_char", "no space, CR / LF or other control character in a webhook URL",
                              target[:40], "printable characters only", sid)
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
            "cves": list(row.get("cves") or []), "ghsas": list(row.get("ghsas") or []), "chains": list(row.get("chains") or []),
            "entities": list(row.get("entities") or []), "vendors": list(row.get("entities") or []), "products": [prod.product_id] if prod else [],
            "exchanges": [x for x in EXCHANGES if re.search(rf"\b{re.escape(x.lower())}\b", text)],
            "exploitation": row.get("exploitation") or "none", "amount_usd": row.get("amount_usd_latest"),
            "tx_confirmed": int(row.get("tx_confirmed") or 0),
            "aws_fix_line": row.get("aws_fix_line"), "aws_fix_url": row.get("aws_fix_url"),
            "has_waf_pack": bool(has_waf_pack), "has_verdict": imp.get("status") in ("affected", "not_affected"),
            "team_send": row.get("team_send") is True, "team_send_reason": row.get("team_send_reason"),
            # published by publish._summary; a row from before the field (an older site file) is computed the same way
            "p0_product": p0class.place(row.get("title") or "", list(row.get("entities") or [])).product,
            "cloud_stack": bool(row["cloud_stack"]) if "cloud_stack" in row
            else cloudstack.is_cloud_stack(row.get("title") or "", list(row.get("entities") or [])),
            "impact": {"status": imp.get("status"), "affected": imp.get("affected", 0), "checked": imp.get("checked", 0)}
            if imp else None, "prs": sorted(set(prs or []))}


# a threshold filter reads the view field it bounds (the view keeps the event's own names: it is what subscribers get)
_BOUNDS = {"min_level": "level", "min_loss_usd": "amount_usd", "not_p0_products": "p0_product"}


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
        if FILTER_FIELDS[k][0] == "notlist":     # an exclusion: the event's value must be none of these
            if str(v.get(_BOUNDS[k]) or "").lower() in {x.lower() for x in want}:
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


# The P0 notice (Neo 2026-11-16: one message per P0, the event itself, a summary, emoji, the link said for what it is).
# Built only from the public view — the radar's own repository findings are other kinds and never in it.
_LEVEL = {"V0": "传闻", "V1": "单一来源", "V2": "多方互证", "V3": "已确认", "V4": "已定论"}
_EXPLOITED = {"confirmed": "已确认在野利用", "reported": "有在野利用报道", "poc": "已有 PoC"}
_URL = re.compile(r"https?:/+\S*|\bt\.co/\S*")   # … also a URL the feed cut short ("… $XMR https:/")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# a security account's own alert tag ("#PeckShieldAlert", "#CertiKAlert"): the source, not the story
_ALERT_TAG = re.compile(r"#\w*Alerts?\b\s*", re.IGNORECASE)


def headline(title: str, limit: int = 100) -> str:
    """A title fit for one chat line: no URLs (a tweet's t.co link), no quote marker, no leading hashtag run, other
    hashtags as plain words (live 2026-11-16: "[P0] https://t.co/… > We are actively investigating …")."""
    t = _URL.sub(" ", title or "")
    t = re.sub(r"(^|\s)>\s*", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    t = _ALERT_TAG.sub("", t)
    t = re.sub(r"#(?=\w)", "", t).strip(" ·-—>:")
    return t if len(t) <= limit else t[:limit - 1].rstrip() + "…"


def p0_parts(v: dict[str, Any], link: str) -> dict[str, Any]:
    """The P0 notice's lines, unescaped: rendered as Slack mrkdwn (slack_p0) or plain text (Lark, webhook)."""
    web3 = v.get("domain") == "web3"
    # 2026-11-18, the notice was too long up front: the tag says what it is; whether it is exploited is the 🔥 fact below
    kind = "Web3 被盗" if web3 else "漏洞"
    facts = []
    if web3 and v.get("amount_usd"):
        facts.append(f"💸 损失 {_usd(v['amount_usd'])}")   # 💸: the headline already opens with 💰 (Neo 2026-11-25)
    ids = (v.get("cves") or []) or [g.upper() for g in (v.get("ghsas") or [])]   # the CVE when there is one, else the GHSA
    if not web3 and ids:
        facts.append("🧩 " + ", ".join(ids[:3]) + (f" 等 {len(ids)} 个" if len(ids) > 3 else ""))
    if not web3 and v.get("exploitation") in _EXPLOITED:
        facts.append(f"🔥 {_EXPLOITED[v['exploitation']]}")
    lv = v.get("level") or ""
    facts.append(f"✅ {lv} {_LEVEL.get(lv, '')}".rstrip())
    if v.get("tx_confirmed"):
        facts.append(f"⛓️ 链上攻击交易已确认 {v['tx_confirmed']} 笔")
    what = "原始来源 · 时间线 · 链上证据" if web3 else "原始来源 · 受影响版本与补丁 · 时间线"
    summary = trim_summary((v.get("summary") or "").strip(), v.get("title") or "")
    if "\ufffd" in summary or _CTRL.search(summary):
        summary = ""        # a cut multibyte character (live 2026-11-16: "可被串联,�蜜罐"): no summary beats a broken one
    # first report = the event's first_seen: the publication time of the earliest report the radar holds (Neo
    # 2026-11-16: every notice says when it was first reported)
    first = first_label(v)
    when = [f"🕐 首报 {first}" if first else "🕐 首报时间未知"]
    if not web3 and v.get("aws_fix_line"):     # Neo 2026-11-18: AWS's own fix status, highlighted (radar.awsfix)
        facts_tail = [v["aws_fix_line"]]
    else:
        facts_tail = []
    # its source, a hyperlink in Slack (Neo 2026-11-18): only AWS's own page, built by radar.awsfix from its template
    aws_url = v.get("aws_fix_url") if facts_tail and str(v.get("aws_fix_url") or "").startswith(AWS_FIX_PREFIX) else None
    head = headline(v.get("title") or "")
    # Neo 2026-11-25: a theft and a vulnerability must not look alike in the channel — 💰 (Neo picked it over 💸) marks
    # the money lost; 🚨 stays the vulnerability alarm
    return {"tag": f"P0 · {kind}", "icon": "💰" if web3 else "🚨", "headline": head, "summary": summary, "ids": id_line(v, head),
            # Neo 2026-11-18 「这两句也不要了」: a vulnerability notice carries no facts row (CVE / exploitation / level —
            # the headline names the CVE, the page holds the rest); a theft keeps its loss and corroboration
            "first": "\n".join(when), "aws": facts_tail, "aws_url": aws_url, "show_facts": web3,
            "facts": facts, "link": link, "link_label": f"雷达事件页（{what}）"}


_CVE_PAREN = re.compile(r"\s*[（(]\s*CVE-\d{4}-\d{4,7}(?:\s*[,，、]\s*CVE-\d{4}-\d{4,7})*\s*[)）]")
_SUBJECT = re.compile(r"^(.{1,40}?)(?:是|为)(?=.)")
_WORD = re.compile(r"[A-Za-z][A-Za-z0-9._+-]*")
# 「Oracle已发布修复」「补丁已发布」: a clause that only says a fix exists — the event page and the 🟧 AWS line say which
# (Neo 2026-11-18: 「这句话不重要」). Only a whole clause between separators, never words inside one.
_FIX_CLAUSE = re.compile(r"[，,；;]\s*(?:[^，,；;。]{0,24}?(?:已|均已|现已)?(?:发布|推出|提供)(?:了)?(?:修复|补丁|更新|修复版本)"
                         r"|(?:补丁|修复|修复版本|更新)(?:已|均已|现已)(?:发布|推出|提供)"
                         r"|(?:已|现已)有(?:修复|补丁|修复版本))(?=[，,；;。]|$)")


def trim_summary(summary: str, title: str) -> str:
    """The summary without what the headline already says (2026-11-18, the notice was too long up front): a bracketed CVE id
    (the headline and the 🧩 fact carry it), and a leading subject 「X 是」 made only of names the headline has
    (「OpenJDK 的 Java4Shell 是…」 under 「Java4Shell: … OpenJDK」). A subject with anything else — a version range, a
    component — stays: it is information. Words are cut, never added: the sentence stays the grounded one."""
    out = _CVE_PAREN.sub("", summary)
    m = _SUBJECT.match(out)
    if m:
        subject = m.group(1)
        words = _WORD.findall(subject)
        rest = _WORD.sub("", subject).replace("的", "").strip(" 　,，、")
        low = title.lower()
        if words and not rest and all(w.lower() in low for w in words):
            out = out[m.end():].lstrip(" ，,")
    out = _FIX_CLAUSE.sub("", out)
    return out or summary


AWS_FIX_PREFIX = "https://explore.alas.aws.amazon.com/"     # the one external link a P0 notice may carry (radar.awsfix)


def first_label(v: dict[str, Any]) -> str | None:
    """「2026-11-17 18:22（UTC+8）」, or 「2026-11-17（来源只给日期）」 when the first report gave only a day — never a
    made-up 08:00 (live 2026-11-18: Puppet's KEV entry 「2026-11-17」 was announced as 首报 08:00)."""
    fs = v.get("first_seen")
    if isinstance(fs, str) and timeutil.day_only(fs):
        return f"{fs[:10]}（来源只给日期）"
    return timeutil.utc8(fs)


def id_line(v: dict[str, Any], head: str) -> str | None:
    """A vulnerability notice names its identifier when the headline does not (Neo 11-19: Ruby2Shell went out with a
    GHSA only; when the CVE came the notice had to change so the sent one is edited). None for web3 and when the
    headline already carries every id shown — the common case, so most notices are unchanged."""
    if v.get("domain") == "web3":
        return None
    cves, ghsas = list(v.get("cves") or []), [g for g in (v.get("ghsas") or [])]
    low = head.lower()
    if cves:
        if all(c.lower() in low for c in cves[:3]):
            return None
        tail = f"（{ghsas[0]}）" if ghsas and ghsas[0].lower() not in low else ""
        return "🧩 " + ", ".join(cves[:3]) + (f" 等 {len(cves)} 个" if len(cves) > 3 else "") + tail
    if ghsas:
        return f"🧩 {ghsas[0]}（CVE 待分配）"
    return None


def p0_text(parts: dict[str, Any]) -> str:
    lines = [f"{parts['icon']} [{parts['tag']}] {parts['headline']}"]
    if parts.get("ids"):
        lines.append(parts["ids"])
    if parts["summary"]:
        lines.append(f"📝 {parts['summary']}")
    aws = [f"{x}（{parts['aws_url']}）" if parts.get("aws_url") else x for x in parts.get("aws", [])]
    facts = [" ｜ ".join(parts["facts"])] if parts.get("show_facts", True) and parts["facts"] else []
    lines += [parts["first"], *facts, *aws, f"🔗 {parts['link_label']}：{parts['link']}"]
    return "\n".join(lines)


def gate(m: dict[str, Any], v: dict[str, Any], site_url: str, recent: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The send gate of a P0 notice (Neo 2026-11-16: the Slack path must be a harness). Every rule is a check on the
    message itself, made right before the send; any problem ⇒ not sent, recorded with its code (notify_station).
    `recent` = the P0s this subscription already sent within Limits.NOTIFY_P0_DEDUP_HOURS (other events)."""
    if m.get("kind") != "p0":
        return []
    p, out = m.get("parts") or {}, []

    def bad(code: str, message: str, actual: Any, limit: Any) -> None:
        out.append({"error": code, "message": message, "actual": actual, "limit": limit})
    if v.get("severity") != "P0":                                                                   # G1
        bad("not_p0", "a P0 notice for an event that is not P0", v.get("severity"), "P0")
    h = p.get("headline") or ""
    if len(h) < Limits.NOTIFY_HEADLINE_MIN_CHARS:                                                   # G4
        bad("no_headline", "the headline is empty after cleaning", h, f">= {Limits.NOTIFY_HEADLINE_MIN_CHARS} chars")
    if _URL.search(h) or "t.co/" in h:
        bad("url_in_headline", "a URL in the headline", h[:80], "no URL")
    want = f"{site_url.rstrip('/')}/#/events/{v.get('event_id')}"
    if p.get("link") != want:                                                                       # G5
        bad("link_not_event_page", "the link is not this event's page on the site", p.get("link"), want)
    text = f"{m.get('text', '')}\n{m.get('slack', '')}"
    if "section=env" in text or "代码目标" in text or "补丁 PR" in text:                              # G6
        bad("repository_content", "a P0 notice carries the radar's own repository findings", "env / PR text", "the event only")
    if "\ufffd" in text or _CTRL.search(text):                                                      # G7
        bad("bad_characters", "a replacement or control character in the message", "\\ufffd / control", "none")
    first = first_label(v)                                                                          # G8
    if first and f"首报 {first}" not in (m.get("text") or ""):
        bad("no_first_report_time", "the notice does not say when the event was first reported", None, first)
    # G9 / G10 (Neo 2026-11-19, live: 4 KEV notices withdrawn): a first report that is only a day is not precise enough
    # to push; a vulnerability notice that names no CVE says nothing a reader can act on (「CISA Adds Four Known
    # Exploited Vulnerabilities」, 「We added 4 CVEs …」). Both can resolve — a report with a time, a CVE attached — so
    # they HOLD the notice (HOLD_CODES: not recorded, checked again next run), unlike the rules above.
    if timeutil.day_only(v.get("first_seen")):                                                      # G9
        bad("first_report_day_only", "the first report gives only a day, not a time", v.get("first_seen"), "a time of day")
    if v.get("domain") == "vuln" and not v.get("cves") and not v.get("ghsas"):                      # G10
        # a GitHub advisory id is an identifier too (Neo 11-19: Ruby2Shell, GHSA only, was held ~1 h 50 min until a
        # source revised its title to the CVE); when the CVE comes, the notice is edited (the 🧩 line changes)
        bad("no_cve", "a vulnerability notice that names no CVE or GitHub advisory", [], ">= 1 CVE or GHSA")
    if len(m.get("text") or "") > Limits.NOTIFY_P0_MAX_CHARS:
        bad("too_long", "the notice is longer than one screen line block", len(m.get("text") or ""), Limits.NOTIFY_P0_MAX_CHARS)
    cves, names = set(v.get("cves") or []), {n.lower() for n in (v.get("entities") or []) if len(n) >= 3}   # G3
    for r in recent:
        if r.get("e") == v.get("event_id"):
            continue
        same = (cves & set(r.get("cves") or [])) or (names & set(r.get("names") or []))
        if same:
            bad("duplicate_p0", f"a P0 for the same {'CVE' if cves & set(r.get('cves') or []) else 'victim'} was sent "
                f"within {Limits.NOTIFY_P0_DEDUP_HOURS} h", sorted(same)[:3], r.get("e"))
            break
    return out


# gate codes that can resolve by themselves: the notice is held (checked again every run), never marked as handled
HOLD_CODES = frozenset({"first_report_day_only", "no_cve"})


def held(problems: list[dict[str, Any]]) -> bool:
    """Every problem is one that can resolve (HOLD_CODES): hold the notice instead of dropping it."""
    return bool(problems) and all(p["error"] in HOLD_CODES for p in problems)


def ledger_entry(v: dict[str, Any], at: str) -> dict[str, Any]:
    """What the duplicate rule (gate G3) remembers of a sent P0: its CVEs and its victim names, never free text."""
    return {"e": v.get("event_id"), "at": at, "cves": sorted(v.get("cves") or [])[:20],
            "names": sorted({n.lower() for n in (v.get("entities") or []) if len(n) >= 3})[:20]}


def slack_p0(parts: dict[str, Any]) -> str:
    """Slack mrkdwn: every third-party piece escaped (slack_escape), the link the radar's own (<url|label>)."""
    e = slack_escape
    lines = [f"{parts['icon']} *[{e(parts['tag'])}]* {e(parts['headline'])}"]
    if parts.get("ids"):
        lines.append(e(parts["ids"]))
    if parts["summary"]:
        lines.append(f"📝 {e(parts['summary'])}")
    # the word AWS itself is the link to AWS's page (Neo 2026-11-18: no separate 「AWS 安全中心」 label)
    aws = [e(x).replace("AWS", f"<{parts['aws_url']}|AWS>", 1) if parts.get("aws_url") else e(x) for x in parts.get("aws", [])]
    facts = [e(" ｜ ".join(parts["facts"]))] if parts.get("show_facts", True) and parts["facts"] else []
    lines += [e(parts["first"]), *facts, *aws,
              f"🔗 <{parts['link']}|{e(parts['link_label'])}>"]
    return "\n".join(lines)


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
        parts = p0_parts(v, link)
        out.append({"key": "p0", "kind": "p0", "text": p0_text(parts), "slack": slack_p0(parts), "parts": parts,
                    "also": standing(v)})
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
    # a credentialed call (bot / tenant token): no redirect is followed — urllib would carry Authorization to the new
    # host — and the answer is capped like every other read
    with fetch.urlopen(req, timeout=Limits.HTTP_TIMEOUT_S, allow_hosts=frozenset()) as r:
        return json.loads(r.read(Limits.HTTP_MAX_BYTES))


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
              # a P0 notice carries its own mrkdwn (escaped piece by piece, the link the radar's); other kinds plain text.
              # No unfurl: one compact message, the event page is the place for detail
              {"channel": sub.target, "text": msg.get("slack") or slack_escape(msg["text"]),
               "unfurl_links": False, "unfurl_media": False, **({"thread_ts": thread} if thread else {})},
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


# What the operator's own code says about an event — the code-impact verdict and the patch PRs on its repositories
# (security review, 2026-11): a self-service subscriber (owner false) is someone else, so these never reach it, in a
# message (the verdict / pr kinds are never planned for it) or in a webhook body. Registration refuses filters on them.
OPERATOR_ONLY_FIELDS = ("impact", "prs", "has_verdict")
OPERATOR_ONLY_KINDS = ("verdict", "pr")


def for_subscriber(sub: Subscription, v: dict[str, Any]) -> dict[str, Any]:
    """The event view as this subscription may see it: the owner's whole, anyone else's without OPERATOR_ONLY_FIELDS."""
    return v if sub.owner else {**v, "impact": None, "prs": [], "has_verdict": False}


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
    if fetch._internal_host(host, unresolvable_is_internal=True):
        raise fetch.FetchError("webhook_internal", "the webhook host resolves to a non-public address, or does not resolve")
    with fetch.urlopen(req, timeout=Limits.HTTP_TIMEOUT_S, allow_hosts=frozenset()):
        pass
    return thread or delivery


def update_slack(cfg: dict[str, Any], sub: Subscription, msg: dict[str, Any], ts: str) -> None:
    """chat.update of a P0 notice this bot posted (Neo 2026-11-18: 「后面再持续更新」 — one message per event, edited
    in place). Raises ValueError("slack: message_not_found") when it was deleted."""
    r = _post("https://slack.com/api/chat.update",
              {"channel": sub.target, "ts": ts, "text": msg.get("slack") or slack_escape(msg["text"])},
              {"Authorization": f"Bearer {cfg['slack_bot_token']}"})
    if not r.get("ok"):
        raise ValueError(f"slack: {r.get('error')}")


def rendered(msg: dict[str, Any]) -> str:
    """What a sent notice said, as a short digest: a change (AWS fixed, a corrected title) means an edit."""
    return hashlib.sha256((msg.get("slack") or msg.get("text") or "").encode()).hexdigest()[:16]


_EXPLOITED_REPLY = {"confirmed": "⚠️ 已确认在野利用", "reported": "⚠️ 有在野利用报道"}


def exploited_reply(v: dict[str, Any], link: str) -> dict[str, Any] | None:
    """The one thread reply a P0 notice gets (Neo 2026-11-18): when its vulnerability turns out exploited. An edit does
    not notify anyone; this does."""
    word = _EXPLOITED_REPLY.get(v.get("exploitation") or "")
    if v.get("domain") != "vuln" or not word:
        return None
    # the status and where its evidence is — never the radar's own grading words (live 2026-11-18: the reply read
    # 「有在野利用报道（confirmed: T1 source (datadog_sl)）」, an internal level_reason)
    return {"key": "exploited", "kind": "exploited", "text": f"{word} · 证据见事件页\n{link}"}


SENDERS = {"slack_channel": send_slack, "slack_dm": send_slack, "lark_chat": send_lark, "lark_dm": send_lark,
           "webhook": send_webhook}


if __name__ == "__main__":   # python -m radar.notify --explain
    print(explain())
