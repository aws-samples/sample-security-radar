"""Self-service webhook subscriptions (roadmap R7.3): a caller whose Cognito token carries radar/subscribe registers
an https endpoint and filters, lists its own subscriptions and deletes them. The only write the token API offers.

  GET    /api/subscriptions            → the caller's subscriptions (never a signing secret)
  POST   /api/subscriptions            {"target": "https://…", "filters": {…}} → the subscription + its secret, once
  DELETE /api/subscriptions/{id}       → gone (only the caller's own)

Bounds: https only, a DNS name (no IP literal, no userinfo, port 443), SELF_SUBSCRIPTIONS_PER_CLIENT per caller,
SELF_SUBSCRIPTIONS_MAX in all. A subscription belongs to the token's client_id; another client's is "not found".
The store is one Secrets Manager secret (it holds the signing keys); this Lambda can read and write that secret and
nothing else, and runs one at a time (reserved concurrency 1 — a read-modify-write of one document).
The notify station reads the same secret; whether non-owner subscriptions receive anything is still the operator's
rollout switch (radar.notify ROLLOUTS).
"""
from __future__ import annotations

import ipaddress
import json
import os
import secrets
import urllib.parse
from datetime import UTC, datetime
from typing import Any

from radar import fetch, notify
from radar.limits import Limits

SCOPE = "radar/subscribe"
BODY_MAX = 4_000


def _answer(status: int, doc: Any) -> dict[str, Any]:
    return {"statusCode": status, "headers": {"Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store",
                                              "X-Content-Type-Options": "nosniff"}, "body": json.dumps(doc, ensure_ascii=False)}


def _error(status: int, code: str, message: str, actual: Any = None, limit: Any = None) -> dict[str, Any]:
    return _answer(status, {"error": code, "message": message, "actual": actual, "limit": limit})


def target_problem(url: Any) -> dict[str, Any] | None:
    """Why this is not an address the radar will POST to, or None."""
    bad = lambda code, msg, limit: {"error": code, "message": msg, "actual": str(url)[:120], "limit": limit}
    if not isinstance(url, str) or not url or len(url) > 300 or url != url.strip():
        return bad("target_not_url", "target must be an https URL of at most 300 characters", "https://host/path")
    try:
        u = urllib.parse.urlsplit(url)
        port = u.port
    except ValueError:
        return bad("target_not_url", "target does not parse as a URL", "https://host/path")
    host = (u.hostname or "").lower()
    if u.scheme != "https":
        return bad("target_not_https", "a webhook target must be https", "https")
    if u.username is not None or u.password is not None:
        return bad("target_has_credentials", "no user:password in the URL — the request is signed instead", "https://host/path")
    if port not in (None, 443):
        return bad("target_port", "only the default https port", 443)
    try:
        ipaddress.ip_address(host.strip("[]"))
        return bad("target_is_ip", "the host must be a DNS name, not an IP address", "a DNS name")
    except ValueError:
        pass
    if "." not in host or host.endswith((".local", ".internal", ".localhost")) or host == "localhost":
        return bad("target_not_public_name", "the host must be a public DNS name", "a public DNS name")
    # a public-looking name may still resolve to 127.0.0.1 / 10.x / 169.254.169.254 (x.nip.io, a rebinding name): the
    # same resolver check the collector's redirects use (fetch._internal_host); the send repeats it (notify.send_webhook)
    if fetch._internal_host(host):
        return bad("target_not_public", "the host resolves to a non-public address", "a name that resolves to public addresses")
    return None


def _public(s: dict[str, Any]) -> dict[str, Any]:
    return {k: s.get(k) for k in ("id", "channel", "target", "filters", "created_at")}


NOTIFY_STATUS_PK = "SRC#__notify_status__"    # = notify_station.STATUS_KEY as DynamoStore keys it; the one row readable here


def _load_status() -> dict[str, Any]:
    """The notify station's status row: how each subscription fared on the last run. Its own IAM grant is this one item
    (dynamodb:LeadingKeys); a read that fails is said in the answer, never shown as "not delivering"."""
    import boto3
    r = boto3.resource("dynamodb").Table(os.environ["TABLE"]).get_item(Key={"pk": NOTIFY_STATUS_PK, "sk": "STATE"}).get("Item")
    return json.loads(r["d"]) if r else {}


def delivery(status: dict[str, Any], sid: str) -> dict[str, Any]:
    """What the caller may know about its own subscription's last run: the state, when, how many messages, the error
    code (never its message — a send error can quote the target). Unknown until the station has run once."""
    row = (status.get("subscriptions") or {}).get(sid)
    if not row:
        return {"state": "not_run_yet", "at": None}
    state = {"ok": "delivering", "baseline": "delivering", "gated_by_rollout": "held_by_operator", "error": "failing",
             "disabled": "disabled", "not_reached": "delivering"}.get(row.get("status"), row.get("status"))
    return {"state": state, "at": row.get("at"), "sent_last_run": row.get("sent", 0),
            **({"error": (row.get("error") or {}).get("error")} if row.get("status") == "error" else {})}


def _load_secret() -> dict[str, Any]:
    import boto3
    raw = boto3.client("secretsmanager").get_secret_value(SecretId=os.environ["SELF_SUBSCRIPTIONS_ARN"])["SecretString"]
    return json.loads(raw) if raw.strip().startswith("{") else {}     # CDK's placeholder is not JSON ⇒ nothing yet


def _save_secret(doc: dict[str, Any]) -> None:
    import boto3
    boto3.client("secretsmanager").put_secret_value(SecretId=os.environ["SELF_SUBSCRIPTIONS_ARN"], SecretString=json.dumps(doc))


def handler(event: dict[str, Any], _ctx: Any = None, load: Any = None, save: Any = None, now: Any = None,
            status: Any = None) -> dict[str, Any]:
    claims = ((event.get("requestContext") or {}).get("authorizer") or {}).get("claims") or {}
    client = str(claims.get("client_id") or "")
    if SCOPE not in str(claims.get("scope") or "").split() or not client:
        return _error(403, "scope_missing", "the token does not carry the subscribe scope", claims.get("scope"), SCOPE)
    load, save = load or _load_secret, save or _save_secret
    method = event.get("httpMethod")
    doc = load()
    subs: list[dict[str, Any]] = list(doc.get("subscriptions") or [])
    mine = [s for s in subs if s.get("owner_client") == client]
    if method == "GET":
        try:
            st, unread = (status or _load_status)(), None
        except Exception as e:  # noqa: BLE001 — any read failure is reported in the answer, the list is still served
            st, unread = {}, type(e).__name__
        rows = [{**_public(s), "delivery": delivery(st, s["id"]) if unread is None else {"state": "unknown", "error": unread}}
                for s in mine]
        return _answer(200, {"subscriptions": rows, "limit": Limits.SELF_SUBSCRIPTIONS_PER_CLIENT})
    if method == "DELETE":
        sid = (event.get("pathParameters") or {}).get("id") or ""
        if sid not in [s["id"] for s in mine]:
            return _error(404, "not_found", "no such subscription of yours", sid[:60], [s["id"] for s in mine])
        save({**doc, "subscriptions": [s for s in subs if s["id"] != sid]})
        return _answer(200, {"deleted": sid})
    if method != "POST":
        return _error(405, "method_not_allowed", "GET, POST or DELETE", method, ["GET", "POST", "DELETE"])
    raw = event.get("body") or ""
    if len(raw) > BODY_MAX:
        return _error(413, "body_too_large", "the request body is too large", len(raw), BODY_MAX)
    try:
        body = json.loads(raw)
    except ValueError:
        body = None
    if not isinstance(body, dict) or set(body) - {"target", "filters"}:
        return _error(400, "bad_body", 'the body is {"target": "https://…", "filters": {…}}',
                      sorted(body) if isinstance(body, dict) else type(body).__name__, ["target", "filters"])
    if (problem := target_problem(body.get("target"))) is not None:
        return _answer(400, problem)
    if len(mine) >= Limits.SELF_SUBSCRIPTIONS_PER_CLIENT:
        return _error(409, "too_many_subscriptions", "delete one of yours first", len(mine), Limits.SELF_SUBSCRIPTIONS_PER_CLIENT)
    if len(subs) >= Limits.SELF_SUBSCRIPTIONS_MAX:
        return _error(409, "subscriptions_full", "the deployment's self-service subscriptions are full; ask the operator",
                      len(subs), Limits.SELF_SUBSCRIPTIONS_MAX)
    used = {s["id"] for s in subs}
    sid = next(f"s-{client[:16].lower()}-{n}" for n in range(1, Limits.SELF_SUBSCRIPTIONS_MAX + 2)
               if f"s-{client[:16].lower()}-{n}" not in used)
    key = secrets.token_urlsafe(32)
    row = {"id": sid, "channel": "webhook", "target": body["target"], "filters": body.get("filters") or {}, "secret": key}
    parsed, err = notify.parse_subscription(row, {})          # the station's own parser: what is stored is what will parse
    if parsed is None:
        return _answer(400, err or {"error": "bad_subscription", "message": "the subscription does not parse"})
    at = (now or (lambda: datetime.now(UTC)))().strftime("%Y-%m-%dT%H:%M:%SZ")
    save({**doc, "subscriptions": [*subs, {**row, "filters": parsed.filters, "owner": False, "owner_client": client, "created_at": at}]})
    print(json.dumps({"type": "subscription_created", "client_id": client, "id": sid}))      # ids only: no target, no key
    return _answer(201, {**_public({**row, "filters": parsed.filters, "created_at": at}), "secret": key,
                         "note": "the secret is shown once: verify X-Radar-Signature with it. Delivery starts with the next "
                                 "new event that matches, if the operator's rollout includes non-owner subscriptions."})


def merge(cfg: dict[str, Any], self_doc: dict[str, Any]) -> dict[str, Any]:
    """The operator's config + the self-service subscriptions, for the notify station. A self-service row is always a
    webhook and never an owner, whatever the stored row says. The operator's rows come first, so an id used twice
    stays the operator's and the other is reported as duplicate_id (notify.parse_config) — not dropped quietly."""
    own = list(cfg.get("subscriptions") or []) if isinstance(cfg.get("subscriptions"), list) else cfg.get("subscriptions")
    if not isinstance(own, list):
        return cfg                                           # parse_config reports the operator's shape problem
    extra = [{**s, "channel": "webhook", "owner": False} for s in self_doc.get("subscriptions") or []
             if isinstance(s, dict)]
    return {**cfg, "subscriptions": [*own, *extra]}
