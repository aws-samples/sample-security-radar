"""The one reader of a deployed radar's published documents. Standard library only, so the skill can run it anywhere.

  RADAR_URL       https://<site>            (required; http is accepted for 127.0.0.1 / localhost only)
  RADAR_CLIENT_ID / RADAR_CLIENT_SECRET / RADAR_TOKEN_URL
                  token access: an app client issued by the operator (scripts/radar-token.py). The client exchanges
                  it at the deployment's Amazon Cognito token endpoint for a one-hour access token and reads /api/data/…
  RADAR_TOKEN     an access token you already hold (same path)
  RADAR_USER / RADAR_PASSWORD               (the site's Basic Auth gate; used when no token is configured)

Credentials are read from the environment, never printed, and never follow a redirect: the client secret goes only to
RADAR_TOKEN_URL, the token and the Basic credential only to RADAR_URL. A fetched token is cached until shortly before
it expires (memory, and a 0600 file, opened without following symlinks, in a 0700 ~/.cache/security-radar) so a command does not buy a token each time.
"""
from __future__ import annotations

import base64
import errno
import hashlib
import json
import os
import re
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

MAX_BYTES = 8_000_000          # the largest published document today is under 1 MB
TIMEOUT_S = 20
SEARCH_SHARDS_MAX = 36         # months read by one search, newest first
LIMIT_MAX = 100
SEVERITIES = ("P0", "P1", "P2")
DOMAINS = ("vuln", "web3", "incident")
_EVENT_ID = re.compile(r"ev_[0-9a-z]{4,32}")
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_MONTH = re.compile(r"\d{4}-\d{2}")


class RadarError(Exception):
    """code = machine-readable; detail carries what was asked and what is allowed."""

    def __init__(self, code: str, message: str, actual: Any = None, limit: Any = None) -> None:
        super().__init__(f"{code}: {message}")
        self.detail = {"error": code, "message": message, "actual": actual, "limit": limit}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        raise RadarError("redirect_refused", "the radar answered with a redirect; credentials are not sent elsewhere",
                         newurl[:120], "no redirect")


def _https(url: str, what: str) -> None:
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" and not (u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost")):
        raise RadarError(f"bad_{what}", f"{what.upper()} must be an https URL", url[:80] or None, "https://…")


def _cache_file(client_id: str, token_url: str, scope: str = "radar/read") -> Path:
    tag = hashlib.sha256(f"{token_url}\n{client_id}\n{scope}".encode()).hexdigest()[:16]     # a name, not a secret
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "security-radar" / f"token-{tag}.json"


def fetch_token(env: dict[str, str], post: Callable[[str, bytes, dict[str, str]], bytes] | None = None,
                now: Callable[[], float] = time.time, cache: Path | None = None, scope: str = "radar/read") -> str:
    """Client-credentials grant at the deployment's token endpoint → an access token, cached until 60 s before expiry."""
    cid, secret, url = env["RADAR_CLIENT_ID"], env.get("RADAR_CLIENT_SECRET") or "", env.get("RADAR_TOKEN_URL") or ""
    if not secret or not url:
        raise RadarError("token_config_incomplete", "token access needs RADAR_CLIENT_ID, RADAR_CLIENT_SECRET and RADAR_TOKEN_URL",
                         sorted(k for k in ("RADAR_CLIENT_SECRET", "RADAR_TOKEN_URL") if not env.get(k)), "all three set")
    _https(url, "radar_token_url")
    cache = cache or _cache_file(cid, url, scope)
    try:
        held = json.loads(_read_nofollow(cache))
        if held["expires_at"] - 60 > now():
            return str(held["access_token"])
    except (OSError, ValueError, KeyError, TypeError):
        pass    # no cache, or an unreadable one: fetch (the cache is an optimisation, never the source of truth)
    basic = base64.b64encode(f"{cid}:{secret}".encode()).decode()
    body = urllib.parse.urlencode({"grant_type": "client_credentials", "scope": scope}).encode()
    head = {"Authorization": "Basic " + basic, "Content-Type": "application/x-www-form-urlencoded"}
    try:
        raw = (post or _post)(url, body, head)
        doc = json.loads(raw)
        token, ttl = str(doc["access_token"]), int(doc.get("expires_in") or 3600)
    except urllib.error.HTTPError as e:
        why = e.read(2_000).decode("utf-8", "replace") if e.fp else ""
        if "invalid_scope" in why:      # the client exists but was not issued with this permission
            raise RadarError("scope_not_granted", "this client was not issued with the requested permission; ask the operator",
                             scope, "a client created with that scope") from None
        raise RadarError("token_refused", f"the token endpoint answered HTTP {e.code} (wrong or revoked client?)", e.code, 200) from None
    except urllib.error.URLError as e:
        raise RadarError("token_unreachable", f"cannot reach the token endpoint: {e.reason}", url[:80], None) from None
    except (ValueError, KeyError, TypeError):
        raise RadarError("token_malformed", "the token endpoint did not return an access token", None, "access_token") from None
    try:
        _private_dir(cache.parent)
        # O_NOFOLLOW: a symlink planted at the cache path is refused (ELOOP), never written through (security review, 2026-11)
        fd = os.open(cache, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"access_token": token, "expires_at": now() + ttl}, f)
    except OSError as e:
        # an unwritable cache costs one token request per process — said on stderr, so "not cached" is visible
        print(f"security-radar: token cache not written ({type(e).__name__}: {e.strerror or e})", file=sys.stderr)
    return token


def _private_dir(d: Path) -> None:
    """The cache directory: created 0700, and tightened to 0700 if it already exists as a real directory of ours."""
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = os.lstat(d)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
        raise OSError(errno.EPERM, "the cache directory is a symlink or not owned by this user", str(d))
    if stat.S_IMODE(st.st_mode) != 0o700:
        os.chmod(d, 0o700)


def _read_nofollow(p: Path) -> str:
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, encoding="utf-8") as f:
        return f.read(64_000)


def _post(url: str, body: bytes, headers: dict[str, str]) -> bytes:
    req = urllib.request.Request(url, data=body, headers=headers)  # noqa: S310 — _https() checked the token URL
    with urllib.request.build_opener(_NoRedirect).open(req, timeout=TIMEOUT_S) as r:  # nosec B310 # nosemgrep
        return r.read(100_000)


def _auth_header(env: dict[str, str]) -> dict[str, str]:
    if env.get("RADAR_TOKEN"):
        return {"Authorization": "Bearer " + env["RADAR_TOKEN"]}
    if env.get("RADAR_CLIENT_ID"):
        return {"Authorization": "Bearer " + fetch_token(env)}
    if env.get("RADAR_USER") and env.get("RADAR_PASSWORD"):
        raw = f"{env['RADAR_USER']}:{env['RADAR_PASSWORD']}".encode()
        return {"Authorization": "Basic " + base64.b64encode(raw).decode()}
    return {}


def http_get(env: dict[str, str] | None = None) -> Callable[[str], Any]:
    """path under the site (data/…) → parsed JSON. Raises RadarError; never returns a partial document."""
    env = dict(os.environ if env is None else env)
    base = (env.get("RADAR_URL") or "").rstrip("/")
    u = urllib.parse.urlsplit(base)
    local = u.hostname in ("127.0.0.1", "localhost")
    if u.scheme != "https" and not (u.scheme == "http" and local):
        raise RadarError("bad_radar_url", "RADAR_URL must be an https URL", base[:80] or None, "https://<site>")
    headers = {"Accept": "application/json", "User-Agent": "security-radar-agentkit", **_auth_header(env)}
    # a token is checked by the API (/api/data/…); the Basic credential by the site's own gate (/data/…)
    prefix = "api/" if headers.get("Authorization", "").startswith("Bearer ") else ""
    opener = urllib.request.build_opener(_NoRedirect)

    def get(path: str) -> Any:
        req = urllib.request.Request(f"{base}/{prefix}{path.lstrip('/')}", headers=headers)  # noqa: S310 — https enforced on RADAR_URL just above
        try:
            with opener.open(req, timeout=TIMEOUT_S) as r:  # nosec B310 # nosemgrep
                body = r.read(MAX_BYTES + 1)
        except urllib.error.HTTPError as e:
            code = {401: "unauthorized", 403: "forbidden", 404: "not_found"}.get(e.code, "http_error")
            raise RadarError(code, f"the radar answered HTTP {e.code} for {path}", e.code, 200) from None
        except urllib.error.URLError as e:
            raise RadarError("unreachable", f"cannot reach the radar: {e.reason}", path, None) from None
        if len(body) > MAX_BYTES:
            raise RadarError("too_large", f"{path} is larger than the client accepts", len(body), MAX_BYTES)
        try:
            return json.loads(body)
        except ValueError:
            raise RadarError("not_json", f"{path} is not JSON (is RADAR_URL the site root?)", body[:40].decode("utf-8", "replace"), "JSON") from None
    return get


def _limit(n: int | None, default: int = 20) -> int:
    n = default if n is None else int(n)
    if not 1 <= n <= LIMIT_MAX:
        raise RadarError("bad_limit", "limit is out of range", n, f"1..{LIMIT_MAX}")
    return n


def _choice(name: str, v: str | None, allowed: tuple[str, ...]) -> str | None:
    if v is not None and v not in allowed:
        raise RadarError(f"bad_{name}", f"unknown {name}", v, list(allowed))
    return v


def _row(e: dict[str, Any]) -> dict[str, Any]:
    keep = ("event_id", "title", "domain", "severity", "level", "exploitation", "first_seen", "last_updated", "cves",
            "entities", "chains", "amount_usd_latest", "independent_sources", "item_count", "summary")
    return {k: e.get(k) for k in keep}


class Radar:
    def __init__(self, get: Callable[[str], Any] | None = None, now: Callable[[], datetime] | None = None) -> None:
        self._get = get or http_get()
        self._now = now or (lambda: datetime.now(UTC))

    def recent_events(self, severity: str | None = None, domain: str | None = None, hours: int | None = None,
                      limit: int | None = None) -> dict[str, Any]:
        """Events on the live listing (the publish window), newest update first."""
        _choice("severity", severity, SEVERITIES)
        _choice("domain", domain, DOMAINS)
        n = _limit(limit)
        doc = self._get("data/events.json")
        floor = (self._now() - timedelta(hours=int(hours))).strftime("%Y-%m-%dT%H:%M:%SZ") if hours else ""
        rows = [e for e in doc["events"] if (not severity or e["severity"] == severity)
                and (not domain or e["domain"] == domain) and e["last_updated"] >= floor]
        rows.sort(key=lambda e: e["last_updated"], reverse=True)
        return {"generated_at": doc["generated_at"], "matched": len(rows), "returned": min(n, len(rows)),
                "events": [_row(e) for e in rows[:n]]}

    def get_event(self, event_id: str) -> dict[str, Any]:
        """One event: summary, evidence items, timeline, amounts, CVE details, response decisions, rule pack."""
        if not _EVENT_ID.fullmatch(event_id or ""):
            raise RadarError("bad_event_id", "an event id looks like ev_<hex>", event_id, "ev_[0-9a-z]+")
        return self._get(f"data/events/{event_id}.json")

    def search_events(self, query: str, domain: str | None = None, severity: str | None = None,
                      since: str | None = None, limit: int | None = None) -> dict[str, Any]:
        """Every event ever published: all terms must match title / CVE / entity. since = YYYY-MM."""
        _choice("severity", severity, SEVERITIES)
        _choice("domain", domain, DOMAINS)
        if since is not None and not _MONTH.fullmatch(since):
            raise RadarError("bad_since", "since is a month", since, "YYYY-MM")
        terms = [t for t in (query or "").lower().split() if t]
        if not terms:
            raise RadarError("empty_query", "give at least one search term", query, "one or more words")
        n = _limit(limit)
        months = sorted((m["month"] for m in self._get("data/search/index.json")["months"]
                         if not since or m["month"] >= since), reverse=True)
        hits: list[dict[str, Any]] = []
        for month in months[:SEARCH_SHARDS_MAX]:
            for e in self._get(f"data/search/{month}.json")["events"]:
                hay = " ".join([e["t"], *e.get("c", []), *e.get("e", [])]).lower()
                if all(t in hay for t in terms) and (not domain or e["d"] == domain) and (not severity or e["s"] == severity):
                    hits.append({"event_id": e["id"], "title": e["t"], "domain": e["d"], "severity": e["s"], "level": e["l"],
                                 "first_seen": e["f"], "last_updated": e["u"], "cves": e.get("c", []),
                                 "amount_usd": e.get("a"), "has_detail_page": bool(e.get("p"))})
        hits.sort(key=lambda h: h["last_updated"], reverse=True)
        return {"matched": len(hits), "returned": min(n, len(hits)), "months_read": min(len(months), SEARCH_SHARDS_MAX),
                "months_not_read": max(0, len(months) - SEARCH_SHARDS_MAX), "events": hits[:n]}

    def cve_status(self, cve: str) -> dict[str, Any]:
        """Where the radar has seen a CVE: events naming it, most recently updated first; not found is said, not empty."""
        if not _CVE.fullmatch(cve or ""):
            raise RadarError("bad_cve", "a CVE id looks like CVE-2026-12345", cve, "CVE-YYYY-NNNN")
        cve = cve.upper()
        found = [h for h in self.search_events(cve, limit=LIMIT_MAX)["events"] if cve in [c.upper() for c in h["cves"]]]
        return {"cve": cve, "known": bool(found), "events": found}

    def rule_pack(self, event_id: str) -> dict[str, Any]:
        """The event's WAF rule pack as published; absent is said, not an empty pack."""
        pack = self.get_event(event_id).get("rule_pack")
        return {"event_id": event_id, "available": pack is not None, "rule_pack": pack}

    def health(self) -> dict[str, Any]:
        """What needs a human on the radar itself (the ops page) and when it last published."""
        ops = self._get("data/ops.json")
        return {"generated_at": ops["generated_at"], "counts": ops.get("counts"),
                "attention": [{k: i.get(k) for k in ("level", "code", "title", "detail", "since")} for i in ops["attention"]]}

    def feeds(self) -> dict[str, Any]:
        """The Atom / JSON feeds a reader or a script can poll."""
        return self._get("data/feeds/index.json")


# name → (description, JSON-schema properties, required). The CLI and the MCP server are both generated from this table.
TOOLS: dict[str, tuple[str, dict[str, Any], list[str]]] = {
    "recent_events": (("Events on the radar's live listing, newest update first. Filter by severity (P0 most urgent), "
                      "domain and how many hours back."),
                      {"severity": {"type": "string", "enum": list(SEVERITIES)}, "domain": {"type": "string", "enum": list(DOMAINS)},
                       "hours": {"type": "integer", "minimum": 1}, "limit": {"type": "integer", "minimum": 1, "maximum": LIMIT_MAX}}, []),
    "get_event": (("Everything the radar published about one event: evidence items with links, timeline, loss amounts, "
                  "CVE details, attack transactions, response decisions."),
                  {"event_id": {"type": "string"}}, ["event_id"]),
    "search_events": ("Search every event the radar ever published by title, CVE id or victim name (all terms must match).",
                      {"query": {"type": "string"}, "domain": {"type": "string", "enum": list(DOMAINS)},
                       "severity": {"type": "string", "enum": list(SEVERITIES)}, "since": {"type": "string", "description": "YYYY-MM"},
                       "limit": {"type": "integer", "minimum": 1, "maximum": LIMIT_MAX}}, ["query"]),
    "cve_status": ("Whether the radar has seen a CVE, and the events that name it.", {"cve": {"type": "string"}}, ["cve"]),
    "rule_pack": ("The AWS WAF rule pack the radar built for an event (rules with their quoted evidence), if any.",
                  {"event_id": {"type": "string"}}, ["event_id"]),
    "health": ("The radar's own state: when it last published and what needs a human (failed sources, anomalies).", {}, []),
    "feeds": ("The Atom / JSON feeds of published events that can be polled.", {}, []),
}


def call(radar: Radar, name: str, args: dict[str, Any]) -> Any:
    if name not in TOOLS:
        raise RadarError("unknown_tool", "no such tool", name, sorted(TOOLS))
    _, props, required = TOOLS[name]
    extra, missing = sorted(set(args) - set(props)), [r for r in required if args.get(r) in (None, "")]
    if extra or missing:
        raise RadarError("bad_arguments", f"{name}: unknown {extra} / missing {missing}", sorted(args), sorted(props))
    return getattr(radar, name)(**args)
