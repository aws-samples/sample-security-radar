"""Network edge: direct HTTP (conditional GET), firecrawl (key rotation), the X data source. Secrets come from
Secrets Manager in Lambda or env vars locally — never from code or argv."""

from __future__ import annotations

import contextvars
import ipaddress
import json
import math
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from radar.limits import Limits

UA = "security-radar/0.1 (+https://github.com/; contact: owner)"


def _ipv4_first_getaddrinfo(real):
    """Lambda outside a VPC has no IPv6 egress: every IPv6 address fails with Errno 99 (EADDRNOTAVAIL), and
    http.client raises the LAST address's error — so a site whose IPv4 addresses failed for a real reason (timeout,
    refusal) reported only the meaningless Errno 99 (live 2026-11-11, ubuntu_usn). Resolve to IPv4 when the host has
    it; a host with only AAAA records keeps them (the error then says so)."""
    def gai(host, port, family=0, type=0, proto=0, flags=0):
        res = real(host, port, family, type, proto, flags)
        v4 = [r for r in res if r[0] == socket.AF_INET]
        return v4 or res
    return gai


if os.environ.get("AWS_LAMBDA_FUNCTION_NAME") and not getattr(socket.getaddrinfo, "_radar_v4", False):
    socket.getaddrinfo = _ipv4_first_getaddrinfo(socket.getaddrinfo)
    socket.getaddrinfo._radar_v4 = True     # type: ignore[attr-defined]  # once per container (module reloads in tests)


class FetchError(Exception):
    """Machine code + human message + actual value (degradation-and-guards §5)."""

    def __init__(self, code: str, message: str, status: int | None = None, url: str = "") -> None:
        super().__init__(f"{code}: {message} (status={status}, url={url[:120]})")
        # reason = what the server / the stack said, without the URL (a rule that reads the text must not match the URL)
        self.code, self.status, self.url, self.reason = code, status, url, message
        self.retry_after_s: float | None = None     # a 429 / 503's Retry-After, in seconds (R2.5)


@dataclass
class Response:
    status: int
    body: str
    etag: str | None = None
    last_modified: str | None = None


def _on_allowlist(url: str, hosts: frozenset[str]) -> bool:
    """https and a host named exactly (no suffix match: raw.githubusercontent.com.evil.io is another host)."""
    p = urllib.parse.urlsplit(url)
    return p.scheme.lower() == "https" and (p.hostname or "").lower() in hosts


class _GuardedRedirect(urllib.request.HTTPRedirectHandler):
    """Follows a redirect only to https on the same allowlist (urllib's default follows http, https and ftp anywhere)."""

    def __init__(self, hosts: frozenset[str]) -> None:
        self.hosts = hosts

    def redirect_request(self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any,
                         newurl: str) -> urllib.request.Request | None:
        if not _on_allowlist(newurl, self.hosts):
            raise FetchError("redirect_refused", f"redirect to {newurl[:120]} is off the allowlist {sorted(self.hosts)}",
                             code, req.full_url)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_INTERNAL_SUFFIXES = (".localhost", ".internal", ".local", ".localdomain")


def _internal_host(host: str) -> bool:
    """A host a redirect must never reach from a collector: loopback (the Lambda runtime API is 127.0.0.1:9001),
    link-local (169.254.169.254 metadata), private / reserved ranges, and the names that mean "this network". A name
    is resolved too, so `x.nip.io`-style names that map to 10.0.0.1 are caught; the open that follows resolves again
    (a rebinding race remains — the allowlist path is the strict one, for URLs taken from feed content)."""
    h = host.strip("[]").lower().rstrip(".")
    if not h or h == "localhost" or h.endswith(_INTERNAL_SUFFIXES):
        return True
    def bad(a: str) -> bool:
        ip = ipaddress.ip_address(a.split("%")[0])
        return not ip.is_global or ip.is_multicast
    try:
        return bad(h)
    except ValueError:
        pass                                # a name, not an address literal
    try:
        return any(bad(r[4][0]) for r in socket.getaddrinfo(h, None))
    except (socket.gaierror, UnicodeError):
        return False                        # unresolvable: the open itself fails with the real DNS error


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """The default for every fetch without an allowlist (roadmap R2.8). urllib follows any redirect: https → http
    (a downgrade a network attacker can then rewrite), and into the account's own network. Refused here, as a
    FetchError the source health ledger shows by name."""

    def redirect_request(self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any,
                         newurl: str) -> urllib.request.Request | None:
        old, new = urllib.parse.urlsplit(req.full_url), urllib.parse.urlsplit(newurl)
        scheme = new.scheme.lower()
        why = ("non-http scheme" if scheme not in ("http", "https") else
               "https → http downgrade" if old.scheme.lower() == "https" and scheme == "http" else
               "internal address" if _internal_host(new.hostname or "") else "")
        if why:
            raise FetchError("redirect_refused", f"redirect to {newurl[:120]} refused: {why}", code, req.full_url)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# R2.5 per-source time budget. Socket timeouts bound one call, not a source: a direct read timeout (25 s) followed by
# the firecrawl fallback (60 s) held one batch thread 86 s (live 2026-11-13, ex_bit2me), and a source with follow-up
# fetches (60 CVE records) makes up to 60 calls. A contextvar, not a parameter: every call site in between keeps its
# signature, and a thread that never entered a budget (scripts, tests, the X profile pool) has none.
_DEADLINE: contextvars.ContextVar[float | None] = contextvars.ContextVar("radar_source_deadline", default=None)


@contextmanager
def source_budget(seconds: float) -> Iterator[None]:
    """Every urlopen inside shares `seconds` of wall time: each call's timeout is clamped to what is left, and a call
    with less than Limits.SOURCE_BUDGET_MIN_CALL_S left is refused as FetchError("source_budget")."""
    tok = _DEADLINE.set(time.monotonic() + seconds)
    try:
        yield
    finally:
        _DEADLINE.reset(tok)


def budget_spent(e: Exception) -> bool:
    """The source ran out of time — not this item's fault: a follow-up loop defers it without counting a miss."""
    return isinstance(e, FetchError) and e.code == "source_budget"


def _clamped(timeout: float, url: str) -> float:
    d = _DEADLINE.get()
    if d is None:
        return timeout
    left = d - time.monotonic()
    if left < Limits.SOURCE_BUDGET_MIN_CALL_S:
        raise FetchError("source_budget", f"the source's {Limits.SOURCE_BUDGET_S} s budget is spent "
                                          f"({max(0.0, left):.1f} s left)", None, url)
    return min(timeout, left)


def urlopen(req: urllib.request.Request | str, timeout: float, allow_hosts: frozenset[str] | None = None) -> Any:
    """THE one place the radar opens a URL (bandit B310 / semgrep dynamic-urllib): http(s) only — a `file:` or custom
    scheme reaching here (a feed URL, a registry typo) is refused as a network error, never opened. Every module and
    script calls this instead of urllib.request.urlopen. `allow_hosts` (a URL taken from feed content) also confines
    every redirect hop to https on those hosts."""
    url = req.full_url if isinstance(req, urllib.request.Request) else req
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in ("https", "http"):
        raise urllib.error.URLError(f"refusing {scheme or 'relative'!r} URL (http/https only)")
    redirect = _GuardedRedirect(allow_hosts) if allow_hosts is not None else _SafeRedirect()
    return _open(req, timeout=_clamped(timeout, url), redirect=redirect)


def _open(req: urllib.request.Request | str, timeout: float, redirect: urllib.request.HTTPRedirectHandler) -> Any:
    """The socket seam (tests replace this one function). Every open carries a redirect policy — there is no path to
    urllib's follow-anything default."""
    return urllib.request.build_opener(redirect).open(req, timeout=timeout)  # nosec B310 # nosemgrep — scheme checked in urlopen


def _gunzip(raw: bytes, status: int, url: str) -> bytes:
    """gzip body → bytes, never more than HTTP_MAX_BYTES out. Why (docs/research/action/05 §3.7): the cap was applied to
    the compressed body only, so a 20 MB gzip bomb could expand to GBs and OOM the Collect Lambda — failing every source
    of its batch. Every member is read, as gzip.decompress did. A member cut before its end-of-stream marker (a dropped
    connection) or corrupt data fails the fetch, as gzip.decompress did (EOFError / BadGzipFile): returning the partial
    output would hand a partial feed over as if the run had succeeded."""
    out, rest = bytearray(), raw
    while rest:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            out += d.decompress(rest, Limits.HTTP_MAX_BYTES + 1 - len(out))
        except zlib.error as e:
            raise FetchError("bad_gzip", f"corrupt gzip body: {e}", status, url) from e
        if len(out) > Limits.HTTP_MAX_BYTES or d.unconsumed_tail:
            raise FetchError("too_large", f"gzip body expands past {Limits.HTTP_MAX_BYTES} bytes", status, url)
        if not d.eof:
            raise FetchError("bad_gzip", f"gzip body truncated after {len(raw)} bytes in, {len(out)} out", status, url)
        rest = d.unused_data.lstrip(b"\0")     # next member; zero padding between members is allowed (gzip.decompress)
    return bytes(out)


def http_get(url: str, headers: dict[str, str] | None = None, etag: str | None = None,
             last_modified: str | None = None, allow_hosts: frozenset[str] | None = None,
             post_json: str | None = None) -> Response:
    """`allow_hosts`: the URL came from feed content (collect.FOLLOWUP_HOSTS) — https on those hosts only, redirects
    included; anything else is refused before a request is made. `post_json`: the registry's body for an API that
    answers only to POST (registry.Source.post_json) — no conditional headers then (a POST is not cacheable)."""
    if allow_hosts is not None and not _on_allowlist(url, allow_hosts):
        raise FetchError("host_not_allowed", f"follow-up URL is off the allowlist {sorted(allow_hosts)}", None, url)
    h = {"User-Agent": UA, "Accept-Encoding": "gzip", **(headers or {})}
    if post_json is not None:
        h.update({"Content-Type": "application/json", "Accept": "application/json"})
    else:
        if etag:
            h["If-None-Match"] = etag
        if last_modified:
            h["If-Modified-Since"] = last_modified
    req = urllib.request.Request(url, headers=h, data=post_json.encode() if post_json is not None else None,  # noqa: S310 — fetch.urlopen refuses non-http(s) schemes
                                 method="POST" if post_json is not None else "GET")
    try:
        with urlopen(req, timeout=Limits.HTTP_TIMEOUT_S, allow_hosts=allow_hosts) as r:
            raw = r.read(Limits.HTTP_MAX_BYTES + 1)
            if len(raw) > Limits.HTTP_MAX_BYTES:
                raise FetchError("too_large", f"body exceeds {Limits.HTTP_MAX_BYTES} bytes", r.status, url)
            if r.headers.get("Content-Encoding") == "gzip":
                raw = _gunzip(raw, r.status, url)
            charset = r.headers.get_content_charset() or "utf-8"
            return Response(r.status, raw.decode(charset, "replace"), r.headers.get("ETag"), r.headers.get("Last-Modified"))
    except urllib.error.HTTPError as e:
        if e.code == 304:
            return Response(304, "", etag, last_modified)
        err = FetchError("http_error", e.reason or "HTTP error", e.code, url)
        err.retry_after_s = retry_after(e.headers.get("Retry-After") if e.headers else None, time.time())
        raise err from e
    except (urllib.error.URLError, TimeoutError) as e:
        raise FetchError("network_error", str(getattr(e, "reason", e)), None, url) from e


def retry_after(value: str | None, now_s: float) -> float | None:
    """Retry-After as seconds from now: delta-seconds or an HTTP date (RFC 9110 §10.2.3); unparsable ⇒ None."""
    if not value:
        return None
    v = value.strip()
    if v.isdigit():
        return float(v)
    try:
        from email.utils import parsedate_to_datetime
        return max(0.0, parsedate_to_datetime(v).timestamp() - now_s)
    except (TypeError, ValueError):
        return None


@lru_cache(maxsize=1)
def secrets() -> dict[str, Any]:
    """Lambda: JSON secret at $SECRET_ARN. Local: env vars. Missing values surface as errors at use time."""
    arn = os.environ.get("SECRET_ARN")
    if arn:
        import boto3  # Lambda runtime provides boto3; keep import off the local hot path
        return json.loads(boto3.client("secretsmanager").get_secret_value(SecretId=arn)["SecretString"])
    fc = [os.environ[k] for k in sorted(os.environ) if k.startswith("FIRECRAWL_API_KEY") and os.environ[k]]
    return {"X_API_KEY": os.environ.get("X_API_KEY", ""), "FIRECRAWL_API_KEYS": fc}


def _firecrawl_scrape(url: str, formats: list[str], timeout: float = 60) -> dict[str, Any]:
    """One firecrawl /v2/scrape → its `data`; keys rotate on auth / credit / rate errors (same policy as the local fc.py).
    A target that answered with an error page (firecrawl succeeded, the site refused) is an error, not content."""
    keys_ = list(secrets().get("FIRECRAWL_API_KEYS") or [])
    if not keys_:
        raise FetchError("no_credentials", "FIRECRAWL_API_KEYS not configured", None, url)
    body = json.dumps({"url": url, "formats": formats, "maxAge": 0}).encode()
    last: FetchError | None = None
    for k in keys_:
        req = urllib.request.Request("https://api.firecrawl.dev/v2/scrape", data=body, method="POST",
                                     headers={"Authorization": f"Bearer {k}", "Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=timeout) as r:
                raw = r.read(Limits.HTTP_MAX_BYTES + 1)
            if len(raw) > Limits.HTTP_MAX_BYTES:    # a scrape is one page; a runaway answer must not OOM the Lambda
                raise FetchError("too_large", "firecrawl response exceeds the cap", None, url)
            data = json.loads(raw).get("data") or {}
        except urllib.error.HTTPError as e:
            last = FetchError("firecrawl_error", e.reason or "error", e.code, url)
            if e.code not in (401, 402, 429):
                raise last from e
            continue
        upstream = (data.get("metadata") or {}).get("statusCode")
        if upstream and upstream >= 400:  # e.g. a WAF 405 page
            raise FetchError("upstream_blocked", "target returned an error page via firecrawl", upstream, url)
        return data
    raise last or FetchError("firecrawl_error", "all keys exhausted", None, url)


def firecrawl_raw(url: str) -> str:
    """rawHtml through firecrawl for sites that block AWS egress. NOT for JSON APIs: rawHtml corrupts JSON
    whose strings contain markup (research/05: GHSA truncated at the first HTML payload)."""
    return _firecrawl_scrape(url, ["rawHtml"]).get("rawHtml") or ""


def twitterapi_unavailable(e: FetchError) -> bool:
    """the X data source has no key / no credit / no quota left (429 after the retries) — the X fallback's trigger. Any other
    failure (5xx, a parse error) is twitterapi being broken: reported as usual, never paid for with firecrawl credits."""
    return e.code == "no_credentials" or e.status in (401, 402, 429)


def firecrawl_x_profiles(handles: tuple[str, ...]) -> str:
    """Profile snapshots x.com/<handle> (≤5 latest posts each) scraped concurrently. One handle failing is listed in
    failed_handles; all failing raises. Body: {"profiles": {handle: markdown}, "failed_handles", "credits", "via"}."""
    from concurrent.futures import ThreadPoolExecutor

    def one(h: str) -> tuple[str, str | None, int]:
        try:
            d = _firecrawl_scrape(f"https://x.com/{h}", ["markdown"], timeout=Limits.X_FIRECRAWL_TIMEOUT_S)
        except FetchError:
            return h, None, 0
        return h, d.get("markdown") or "", int((d.get("metadata") or {}).get("creditsUsed") or Limits.FIRECRAWL_CREDITS_X_PROFILE)

    with ThreadPoolExecutor(Limits.X_FIRECRAWL_CONCURRENCY) as pool:
        got = list(pool.map(one, handles))
    profiles = {h: md for h, md, _ in got if md is not None}
    if not profiles:
        raise FetchError("firecrawl_x_failed", f"all {len(handles)} profile snapshots failed", None, "https://x.com/")
    return json.dumps({"profiles": profiles, "failed_handles": [h for h, md, _ in got if md is None],
                       "credits": sum(c for _, _, c in got), "via": "firecrawl"})


def twitterapi_search(handles: tuple[str, ...], cadence_min: int, max_pages: int = 2,
                      since_minutes: float | None = None) -> str:
    """One OR-query over all handles. Window = 2× cadence, or back to the last successful run when that is longer
    (R2.4, audit 01 #6: after a failed run the next window did not reach back, and the gap was lost silently), capped
    at Limits.X_WINDOW_MAX_H. Overlap is deduped by item id. Returns a body shaped like a single advanced_search page
    (tweets merged across pages) plus "truncated": true when the page limit ended the search with pages left."""
    key = secrets().get("X_API_KEY")
    if not key:
        raise FetchError("no_credentials", "X_API_KEY not configured")
    if not os.environ.get("X_SEARCH_URL"):
        raise FetchError("no_endpoint", "X_SEARCH_URL not configured (bring an X data source you are licensed to use)")
    minutes = max(2 * cadence_min, (since_minutes or 0) + cadence_min)
    hours = max(1, min(Limits.X_WINDOW_MAX_H, math.ceil(minutes / 60)))
    q = "(" + " OR ".join(f"from:{h}" for h in handles) + f") within_time:{hours}h"
    tweets: list[dict[str, Any]] = []
    cursor, truncated = "", False
    for page in range(max_pages):
        url = os.environ["X_SEARCH_URL"] + "?" + urllib.parse.urlencode(
            {"query": q, "queryType": "Latest", "cursor": cursor})
        d = json.loads(_twitterapi_get(url, key))
        tweets += d.get("tweets") or []
        if not d.get("has_next_page") or not d.get("next_cursor"):
            break
        if page == max_pages - 1:
            truncated = True                 # pages left: the oldest part of the window was not read
            break
        cursor = d["next_cursor"]
        time.sleep(Limits.TWITTERAPI_MIN_INTERVAL_S)  # stay under the per-key request rate between pages
    return json.dumps({"tweets": tweets, **({"truncated": True} if truncated else {})})


def _twitterapi_get(url: str, key: str) -> str:
    for attempt in range(Limits.TWITTERAPI_RETRIES + 1):
        try:
            return http_get(url, {"x-api-key": key}).body
        except FetchError as e:
            if e.status != 429 or attempt == Limits.TWITTERAPI_RETRIES:
                raise
            time.sleep(Limits.TWITTERAPI_MIN_INTERVAL_S * (attempt + 1))  # documented: wait briefly, retry
    raise AssertionError("unreachable")
