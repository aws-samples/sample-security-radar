"""Network edge: direct HTTP (conditional GET), firecrawl (key rotation), the X data source. Secrets come from
Secrets Manager in Lambda or env vars locally — never from code or argv."""

from __future__ import annotations

import gzip
import json
import math
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from radar.limits import Limits

UA = "security-radar/0.1 (+https://github.com/; contact: owner)"


class FetchError(Exception):
    """Machine code + human message + actual value (degradation-and-guards §5)."""

    def __init__(self, code: str, message: str, status: int | None = None, url: str = "") -> None:
        super().__init__(f"{code}: {message} (status={status}, url={url[:120]})")
        self.code, self.status, self.url = code, status, url


@dataclass
class Response:
    status: int
    body: str
    etag: str | None = None
    last_modified: str | None = None


def urlopen(req: urllib.request.Request | str, timeout: float) -> Any:
    """THE one place the radar opens a URL (bandit B310 / semgrep dynamic-urllib): http(s) only — a `file:` or custom
    scheme reaching here (a feed URL, a registry typo) is refused as a network error, never opened. Every module and
    script calls this instead of urllib.request.urlopen."""
    url = req.full_url if isinstance(req, urllib.request.Request) else req
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in ("https", "http"):
        raise urllib.error.URLError(f"refusing {scheme or 'relative'!r} URL (http/https only)")
    return urllib.request.urlopen(req, timeout=timeout)  # nosec B310 # nosemgrep — scheme checked on the line above


def http_get(url: str, headers: dict[str, str] | None = None, etag: str | None = None,
             last_modified: str | None = None) -> Response:
    h = {"User-Agent": UA, "Accept-Encoding": "gzip", **(headers or {})}
    if etag:
        h["If-None-Match"] = etag
    if last_modified:
        h["If-Modified-Since"] = last_modified
    req = urllib.request.Request(url, headers=h)
    try:
        with urlopen(req, timeout=Limits.HTTP_TIMEOUT_S) as r:
            raw = r.read(Limits.HTTP_MAX_BYTES + 1)
            if len(raw) > Limits.HTTP_MAX_BYTES:
                raise FetchError("too_large", f"body exceeds {Limits.HTTP_MAX_BYTES} bytes", r.status, url)
            if r.headers.get("Content-Encoding") == "gzip":
                raw = gzip.decompress(raw)
            charset = r.headers.get_content_charset() or "utf-8"
            return Response(r.status, raw.decode(charset, "replace"), r.headers.get("ETag"), r.headers.get("Last-Modified"))
    except urllib.error.HTTPError as e:
        if e.code == 304:
            return Response(304, "", etag, last_modified)
        raise FetchError("http_error", e.reason or "HTTP error", e.code, url) from e
    except (urllib.error.URLError, TimeoutError) as e:
        raise FetchError("network_error", str(getattr(e, "reason", e)), None, url) from e


@lru_cache(maxsize=1)
def secrets() -> dict[str, Any]:
    """Lambda: JSON secret at $SECRET_ARN. Local: env vars. Missing values surface as errors at use time."""
    arn = os.environ.get("SECRET_ARN")
    if arn:
        import boto3  # Lambda runtime provides boto3; keep import off the local hot path
        return json.loads(boto3.client("secretsmanager").get_secret_value(SecretId=arn)["SecretString"])
    fc = [os.environ[k] for k in sorted(os.environ) if k.startswith("FIRECRAWL_API_KEY") and os.environ[k]]
    return {"X_API_KEY": os.environ.get("X_API_KEY", ""), "FIRECRAWL_API_KEYS": fc}


def firecrawl_raw(url: str) -> str:
    """rawHtml through firecrawl for sites that block AWS egress. NOT for JSON APIs: rawHtml corrupts JSON
    whose strings contain markup (research/05: GHSA truncated at the first HTML payload)."""
    keys_ = list(secrets().get("FIRECRAWL_API_KEYS") or [])
    if not keys_:
        raise FetchError("no_credentials", "FIRECRAWL_API_KEYS not configured", None, url)
    body = json.dumps({"url": url, "formats": ["rawHtml"], "maxAge": 0}).encode()
    last: FetchError | None = None
    for k in keys_:  # rotate on auth/credit/rate errors, same policy as the local fc.py
        req = urllib.request.Request("https://api.firecrawl.dev/v2/scrape", data=body, method="POST",
                                     headers={"Authorization": f"Bearer {k}", "Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=60) as r:
                data = json.loads(r.read()).get("data") or {}
        except urllib.error.HTTPError as e:
            last = FetchError("firecrawl_error", e.reason or "error", e.code, url)
            if e.code not in (401, 402, 429):
                raise last from e
            continue
        upstream = (data.get("metadata") or {}).get("statusCode")
        if upstream and upstream >= 400:  # firecrawl succeeded, the target site refused (e.g. WAF 405 page)
            raise FetchError("upstream_blocked", "target returned an error page via firecrawl", upstream, url)
        return data.get("rawHtml") or ""
    raise last or FetchError("firecrawl_error", "all keys exhausted", None, url)


def twitterapi_search(handles: tuple[str, ...], cadence_min: int, max_pages: int = 2) -> str:
    """One OR-query over all handles, window = 2× cadence (overlap is deduped by item id).
    Returns a body shaped like a single advanced_search page (tweets merged across pages)."""
    key = secrets().get("X_API_KEY")
    if not key:
        raise FetchError("no_credentials", "X_API_KEY not configured")
    if not os.environ.get("X_SEARCH_URL"):
        raise FetchError("no_endpoint", "X_SEARCH_URL not configured (bring an X data source you are licensed to use)")
    hours = max(1, math.ceil(2 * cadence_min / 60))
    q = "(" + " OR ".join(f"from:{h}" for h in handles) + f") within_time:{hours}h"
    tweets: list[dict[str, Any]] = []
    cursor = ""
    for _ in range(max_pages):
        url = os.environ["X_SEARCH_URL"] + "?" + urllib.parse.urlencode(
            {"query": q, "queryType": "Latest", "cursor": cursor})
        d = json.loads(_twitterapi_get(url, key))
        tweets += d.get("tweets") or []
        if not d.get("has_next_page") or not d.get("next_cursor"):
            break
        cursor = d["next_cursor"]
        time.sleep(Limits.TWITTERAPI_MIN_INTERVAL_S)  # stay under the per-key request rate between pages
    return json.dumps({"tweets": tweets})


def _twitterapi_get(url: str, key: str) -> str:
    for attempt in range(Limits.TWITTERAPI_RETRIES + 1):
        try:
            return http_get(url, {"x-api-key": key}).body
        except FetchError as e:
            if e.status != 429 or attempt == Limits.TWITTERAPI_RETRIES:
                raise
            time.sleep(Limits.TWITTERAPI_MIN_INTERVAL_S * (attempt + 1))  # documented: wait briefly, retry
    raise AssertionError("unreachable")
