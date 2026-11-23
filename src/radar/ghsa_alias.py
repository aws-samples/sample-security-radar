"""R12 (Neo 11-19): link a GitHub advisory id to its CVE, so a GHSA-only event and the CVE's event are one.

Live 11-19, Ruby2Shell: the first reports named GHSA-34m4-m9fh-gqp5 (a REPOSITORY advisory of ruby/ruby, CVE field still
empty hours later); the CVE arrived 7 h later under another, unreviewed global advisory GHSA-8452-w857-wpmw whose
`references` hold the repository advisory's URL — the only link. A plain "look the GHSA up, read cve_id" fails there,
so the lookup goes, per pending GHSA (radar ≤ GHSA_ALIAS_PER_RUN a run, GitHub REST with a read-only token):
  1. GET /advisories/{ghsa}                      — the global database: cve_id / identifiers[type=CVE]
  2. on 404: GET /repos/{o}/{r}/security-advisories/{ghsa}   — owner/repo from a github.com/{o}/{r}/security/advisories/
     URL in the event's reports (a repository advisory is public; its CVE is often still null)
and once a run: GET /advisories?type=unreviewed&modified=>={last}  — a record whose references name a pending GHSA
links it to that record's CVE (the Ruby2Shell shape).
resolve / scan_unreviewed are pure (the getter is injected: (status, json) per URL); github_get is the one credentialed
open — https://api.github.com/ only, never a redirect — so the station file (handlers) holds no credential.
"""
from __future__ import annotations

import http.client
import json
import re
from collections.abc import Callable
from typing import Any

from radar.limits import Limits

KEY = "__ghsa_alias__"               # {"map": {ghsa: {cve, via, at}}, "checked": {ghsa: at}, "scan_at": iso}
API = "https://api.github.com"
HOST = "api.github.com"
_ID = r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}"
# GitHub's own name rules, ASCII only (security review 2026-11-20: \w also matched non-ASCII letters — one report naming
# github.com/<non-ASCII owner>/… built a URL urllib cannot encode and failed the Analyze step every run): an owner is
# letters, digits and hyphens (≤ 39), a repository adds "." and "_" (≤ 100); "." and ".." are refused in repos()
REPO_ADVISORY = re.compile(r"github\.com/([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100})/security/advisories/(" + _ID + ")",
                           re.IGNORECASE | re.ASCII)   # without ASCII, IGNORECASE lets [A-Za-z] match the Kelvin sign and long s
CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")

Get = Callable[[str], tuple[int, Any]]


def _cve_of(adv: dict[str, Any]) -> str | None:
    cve = adv.get("cve_id") or next((i.get("value") for i in adv.get("identifiers") or [] if i.get("type") == "CVE"), None)
    return cve if isinstance(cve, str) and CVE.match(cve) else None


def repo_advisories(texts: list[str]) -> dict[str, tuple[str, str]]:
    """{ghsa (lower-case groups): (owner, repo)} from repository-advisory URLs in report texts / links."""
    out: dict[str, tuple[str, str]] = {}
    for t in texts:
        for o, r, g in REPO_ADVISORY.findall(t or ""):
            if r in (".", "..") or o.startswith("-"):      # a path segment, not a repository
                continue
            out.setdefault("GHSA" + g[4:].lower(), (o, r))
    return out


def resolve(ghsa: str, repos: dict[str, tuple[str, str]], get: Get) -> dict[str, Any]:
    """{"cve": CVE | None, "via": global | repo | not_found | error, "status": http status}."""
    status, adv = get(f"{API}/advisories/{ghsa}")
    if status == 200 and isinstance(adv, dict):
        return {"cve": _cve_of(adv), "via": "global", "status": status}
    if status == 404 and ghsa in repos:
        o, r = repos[ghsa]
        s2, rep = get(f"{API}/repos/{o}/{r}/security-advisories/{ghsa}")
        if s2 == 200 and isinstance(rep, dict):
            return {"cve": _cve_of(rep), "via": "repo", "status": s2, "repo": f"{o}/{r}"}
        return {"cve": None, "via": "not_found" if s2 == 404 else "error", "status": s2}
    return {"cve": None, "via": "not_found" if status == 404 else "error", "status": status}


def scan_unreviewed(pending: set[str], since_iso: str, get: Get) -> dict[str, str]:
    """{pending ghsa: cve} from unreviewed global advisories modified since since_iso whose references name it."""
    if not pending:
        return {}
    status, rows = get(f"{API}/advisories?type=unreviewed&modified=%3E%3D{since_iso[:19]}Z&per_page=100"
                       "&sort=updated&direction=desc")
    if status != 200 or not isinstance(rows, list):
        return {}
    out: dict[str, str] = {}
    for adv in rows:
        cve = _cve_of(adv) if isinstance(adv, dict) else None
        refs = " ".join(str(r) for r in (adv.get("references") or [])).lower() if cve else ""
        for g in pending:
            if cve and g.lower() in refs:
                out.setdefault(g, cve)
    return out


def github_get(token: str) -> Callable[[str], tuple[int, Any]]:
    """GET api.github.com with the read-only advisory token: (status, json); a token never follows a redirect."""
    import urllib.error
    import urllib.request

    from radar import fetch

    seen: dict[str, str] = {}

    def get(url: str) -> tuple[int, Any]:
        if not url.startswith("https://api.github.com/"):      # only the fixed advisory API (radar.ghsa_alias builds the URLs)
            raise ValueError(f"ghsa alias: refused URL {url[:80]}")
        req = urllib.request.Request(url, headers={  # noqa: S310 — https://api.github.com/ only (checked above), opened via fetch.urlopen
            "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
        try:
            with fetch.urlopen(req, timeout=15, allow_hosts=frozenset()) as r:
                # GitHub says when a fine-grained token expires on every authenticated answer: #/ops warns before it does
                if r.headers.get("github-authentication-token-expiration"):
                    seen["token_expires"] = r.headers["github-authentication-token-expiration"]
                return r.status, json.loads(r.read(Limits.HTTP_MAX_BYTES))
        except urllib.error.HTTPError as e:
            return e.code, None
        except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException, ValueError) as e:
            # a timeout, a reset, a non-JSON answer, a URL urllib cannot encode: a failed lookup (status 0), said in the
            # state by the caller — never an exception out of the Analyze step (security review 2026-11-20)
            seen["last_error"] = type(e).__name__
            return 0, None
    get.seen = seen  # type: ignore[attr-defined]
    return get
