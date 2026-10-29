"""Demo-fleet PRs → event pages (C2c). The PRs are opened by scripts/deliver_prs.py in the hourly GitLab schedule,
which has no AWS credentials; this module is the single writer of their links into the radar state.

Pure: links() maps the GitHub pull-request list to {event_id_prefix: {issue_id: url}}; the Respond handler fetches
the list with a read-only, single-repository token (Secrets Manager) and applies it."""

from __future__ import annotations

import re
from typing import Any

BRANCH = re.compile(r"^continuum/([0-9a-f]{8})-")
ISSUE = re.compile(r"\*\*AWS Continuum\*\* issue `([^`]+)`")  # first line of deliver_prs.pr_body — keep in sync


def links(pulls: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    """{'ev_<8 hex>': {issue_id: html_url}} for radar PRs whose body names the Continuum issue they deliver."""
    out: dict[str, dict[str, str]] = {}
    for p in pulls:
        b, m = BRANCH.match((p.get("head") or {}).get("ref", "")), ISSUE.search(p.get("body") or "")
        if b and m:
            out.setdefault(f"ev_{b.group(1)}", {})[m.group(1)] = p["html_url"]
    return out


def apply(st: dict[str, Any], issue_urls: dict[str, str]) -> bool:
    """Fold one event's PR links into its response state; True when something changed."""
    have = st.setdefault("delivered_prs", {})
    new = {k: v for k, v in issue_urls.items() if have.get(k) != v}
    have.update(new)
    return bool(new)


def fetch_pulls(repo: str, token: str) -> list[dict[str, Any]]:
    """All PRs of the demo-fleet repo (read-only token; GitHub REST, 100 per page)."""
    import json
    import urllib.request
    out: list[dict[str, Any]] = []
    for page in range(1, 6):  # ≤ 500 PRs — far above what the demo produces; a bound keeps the station time fixed
        req = urllib.request.Request(f"https://api.github.com/repos/{repo}/pulls?state=all&per_page=100&page={page}",
                                     headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                                              "X-GitHub-Api-Version": "2022-11-28"})
        with urllib.request.urlopen(req, timeout=20) as r:
            batch = json.loads(r.read())
        out += batch
        if len(batch) < 100:
            break
    return out
