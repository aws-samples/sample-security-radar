"""Issue, list and revoke token access to this deployment's read API (roadmap R7.1) — the operator's own AWS credentials.

  AWS_PROFILE=<profile> uv run python scripts/radar-token.py create <name>     # one app client per consumer
  AWS_PROFILE=<profile> uv run python scripts/radar-token.py list
  AWS_PROFILE=<profile> uv run python scripts/radar-token.py revoke <name> --yes
  AWS_PROFILE=<profile> uv run python scripts/radar-token.py usage [--days 7]  # who read how much (from the API's own log)

`create` makes an Amazon Cognito app client (client-credentials grant, scope radar/read, one-hour tokens) and writes
the four values the consumer needs to a 0600 file — the secret is never printed. Hand the file over through a channel
you trust. `revoke` deletes the client: it gets no new token; a token it already holds is accepted until it expires
(at most one hour).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[1]
NAME = re.compile(r"[a-z0-9][a-z0-9-]{1,40}")
PREFIX = "radar-read-"
SCOPE = "radar/read"
WRITE_SCOPE = "radar/subscribe"     # off unless --subscribe: the one write the token API offers


def env_text(site: str, token_url: str, client_id: str, secret: str) -> str:
    return (f"RADAR_URL={site}\nRADAR_TOKEN_URL={token_url}\nRADAR_CLIENT_ID={client_id}\nRADAR_CLIENT_SECRET={secret}\n")


def clients(idp, pool: str) -> dict[str, str]:
    out, tok = {}, None
    while True:
        r = idp.list_user_pool_clients(UserPoolId=pool, MaxResults=60, **({"NextToken": tok} if tok else {}))
        out.update({c["ClientName"][len(PREFIX):]: c["ClientId"] for c in r["UserPoolClients"] if c["ClientName"].startswith(PREFIX)})
        tok = r.get("NextToken")
        if not tok:
            return out


USAGE_QUERY = 'filter type = "api_read" | stats count(*) as reads, max(@timestamp) as last by client_id | sort reads desc'


def usage_rows(results: list[list[dict[str, str]]], names: dict[str, str]) -> list[dict[str, str | int]]:
    """Logs Insights rows → one row per client, named where the client still exists. A client that read and was
    revoked since shows as (revoked): its reads happened."""
    by_id = {cid: n for n, cid in names.items()}
    rows = []
    for r in results:
        f = {c["field"]: c["value"] for c in r}
        cid = f.get("client_id") or ""
        rows.append({"name": by_id.get(cid, "(revoked)"), "client_id": cid, "reads": int(f.get("reads") or 0), "last": f.get("last") or ""})
    seen = {r["client_id"] for r in rows}
    rows += [{"name": n, "client_id": cid, "reads": 0, "last": ""} for n, cid in sorted(names.items()) if cid not in seen]
    return rows


def usage(session, pool_clients: dict[str, str], days: int) -> list[dict[str, str | int]]:
    import time
    cfn, logs = session.client("cloudformation"), session.client("logs")
    group = next(r["PhysicalResourceId"] for page in cfn.get_paginator("list_stack_resources").paginate(StackName="SecurityRadar")
                 for r in page["StackResourceSummaries"] if r["LogicalResourceId"].startswith("ApiFnLogs"))
    now = int(time.time())
    qid = logs.start_query(logGroupName=group, startTime=now - days * 86400, endTime=now, queryString=USAGE_QUERY)["queryId"]
    for _ in range(60):
        got = logs.get_query_results(queryId=qid)
        if got["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
            break
        # polling a Logs Insights query (it has no wait call): one-second steps, at most 60
        time.sleep(1)  # nosemgrep
    if got["status"] != "Complete":
        raise RuntimeError(f"usage query {got['status']}")
    return usage_rows(got["results"], pool_clients)


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create")
    c.add_argument("name")
    c.add_argument("--subscribe", action="store_true", help="also allow the consumer to register its own webhooks (scope radar/subscribe)")
    c.add_argument("--out", type=Path, help="where to write the consumer's env file (default ~/.config/security-radar/clients/<name>.env)")
    sub.add_parser("list")
    u = sub.add_parser("usage")
    u.add_argument("--days", type=int, default=7)
    r = sub.add_parser("revoke")
    r.add_argument("name")
    r.add_argument("--yes", action="store_true")
    a = ap.parse_args()
    out = json.loads((ROOT / "build" / "outputs.json").read_text())["SecurityRadar"]
    pool, token_url, site = out["ApiUserPoolId"], out["ApiTokenUrl"], out["SiteUrl"]
    session = boto3.Session(region_name="ap-northeast-1")
    idp = session.client("cognito-idp")
    have = clients(idp, pool)
    if a.cmd == "usage":
        rows = usage(session, have, a.days)
        for r in rows:
            print(f"{r['name']:24s} {r['reads']:6d} reads  last {r['last'] or '—'}")
        live = sum(1 for r in rows if r["reads"] and r["name"] != "(revoked)")
        gone = sum(1 for r in rows if r["name"] == "(revoked)")
        print(f"{live} of {len(have)} current clients read something in the last {a.days} days"
              + (f"; {gone} revoked since also did" if gone else ""))
        return 0
    if a.cmd == "list":
        for n, cid in sorted(have.items()):
            print(f"{n}\t{cid}")
        print(f"{len(have)} clients")
        return 0
    if not NAME.fullmatch(a.name):
        print(f"bad name {a.name!r}: lower-case letters, digits and '-' (2–41 characters)", file=sys.stderr)
        return 2
    if a.cmd == "create":
        if a.name in have:
            print(f"{a.name} already exists ({have[a.name]}); revoke it first to issue a new secret", file=sys.stderr)
            return 1
        path = a.out or Path.home() / ".config" / "security-radar" / "clients" / f"{a.name}.env"
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)     # never overwrite, never world-readable
        cl = idp.create_user_pool_client(
            UserPoolId=pool, ClientName=PREFIX + a.name, GenerateSecret=True, AllowedOAuthFlowsUserPoolClient=True,
            AllowedOAuthFlows=["client_credentials"], AllowedOAuthScopes=[SCOPE, *([WRITE_SCOPE] if a.subscribe else [])],
            AccessTokenValidity=60,
            TokenValidityUnits={"AccessToken": "minutes"}, EnableTokenRevocation=True)["UserPoolClient"]
        with os.fdopen(fd, "w") as f:
            f.write(env_text(site, token_url, cl["ClientId"], cl["ClientSecret"]))
        print(f"created {a.name} ({cl['ClientId']}); the consumer's settings are in {path} (0600) — the secret is not shown")
        return 0
    if a.name not in have:
        print(f"no client named {a.name}", file=sys.stderr)
        return 1
    if not a.yes:
        print(f"would delete {a.name} ({have[a.name]}) — add --yes")
        return 0
    idp.delete_user_pool_client(UserPoolId=pool, ClientId=have[a.name])
    print(f"revoked {a.name}: no new tokens; a token already issued is accepted until it expires (≤ 60 minutes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
