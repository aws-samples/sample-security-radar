"""`python -m radar.agentkit.subscriptions list | add --target https://… [--filters JSON] | remove --id …`

Your own webhook subscriptions on a radar (roadmap R7.3). Needs token access whose client was issued with
`--subscribe`. Kept out of the tool table (radar.agentkit.client.TOOLS): the agent tools stay read-only; registering
an endpoint is something a person decides.

`add` writes the signing secret to a 0600 file and prints its path — the secret itself is never printed.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from radar.agentkit.client import TIMEOUT_S, RadarError, _https, _NoRedirect, fetch_token

SCOPE = "radar/subscribe"


def send(method: str, path: str, body: dict[str, Any] | None = None, env: dict[str, str] | None = None) -> Any:
    env = dict(os.environ if env is None else env)
    base = (env.get("RADAR_URL") or "").rstrip("/")
    _https(base, "radar_url")
    if not env.get("RADAR_CLIENT_ID"):
        raise RadarError("token_config_incomplete", "subscriptions need token access (RADAR_CLIENT_ID …)", None, "a client issued with --subscribe")
    headers = {"Authorization": "Bearer " + fetch_token(env, scope=SCOPE), "Accept": "application/json",
               "User-Agent": "security-radar-agentkit"}
    data = None
    if body is not None:
        data, headers["Content-Type"] = json.dumps(body).encode(), "application/json"
    req = urllib.request.Request(f"{base}/api/{path}", data=data, headers=headers, method=method)  # noqa: S310 — base checked by client._https
    try:
        with urllib.request.build_opener(_NoRedirect).open(req, timeout=TIMEOUT_S) as r:  # nosec B310 # nosemgrep
            return json.loads(r.read(200_000))
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read(20_000))
        except ValueError:
            detail = {}
        raise RadarError(detail.get("error") or f"http_{e.code}", detail.get("message") or f"the radar answered HTTP {e.code}",
                         detail.get("actual", e.code), detail.get("limit")) from None
    except urllib.error.URLError as e:
        raise RadarError("unreachable", f"cannot reach the radar: {e.reason}", path, None) from None


def keep_secret(doc: dict[str, Any], directory: Path) -> Path:
    """The creation answer's secret → a 0600 file; the returned document no longer carries it."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"webhook-{doc['id']}.secret"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(doc.pop("secret") + "\n")
    return path


def main(argv: list[str] | None = None, sender: Any = send, directory: Path | None = None) -> int:
    ap = argparse.ArgumentParser(prog="radar.agentkit.subscriptions")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    a = sub.add_parser("add")
    a.add_argument("--target", required=True, help="the https URL the radar will POST to")
    a.add_argument("--filters", default="{}", help='JSON, e.g. \'{"severity": ["P0"], "min_loss_usd": 1000000}\'')
    r = sub.add_parser("remove")
    r.add_argument("--id", required=True)
    args = ap.parse_args(argv)
    try:
        if args.cmd == "list":
            out = sender("GET", "subscriptions")
        elif args.cmd == "remove":
            out = sender("DELETE", f"subscriptions/{args.id}")
        else:
            try:
                filters = json.loads(args.filters)
            except ValueError:
                raise RadarError("bad_filters", "--filters is not JSON", args.filters[:80], "a JSON object") from None
            out = sender("POST", "subscriptions", {"target": args.target, "filters": filters})
            out["secret_file"] = str(keep_secret(out, directory or Path.home() / ".config" / "security-radar"))
        print(json.dumps(out, ensure_ascii=False, indent=1))
        return 0
    except RadarError as e:
        print(json.dumps(e.detail, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
