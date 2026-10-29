"""Mirror the demo targets into the code host each repository channel scans — ONE tool for every channel.

  uv run python scripts/sync-fleet.py --channel github            # dry run: what would change
  uv run python scripts/sync-fleet.py --channel github --apply    # create the private repo if needed, push
  AWS_PROFILE=<your-profile> uv run python scripts/sync-fleet.py --channel gitlab --apply   # + the Continuum integration

Single source: integrations/continuum/targets/<id>/ — only the targets whose channel is <channel>
(src/radar/targets.py CHANNEL); a target that moved to another channel is removed from the mirror (every file in a
mirror is scanned and paid for; a target lives in exactly one environment). Same layout on every host (<target>/...),
so finding locations are identical across channels. Never edit a mirror by hand except to merge Continuum's PRs / MRs.

  github  repo <gh user>/security-radar-demo-fleet via `gh`; push through the credential store. The Continuum GitHub
          integration is a one-time browser App authorization (not scriptable).
  gitlab  gitlab.com project <GITLAB_COM_USER>/security-radar-demo-fleet via the REST API; GITLAB_COM_TOKEN / _USER are
          read from ~/.env (never argv, never printed) and reach git only through a one-shot credential helper. With
          --apply also find-or-create the Continuum integration `<env>-gitlab` (the token goes only to Continuum).
Then set cdk.json `github_repo` / `gitlab_project` and deploy: the respond station keeps the environment (PT0H).
Replaces scripts/sync-demo-fleet.sh (GitHub, bash) and scripts/setup-gitlab-channel.py (GitLab) — R13.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from radar import respond, targets  # src/ is not installed for scripts

REPO = "security-radar-demo-fleet"
TARGETS_DIR = ROOT / "integrations" / "continuum" / "targets"
README = ROOT / "integrations" / "continuum" / "fleet-README.md"
ENV_NAME = os.environ.get("CN_ENV_NAME", "security-radar")
GITLAB_URL = os.environ.get("GITLAB_URL", "https://gitlab.com").rstrip("/")   # self-managed: same value as cdk.json gitlab_url
GITLAB_API = f"{GITLAB_URL}/api/v4"
ENV_LINE = re.compile(r"\s*(?:export\s+)?(GITLAB_COM_TOKEN|GITLAB_COM_USER)=(.*)")


@dataclass(frozen=True)
class Plan:
    remove: tuple[str, ...]     # top-level dirs in the mirror that are no longer on this channel
    copy: tuple[str, ...]       # targets on this channel (always re-copied: the mirror is overwritten, never merged)


def plan(channel: str, existing_dirs: set[str]) -> Plan:
    """Pure: what the mirror must look like for `channel`. `.git` is never touched."""
    if channel not in respond.REPO_CHANNELS:
        raise SystemExit(f"[sync-fleet] unknown channel {channel!r}: one of {sorted(respond.REPO_CHANNELS)}")
    ids = targets.on(channel)
    return Plan(tuple(sorted(d for d in existing_dirs - set(ids) - {".git"})), tuple(ids))


def mirror_dir(channel: str) -> Path:
    # GitHub's clone predates the channel model and kept the plain name; every other host gets a suffix
    return Path(os.environ.get("FLEET_DIR") or Path.home() / "Code" / (REPO if channel == "github" else f"{REPO}-{channel}"))


def read_env() -> dict[str, str]:
    out = {}
    for line in (Path.home() / ".env").read_text(encoding="utf-8").splitlines():
        m = ENV_LINE.fullmatch(line)
        if m:
            out[m.group(1)] = m.group(2).strip().strip("'\"")
    missing = {"GITLAB_COM_TOKEN", "GITLAB_COM_USER"} - {k for k, v in out.items() if v}
    if missing:
        raise SystemExit(f"[sync-fleet] missing in ~/.env: {sorted(missing)} (PAT scopes api, read_repository, write_repository)")
    return out


def run(*cmd: str, cwd: Path | None = None, env: dict[str, str] | None = None, check: bool = True) -> subprocess.CompletedProcess:
    # semgrep dangerous-subprocess-use-audit: argv list (no shell); every caller passes code constants or repo paths
    return subprocess.run(cmd, cwd=cwd, env=env, check=check, capture_output=True, text=True)  # nosemgrep


def gitlab(token: str, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(GITLAB_API + path, method=method, data=json.dumps(body).encode() if body else None,
                                 headers={"PRIVATE-TOKEN": token, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


# ---------------------------------------------------------------- per host: owner, ensure private repo, push

def github_owner(_: dict[str, str]) -> str:
    return run("gh", "api", "user", "--jq", ".login").stdout.strip()


def github_ensure(owner: str, d: Path, _: dict[str, str]) -> None:
    if run("gh", "repo", "view", f"{owner}/{REPO}", check=False).returncode:
        # two steps on purpose: `gh repo create --push` cannot reach the credential store in a non-interactive shell
        run("gh", "repo", "create", REPO, "--private", "--source=.", "--remote=origin",
            "--description", "Deliberately vulnerable demo repositories scanned by Security Radar × AWS Continuum", cwd=d)
    vis = run("gh", "repo", "view", f"{owner}/{REPO}", "--json", "visibility", "--jq", ".visibility").stdout.strip()
    if vis != "PRIVATE":
        raise SystemExit(f"[sync-fleet] {owner}/{REPO} is {vis}: refusing to push demo code to a non-private repo")


def github_push(d: Path, _: dict[str, str]) -> None:
    run("git", "push", "-q", "-u", "origin", "main", cwd=d)     # credential store; never a token in the URL


def gitlab_owner(cfg: dict[str, str]) -> str:
    st, me = gitlab(cfg["GITLAB_COM_TOKEN"], "GET", "/user")
    if st != 200:
        raise SystemExit(f"[sync-fleet] token rejected by {GITLAB_URL}: HTTP {st} {me.get('message', '')} — the Continuum integration "
                         "rotates its token (tokenRotation AUTOMATIC); if this PAT was the one given to it, issue a new one into ~/.env")
    if me.get("username") != cfg["GITLAB_COM_USER"]:
        raise SystemExit(f"[sync-fleet] token belongs to {me.get('username')!r}, GITLAB_COM_USER is {cfg['GITLAB_COM_USER']!r}")
    return cfg["GITLAB_COM_USER"]


def gitlab_ensure(owner: str, d: Path, cfg: dict[str, str]) -> None:
    tok, path = cfg["GITLAB_COM_TOKEN"], f"{owner}/{REPO}"
    st, proj = gitlab(tok, "GET", "/projects/" + urllib.parse.quote(path, safe=""))
    if st == 404:
        st, proj = gitlab(tok, "POST", "/projects", {"name": REPO, "path": REPO, "visibility": "private",
                                                     "description": "Deliberately vulnerable demo repositories scanned "
                                                                    "by Security Radar × AWS Continuum (GitLab channel)"})
    if st not in (200, 201):
        raise SystemExit(f"[sync-fleet] project {path}: HTTP {st} {proj}")
    if proj.get("visibility") != "private":
        raise SystemExit(f"[sync-fleet] {path} is {proj.get('visibility')}: refusing to push demo code to a non-private project")
    if run("git", "remote", "get-url", "origin", cwd=d, check=False).returncode:
        run("git", "remote", "add", "origin", f"{GITLAB_URL}/{path}.git", cwd=d)


def gitlab_push(d: Path, cfg: dict[str, str]) -> None:
    # token via the environment into a one-shot credential helper: never in the URL, argv or stderr
    helper = "!f() { echo username=oauth2; echo \"password=$GL_PUSH_TOKEN\"; }; f"
    run("git", "-c", "credential.helper=", "-c", f"credential.helper={helper}", "push", "-q", "-u", "origin", "main",
        cwd=d, env={**os.environ, "GL_PUSH_TOKEN": cfg["GITLAB_COM_TOKEN"]})


HOSTS = {"github": (github_owner, github_ensure, github_push), "gitlab": (gitlab_owner, gitlab_ensure, gitlab_push)}


def ensure_gitlab_integration(owner: str, cfg: dict[str, str], apply: bool) -> None:
    import boto3
    cn = boto3.client("continuum", region_name="us-east-1")
    name = f"{ENV_NAME}-gitlab"
    found = [i for i in cn.list_integrations().get("items", []) if i.get("name") == name]
    if found or not apply:
        print(f"Continuum integration {name}: {found[0]['integrationId'] if found else 'to create'}")
        return
    r = cn.create_integration(name=name, clientToken=f"{name}-integration", providerConfiguration={"gitlab": {
        "instanceUrl": GITLAB_URL, "targetType": "PROJECT", "targetPath": f"{owner}/{REPO}",
        "accessToken": cfg["GITLAB_COM_TOKEN"]}})
    print(f"Continuum integration {name}: created {r['integrationId']}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--channel", required=True, choices=sorted(respond.REPO_CHANNELS))
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args(argv)
    cfg = read_env() if a.channel == "gitlab" else {}
    owner_of, ensure, push = HOSTS[a.channel]
    owner, d = owner_of(cfg), mirror_dir(a.channel)
    p = plan(a.channel, {x.name for x in d.iterdir() if x.is_dir()} if d.exists() else set())
    print(f"{a.channel}: {owner}/{REPO} ← {list(p.copy)}" + (f"; remove {list(p.remove)}" if p.remove else "") + f"  ({d})")
    if a.channel == "gitlab":
        ensure_gitlab_integration(owner, cfg, a.apply)
    if not a.apply:
        print("dry run — nothing written (add --apply)")
        return 0
    if not (d / ".git").exists():
        d.mkdir(parents=True, exist_ok=True)
        run("git", "init", "-q", "-b", "main", cwd=d)
    ensure(owner, d, cfg)
    run("git", "pull", "-q", "--ff-only", "origin", "main", cwd=d, check=False)   # merged PRs / MRs come back first
    for name in p.remove:
        run("git", "rm", "-rq", name, cwd=d)
    for t in p.copy:
        shutil.rmtree(d / t, ignore_errors=True)
        shutil.copytree(TARGETS_DIR / t, d / t)
    shutil.copy(README, d / "README.md")
    run("git", "add", "-A", cwd=d)
    if run("git", "diff", "--cached", "--quiet", cwd=d, check=False).returncode:     # 1 = staged changes
        sha = run("git", "rev-parse", "--short", "HEAD", cwd=ROOT).stdout.strip()
        run("git", "commit", "-qm", f"sync demo targets from security-radar {sha}", cwd=d)
    push(d, cfg)
    print(f"synced {a.channel}: {owner}/{REPO}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
