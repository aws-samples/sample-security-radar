"""Deliver AWS Continuum patches as GitHub pull requests on the demo-fleet repository.

Continuum (code vulnerabilities, preview) produces a git patch per issue but does not open pull requests: GitHub
sources are off in the production preview and PR delivery is not implemented for code vulnerabilities while the GitHub source was unavailable). The radar
therefore delivers the patch itself: one branch + PR per (event, target), only for issues Continuum judged EXPLOITABLE.
A human still reviews and merges — that stays the one human step in the loop.

Reads only the published site (CloudFront, Basic Auth) and writes only to GitHub — no AWS credentials, so it runs in
the hourly GitLab schedule (C2c). The PR links flow
back into the event pages through the Respond Lambda's read-only PR sync (radar/prsync.py), the single writer.

  RADAR_SITE_URL=… RADAR_UI_USER=… RADAR_UI_PASSWORD=… uv run python scripts/deliver_prs.py          # dry run
  … uv run python scripts/deliver_prs.py --open   # push branches + open PRs (idempotent); gh uses GH_TOKEN
Locally the three RADAR_* values come from build/outputs.json (SiteUrl) and the UiSecretArn secret.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import urllib.request
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from radar import fetch

REPO = os.environ.get("FLEET_REPO", "your-org/security-radar-demo-fleet")
TARGETS = ROOT / "integrations" / "continuum" / "targets"


def sh(*a: str, cwd: Path | None = None) -> str:
    # semgrep dangerous-subprocess-use-audit: argv list (no shell); every caller passes code constants or repo paths
    return subprocess.run(a, cwd=cwd, capture_output=True, text=True, check=True).stdout  # nosemgrep # nosec B603


def site_reader(url: str, user: str, password: str) -> Callable[[str], bytes]:
    auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()

    def get(path: str) -> bytes:
        req = urllib.request.Request(f"{url.rstrip('/')}/data/{path}", headers={"Authorization": auth})
        with fetch.urlopen(req, timeout=30) as r:
            return r.read()
    return get


def responses(get: Callable[[str], bytes]) -> list[dict]:
    """Events whose published response is past eligibility — the same rows respond_status.py prints."""
    out = []
    for row in json.loads(get("events.json"))["events"]:
        if not row.get("impact"):
            continue
        r = json.loads(get(f"events/{row['event_id']}.json")).get("response") or {}
        if r.get("issues"):
            out.append({"event_id": row["event_id"], "reason": r.get("reason", ""), "issues": r["issues"]})
    return out


def plan(resps: list[dict], get: Callable[[str], bytes]) -> list[dict]:
    """One PR per (event, target): several issues on one repo yield overlapping patches; keep the widest one.
    An (event, target) that already has a PR is skipped: once Continuum's GitHub environment is live (2026-10-27,) the same finding is validated in both environments and Continuum opens the native PR for its
    GitHub-environment issue — delivering the S3-environment patch too would give one fix two PRs."""
    seen: set[str] = set()
    cands = []
    has_pr = {(r["event_id"], target_of(get(i["patch_path"]).decode()))
              for r in resps for i in r["issues"] if i.get("pr_url") and i.get("patch_path")}
    for r in resps:
        for i in r["issues"]:
            if i.get("exploitable") != "EXPLOITABLE" or not i.get("patch_path"):
                continue
            body = get(i["patch_path"]).decode()
            h = hashlib.sha256(body.encode()).hexdigest()[:10]
            if h in seen:
                continue  # several issues often share one patch
            seen.add(h)
            tgt = target_of(body)
            if (r["event_id"], tgt) in has_pr:
                continue  # native (or earlier) PR exists for this event on this repo
            cands.append({"event": r["event_id"], "reason": r["reason"], "issue": i, "patch": body, "target": tgt})
    best: dict[tuple[str, str | None], dict] = {}
    for p in cands:
        k = (p["event"], p["target"])
        if k not in best or p["patch"].count("\n--- a/") > best[k]["patch"].count("\n--- a/"):
            best[k] = p
    return list(best.values())


def branch_of(p: dict) -> str:
    return f"continuum/{p['event'][3:11]}-{p['target'] or 'unknown'}"


def _hunks(patch: str) -> dict[str, list[str]]:
    """file → the lines a hunk expects to find there (context ' ' and removed '-' lines)."""
    out: dict[str, list[str]] = {}
    cur = None
    for ln in patch.splitlines():
        if ln.startswith("--- a/"):
            cur = out.setdefault(ln[6:], [])
        elif ln.startswith(("+++ ", "@@", "diff ", "index ")) or cur is None:
            continue
        elif ln[:1] in (" ", "-"):
            cur.append(ln[1:])
    return out


def target_of(patch: str, root: Path = TARGETS) -> str | None:
    """The one demo target the patch applies to. Patch paths are repo-relative and ambiguous (every target has a
    Dockerfile; live 2026-10-27: a Node.js Dockerfile patch was matched to demo-shop by name alone), so a target
    must contain every file AND every line the hunks expect. None (skipped, printed) unless exactly one matches."""
    hunks = _hunks(patch)
    if not hunks:
        return None
    fits = []
    for t in sorted(p.name for p in root.iterdir() if p.is_dir()):
        files = {f: root / t / f for f in hunks}
        if all(p.is_file() for p in files.values()):
            text = {f: set(p.read_text().splitlines()) for f, p in files.items()}
            if all(ln in text[f] for f, lines in hunks.items() for ln in lines):
                fits.append(t)
    return fits[0] if len(fits) == 1 else None


def pr_body(p: dict) -> str:
    i = p["issue"]
    return "\n".join([
        # the issue id line is parsed back by radar/prsync.py (PR → event page) — keep the format
        f"**AWS Continuum** issue `{i['issue_id']}` — {i['severity']} · validation **{i['exploitable']}**"
        + (f" · effect {i['effect']}" if i.get("effect") else ""),
        "", f"**Security Radar** event `{p['event']}`: {p['reason']}", "",
        (i.get("synopsis") or ""), "",
        "<details><summary>Continuum validation evidence (source analysis)</summary>\n\n```\n"
        + (i.get("evidence_summary") or "n/a")[:6000] + "\n```\n</details>", "",
        ("Patch generated by AWS Continuum; delivered as this PR by Security Radar (scripts/deliver_prs.py). "
         "Review before merging — merging is the one human step in the loop.")])


def open_pr(p: dict, branch: str) -> str:
    with tempfile.TemporaryDirectory() as d:
        wd = Path(d) / "fleet"
        sh("gh", "repo", "clone", REPO, str(wd), "--", "-q")
        sh("git", "checkout", "-q", "-b", branch, cwd=wd)
        pf = Path(d) / "fix.patch"
        pf.write_text(p["patch"])
        sh("git", "apply", f"--directory={p['target']}", str(pf), cwd=wd)
        sh("git", "add", "-A", cwd=wd)
        sh("git", "-c", "user.name=Security Radar", "-c", "user.email=security-radar@users.noreply.github.com",
           "commit", "-q", "-m", f"fix({p['target']}): {p['issue']['name'][:60]}", cwd=wd)
        sh("git", "push", "-q", "-u", "origin", branch, cwd=wd)
        i = p["issue"]
        return sh("gh", "pr", "create", "-R", REPO, "--head", branch, "--base", "main",
                  "--title", f"[Continuum · {i['severity']} · {i['exploitable']}] {i['name'][:80]}",
                  "--body", pr_body(p), cwd=wd).strip()


def main() -> int:
    do_open = "--open" in sys.argv
    missing = [k for k in ("RADAR_SITE_URL", "RADAR_UI_USER", "RADAR_UI_PASSWORD") if not os.environ.get(k)]
    if missing:
        print(f"missing env: {', '.join(missing)}", file=sys.stderr)
        return 2
    get = site_reader(os.environ["RADAR_SITE_URL"], os.environ["RADAR_UI_USER"], os.environ["RADAR_UI_PASSWORD"])
    todo = plan(responses(get), get)
    existing = json.loads(sh("gh", "pr", "list", "-R", REPO, "--state", "all", "--json", "headRefName", "-L", "200"))
    heads = {x["headRefName"] for x in existing}
    opened = 0
    for p in todo:
        branch = branch_of(p)
        tag = "exists" if branch in heads else ("skip (target unknown)" if not p["target"] else "new")
        print(f"{tag:<22} {branch:<40} {p['issue']['severity']} {p['issue']['name'][:70]}")
        if do_open and tag == "new":
            print(f"  opened {open_pr(p, branch)}")
            opened += 1
    print(f"{len(todo)} planned · {opened} opened" + ("" if do_open else " (dry run)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
