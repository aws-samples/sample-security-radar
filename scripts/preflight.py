#!/usr/bin/env python3
"""What must be true before anything is deployed (roadmap R0.4). Exit 1 with the reason; 0 = go.

- The working tree is clean for what gets deployed (src/, infra/, scripts/, ui/src, ui/package*.json): the Lambda
  asset is copied from the directory, so an uncommitted edit would be live under a commit that does not contain it.
- HEAD is not older than MIN_DEPLOYABLE. Raise the floor in the same commit as any one-way data migration.
- The checks CI runs on every commit pass here first (CI_PARITY): a deployment must never be the first place a lint,
  type, UI test, build or axe failure shows up (live 2026-11-19: an axe violation reached the site, CI found it after).
- The tests pass.

  uv run python scripts/preflight.py            # all three
  DEPLOY_ALLOW_DIRTY=1 …                        # said out loud, for a repair in progress
  DEPLOY_SKIP_TESTS=1 …                         # said out loud, when the gate that calls this already ran them
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
# R11 (620b1f5): the S3 channel state changed shape and is migrated on read — an older commit reads the new rows as
# "never scanned" and buys every paid scan again (docs/research/14 §6.1).
MIN_DEPLOYABLE = None
# the code that decides what an event is: a change here changes stored events when they are next recomputed
JUDGEMENT_PATHS = ("src/radar/pipeline.py", "src/radar/signals.py", "src/radar/keys.py")
DEPLOYED_MARK = "build/deployed-commit"          # written by deploy-all.sh after its checks pass
RECOMPUTE_REPORT = "build/recompute-check.json"  # written by scripts/recompute_check.py
DEPLOYED_PATHS = ("src", "infra", "scripts", "ui/src", "ui/package.json", "ui/package-lock.json", "integrations")
# What CI runs per commit is run before deploying by scripts/ci-parity.sh (static commands; see its header).
CI_PARITY_SCRIPT = "scripts/ci-parity.sh"
# CI commands that are deliberately not repeated before a deployment, and why
CI_ONLY = {
    "mutate.py": "mutation testing is heavy work; it runs on the CI runner only (managed EC2), never on this machine",
    "npm run mutate": "UI mutation testing: same reason",
    "cdk": "the deployment itself synthesizes with cdk-nag on (deploy-all.sh -c nag=on); the stage copy is CI's",
    "build-lambda.sh": "the deployment builds the asset itself",
    "build-targets.sh": "the deployment builds the targets itself",
    "check_cycle_wiring.py": "reads CI's synthesized stage copy",
    "deliver_prs.py": "scheduled job, not a check",
    "touchstone": "CI fetches the contract gate; here it runs from ~/Code/touchstone (contract_gate)",
    "pytest -q -n auto": "the full test run is the last preflight step (single process here)",
    "install": "runner setup",
    "$HOME/.local/bin": "runner setup",
}


def ci_parity() -> dict[str, Any] | None:
    """Run scripts/ci-parity.sh; its first failing check is the problem (its last lines say why). Only where the
    maintainer's pipeline lives (.gitlab-ci.yml): a copy deployed from the public sample needs no Playwright browser,
    shellcheck or budget gate to deploy, and says that these checks did not run."""
    if not (ROOT / ".gitlab-ci.yml").exists():
        print("preflight: CI checks SKIPPED — no .gitlab-ci.yml here (they are the maintainer's gate)")
        return None
    r = subprocess.run(["bash", "scripts/ci-parity.sh"], cwd=ROOT, capture_output=True, text=True, check=False)
    print("\n".join(line for line in r.stdout.splitlines() if line.startswith("preflight: ")))
    if r.returncode != 0:
        tail = "\n".join((r.stdout + r.stderr).strip().splitlines()[-14:])
        return {"error": "ci_check_failed", "message": f"a CI check fails here, so it would fail in CI:\n{tail}",
                "actual": r.returncode, "limit": 0}
    return None


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=False)


def recompute_problem(root: Path) -> dict[str, Any] | None:
    """The judgement code changed since the last deployment and nobody looked at what it does to the stored events
    (roadmap R8.1). No record of a last deployment ⇒ nothing to compare with (a first deployment, a fresh clone)."""
    mark = root / DEPLOYED_MARK
    if not mark.is_file():
        return None
    last = mark.read_text().strip()
    head = _git(root, "rev-parse", "HEAD").stdout.strip()
    if _git(root, "cat-file", "-e", f"{last}^{{commit}}").returncode != 0:
        return None                                # the marked commit is not in this clone: cannot tell what changed
    if _git(root, "diff", "--quiet", last, "HEAD", "--", *JUDGEMENT_PATHS).returncode == 0:
        return None
    try:
        rep = json.loads((root / RECOMPUTE_REPORT).read_text())
    except (OSError, ValueError):
        rep = {}
    if rep.get("commit") == head and not rep.get("dirty") and not rep.get("domain"):
        return None
    return {"error": "recompute_report_missing", "actual": (rep.get("commit") or "no report")[:12], "limit": head[:12],
            "message": "pipeline / signals / keys changed since the last deployment: run scripts/recompute_check.py and "
                       "read what changes in the stored events (DEPLOY_SKIP_RECOMPUTE=1 to deploy without)"}


def problems(root: Path, minimum: str | None = MIN_DEPLOYABLE, allow_dirty: bool = False) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    present = [p for p in DEPLOYED_PATHS if (root / p).exists()]
    st = _git(root, "status", "--porcelain", "--untracked-files=all", "--", *present)
    dirty = sorted(ln[3:].split(" -> ")[-1] for ln in st.stdout.splitlines() if ln.strip())
    if dirty and not allow_dirty:
        out.append({"error": "working_tree_dirty", "message": "uncommitted changes in deployed paths would go live",
                    "actual": dirty, "limit": "clean (or DEPLOY_ALLOW_DIRTY=1)"})
    if minimum:
        head = _git(root, "rev-parse", "HEAD").stdout.strip()
        if _git(root, "cat-file", "-e", f"{minimum}^{{commit}}").returncode != 0:
            # a shallow clone (CI's default depth) does not have the floor: "cannot tell" is not "too old"
            out.append({"error": "minimum_commit_unknown", "actual": head, "limit": minimum,
                        "message": "the floor commit is not in this clone (shallow?); fetch full history to check"})
        elif _git(root, "merge-base", "--is-ancestor", minimum, "HEAD").returncode != 0:
            out.append({"error": "commit_older_than_minimum", "actual": head, "limit": minimum,
                        "message": "this commit predates a one-way data migration; deploying it corrupts or re-buys state"})
    return out


def main() -> int:
    allow = os.environ.get("DEPLOY_ALLOW_DIRTY") == "1"
    if allow:
        print("preflight: DEPLOY_ALLOW_DIRTY=1 — deploying the working tree as it is", file=sys.stderr)
    bad = problems(ROOT, allow_dirty=allow)
    if os.environ.get("DEPLOY_SKIP_RECOMPUTE") == "1":
        print("preflight: DEPLOY_SKIP_RECOMPUTE=1 — stored events not recomputed with this code", file=sys.stderr)
    elif (p := recompute_problem(ROOT)) is not None:
        bad.append(p)
    for p in bad:
        print(f"preflight FAIL {p['error']}: {p['message']} (actual {p['actual']!r}, limit {p['limit']!r})", file=sys.stderr)
    if bad:
        return 1
    if os.environ.get("DEPLOY_SKIP_TESTS") == "1":
        print("preflight: DEPLOY_SKIP_TESTS=1 — tests not run here", file=sys.stderr)
    else:
        if (p := ci_parity()) is not None:
            print(f"preflight FAIL {p['error']}: {p['message']}", file=sys.stderr)
            return 1
        r = subprocess.run(["uv", "run", "pytest", "-q", "-x", "-p", "no:cacheprovider"], cwd=ROOT, capture_output=True,
                           text=True, check=False)
        if r.returncode != 0:
            print("preflight FAIL tests_failed:\n" + "\n".join(r.stdout.splitlines()[-8:]), file=sys.stderr)
            return 1
        print("preflight: " + r.stdout.splitlines()[-1])
    print("preflight: ok — " + _git(ROOT, "log", "--oneline", "-1").stdout.strip())
    return 0


if __name__ == "__main__":
    sys.exit(main())
