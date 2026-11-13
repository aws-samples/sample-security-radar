#!/usr/bin/env python3
"""What must be true before anything is deployed (roadmap R0.4). Exit 1 with the reason; 0 = go.

- The working tree is clean for what gets deployed (src/, infra/, scripts/, ui/src, ui/package*.json): the Lambda
  asset is copied from the directory, so an uncommitted edit would be live under a commit that does not contain it.
- HEAD is not older than MIN_DEPLOYABLE. Raise the floor in the same commit as any one-way data migration.
- The tests pass.

  uv run python scripts/preflight.py            # all three
  DEPLOY_ALLOW_DIRTY=1 …                        # said out loud, for a repair in progress
  DEPLOY_SKIP_TESTS=1 …                         # said out loud, when the gate that calls this already ran them
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
# R11 (620b1f5): the S3 channel state changed shape and is migrated on read — an older commit reads the new rows as
# "never scanned" and buys every paid scan again (docs/research/14 §6.1).
MIN_DEPLOYABLE = None
DEPLOYED_PATHS = ("src", "infra", "scripts", "ui/src", "ui/package.json", "ui/package-lock.json", "integrations")


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=False)


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
    for p in bad:
        print(f"preflight FAIL {p['error']}: {p['message']} (actual {p['actual']!r}, limit {p['limit']!r})", file=sys.stderr)
    if bad:
        return 1
    if os.environ.get("DEPLOY_SKIP_TESTS") == "1":
        print("preflight: DEPLOY_SKIP_TESTS=1 — tests not run here", file=sys.stderr)
    else:
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
