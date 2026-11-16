"""Recompute the stored events with the code in this checkout and report what would change (roadmap R8.1). Read-only.

  AWS_PROFILE=<profile> uv run python scripts/recompute_check.py [--days 14] [--domain vuln|web3|incident]

Writes build/recompute-check.json (the commit it was made for, counts, every changed event) and prints a summary.
scripts/preflight.py asks for a report of the commit being deployed whenever the judgement code changed since the
last deployment — read the list before you deploy: every changed event should be one you meant to change.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from radar import recheck
from radar.dynamo import DynamoStore

REPORT = ROOT / "build" / "recompute-check.json"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--domain", choices=["vuln", "web3", "incident"])
    a = ap.parse_args()
    out = json.loads((ROOT / "build" / "outputs.json").read_text())["SecurityRadar"]
    store = DynamoStore(boto3.Session(region_name="ap-northeast-1").resource("dynamodb").Table(out["TableName"]))
    rep = recheck.diff(store, datetime.now(UTC), a.days, a.domain)
    head = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain", "--", "src"], capture_output=True, text=True,
                                check=True).stdout.strip())
    rep.update(commit=head, dirty=dirty, domain=a.domain)
    REPORT.write_text(json.dumps(rep, ensure_ascii=False, indent=1))
    print(recheck.summary(rep))
    print(f"report: {REPORT.relative_to(ROOT)} (commit {head[:7]}{', working tree dirty' if dirty else ''})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
