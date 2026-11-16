"""Undo a bad write (roadmap R5.5). Dry run by default; nothing is ever deleted for good.

  AWS_PROFILE=<profile> uv run python scripts/restore.py bucket site --prefix data/ --at 2026-11-15T10:00:00Z [--apply]
  AWS_PROFILE=<profile> uv run python scripts/restore.py table --at 2026-11-15T10:00:00Z --to SecurityRadar-restore-1115 [--apply]

bucket: the bucket (site | raw | code) reads under --prefix as it did at --at — the version current then is copied
  on top (radar.restore.plan), keys created later get a delete marker. Both are new versions: a restore is undone by
  restoring again. The site is rewritten by every Publish: stop the schedule first, or the next cycle writes over it.
table: DynamoDB point-in-time recovery into a NEW table (--to); the live table is never overwritten. Point the stack
  at it (or copy rows back) by hand after reading it — see docs/RUNBOOK.md.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from radar import restore, timeutil

BUCKETS = {"site": "SiteBucketName", "raw": "RawBucketName", "code": "SaCodeBucketName"}
# recovery windows — deliberate copy of infra/stack.py *_NONCURRENT_DAYS (the authority; tests/test_recovery.py keeps
# them equal). Past the window, old versions have expired: "no version at --at" would read as "did not exist" and
# plan a delete of a key that did exist then.
WINDOW_DAYS = {"site": 7, "raw": 30, "code": 30}


def _versions(s3, bucket: str, prefix: str) -> tuple[list[dict], list[dict]]:
    versions, markers = [], []
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket, Prefix=prefix):
        versions += page.get("Versions", [])
        markers += page.get("DeleteMarkers", [])
    return versions, markers


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("bucket")
    b.add_argument("which", choices=sorted(BUCKETS))
    b.add_argument("--prefix", required=True, help="e.g. data/ — a whole-bucket restore is never implied")
    b.add_argument("--at", required=True, help="ISO time, UTC (…Z)")
    b.add_argument("--apply", action="store_true")
    t = sub.add_parser("table")
    t.add_argument("--at", required=True)
    t.add_argument("--to", required=True, help="name of the NEW table")
    t.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    at = timeutil.parse(args.at)
    out = json.loads((ROOT / "build" / "outputs.json").read_text())["SecurityRadar"]
    sess = boto3.Session(region_name="ap-northeast-1")
    if args.cmd == "table":
        src = out["TableName"]
        if args.to == src:
            print("refusing: --to is the live table", file=sys.stderr)
            return 2
        print(f"restore {src} as of {timeutil.iso(at)} → new table {args.to}")
        if args.apply:
            r = sess.client("dynamodb").restore_table_to_point_in_time(
                SourceTableName=src, TargetTableName=args.to, RestoreDateTime=at, BillingModeOverride="PAY_PER_REQUEST")
            print(r["TableDescription"]["TableStatus"])
        else:
            print("dry run — add --apply")
        return 0
    bucket = out[BUCKETS[args.which]]
    s3 = sess.client("s3")
    if (timeutil.now() - at).days >= WINDOW_DAYS[args.which]:
        print(f"refusing: --at is outside the {WINDOW_DAYS[args.which]}-day window of {args.which}", file=sys.stderr)
        return 2
    if args.apply and s3.get_bucket_versioning(Bucket=bucket).get("Status") != "Enabled":
        print("refusing --apply: versioning is not enabled — a delete here would be permanent", file=sys.stderr)
        return 2
    steps = restore.plan(*_versions(s3, bucket, args.prefix), at=at)
    print(dict(Counter(s.action for s in steps)), f"under s3://{bucket}/{args.prefix} as of {timeutil.iso(at)}")
    todo = [s for s in steps if s.action != "keep"]
    for s in todo[:20]:
        print(f"  {s.action:7} {s.key}" + (f" ← {s.version_id}" if s.version_id else ""))
    if len(todo) > 20:
        print(f"  … {len(todo) - 20} more")
    if not args.apply:
        print("dry run — add --apply")
        return 0
    failed = 0
    for s in todo:
        try:
            if s.action == "restore":
                s3.copy_object(Bucket=bucket, Key=s.key, CopySource={"Bucket": bucket, "Key": s.key, "VersionId": s.version_id})
            else:
                s3.delete_object(Bucket=bucket, Key=s.key)          # a delete marker: the versions stay
        except ClientError as e:   # one key failing must not hide the rest; reported, and the exit code says so
            failed += 1
            print(f"FAILED {s.action} {s.key}: {e}", file=sys.stderr)
    print(f"done: {len(todo) - failed} applied, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
