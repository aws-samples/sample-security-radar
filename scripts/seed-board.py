"""Seed the announcement board (__board__) once from the radar's own raw batches — no third-party fetch.

  AWS_PROFILE=<profile> uv run python scripts/seed-board.py --since 2026-11-09 [--apply]

Why: the board ledger is filled by Process from new notices only (collection is incremental), so notices collected
before the board existed never reach it. This replays this week's raw/<day>/ batches of board sources through the same
announcements.board_add. Refuses while a cycle runs (Process is the ledger's single writer).
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date, timedelta
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from radar import announcements, timeutil
from radar.dynamo import DynamoStore
from radar.model import RawItem
from radar.registry import BY_ID


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", required=True, help="YYYY-MM-DD: first raw/ day to replay")
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    out = json.loads((ROOT / "build" / "outputs.json").read_text())["SecurityRadar"]
    sess = boto3.Session(region_name="ap-northeast-1")
    s3, bucket = sess.client("s3"), out["RawBucketName"]
    boards = {sid for sid, s in BY_ID.items() if s.board}
    raws: list[RawItem] = []
    day = date.fromisoformat(args.since)
    while day <= date.today():
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=f"raw/{day.isoformat()}/"):
            for o in page.get("Contents", []):
                if o["Key"].rsplit("/", 1)[-1].removesuffix(".jsonl") in boards:
                    body = s3.get_object(Bucket=bucket, Key=o["Key"])["Body"].read().decode()
                    raws += [RawItem.from_dict(json.loads(ln)) for ln in body.splitlines() if ln.strip()]
        day += timedelta(days=1)
    store = DynamoStore(sess.resource("dynamodb").Table(out["TableName"]))
    led = announcements.board_add(store.get_source_state(announcements.BOARD_KEY), raws, BY_ID, timeutil.iso(timeutil.now()))
    counts = {k: sum(r["kind"] == k for r in led["notices"]) for k in announcements.PRIORITY}
    print(f"{len(raws)} notices in raw batches → board {len(led['notices'])}  {counts}")
    if not args.apply:
        print("dry run — nothing written (add --apply)")
        return 0
    sfn = sess.client("stepfunctions")
    if sfn.list_executions(stateMachineArn=out["StateMachineArn"], statusFilter="RUNNING")["executions"]:
        print("refusing: a cycle is running — Process is the board's single writer", file=sys.stderr)
        return 2
    store.put_source_state(announcements.BOARD_KEY, led)
    print("applied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
