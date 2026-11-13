"""Correct an event's title once its root cause is clear, citing the source — with your own AWS IAM credentials.

  AWS_PROFILE=<profile> uv run python scripts/retitle.py ev_… "Binance CEX — Unauthorized Withdrawals via …" \
      --source https://… --note "币安官方：未发现私钥泄露"
  AWS_PROFILE=<profile> uv run python scripts/retitle.py --list

The next process cycle republishes the event; the page shows the corrected title, its source and the original.
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from radar import retitle, timeutil
from radar.dynamo import DynamoStore


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("event_id", nargs="?")
    ap.add_argument("title", nargs="?")
    ap.add_argument("--source", default="")
    ap.add_argument("--note", default="")
    ap.add_argument("--by", default=getpass.getuser())
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    out = json.loads((ROOT / "build" / "outputs.json").read_text())["SecurityRadar"]
    store = DynamoStore(boto3.Session(region_name="ap-northeast-1").resource("dynamodb").Table(out["TableName"]))
    if args.list:
        for eid, e in sorted(store.get_source_state(retitle.KEY).items(), key=lambda kv: kv[1].get("at", ""), reverse=True):
            print(f"{e.get('at', '')}  {eid}  {e.get('title', '')}  ← {e.get('source', '')}")
        return 0
    if not (args.event_id and args.title):
        ap.error("event_id and title are required (or --list)")
    try:
        e = retitle.set_title(store, args.event_id, args.title, args.source, args.note, args.by, timeutil.now())
    except retitle.RetitleError as err:
        print(json.dumps(err.detail, ensure_ascii=False), file=sys.stderr)
        return 2
    print(f"{args.event_id} → {e['title']}（{e['at']}）— the next cycle republishes it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
