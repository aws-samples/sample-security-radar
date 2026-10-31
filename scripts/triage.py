"""Set an event's disposition (研判中 / 跟进中 / 已关闭 / 误报) with your own AWS IAM credentials — no web write surface.

  AWS_PROFILE=<profile> uv run python scripts/triage.py ev_0a4e5c3e0fce8be9 tracking --note "链上复盘跟进中"
  AWS_PROFILE=<profile> uv run python scripts/triage.py --list            # current dispositions

The next process cycle republishes the event (radar.triage.changed); the page and #/ops show it read-only.
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
from radar import timeutil, triage
from radar.dynamo import DynamoStore


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("event_id", nargs="?")
    ap.add_argument("status", nargs="?", choices=sorted(triage.STATUSES))
    ap.add_argument("--note", default="")
    ap.add_argument("--by", default=getpass.getuser())
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    out = json.loads((ROOT / "build" / "outputs.json").read_text())["SecurityRadar"]
    store = DynamoStore(boto3.Session(region_name="ap-northeast-1").resource("dynamodb").Table(out["TableName"]))
    if args.list:
        for eid, e in sorted(store.get_source_state(triage.KEY).items(), key=lambda kv: kv[1].get("at", ""), reverse=True):
            print(f"{e.get('at', '')}  {eid}  {e.get('label', ''):4}  {e.get('by', '')}  {e.get('note', '')}")
        return 0
    if not (args.event_id and args.status):
        ap.error("event_id and status are required (or --list)")
    try:
        e = triage.set_status(store, args.event_id, args.status, args.note, args.by, timeutil.now())
    except triage.TriageError as err:
        print(json.dumps(err.detail, ensure_ascii=False), file=sys.stderr)
        return 2
    print(f"{args.event_id} → {e['label']}（{e['at']}）— the next cycle republishes it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
