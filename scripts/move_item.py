"""Move one report to another event, or list the reports the current rules would not put where they sit (R1.2).

  AWS_PROFILE=<profile> uv run python scripts/move_item.py --candidates --since 2026-10-20 [--domain web3]
  AWS_PROFILE=<profile> uv run python scripts/move_item.py --item it_… --from ev_… --to ev_…|new            # dry run
  AWS_PROFILE=<profile> uv run python scripts/move_item.py --item it_… --from ev_… --to ev_…|new --apply

The move itself is radar.moves.move_item (both events recomputed, keys follow the report, the report is pinned).
--apply refuses while a cycle is running (Process is the single writer); follow it with a full publish.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from radar import moves
from radar.dynamo import DynamoStore


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidates", action="store_true")
    ap.add_argument("--since", help="with --candidates: YYYY-MM-DD, events updated since then")
    ap.add_argument("--domain", default="web3", choices=["web3", "vuln", "incident"])
    ap.add_argument("--limit", type=int, default=200)
    ap.add_argument("--item")
    ap.add_argument("--from", dest="src")
    ap.add_argument("--to", help="an event id, or 'new' (the report opens its own event)")
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    out = json.loads((ROOT / "build" / "outputs.json").read_text())["SecurityRadar"]
    sess = boto3.Session(region_name="ap-northeast-1")
    store = DynamoStore(sess.resource("dynamodb").Table(out["TableName"]))
    if args.candidates:
        if not args.since:
            ap.error("--candidates needs --since")
        evs = [e for e in store.events_updated_since(f"{args.since}T00:00:00Z") if e.domain == args.domain]
        found = moves.misplaced_candidates(store, evs, args.limit)
        for c in found:
            if c.get("truncated"):
                print(f"… more than {c['limit']} — list cut here (raise --limit)")
            else:
                print(f"{c['kind']:9s} {c['item_id']}  {c['title'][:70]}\n          in {c['event_id']} {c['event_title'][:50]}"
                      f"  →  {c['to'] or 'an event of its own'}")
        print(f"{len([c for c in found if not c.get('truncated')])} reports in {len(evs)} {args.domain} events")
        return 0
    if not (args.item and args.src and args.to):
        ap.error("a move needs --item, --from and --to")
    item, src = store.get_item(args.item), store.get_event(args.src)
    dst = None if args.to == "new" else store.get_event(args.to)
    print(f"report  {args.item}  {item.title[:80] if item else '(not found)'}")
    print(f"from    {args.src}  {f'{len(src.item_ids)} reports  {src.title[:60]}' if src else '(not found)'}")
    print(f"to      {args.to}  {f'{len(dst.item_ids)} reports  {dst.title[:60]}' if dst else ('a new event' if args.to == 'new' else '(not found)')}")
    if not args.apply:
        print("dry run — nothing written (add --apply)")
        return 0
    running = sess.client("stepfunctions").list_executions(stateMachineArn=out["StateMachineArn"],
                                                           statusFilter="RUNNING")["executions"]
    if running:
        print(f"refusing: a cycle is running ({running[0]['name']}) — Process is the single writer", file=sys.stderr)
        return 2
    try:
        res = moves.move_item(store, args.item, args.src, None if args.to == "new" else args.to, datetime.now(UTC))
    except moves.MoveError as e:
        print(f"not moved — {e}", file=sys.stderr)
        return 1
    print(f"moved: {res['from']} → {res['to']}" + ("  (the source event held nothing else and is removed)" if res["removed"] else "")
          + ". Next: a full publish.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
