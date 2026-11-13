"""Delete key-index rows (KEY#<key> / EVENT#<id>) whose event no longer exists.

Merges before 2026-11-02 deleted the absorbed event but left its index rows (live: 49 rows over 9 events, e.g.
ev_1119fbc978f9f673's CVE-2026-98432 rows). Readers skip them, so this is hygiene, not a fix of a wrong page; since
pipeline.attach now calls store.remove_keys on merge, a second run should find nothing.

  AWS_PROFILE=<profile> uv run python scripts/prune_index.py            # dry run: count and list
  AWS_PROFILE=<profile> uv run python scripts/prune_index.py --apply    # delete them
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[1]


def dangling(table) -> list[tuple[str, str]]:
    rows, events, kw = [], set(), {"ProjectionExpression": "pk,sk"}
    while True:
        r = table.scan(**kw)
        for x in r["Items"]:
            if x["pk"].startswith("KEY#"):
                rows.append((x["pk"], x["sk"]))
            elif x["pk"].startswith("EVENT#") and x["sk"] == "META":
                events.add(x["pk"][6:])
        if "LastEvaluatedKey" not in r:
            return [(pk, sk) for pk, sk in rows if sk[6:] not in events]
        kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    out = json.loads((ROOT / "build" / "outputs.json").read_text())["SecurityRadar"]
    table = boto3.Session(region_name="ap-northeast-1").resource("dynamodb").Table(out["TableName"])
    gone = dangling(table)
    for eid, n in Counter(sk[6:] for _, sk in gone).most_common():
        print(f"  {eid}: {n} row(s)")
    print(f"{len(gone)} dangling index row(s)" + ("" if args.apply else " — dry run, --apply to delete"))
    if args.apply and gone:
        with table.batch_writer() as w:
            for pk, sk in gone:
                w.delete_item(Key={"pk": pk, "sk": sk})
        left = dangling(table)
        print(f"deleted; {len(left)} left")
        return 1 if left else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
