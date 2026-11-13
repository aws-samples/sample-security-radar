#!/usr/bin/env python3
"""One-off: record search rows whose event no longer exists, so the next publish prunes them (radar.removals).

Why: until radar.removals, a merge or a recluster repair deleted the event but left its search row (data/search/<m>.json)
and its detail page (data/events/<id>.json) — live 2026-11-12, a Binance search still listed the pre-repair events. New
removals are recorded as they happen; this finds the ones from before.

Dry run by default (prints the count per month); --apply writes the ledger. Then run a full publish.
  AWS_PROFILE=<profile> uv run python scripts/prune-search.py [--apply]
"""
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from radar import removals, timeutil


def shard_rows(s3: Any, bucket: str) -> dict[str, list[str]]:
    """Every event id in every month shard the index lists."""
    idx = json.loads(s3.get_object(Bucket=bucket, Key="data/search/index.json")["Body"].read())
    out: dict[str, list[str]] = {}
    for m in (x["month"] for x in idx.get("months") or []):
        doc = json.loads(s3.get_object(Bucket=bucket, Key=f"data/search/{m}.json")["Body"].read())
        out[m] = [r["id"] for r in doc.get("events") or []]
    return out


def orphans(rows: dict[str, list[str]], exists: Callable[[list[str]], set[str]]) -> list[tuple[str, str, None]]:
    """(event_id, month, successor=None) for each row whose event is gone; `exists` answers for a batch of ids."""
    out = []
    for m, ids in sorted(rows.items()):
        for i in range(0, len(ids), 100):
            batch = ids[i:i + 100]
            live = exists(batch)
            out += [(e, m, None) for e in batch if e not in live]
    return out


def dynamo_exists(table: Any) -> Callable[[list[str]], set[str]]:
    client = table.meta.client

    def exists(ids: list[str]) -> set[str]:
        keys = [{"pk": f"EVENT#{e}", "sk": "META"} for e in dict.fromkeys(ids)]
        found: set[str] = set()
        req: dict[str, Any] = {table.name: {"Keys": keys, "ProjectionExpression": "pk"}}
        while req:
            r = client.batch_get_item(RequestItems=req)
            found |= {it["pk"].removeprefix("EVENT#") for it in r["Responses"].get(table.name, [])}
            req = r.get("UnprocessedKeys") or {}
        return found
    return exists


def main() -> int:
    import boto3
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    out = json.loads((ROOT / "build" / "outputs.json").read_text())["SecurityRadar"]
    sess = boto3.Session(region_name="ap-northeast-1")
    table = sess.resource("dynamodb").Table(out["TableName"])
    rows = shard_rows(sess.client("s3"), out["SiteBucketName"])
    gone = orphans(rows, dynamo_exists(table))
    per: dict[str, int] = {}
    for _, m, _ in gone:
        per[m] = per.get(m, 0) + 1
    print(f"{sum(len(v) for v in rows.values())} search rows, {len(gone)} without an event: {per}")
    if not args.apply:
        print("dry run — nothing written (add --apply)")
        return 0
    from radar.dynamo import DynamoStore
    removals.record(DynamoStore(table), gone, timeutil.iso(timeutil.now()))
    print("recorded. Next: a full publish prunes them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
