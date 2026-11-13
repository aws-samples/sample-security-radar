"""Backfill the static search index (data/search/) with every event in the table — once, after radar.search shipped.

  AWS_PROFILE=<profile> uv run python scripts/seed-search.py [--apply]

Publish merges only the 60-day window into its month shards; events older than that were never indexed. Reads the
radar's own table and writes its own site bucket — no third party. Same merge as the station (upsert by event id).

Detail-page marks ("p", radar.search.record): Publish marks only the detail docs it writes in that run, so every
event whose data/events/<id>.json predates the mark would read 「无详情页」 forever. Those docs are never deleted
(deploy-ui.sh syncs with --exclude "data/*"), so the backfill lists data/events/ once and marks every id that has one.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import boto3

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from radar import search, timeutil
from radar.dynamo import DynamoStore

EVENTS_PREFIX = "data/events/"


def published_ids(s3: Any, bucket: str, page_size: int = 1000) -> set[str]:
    """Every event id with a detail doc in the site bucket (data/events/<id>.json), across all listing pages."""
    ids: set[str] = set()
    pages = s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=EVENTS_PREFIX,
                                                         PaginationConfig={"PageSize": page_size})
    for page in pages:
        for o in page.get("Contents") or []:
            name = o["Key"][len(EVENTS_PREFIX):]
            if name.endswith(".json") and "/" not in name:
                ids.add(name[:-len(".json")])
    return ids


def seed(s3: Any, bucket: str, events: list[Any], apply: bool) -> dict[str, int]:
    """Merge `events` into their month shards, marking those with a detail doc; returns the months' counts written."""
    with_page = published_ids(s3, bucket)
    shards = search.shards(events, published=with_page)
    print(f"{len(events)} events ({len(with_page)} detail pages in the bucket) → {len(shards)} months: "
          + ", ".join(f"{m}={len(r)}" for m, r in sorted(shards.items())))
    if not apply:
        print("dry run — nothing written (add --apply)")
        return {}
    at = timeutil.iso(timeutil.now())

    def read(key: str) -> dict:
        try:
            return json.loads(s3.get_object(Bucket=bucket, Key=key)["Body"].read())
        except s3.exceptions.NoSuchKey:
            return {}
    counts = {m["month"]: m["events"] for m in read("data/search/index.json").get("months") or []}
    for m, fresh in shards.items():
        rows = search.merge(read(f"data/search/{m}.json").get("events") or [], fresh)
        counts[m] = len(rows)
        s3.put_object(Bucket=bucket, Key=f"data/search/{m}.json", ContentType="application/json", CacheControl="max-age=300",
                      Body=json.dumps(search.shard_doc(m, rows, at), ensure_ascii=False).encode())
    s3.put_object(Bucket=bucket, Key="data/search/index.json", ContentType="application/json", CacheControl="max-age=60",
                  Body=json.dumps(search.index_doc(counts, at)).encode())
    print(f"applied: {sum(counts.values())} events in {len(counts)} months")
    return counts


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    out = json.loads((ROOT / "build" / "outputs.json").read_text())["SecurityRadar"]
    sess = boto3.Session(region_name="ap-northeast-1")
    store = DynamoStore(sess.resource("dynamodb").Table(out["TableName"]))
    seed(sess.client("s3"), out["SiteBucketName"], store.events_updated_since("1970-01-01T00:00:00Z"), args.apply)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
