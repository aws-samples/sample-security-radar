"""How many site opens come from phones — the number the ROADMAP R3.6 veto waits for before the phone layout ships.

  AWS_PROFILE=<profile> uv run python scripts/phone_share.py [--days 7]

Reads the CloudFront standard logs (infra/stack.py AccessLogBucket, prefix site/) and counts page loads: GET of `/` or
`/index.html` answered 200 / 304 (a 401 is the Basic Auth prompt, not an open). Routes are hash fragments (#/events/…)
and never reach the server, so this is the share of all opens, not of pushed-link opens — the closest the logs can say.
"""
from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
import urllib.parse
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGES = ("/", "/index.html")
_PHONE = re.compile(r"iPhone|Android.*Mobile|Mobile Safari|Windows Phone|Lark.*Mobile|Slack.*(iOS|Android)", re.IGNORECASE)
_TABLET = re.compile(r"iPad|Android(?!.*Mobile)|Tablet", re.IGNORECASE)
_BOT = re.compile(r"bot|crawl|spider|curl|python|Go-http|HeadlessChrome|Playwright", re.IGNORECASE)


def kind(ua: str) -> str:
    """phone | tablet | desktop | bot — from a user agent as CloudFront logs it (URL-encoded)."""
    ua = urllib.parse.unquote(urllib.parse.unquote(ua))     # CloudFront encodes once; %2520 for spaces is common
    return ("bot" if _BOT.search(ua) else "phone" if _PHONE.search(ua) else
            "tablet" if _TABLET.search(ua) else "desktop")


def opens(lines: list[str]) -> Counter[str]:
    """Page loads by device kind, from the lines of standard log files (#Fields header names the columns)."""
    out: Counter[str] = Counter()
    fields: list[str] = []
    for line in lines:
        if line.startswith("#Fields:"):
            fields = line.split()[1:]
            continue
        if line.startswith("#") or not fields:
            continue
        r = dict(zip(fields, line.rstrip("\n").split("\t"), strict=False))
        if r.get("cs-method") == "GET" and r.get("cs-uri-stem") in PAGES and r.get("sc-status") in ("200", "304"):
            out[kind(r.get("cs(User-Agent)", ""))] += 1
    return out


def main() -> int:
    import boto3
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=7)
    args = ap.parse_args()
    bucket = json.loads((ROOT / "build" / "outputs.json").read_text())["SecurityRadar"]["AccessLogBucketName"]
    s3 = boto3.Session(region_name="ap-northeast-1").client("s3")
    since = datetime.now(UTC) - timedelta(days=args.days)
    total: Counter[str] = Counter()
    files = 0
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix="site/"):
        for o in page.get("Contents", []):
            if o["LastModified"] < since:
                continue
            body = gzip.decompress(s3.get_object(Bucket=bucket, Key=o["Key"])["Body"].read()).decode("utf-8", "replace")
            total += opens(body.splitlines())
            files += 1
    people = total["phone"] + total["tablet"] + total["desktop"]
    print(f"{files} log files, last {args.days} days: {dict(total)}")
    if not people:
        print("no page opens yet — not enough data for the R3.6 decision")
        return 1
    print(f"phone share of opens: {total['phone'] / people:.0%} (of {people}, bots excluded)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
