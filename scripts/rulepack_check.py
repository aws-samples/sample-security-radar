"""--check of the stored WAF rule packs (01-waf §4 「回源核验」): every quote read back against its source.

  STAGE= uv run python scripts/rulepack_check.py --check                 # every pack in the mitigate window
  STAGE= uv run python scripts/rulepack_check.py --check ev_…            # named events only
  STAGE= uv run python scripts/rulepack_check.py --check --refetch       # templates re-read from GitHub at the pinned SHA

Template quotes are read back from the template rows the station stored (`__poc_tpl__#<CVE>`, the bytes at the pinned
SHA — no network call by default); evidence quotes from the items in the table (token at its span). Read-only: DynamoDB
GetItem / Query, nothing written. Exit 1 on any failure, and when no pack was checked (nothing checked ≠ ok).
scripts/verify.sh runs it as one acceptance check."""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from radar import rulepack
from radar.dynamo import DynamoStore


def _store() -> DynamoStore:
    stage = os.environ.get("STAGE", "")
    outputs = json.loads((ROOT / "build" / f"outputs{'-' + stage if stage else ''}.json").read_text())
    table = boto3.resource("dynamodb", region_name="ap-northeast-1").Table(outputs[f"SecurityRadar{stage.capitalize()}"]["TableName"])
    return DynamoStore(table)


if __name__ == "__main__":
    sys.exit(rulepack.cli(sys.argv[1:], _store(), datetime.now(UTC)))
