"""Live view of the respond station: every eligible event's response, per target and per action.

  STAGE= uv run python scripts/respond_status.py            # table
  STAGE= uv run python scripts/respond_status.py --json     # machine-readable (deck / docs evidence)
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import boto3
from boto3.dynamodb.conditions import Attr

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from radar import respond
from radar.targets import NAMES


def main() -> None:
    stage = os.environ.get("STAGE", "")
    outputs = json.loads((ROOT / "build" / f"outputs{'-' + stage if stage else ''}.json").read_text())
    table = boto3.resource("dynamodb", region_name="ap-northeast-1").Table(
        outputs[f"SecurityRadar{stage.capitalize()}"]["TableName"])
    rows, kw = [], {"FilterExpression": Attr("sk").eq("RESPONSE")}
    while True:  # paginate: one scan page is ≤1 MB
        page = table.scan(**kw)
        rows += page["Items"]
        if "LastEvaluatedKey" not in page:
            break
        kw["ExclusiveStartKey"] = page["LastEvaluatedKey"]
    out = []
    for r in rows:
        st = json.loads(r["d"])
        resp = respond.to_response(st, NAMES, "")
        if resp and resp["status"] != "not_eligible":
            out.append({"event_id": r["pk"][6:], **resp})
    out.sort(key=lambda r: r["event_id"])
    if "--json" in sys.argv:
        print(json.dumps(out, ensure_ascii=False, indent=1))
        return
    print(f"{len(rows)} response rows, {len(out)} eligible")
    for r in out:
        print(f"\n## {r['event_id']}  {r['status']}  {r['reason'][:140]}")
        for t in r["targets"]:
            if t["relevant"]:
                print(f"   ◆ {t['target_id']:<15} {t['verdict']:<13} {t['detail']}")
        for a in r["actions"]:
            print(f"   · {a['service']:<15} {a['kind']:<13} {a['target_id'] or '':<15} {a['status']:<10} {a['detail'][:110]}")
        for i in r["issues"]:
            print(f"   ★ issue {i['severity']} {i['phase']}/{i['status']} exploitable={i.get('exploitable')} {i['name'][:80]}")


if __name__ == "__main__":
    main()
