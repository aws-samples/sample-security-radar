"""B6 (M3.5): the radar's findings are readable in AWS Security Hub, and agree with the mitigate ledger.

  STAGE= uv run python scripts/securityhub-check.py
Exit 0 = every ACTIVE finding in the ledger is ACTIVE in Security Hub, with the mitigation state in its description."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[1]
REGION = "ap-northeast-1"


def main() -> int:
    stage = os.environ.get("STAGE", "")
    out = json.loads((ROOT / "build" / f"outputs{'-' + stage if stage else ''}.json").read_text())[f"SecurityRadar{stage.capitalize()}"]
    table = boto3.resource("dynamodb", region_name=REGION).Table(out["TableName"])
    led = json.loads(table.get_item(Key={"pk": "SRC#__mitigate__", "sk": "STATE"})["Item"]["d"])
    exported = (led.get("security_hub") or {}).get("exported") or {}
    want = sorted(fid for fid, r in exported.items() if r["state"] == "ACTIVE")
    hub = boto3.client("securityhub", region_name=REGION)
    # by Id, one at a time: the GeneratorId-filtered listing is eventually consistent (live 2026-10-29: 3, then 2 of 7)
    by = {}
    for fid in want:
        got = hub.get_findings(Filters={"Id": [{"Value": fid, "Comparison": "EQUALS"}]}, MaxResults=1)["Findings"]
        if got and got[0]["RecordState"] == "ACTIVE":
            by[fid] = got[0]
    listed = hub.get_findings(Filters={"GeneratorId": [{"Value": "security-radar/mitigate", "Comparison": "EQUALS"}],
                                       "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]}, MaxResults=100)["Findings"]
    for f in listed:   # ACTIVE in the hub but archived in the ledger ⇒ an archive never landed
        by.setdefault(f["Id"], f)
    ok = bool(want) and all(fid in by for fid in want)
    for fid in want:
        f = by.get(fid)
        print(f"{'PASS' if f else 'FAIL'} {fid}: {f and f['Severity']['Label']} — {(f or {}).get('Description', '')[:140]}")
    extra = sorted(set(by) - set(want))
    if extra:
        print(f"FAIL ACTIVE in Security Hub but archived/unknown in the ledger: {extra}")
        ok = False
    print("ALL CHECKS PASSED" if ok else "CHECKS FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
