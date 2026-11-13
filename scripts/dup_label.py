"""Label a pair of events as the same incident or not (C4 overrides, item 6) with your own AWS IAM credentials.

  AWS_PROFILE=<profile> uv run python scripts/dup_label.py ev_aaaa… ev_bbbb… same --note "同一份新闻稿"
  AWS_PROFILE=<profile> uv run python scripts/dup_label.py ev_aaaa… ev_bbbb… different
  AWS_PROFILE=<profile> uv run python scripts/dup_label.py --list      # the judge's open pairs, with any label
  AWS_PROFILE=<profile> uv run python scripts/dup_label.py --report    # judge precision against the labels

'different' hides the page's "possible duplicate" hint; 'same' shows it and queues the pair in #/ops for a repair
(scripts/recluster_web3.py --event A --event B). The next full publish shows the change.
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
from radar import duplabels, timeutil
from radar.dynamo import DynamoStore


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("a", nargs="?")
    ap.add_argument("b", nargs="?")
    ap.add_argument("label", nargs="?", choices=sorted(duplabels.LABELS))
    ap.add_argument("--note", default="")
    ap.add_argument("--by", default=getpass.getuser())
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--report", action="store_true")
    args = ap.parse_args()
    out = json.loads((ROOT / "build" / "outputs.json").read_text())["SecurityRadar"]
    store = DynamoStore(boto3.Session(region_name="ap-northeast-1").resource("dynamodb").Table(out["TableName"]))
    labels = store.get_source_state(duplabels.KEY)
    judged = store.get_source_state("__cluster_judge__").get("pairs") or {}
    if args.report:
        print(json.dumps(duplabels.report(labels, judged), ensure_ascii=False))
        return 0
    if args.list:
        for r in sorted(judged.values(), key=lambda r: r.get("at", ""), reverse=True):
            lab = duplabels.label_of(labels, r["a"], r["b"])
            print(f"{r.get('verdict', ''):9}  {r['a']}  {r['b']}  人工={(lab or {}).get('label', '-'):9}  {r.get('why', '')[:80]}")
        return 0
    if not (args.a and args.b and args.label):
        ap.error("two event ids and a label are required (or --list / --report)")
    try:
        e = duplabels.set_label(store, args.a, args.b, args.label, args.note, args.by, timeutil.now())
    except duplabels.LabelError as err:
        print(json.dumps(err.detail, ensure_ascii=False), file=sys.stderr)
        return 2
    print(f"{duplabels.pair(args.a, args.b)} → {duplabels.LABELS[e['label']]}（{e['at']}）— the next full publish shows it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
