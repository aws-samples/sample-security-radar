"""R1.5 step 1 — DRY RUN: re-normalize stored items from their raw batches under today's rules, and show what would change.

Why (Neo 2026-11-18, 「把优先级提前」): an item's judgement (exploited / kev / poc, keys, domain, eventful) is made once, at
normalize, from the raw text — and only the first Limits.ITEM_TEXT_MAX characters are kept. A rule fixed later cannot
reach a sentence beyond them: Tenable's Java4Shell FAQ said 「not listed in … Known Exploited Vulnerabilities」 past the
cut, the old rule read it as exploited, and recompute kept believing it (repaired by hand). The raw batches keep the
whole text (raw/<day>/<slot>/<source>.jsonl), so the cure is to normalize them again.

By default this script writes NOTHING (only --apply-signals writes, and refuses while a cycle runs). It reads the raw batches of a window, re-normalizes each item it finds in the store, and
reports per field what would change; then, for every event holding a changed item, recomputes the event with the new
items and reports exploitation / severity / level / first report / CVE changes. Key changes are listed as "would
re-cluster" — membership is decided by a replay, not here. Step 2 (after Neo has read the report) writes per event.

  uv run python scripts/renormalize.py --since 2026-10-23 --report build/renormalize.json
"""
from __future__ import annotations

import argparse
import collections
import copy
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from radar import pipeline, timeutil
from radar.dynamo import DynamoStore
from radar.model import RawItem
from radar.registry import BY_ID

FIELDS = ("signals", "keys", "domain", "eventful", "entity", "digest", "roundup")
EVENT_FIELDS = ("exploitation", "severity", "level", "first_seen", "cves")


def _view(it) -> dict:
    return {"signals": {k: it.signals.get(k) for k in ("exploited", "kev", "poc", "amount_usd")},
            "keys": sorted(it.keys), "domain": it.domain, "eventful": it.eventful, "entity": it.entity,
            "published_at": it.published_at, "digest": bool(it.extra.get("digest")),
            "roundup": bool(it.extra.get("roundup"))}


def _slot_time(key: str) -> datetime:
    slot = key.split("/")[2]
    return timeutil.parse(slot) or datetime.now(UTC)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", required=True, help="YYYY-MM-DD, first raw day")
    ap.add_argument("--until", default=None, help="YYYY-MM-DD, last raw day (default today)")
    ap.add_argument("--report", default=str(ROOT / "build" / "renormalize.json"))
    ap.add_argument("--workers", type=int, default=32)
    ap.add_argument("--recluster-plan", action="store_true",
                    help="step 2, batch 2 (dry run): re-cluster, in memory, the reports of every event whose keys change, "
                         "and report how each live event would end up (intact / split / merged)")
    ap.add_argument("--apply-signals", action="store_true",
                    help="step 2, batch 1: write the judgement fields only (signals, digest / roundup flags) of changed items "
                         "and the recomputed events — keys and domain stay (no re-clustering); refuses while a cycle runs")
    a = ap.parse_args()
    out = json.loads((ROOT / "build" / "outputs.json").read_text())["SecurityRadar"]
    sess = boto3.Session(region_name="ap-northeast-1")
    s3 = sess.client("s3")
    bucket = next(v for k, v in out.items() if "Raw" in k and "Bucket" in k)
    store = DynamoStore(sess.resource("dynamodb").Table(out["TableName"]))

    days = sorted(p["Prefix"].split("/")[1] for page in s3.get_paginator("list_objects_v2").paginate(
        Bucket=bucket, Prefix="raw/", Delimiter="/") for p in page.get("CommonPrefixes", []))
    days = [d for d in days if d >= a.since and (a.until is None or d <= a.until)]
    keys_ = [o["Key"] for d in days for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=f"raw/{d}/")
             for o in page.get("Contents", [])]
    print(f"raw days {days[0] if days else '-'} … {days[-1] if days else '-'}: {len(keys_)} batches", file=sys.stderr)

    def load(key: str) -> list[tuple[str, RawItem]]:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8", "replace")
        rows = []
        for line in body.splitlines():
            if line.strip():
                try:
                    rows.append((key, RawItem.from_dict(json.loads(line))))
                except (ValueError, TypeError, KeyError):
                    continue
        return rows

    raws: dict[str, tuple[str, RawItem]] = {}
    with ThreadPoolExecutor(a.workers) as ex:
        for rows in ex.map(load, keys_):
            for key, r in rows:
                src = BY_ID.get(r.source_id)
                if src is None:
                    continue
                it = pipeline.normalize(r, src, _slot_time(key))
                raws.setdefault(it.item_id, []).append((key, r))     # every capture: the one matching the stored text wins
    print(f"raw items: {len(raws)}", file=sys.stderr)

    stored: dict[str, object] = {}
    ids = sorted(raws)
    for i in range(0, len(ids), 100):
        for it in store.get_items(ids[i:i + 100]):
            stored[it.item_id] = it
    field_changes: collections.Counter[str] = collections.Counter()
    unmatched = 0
    matched: dict[str, tuple[str, RawItem]] = {}
    exploited_flips: list[dict] = []
    changed_items: dict[str, object] = {}
    for iid, old in stored.items():
        # the capture whose text IS the stored one (a feed revises an entry; Google News reuses a guid): comparing another
        # capture would report a rule change that is a content change (the first full run: Chrome, gn_0day)
        pick = next(((k, r) for k, r in raws[iid]
                     if pipeline.normalize(r, BY_ID[r.source_id], _slot_time(k)).text == old.text
                     and r.title[:300] == old.title), None)
        if pick is None:
            unmatched += 1
            continue
        key, r = pick
        matched[iid] = (key, r)
        new = pipeline.normalize(r, BY_ID[r.source_id], _slot_time(key))
        # identity, capture time and the FIRST publication time are not judgements: a source that revises (MSRC) gives a
        # later date in a later capture, and the stored item keeps the first one (the 1-day trial moved 95 first reports)
        new.item_id, new.fetched_at, new.published_at = old.item_id, old.fetched_at, old.published_at
        new.extra = {**old.extra, **{k: v for k, v in new.extra.items() if k in ("digest", "roundup")}}
        a_, b_ = _view(old), _view(new)
        diff = [f for f in FIELDS if a_[f] != b_[f]]
        if not diff:
            continue
        for f in diff:
            field_changes[f] += 1
        if a_["signals"]["exploited"] != b_["signals"]["exploited"]:
            exploited_flips.append({"item": iid, "source": old.source_id, "title": old.title[:90],
                                    "from": a_["signals"]["exploited"], "to": b_["signals"]["exploited"],
                                    "stored_chars": len(old.text), "raw_chars": len(r.text or "")})
        changed_items[iid] = new

    since = timeutil.iso(timeutil.parse(a.since + "T00:00:00Z"))
    events = store.events_updated_since(since)
    owner = {i: e for e in events for i in e.item_ids}
    touched = {owner[i].event_id: owner[i] for i in changed_items if i in owner}
    now = datetime.now(UTC)
    event_changes = []
    for eid, ev in sorted(touched.items()):
        items = [changed_items.get(it.item_id, it) for it in store.get_items(ev.item_ids)]
        old_items = store.get_items(ev.item_ids)
        before = pipeline.recompute(copy.deepcopy(ev), old_items, now)
        after = pipeline.recompute(copy.deepcopy(ev), items, now)
        d = {f: [getattr(before, f), getattr(after, f)] for f in EVENT_FIELDS if getattr(before, f) != getattr(after, f)}
        rekey = any(set(changed_items[i].keys) != set(next(o for o in old_items if o.item_id == i).keys)
                    for i in ev.item_ids if i in changed_items)
        if d or rekey:
            event_changes.append({"event_id": eid, "domain": ev.domain, "title": ev.title[:80], "items": len(ev.item_ids),
                                  "changes": d, "would_recluster": rekey})

    # batch 1: the judgement fields only — keys / domain changes re-cluster and wait for their own replay
    patched: dict[str, object] = {}
    for iid, new in changed_items.items():
        old = stored[iid]
        flags = {k: new.extra.get(k) for k in ("digest", "roundup")}
        if new.signals != old.signals or any(bool(old.extra.get(k)) != bool(v) for k, v in flags.items()):
            p = copy.deepcopy(old)
            p.signals = dict(new.signals)
            p.extra = {**old.extra, **{k: v for k, v in flags.items() if v is not None},
                       "renormalized_at": timeutil.iso(now)}
            patched[iid] = p
    sig_events = {owner[i].event_id: owner[i] for i in patched if i in owner}
    signal_changes, writes = [], []
    for eid, ev in sorted(sig_events.items()):
        old_items = store.get_items(ev.item_ids)
        before = pipeline.recompute(copy.deepcopy(ev), old_items, now)
        after = pipeline.recompute(copy.deepcopy(ev), [patched.get(i.item_id, i) for i in old_items], now)
        d = {f: [getattr(before, f), getattr(after, f)] for f in EVENT_FIELDS if getattr(before, f) != getattr(after, f)}
        if d:      # an event the patch does not move is not rewritten (its timeline stays clean)
            signal_changes.append({"event_id": eid, "title": ev.title[:80], "changes": d})
            writes.append(after)
    if a.apply_signals:
        sfn = sess.client("stepfunctions")
        if sfn.list_executions(stateMachineArn=out["StateMachineArn"], statusFilter="RUNNING")["executions"]:
            print("refusing: a cycle is running — Process is the single writer", file=sys.stderr)
            return 2
        for p in patched.values():
            store.put_item(p)
        for ev in writes:
            ev.timeline = [*(ev.timeline or []), {"at": timeutil.iso(now), "kind": "repaired", "from": None, "to": ev.level,
                                                  "item_id": None}]
            store.put_event(ev)
        print(f"applied: {len(patched)} items, {len(writes)} events. Next: a full publish.", file=sys.stderr)

    plan = None
    if a.recluster_plan:
        from radar.store import MemoryStore
        moving = [c["event_id"] for c in event_changes if c["would_recluster"]]
        evs = {e.event_id: e for e in events if e.event_id in set(moving)}
        covered = {eid: ev for eid, ev in evs.items() if all(i in matched for i in ev.item_ids)}
        mem = MemoryStore()
        raws_in = sorted((matched[i][1] for ev in covered.values() for i in ev.item_ids),
                         key=lambda r: r.published_at or now)
        pipeline.ingest(raws_in, mem, now)
        where = {i: eid for eid, e in mem.events.items() for i in e["item_ids"]}
        outcome = collections.Counter()
        rows = []
        for eid, ev in sorted(covered.items()):
            dest = collections.Counter(where.get(i, "-") for i in ev.item_ids)
            # a new event holding this event's items together with another live event's items ⇒ merged
            others = {owner[i].event_id for d_ in dest for i in (mem.events.get(d_) or {}).get("item_ids", [])
                      if i in owner and owner[i].event_id != eid}
            kind = "intact" if len(dest) == 1 and not others else ("split" if len(dest) > 1 else "merged")
            outcome[kind] += 1
            if kind != "intact":
                rows.append({"event_id": eid, "title": ev.title[:80], "items": len(ev.item_ids), "outcome": kind,
                             "into": dict(dest.most_common(4)), "with": sorted(others)[:4]})
        plan = {"events": len(moving), "fully_covered": len(covered), "outcome": dict(outcome), "changes": rows}
        print(f"recluster plan: {len(covered)}/{len(moving)} events covered by raw · {dict(outcome)}")

    sev = collections.Counter(f"{c['changes']['severity'][0]}→{c['changes']['severity'][1]}"
                              for c in event_changes if "severity" in c["changes"])
    report = {"generated_at": timeutil.iso(now), "window": {"since": a.since, "until": a.until or "today", "raw_days": len(days),
              "batches": len(keys_)}, "raw_items": len(raws), "stored_items_found": len(stored),
              "items_changed": len(changed_items), "items_without_matching_capture": unmatched, "field_changes": dict(field_changes),
              "exploited_flips": exploited_flips, "events_touched": len(touched), "event_changes": event_changes,
              "severity_moves": dict(sev),
              "recluster_plan": plan,
              "signals_batch": {"items": len(patched), "events": len(sig_events), "event_changes": signal_changes,
                                "applied": bool(a.apply_signals)},
              "not_covered": "events first seen before the oldest raw day keep their items as stored"}
    Path(a.report).parent.mkdir(parents=True, exist_ok=True)
    Path(a.report).write_text(json.dumps(report, ensure_ascii=False, indent=1))
    print(json.dumps({k: report[k] for k in ("window", "raw_items", "stored_items_found", "items_changed",
                                             "items_without_matching_capture", "field_changes",
                                             "events_touched", "severity_moves")}, ensure_ascii=False))
    print(f"signals batch: {len(patched)} items, {len(sig_events)} events, {len(signal_changes)} with event changes"
          f"{' (APPLIED)' if a.apply_signals else ' (dry run)'}")
    print(f"exploited flips: {len(exploited_flips)} · events with changes: {len(event_changes)} "
          f"(would re-cluster: {sum(c['would_recluster'] for c in event_changes)}) · report {a.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
