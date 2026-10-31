"""Re-cluster recent events with the current pipeline (repair after a clustering fix, e.g. commit 1799544).
Web3 by default; `--domain vuln` (2026-10-31: an Arista + Collabora event merged under the pre-10-27 rules) re-plays
vulnerability events without re-keying (their keys are CVEs / URLs, unchanged by the free-text rules).

  AWS_PROFILE=<profile> uv run python scripts/recluster_web3.py --since 2026-10-26            # dry run: print the plan
  AWS_PROFILE=<profile> uv run python scripts/recluster_web3.py --since 2026-10-26 --apply    # write it

What it does: takes every web3 event updated since --since, re-keys their stored items with the current free-text rules
(pipeline.web3_text_keys — items keep their strong keys), replays them in arrival order through pipeline.attach into a
scratch MemoryStore, and writes back only the difference: changed/new events, removed events, their key-index rows.
Event ids are deterministic (seeded by the first item), so an event whose story did not change keeps its id and
timeline. A removed event's respond state (AWS job records) moves to the event that now holds its first item.
Run it between cycles (it refuses while a Step Functions cycle is running) and follow with a full publish.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import boto3
from boto3.dynamodb.conditions import Key

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from radar import keys, pipeline, respond, timeutil
from radar.dynamo import DynamoStore
from radar.model import Event, Item
from radar.store import MemoryStore

TEXT_PREFIXES = ("tok:", "tt:")


def rekey(it: Item) -> Item:
    """Stored keys were computed by the old rules: recompute the name-derived ones (structured victim ent:, or the
    free-text tok:/tt: of an item without one), keep every other key — same branches as pipeline.normalize."""
    if it.domain != "web3":
        return it
    kept = [k for k in it.keys if not k.startswith((*TEXT_PREFIXES, "ent:"))]
    if it.entity:
        ent = keys.entity_key(it.entity)
        it.keys = sorted(set(kept) | ({f"ent:{ent}"} if ent else set()))
    else:
        it.keys = sorted(set(kept) | set(pipeline.web3_text_keys(it.title, f"{it.title}\n{it.text}")))
    return it


def replay(items: list[Item], now) -> MemoryStore:
    mem = MemoryStore()
    res = pipeline.IngestResult()
    for it in sorted(items, key=lambda i: (i.fetched_at, i.published_at, i.item_id)):
        mem.put_item(it)
        pipeline.attach(it, mem, it.fetched_at, now, res)
    return mem


def adopt(old: dict[str, Event], new: dict[str, Event], by_id: dict[str, Item], now) -> None:
    """Items the replay leaves unattached keep their story: a context-only report (or one revised into one after it
    attached — live: Odaily's 「Specter：已冻结币安黑客资金…」) can only attach through hard links on replay, but it was
    in an event, so it goes to the new event holding most of that event's items. Never drop a report."""
    placed = {i for ev in new.values() for i in ev.item_ids}
    for oev in old.values():
        orphans = [i for i in oev.item_ids if i not in placed and i in by_id]
        if not orphans:
            continue
        home = max(new.values(), key=lambda ev: len(set(ev.item_ids) & set(oev.item_ids)), default=None)
        if home is None or not set(home.item_ids) & set(oev.item_ids):
            print(f"  ! {len(orphans)} item(s) of {oev.event_id} have no successor event — left unattached")
            continue
        its = [by_id[i] for i in home.item_ids + orphans if i in by_id]
        new[home.event_id] = pipeline.recompute(home, its, now)
        placed |= set(orphans)


def fold_strays(new: dict[str, Event], by_id: dict[str, Item], now) -> None:
    """Targeted repair only: a one-report event without a CVE that the replay split off (2026-10-31: SecurityWeek's
    "Attackers Exploit Third Arista VCO Zero-Day" — no CVE, no shared token) rejoins the largest successor, as it
    was in the repaired event. Never applied to a domain-wide replay (there a one-report event is a real event)."""
    strays = [eid for eid, ev in new.items() if len(ev.item_ids) == 1 and not ev.cves]
    rest = [ev for eid, ev in new.items() if eid not in strays]
    if not rest:
        return
    home = max(rest, key=lambda ev: len(ev.item_ids))
    for eid in strays:
        ids = home.item_ids + new.pop(eid).item_ids
        home = pipeline.recompute(home, [by_id[i] for i in ids if i in by_id], now)
    new[home.event_id] = home


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", required=True, help="YYYY-MM-DD: web3 events updated since then are re-clustered")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--domain", default="web3", choices=["web3", "vuln", "incident"])
    ap.add_argument("--event", action="append", default=[],
                    help="repair only these events (repeatable); a domain-wide replay re-seeds unrelated events' ids")
    args = ap.parse_args()
    out = json.loads((ROOT / "build" / "outputs.json").read_text())["SecurityRadar"]
    sess = boto3.Session(region_name="ap-northeast-1")
    if args.apply:
        sfn = sess.client("stepfunctions")
        running = sfn.list_executions(stateMachineArn=out["StateMachineArn"], statusFilter="RUNNING")["executions"]
        if running:
            print(f"refusing: a cycle is running ({running[0]['name']}) — Process is the single writer", file=sys.stderr)
            return 2
    table = sess.resource("dynamodb").Table(out["TableName"])
    store = DynamoStore(table)
    if args.event:
        old = {e.event_id: e for e in (store.get_event(x) for x in args.event) if e}
    else:
        old = {e.event_id: e for e in store.events_updated_since(f"{args.since}T00:00:00Z") if e.domain == args.domain}
    items = [rekey(i) for i in store.get_items(sorted({i for e in old.values() for i in e.item_ids}))]
    now = timeutil.now()
    mem = replay(items, now)
    new = {eid: Event.from_dict(d) for eid, d in mem.events.items()}
    adopt(old, new, {i.item_id: i for i in items}, now)
    if args.event:
        fold_strays(new, {i.item_id: i for i in items}, now)

    changed = [eid for eid, ev in new.items() if eid not in old or sorted(ev.item_ids) != sorted(old[eid].item_ids)]
    removed = [eid for eid in old if eid not in new]
    print(f"{args.domain} events since {args.since}: {len(old)} → {len(new)}  (changed/new {len(changed)}, removed {len(removed)})")
    root_owner = {i: eid for eid, ev in new.items() for i in ev.item_ids}
    for eid in sorted(changed, key=lambda e: -len(new[e].item_ids)):
        ev, was = new[eid], old.get(eid)
        tag = "NEW " if was is None else f"was {len(was.item_ids):2d}"
        print(f"  {eid} {tag} → {len(ev.item_ids):2d} items  {ev.severity} {ev.level}  first={ev.first_seen[:16]}  {ev.title[:60]}")
    moves = {}
    for eid in removed:
        dest = root_owner.get(old[eid].item_ids[0]) if old[eid].item_ids else None
        resp = store.get_response(eid)
        print(f"  {eid} removed ({len(old[eid].item_ids)} items){'; respond state → ' + str(dest) if resp else ''}  {old[eid].title[:50]}")
        if resp and dest:
            moves[eid] = (dest, resp)
    if not args.apply:
        print("dry run — nothing written (add --apply)")
        return 0

    at = timeutil.iso(now)
    for eid in changed:
        ev = new[eid]
        was = old.get(eid)
        ev.timeline = (was.timeline if was else []) + [{"at": at, "kind": "repaired", "from": None, "to": ev.level, "item_id": None}]
        store.put_event(ev)
    for it in items:   # re-keyed items, so the next cycle matches with the new keys too
        store.put_item(it)
    for eid in removed:
        store.delete_event(eid)
    for eid, (dest, resp) in moves.items():
        store.put_response(dest, respond.merge_states(dest, store.get_response(dest), eid, resp))
        store.delete_response(eid)
    # key index: drop every row of the touched events, write the new ones
    stale = 0
    for eid in set(changed) | set(removed):
        for k in (old[eid].keys if eid in old else []):
            table.delete_item(Key={"pk": f"KEY#{k}", "sk": f"EVENT#{eid}"})
            stale += 1
    for eid in changed:
        store.add_keys(eid, new[eid].keys)
    left = [r for eid in removed for k in old[eid].keys
            for r in table.query(KeyConditionExpression=Key("pk").eq(f"KEY#{k}"))["Items"] if r["sk"] == f"EVENT#{eid}"]
    print(f"applied: {len(changed)} events written, {len(removed)} removed, {stale} index rows dropped "
          f"(left pointing at removed events: {len(left)}). Next: a full publish.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
