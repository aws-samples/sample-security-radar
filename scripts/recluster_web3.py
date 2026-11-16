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
from radar import keys, pipeline, removals, respond, signals, timeutil
from radar.dynamo import DynamoStore
from radar.model import Event, Item
from radar.registry import BY_ID
from radar.store import MemoryStore

TEXT_PREFIXES = ("tok:", "tt:")


def rekey(it: Item) -> Item:
    """Stored keys were computed by the old rules: recompute the name-derived ones (structured victim ent:, or the
    free-text tok:/tt: of an item without one), keep every other key — same branches as pipeline.normalize."""
    if BY_ID[it.source_id].parser == "twitterapi":      # C4 F1: a tweet's cited article is now a key of its own
        it.keys = sorted(set(it.keys) | set(pipeline.cited_article_keys(it.links)))
    # ae4445c: tx forms the extractor learned later (Phalcon path links) — same call as pipeline.normalize; tx found
    # earlier (incl. DeFiHackLabs PoC attack_tx) are kept
    have = {t["hash"] for t in it.extra.get("tx") or []}
    new = [t for t in keys.tx_refs(f"{it.title}\n{it.text}\n" + "\n".join(it.links)) if t["hash"] not in have]
    if new:
        it.extra = {**it.extra, "tx": [*(it.extra.get("tx") or []), *new]}
        it.keys = sorted(set(it.keys) | {f"tx:{t['hash']}" for t in new})
    if it.domain == "incident" and signals.security_event(it.title) and "amount_usd" not in it.extra \
            and not signals.is_roundup_report(it.title):
        # same as normalize: an incident report's headline loss is an amt: key too (The Block's 「French bank Crédit
        # Mutuel Arkéa exploited for over $133 million」 must meet the web3 Arkéa event)
        it.keys = sorted({k for k in it.keys if not k.startswith("amt:")}
                         | set(pipeline.amount_keys(signals.loss_amounts(it.title, None))))
    if BY_ID[it.source_id].parser == "rolie":         # d609505: one CSAF advisory keys all its own CVEs (no ≤ 3 cap)
        it.keys = sorted(set(it.keys) | {f"cve:{c}" for c in it.extra.get("cves") or []})
    if it.domain != "web3":
        # same as normalize: outside web3 the free-text keys are the headline's named tokens (keys.named_tokens) —
        # recomputed, so a rule change there (an advisory number's prefix is no name) reaches stored items
        it.keys = sorted({k for k in it.keys if not k.startswith("tok:")} | {f"tok:{t}" for t in keys.named_tokens(it.title)})
        return it
    reextract(it)
    kept = [k for k in it.keys if not k.startswith((*TEXT_PREFIXES, "ent:"))]
    if it.entity:
        ent = keys.entity_key(it.entity)
        it.keys = sorted(set(kept) | ({f"ent:{ent}"} if ent else set()))
    else:
        it.keys = sorted(set(kept) | set(pipeline.web3_text_keys(it.title, f"{it.title}\n{it.text}")))
    return it


def reextract(it: Item) -> None:
    """A prose report's loss figure under the current rules (2026-11-04: signals.loss_amount — the stated loss, not the
    largest number: PANews' 「…资产规模达2350亿美元」 had stored $235B), the same call as pipeline.normalize, plus its amt:
    keys. A hack database's structured amount is never touched. History points equal to the old value follow it."""
    if it.extra.get("amount_usd") is not None:        # structured: the figure stays, it only gains its amt: key
        it.keys = sorted({k for k in it.keys if not k.startswith("amt:")}
                         | set(pipeline.amount_keys([float(it.extra["amount_usd"])])))
        return
    if "amount_usd" in it.extra or not signals.web3_incident(f"{it.title}\n{it.text}"):
        return
    old, new = it.signals.get("amount_usd"), signals.loss_amount(it.title, it.text)
    if new != old:
        it.signals = {**it.signals, "amount_usd": new}
        hist = it.extra.get("amount_history") or []
        it.extra = {**it.extra, "amount_history": [{**p, "value": new} if p.get("value") == old else p for p in hist
                                                   if new is not None or p.get("value") != old]}
    title_keys = [] if signals.is_roundup_report(it.title) else pipeline.amount_keys(signals.loss_amounts(it.title, None))
    it.keys = sorted({k for k in it.keys if not k.startswith("amt:")} | set(title_keys))   # same rule as normalize


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


def fold_strays(new: dict[str, Event], by_id: dict[str, Item], now, old: dict[str, Event] | None = None) -> None:
    """Targeted repair only: a one-report event without a CVE that the replay split off (2026-10-31: SecurityWeek's
    "Attackers Exploit Third Arista VCO Zero-Day" — no CVE, no shared token) rejoins the largest successor, as it
    was in the repaired event. Never applied to a domain-wide replay (there a one-report event is a real event)."""
    strays = [eid for eid, ev in new.items() if len(ev.item_ids) == 1 and not ev.cves]
    rest = [ev for eid, ev in new.items() if eid not in strays]
    if not rest:
        return
    home = max(rest, key=lambda ev: len(ev.item_ids))
    # only a stray that shares a key with its new home (2026-11-04 dry run: eleven unrelated events passed together —
    # GMO, PrimeFinance, Cysic … — all folded into Binance). An unrelated stray stays its own event.
    # only a stray that was in home's old event ("as it was") or shares a key with it (2026-11-04 dry run: eleven
    # unrelated events passed together — GMO, PrimeFinance, Cysic … — were all folded into Binance)
    was_with = {i for ev in (old or {}).values() if set(ev.item_ids) & set(home.item_ids) for i in ev.item_ids}
    strays = [eid for eid in strays if set(new[eid].item_ids) & was_with
              or set(new[eid].keys) & set(home.keys) - {k for k in home.keys if k.startswith("url:")}]
    for eid in strays:
        ids = home.item_ids + new.pop(eid).item_ids
        home = pipeline.recompute(home, [by_id[i] for i in ids if i in by_id], now)
    new[home.event_id] = home


def _tx(ev: Event) -> list[str]:
    return sorted(t["hash"] for t in ev.tx or [])


def changed_events(old: dict[str, Event], new: dict[str, Event]) -> list[str]:
    """Events the repair must write: new, or a different membership, or a tx the re-key found (304a847: a tx-only
    change was never written — the Binance P0 kept tx = []), or a headline amount the re-extraction moved
    (2026-11-04: the $235B bank balance sheet), or CVE keys the re-key added (2026-11-06: CSAF advisories with 4 CVEs)."""
    return [eid for eid, ev in new.items() if eid not in old or sorted(ev.item_ids) != sorted(old[eid].item_ids)
            or _tx(ev) != _tx(old[eid]) or ev.amount_usd_latest != old[eid].amount_usd_latest
            or ev.cves != old[eid].cves]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", required=True, help="YYYY-MM-DD: web3 events updated since then are re-clustered")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--domain", default="web3", choices=["web3", "vuln", "incident"])
    ap.add_argument("--dump", metavar="PATH", help="write the stored items of these events as gzip JSON lines, in replay "
                    "order, and stop — the clustering corpus (tests/fixtures/cluster_golden, scripts/cluster_eval.py)")
    ap.add_argument("--min-items", type=int, default=1, help="with --dump: only events with at least this many items")
    ap.add_argument("--event", action="append", default=[],
                    help="repair only these events (repeatable); a domain-wide replay re-seeds unrelated events' ids")
    ap.add_argument("--split", action="store_true",
                    help="with --event: the event holds several stories — keep every one-report event the replay splits "
                         "off (the default folds them back into the largest, which is right for a story that lost a report)")
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
    if args.dump:
        keep = [e for e in old.values() if len(e.item_ids) >= args.min_items]
        stored = sorted(store.get_items(sorted({i for e in keep for i in e.item_ids})),
                        key=lambda i: (i.fetched_at, i.published_at, i.item_id))
        import gzip
        with gzip.open(args.dump, "wt", encoding="utf-8") as f:
            for it in stored:
                f.write(json.dumps(it.to_dict(), ensure_ascii=False, sort_keys=True) + "\n")
        print(f"{args.domain}: {len(keep)} events, {len(stored)} items → {args.dump}")
        return 0
    items = [rekey(i) for i in store.get_items(sorted({i for e in old.values() for i in e.item_ids}))]
    now = timeutil.now()
    mem = replay(items, now)
    new = {eid: Event.from_dict(d) for eid, d in mem.events.items()}
    adopt(old, new, {i.item_id: i for i in items}, now)
    if args.event and not args.split:
        fold_strays(new, {i.item_id: i for i in items}, now, old)

    changed = changed_events(old, new)
    removed = [eid for eid in old if eid not in new]
    print(f"{args.domain} events since {args.since}: {len(old)} → {len(new)}  (changed/new {len(changed)}, removed {len(removed)})")
    root_owner = {i: eid for eid, ev in new.items() for i in ev.item_ids}
    for eid in sorted(changed, key=lambda e: -len(new[e].item_ids)):
        ev, was = new[eid], old.get(eid)
        tag = "NEW " if was is None else f"was {len(was.item_ids):2d}"
        gained = sorted(set(_tx(ev)) - set(_tx(was) if was else []))
        was = old.get(eid)
        if was and was.amount_usd_latest != ev.amount_usd_latest:
            print(f"  {eid} amount {was.amount_usd_latest} → {ev.amount_usd_latest}")
        print(f"  {eid} {tag} → {len(ev.item_ids):2d} items  {ev.severity} {ev.level}  first={ev.first_seen[:16]}  {ev.title[:60]}"
              + (f"  +tx {', '.join(h[:10] for h in gained)}" if gained else ""))
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
    # their search rows and detail pages leave the site at the next publish (radar.removals)
    removals.record(store, [(eid, old[eid].first_seen[:7], root_owner.get(old[eid].item_ids[0]) if old[eid].item_ids else None)
                            for eid in removed], at)
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
