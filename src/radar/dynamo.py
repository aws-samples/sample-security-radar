"""DynamoDB single-table Store. Values are JSON strings in attribute `d` (no Decimal conversion bugs).

  ITEM#<id>  META        item
  EVENT#<id> META        event        gsi1pk="EVENT", gsi1sk=last_updated
  KEY#<key>  EVENT#<id>  key index
  SRC#<id>   STATE       source state
  RAW#<s3key> DONE       raw batch fully ingested (resume marker)
"""

from __future__ import annotations

import json
import logging
from dataclasses import replace
from typing import Any

from boto3.dynamodb.conditions import Key

from radar.limits import Limits
from radar.model import Event, Item

log = logging.getLogger(__name__)


def compact_event(event: Event) -> Event:
    """Drop repeated timeline entries (same kind / from / to / item) and repeated amount points (same value / source /
    kind), keeping the first of each — a flip-flop collapses to its two states; the audit trail keeps every distinct
    transition. Pure; the caller logs that it happened."""
    seen_t, tl = set(), []
    for x in event.timeline:
        k = (x.get("kind"), x.get("from"), x.get("to"), x.get("item_id"))
        if k not in seen_t:
            seen_t.add(k)
            tl.append(x)
    seen_a, ah = set(), []
    for x in event.amount_history:
        k = (x.get("value"), x.get("source_id"), x.get("kind"))
        if k not in seen_a:
            seen_a.add(k)
            ah.append(x)
    out = replace(event, timeline=tl, amount_history=ah)
    if len(json.dumps(out.to_dict()).encode()) <= Limits.EVENT_ROW_COMPACT_BYTES:
        return out
    # still too big with every entry distinct (a Binance-sized story: 448 reports, 177 KB at 28 sources): keep every
    # state change and the newest stream entries. Nothing is lost — item_ids lists every report and each item keeps its
    # own amount; only the derived "report added" / "amount changed" stream is shortened (logged by the caller).
    keep = Limits.EVENT_STREAM_KEEP
    stream = [x for x in tl if x.get("kind") in ("item_added", "amount_change")]
    tail = {id(x) for x in stream[-keep:]}
    tl = [x for x in tl if x.get("kind") not in ("item_added", "amount_change") or id(x) in tail]
    ah = ah[:1] + ah[1:][-keep:]
    return replace(out, timeline=tl, amount_history=ah)


class DynamoStore:
    def __init__(self, table: Any) -> None:
        self.t = table
        self.begin_run()

    def begin_run(self) -> None:
        """Forget the event window (a station run starts here: Lambda containers outlive one invocation)."""
        self._win_since: str | None = None
        self._win: dict[str, dict[str, Any]] = {}
        # per-run caches (research/19 B3 / live 2026-11-11: Publish made 3,458 serial reads and timed out at 300 s);
        # written through on put_*, so a station reads its own writes. Fresh objects per call.
        self._items: dict[str, dict[str, Any] | None] = {}
        self._resp: dict[str, dict[str, Any] | None] = {}
        self._ev: dict[str, dict[str, Any] | None] = {}
        self._keyidx: dict[str, list[str]] = {}
        # source-state rows as raw JSON (ledgers run to 300 KB; Publish read triage/retitle/duplabels once per page)
        self._src: dict[str, str | None] = {}
        self.window_queries = 0
        self.window_hits = 0

    def _get(self, pk: str, sk: str) -> dict[str, Any] | None:
        # read-after-write inside one ingest run: eventual consistency would drop just-written rows
        r = self.t.get_item(Key={"pk": pk, "sk": sk}, ConsistentRead=True).get("Item")
        return json.loads(r["d"]) if r else None

    def _batch(self, keys: list[tuple[str, str]]) -> dict[tuple[str, str], dict[str, Any]]:
        """BatchGetItem in chunks of 100, chunks fetched concurrently (the low-level client is thread-safe)."""
        from concurrent.futures import ThreadPoolExecutor
        client = self.t.meta.client

        def chunk(part: list[tuple[str, str]]) -> dict[tuple[str, str], dict[str, Any]]:
            got: dict[tuple[str, str], dict[str, Any]] = {}
            req: dict[str, Any] = {self.t.name: {"Keys": [{"pk": pk, "sk": sk} for pk, sk in part], "ConsistentRead": True}}
            while req:
                r = client.batch_get_item(RequestItems=req)
                for row in r["Responses"].get(self.t.name, []):
                    got[(row["pk"], row["sk"])] = json.loads(row["d"])
                req = r.get("UnprocessedKeys") or {}
            return got
        parts = [keys[i:i + 100] for i in range(0, len(keys), 100)]
        out: dict[tuple[str, str], dict[str, Any]] = {}
        if len(parts) <= 1:
            for p in parts:
                out.update(chunk(p))
            return out
        with ThreadPoolExecutor(min(8, len(parts))) as ex:
            for got in ex.map(chunk, parts):
                out.update(got)
        return out

    def get_item(self, item_id: str) -> Item | None:
        if item_id not in self._items:
            self._items[item_id] = self._get(f"ITEM#{item_id}", "META")
        d = self._items[item_id]
        return Item.from_dict(d) if d else None

    def put_item(self, item: Item) -> None:
        d = item.to_dict()
        self.t.put_item(Item={"pk": f"ITEM#{item.item_id}", "sk": "META", "d": json.dumps(d)})
        self._items[item.item_id] = json.loads(json.dumps(d))

    def get_items(self, item_ids: list[str]) -> list[Item]:
        ids = list(dict.fromkeys(item_ids))
        missing = [x for x in ids if x not in self._items]
        if missing:
            got = self._batch([(f"ITEM#{x}", "META") for x in missing])
            for x in missing:
                self._items[x] = got.get((f"ITEM#{x}", "META"))
        return [Item.from_dict(self._items[x]) for x in ids if self._items.get(x)]

    def get_event(self, event_id: str) -> Event | None:
        d = self._win.get(event_id)
        if d is None:
            if event_id not in self._ev:
                self._ev[event_id] = self._get(f"EVENT#{event_id}", "META")
            d = self._ev[event_id]
        return Event.from_dict(d) if d else None

    def put_event(self, event: Event) -> None:
        d = json.dumps(event.to_dict())
        if len(d.encode()) > Limits.EVENT_ROW_COMPACT_BYTES:
            # DynamoDB rejects items > 400 KB, and Process is the single writer: one oversized event fails every cycle.
            # Live 2026-11-10: Gamma / OcelotDex reached 396 / 394 KB from a flip-flopping amount (DeFiLlama guid clash)
            d = json.dumps(compact_event(event).to_dict())
            log.error(json.dumps({"store": "put_event", "degraded": "event_row_compacted", "event_id": event.event_id,
                                  "bytes_after": len(d.encode())}))
        self.t.put_item(Item={"pk": f"EVENT#{event.event_id}", "sk": "META", "d": d,
                              "gsi1pk": "EVENT", "gsi1sk": event.last_updated})
        self._ev[event.event_id] = json.loads(d)
        if self._win_since is not None:            # write-through: the run reads its own writes from the window
            if event.last_updated >= self._win_since:
                self._win[event.event_id] = json.loads(d)
            else:
                self._win.pop(event.event_id, None)

    def delete_event(self, event_id: str) -> None:
        self.t.delete_item(Key={"pk": f"EVENT#{event_id}", "sk": "META"})
        self._win.pop(event_id, None)
        self._ev[event_id] = None

    def event_ids_for_key(self, key: str) -> list[str]:
        """Every event under a key (all pages — a single Query page stops at 1 MB), memoised for the run."""
        if key not in self._keyidx:
            ids, kw = [], {"KeyConditionExpression": Key("pk").eq(f"KEY#{key}"), "ConsistentRead": True}
            while True:
                r = self.t.query(**kw)
                ids += [row["sk"][6:] for row in r["Items"]]
                if "LastEvaluatedKey" not in r:
                    break
                kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]
            self._keyidx[key] = ids
        return list(self._keyidx[key])

    def add_keys(self, event_id: str, keys: list[str]) -> None:
        with self.t.batch_writer(overwrite_by_pkeys=["pk", "sk"]) as w:
            for k in set(keys):
                w.put_item(Item={"pk": f"KEY#{k}", "sk": f"EVENT#{event_id}"})
        for k in set(keys):
            if k in self._keyidx and event_id not in self._keyidx[k]:
                self._keyidx[k].append(event_id)

    def remove_keys(self, event_id: str, keys: list[str]) -> None:
        with self.t.batch_writer(overwrite_by_pkeys=["pk", "sk"]) as w:
            for k in set(keys):
                w.delete_item(Key={"pk": f"KEY#{k}", "sk": f"EVENT#{event_id}"})
        for k in set(keys):
            if k in self._keyidx:
                self._keyidx[k] = [x for x in self._keyidx[k] if x != event_id]

    def events_updated_since(self, iso: str) -> list[Event]:
        """The window of events updated since `iso`. Within one station run the GSI is queried once for the widest
        window asked; narrower or equal windows are served from it, writes go through it (research/19 B3: 17 call
        sites, ≥ 5 full-window reads per cycle, 3.7k RCU/cycle at 28 sources). Fresh Event objects each call —
        a caller mutating one never changes another's."""
        if self._win_since is None or iso < self._win_since:
            rows, kw = {}, {"IndexName": "gsi1", "KeyConditionExpression": Key("gsi1pk").eq("EVENT") & Key("gsi1sk").gte(iso)}
            while True:
                r = self.t.query(**kw)
                for row in r["Items"]:
                    d = json.loads(row["d"])
                    rows[d["event_id"]] = d
                if "LastEvaluatedKey" not in r:
                    break
                kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]
            self._win_since, self._win = iso, rows
            self.window_queries += 1
        else:
            self.window_hits += 1
        return [Event.from_dict(d) for d in sorted(self._win.values(), key=lambda d: d["last_updated"])
                if d["last_updated"] >= iso]

    def is_raw_processed(self, key: str) -> bool:
        return self._get(f"RAW#{key}", "DONE") is not None

    def mark_raw_processed(self, key: str, at: str) -> None:
        self.t.put_item(Item={"pk": f"RAW#{key}", "sk": "DONE", "d": json.dumps({"at": at})})

    def get_source_state(self, source_id: str) -> dict[str, Any]:
        if source_id not in self._src:
            r = self.t.get_item(Key={"pk": f"SRC#{source_id}", "sk": "STATE"}, ConsistentRead=True).get("Item")
            self._src[source_id] = r["d"] if r else None
        d = self._src[source_id]
        return json.loads(d) if d else {}       # a fresh object per call: callers mutate and put it back

    def put_source_state(self, source_id: str, state: dict[str, Any]) -> None:
        d = json.dumps(state)
        if len(d.encode()) > Limits.STATE_ROW_WARN_BYTES:
            # every 413 so far came from a ledger that only grew (__cve_meta__, the event rows, __cluster_judge__):
            # say so while there is still headroom, with the key, so the next one is fixed before it fails a cycle
            log.error(json.dumps({"store": "put_source_state", "degraded": "state_row_near_limit", "key": source_id,
                                  "bytes": len(d.encode()), "limit": 400_000}))
        self.t.put_item(Item={"pk": f"SRC#{source_id}", "sk": "STATE", "d": d})
        self._src[source_id] = d

    def delete_source_state(self, source_id: str) -> None:
        self.t.delete_item(Key={"pk": f"SRC#{source_id}", "sk": "STATE"})
        self._src[source_id] = None         # the run cache must not resurrect the deleted row

    def get_source_states(self, source_ids: list[str]) -> dict[str, dict[str, Any]]:
        """Plan reads every source's state each cycle: one BatchGetItem per 100 instead of N serial GetItems
        (167 sources ≈ 1–1.5 s serial, research/17 §0)."""
        out: dict[str, dict[str, Any]] = {}
        ids, client = list(dict.fromkeys(source_ids)), self.t.meta.client
        for i in range(0, len(ids), 100):
            req: dict[str, Any] = {self.t.name: {"Keys": [{"pk": f"SRC#{x}", "sk": "STATE"} for x in ids[i:i + 100]],
                                                 "ConsistentRead": True}}
            while req:
                r = client.batch_get_item(RequestItems=req)
                for row in r["Responses"].get(self.t.name, []):
                    out[row["pk"][4:]] = json.loads(row["d"])
                    self._src[row["pk"][4:]] = row["d"]
                req = r.get("UnprocessedKeys") or {}
        for x in ids:
            self._src.setdefault(x, None)
        return {x: out.get(x, {}) for x in ids}

    def get_response(self, event_id: str) -> dict[str, Any] | None:
        if event_id not in self._resp:
            self._resp[event_id] = self._get(f"EVENT#{event_id}", "RESPONSE")
        d = self._resp[event_id]
        return json.loads(json.dumps(d)) if d is not None else None

    def get_responses(self, event_ids: list[str]) -> None:
        """Warm the response cache for many events in one batched read (Publish: 500 pages)."""
        missing = [x for x in dict.fromkeys(event_ids) if x not in self._resp]
        got = self._batch([(f"EVENT#{x}", "RESPONSE") for x in missing]) if missing else {}
        for x in missing:
            self._resp[x] = got.get((f"EVENT#{x}", "RESPONSE"))

    def put_response(self, event_id: str, state: dict[str, Any]) -> None:
        self.t.put_item(Item={"pk": f"EVENT#{event_id}", "sk": "RESPONSE", "d": json.dumps(state)})
        self._resp[event_id] = json.loads(json.dumps(state))

    def delete_response(self, event_id: str) -> None:
        self.t.delete_item(Key={"pk": f"EVENT#{event_id}", "sk": "RESPONSE"})
        self._resp[event_id] = None
