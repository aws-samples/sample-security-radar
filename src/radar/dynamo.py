"""DynamoDB single-table Store. Values are JSON strings in attribute `d` (no Decimal conversion bugs).

  ITEM#<id>  META        item
  EVENT#<id> META        event        gsi1pk="EVENT", gsi1sk=last_updated
  KEY#<key>  EVENT#<id>  key index
  SRC#<id>   STATE       source state
  RAW#<s3key> DONE       raw batch fully ingested (resume marker)
"""

from __future__ import annotations

import json
from typing import Any

from boto3.dynamodb.conditions import Key

from radar.model import Event, Item


class DynamoStore:
    def __init__(self, table: Any) -> None:
        self.t = table

    def _get(self, pk: str, sk: str) -> dict[str, Any] | None:
        # read-after-write inside one ingest run: eventual consistency would drop just-written rows
        r = self.t.get_item(Key={"pk": pk, "sk": sk}, ConsistentRead=True).get("Item")
        return json.loads(r["d"]) if r else None

    def get_item(self, item_id: str) -> Item | None:
        d = self._get(f"ITEM#{item_id}", "META")
        return Item.from_dict(d) if d else None

    def put_item(self, item: Item) -> None:
        self.t.put_item(Item={"pk": f"ITEM#{item.item_id}", "sk": "META", "d": json.dumps(item.to_dict())})

    def get_items(self, item_ids: list[str]) -> list[Item]:
        out: dict[str, Item] = {}
        ids = list(dict.fromkeys(item_ids))
        client = self.t.meta.client
        for i in range(0, len(ids), 100):
            req: dict[str, Any] = {self.t.name: {"Keys": [{"pk": f"ITEM#{x}", "sk": "META"} for x in ids[i:i + 100]],
                                                 "ConsistentRead": True}}
            while req:
                r = client.batch_get_item(RequestItems=req)
                for row in r["Responses"].get(self.t.name, []):
                    it = Item.from_dict(json.loads(row["d"]))
                    out[it.item_id] = it
                req = r.get("UnprocessedKeys") or {}
        return [out[x] for x in ids if x in out]

    def get_event(self, event_id: str) -> Event | None:
        d = self._get(f"EVENT#{event_id}", "META")
        return Event.from_dict(d) if d else None

    def put_event(self, event: Event) -> None:
        self.t.put_item(Item={"pk": f"EVENT#{event.event_id}", "sk": "META", "d": json.dumps(event.to_dict()),
                              "gsi1pk": "EVENT", "gsi1sk": event.last_updated})

    def delete_event(self, event_id: str) -> None:
        self.t.delete_item(Key={"pk": f"EVENT#{event_id}", "sk": "META"})

    def event_ids_for_key(self, key: str) -> list[str]:
        r = self.t.query(KeyConditionExpression=Key("pk").eq(f"KEY#{key}"), ConsistentRead=True)
        return [row["sk"][6:] for row in r["Items"]]

    def add_keys(self, event_id: str, keys: list[str]) -> None:
        with self.t.batch_writer(overwrite_by_pkeys=["pk", "sk"]) as w:
            for k in set(keys):
                w.put_item(Item={"pk": f"KEY#{k}", "sk": f"EVENT#{event_id}"})

    def events_updated_since(self, iso: str) -> list[Event]:
        out, kw = [], {"IndexName": "gsi1", "KeyConditionExpression": Key("gsi1pk").eq("EVENT") & Key("gsi1sk").gte(iso)}
        while True:
            r = self.t.query(**kw)
            out += [Event.from_dict(json.loads(row["d"])) for row in r["Items"]]
            if "LastEvaluatedKey" not in r:
                return out
            kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]

    def is_raw_processed(self, key: str) -> bool:
        return self._get(f"RAW#{key}", "DONE") is not None

    def mark_raw_processed(self, key: str, at: str) -> None:
        self.t.put_item(Item={"pk": f"RAW#{key}", "sk": "DONE", "d": json.dumps({"at": at})})

    def get_source_state(self, source_id: str) -> dict[str, Any]:
        return self._get(f"SRC#{source_id}", "STATE") or {}

    def put_source_state(self, source_id: str, state: dict[str, Any]) -> None:
        self.t.put_item(Item={"pk": f"SRC#{source_id}", "sk": "STATE", "d": json.dumps(state)})

    def get_response(self, event_id: str) -> dict[str, Any] | None:
        return self._get(f"EVENT#{event_id}", "RESPONSE")

    def put_response(self, event_id: str, state: dict[str, Any]) -> None:
        self.t.put_item(Item={"pk": f"EVENT#{event_id}", "sk": "RESPONSE", "d": json.dumps(state)})

    def delete_response(self, event_id: str) -> None:
        self.t.delete_item(Key={"pk": f"EVENT#{event_id}", "sk": "RESPONSE"})
