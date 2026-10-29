"""Persistence behind one small interface, so the pipeline is tested against MemoryStore and runs on
DynamoStore unchanged (tests/test_store_contract.py runs the same replay on both)."""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, Protocol

from radar.model import Event, Item


class Store(Protocol):
    def get_item(self, item_id: str) -> Item | None: ...
    def put_item(self, item: Item) -> None: ...
    def get_items(self, item_ids: list[str]) -> list[Item]: ...
    def get_event(self, event_id: str) -> Event | None: ...
    def put_event(self, event: Event) -> None: ...
    def delete_event(self, event_id: str) -> None: ...
    def event_ids_for_key(self, key: str) -> list[str]: ...
    def add_keys(self, event_id: str, keys: list[str]) -> None: ...
    def events_updated_since(self, iso: str) -> list[Event]: ...
    def get_source_state(self, source_id: str) -> dict[str, Any]: ...
    def put_source_state(self, source_id: str, state: dict[str, Any]) -> None: ...
    # respond-station state lives beside the event, not in it: the process station rewrites events every
    # cycle and must never race with (or erase) an AWS job record
    def get_response(self, event_id: str) -> dict[str, Any] | None: ...
    def put_response(self, event_id: str, state: dict[str, Any]) -> None: ...
    def delete_response(self, event_id: str) -> None: ...


class MemoryStore:
    def __init__(self) -> None:
        self.items: dict[str, dict[str, Any]] = {}
        self.events: dict[str, dict[str, Any]] = {}
        self.keys: dict[str, list[str]] = defaultdict(list)
        self.sources: dict[str, dict[str, Any]] = {}
        self.responses: dict[str, dict[str, Any]] = {}

    # values are stored as JSON round-trips so tests catch anything DynamoDB could not persist
    def get_item(self, item_id: str) -> Item | None:
        d = self.items.get(item_id)
        return Item.from_dict(json.loads(json.dumps(d))) if d else None

    def put_item(self, item: Item) -> None:
        self.items[item.item_id] = json.loads(json.dumps(item.to_dict()))

    def get_items(self, item_ids: list[str]) -> list[Item]:
        return [i for i in (self.get_item(x) for x in item_ids) if i]

    def get_event(self, event_id: str) -> Event | None:
        d = self.events.get(event_id)
        return Event.from_dict(json.loads(json.dumps(d))) if d else None

    def put_event(self, event: Event) -> None:
        self.events[event.event_id] = json.loads(json.dumps(event.to_dict()))

    def delete_event(self, event_id: str) -> None:
        # key index entries pointing here go stale; readers skip ids whose event is gone
        self.events.pop(event_id, None)

    def event_ids_for_key(self, key: str) -> list[str]:
        return list(self.keys.get(key, []))

    def add_keys(self, event_id: str, keys: list[str]) -> None:
        for k in keys:
            if event_id not in self.keys[k]:
                self.keys[k].append(event_id)

    def events_updated_since(self, iso: str) -> list[Event]:
        return [Event.from_dict(d) for d in self.events.values() if d["last_updated"] >= iso]

    def get_source_state(self, source_id: str) -> dict[str, Any]:
        return dict(self.sources.get(source_id, {}))

    def put_source_state(self, source_id: str, state: dict[str, Any]) -> None:
        self.sources[source_id] = json.loads(json.dumps(state))

    def get_response(self, event_id: str) -> dict[str, Any] | None:
        d = self.responses.get(event_id)
        return json.loads(json.dumps(d)) if d else None

    def put_response(self, event_id: str, state: dict[str, Any]) -> None:
        self.responses[event_id] = json.loads(json.dumps(state))

    def delete_response(self, event_id: str) -> None:
        self.responses.pop(event_id, None)
