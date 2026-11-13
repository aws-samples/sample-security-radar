"""The pipeline must behave identically on MemoryStore and DynamoStore (moto). Same replay ⇒ same events."""

import json

import boto3
import pytest
from moto import mock_aws
from test_pipeline_replay import FETCHED, snapshot_raws

from radar import pipeline
from radar.dynamo import DynamoStore
from radar.store import MemoryStore


@pytest.fixture
def table():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="ap-northeast-1")
        t = ddb.create_table(
            TableName="radar", BillingMode="PAY_PER_REQUEST",
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": n, "AttributeType": "S"} for n in ("pk", "sk", "gsi1pk", "gsi1sk")],
            GlobalSecondaryIndexes=[{"IndexName": "gsi1", "Projection": {"ProjectionType": "ALL"},
                                     "KeySchema": [{"AttributeName": "gsi1pk", "KeyType": "HASH"},
                                                   {"AttributeName": "gsi1sk", "KeyType": "RANGE"}]}])
        yield t


def test_dynamo_replay_equals_memory_replay(table):
    raws = [r for r in snapshot_raws() if r.source_id != "cisa_kev"]  # KEV adds volume, not new code paths
    mem, dyn = MemoryStore(), DynamoStore(table)
    pipeline.ingest(raws, mem, FETCHED)
    pipeline.ingest(raws, dyn, FETCHED)
    d_events = {e.event_id: e.to_dict() for e in dyn.events_updated_since("2000")}
    assert json.dumps(d_events, sort_keys=True) == json.dumps(mem.events, sort_keys=True)
    # idempotent on DynamoDB too
    res = pipeline.ingest(raws, dyn, FETCHED)
    assert (res.new_items, res.updated_items) == (0, 0)


def test_dynamo_delete_and_source_state(table):
    s = DynamoStore(table)
    s.put_source_state("x", {"last_run": "2026-10-23T00:00:00Z", "runs": [["2026-10-23T00:00:00Z", 3]]})
    assert s.get_source_state("x")["runs"] == [["2026-10-23T00:00:00Z", 3]]
    assert s.get_source_state("missing") == {}
    s.delete_source_state("x")
    s.delete_source_state("missing")                      # deleting an absent row is not an error
    assert s.get_source_state("x") == {}                  # within the run (cache)
    s.begin_run()
    assert s.get_source_state("x") == {}                  # and in the table (a fresh run reads DynamoDB)


def test_base_table_reads_are_strongly_consistent():
    """Regression (first live cycle 2026-10-23): BatchGetItem right after PutItem returned nothing under the
    default eventually-consistent read ⇒ recompute() got 0 items. moto is always consistent, so assert the flag."""
    calls = []

    class Spy:
        name = "radar"
        def get_item(self, **kw):
            calls.append(("get_item", kw)); return {}
        def query(self, **kw):
            calls.append(("query", kw)); return {"Items": []}
        class meta:
            class client:
                @staticmethod
                def batch_get_item(**kw):
                    calls.append(("batch_get_item", kw)); return {"Responses": {}}

    s = DynamoStore(Spy())
    s.get_item("x"); s.get_items(["y"]); s.event_ids_for_key("cve:CVE-1")   # distinct ids: the run cache answers repeats
    assert calls[0][1]["ConsistentRead"] is True
    assert calls[1][1]["RequestItems"]["radar"]["ConsistentRead"] is True
    assert calls[2][1]["ConsistentRead"] is True


def test_dynamo_response_delete_keeps_the_event_row(table):
    """delete_response (R2 merge migration) must remove only the RESPONSE row, never the event's META."""
    s = DynamoStore(table)
    s.put_response("ev_x", {"issues": []})
    table.put_item(Item={"pk": "EVENT#ev_x", "sk": "META", "d": "{}"})
    s.delete_response("ev_x")
    assert s.get_response("ev_x") is None and "Item" in table.get_item(Key={"pk": "EVENT#ev_x", "sk": "META"})


def test_a_station_run_reads_each_item_response_and_key_once_and_sees_its_own_writes(table):
    """Live 2026-11-11: Publish made 3,458 serial reads (one per item list, response, key, event) and timed out."""
    from radar.model import Event, Item
    s = DynamoStore(table)
    it = Item(item_id="it_1", source_id="krebs", tier="T2", org="krebs", domain="vuln", url="https://k/1",
              canonical_url="https://k/1", title="t", text="x", published_at="2026-11-10T00:00:00Z",
              fetched_at="2026-11-10T00:00:00Z", content_hash="c", keys=["cve:CVE-1"], links=[], entity=None,
              eventful=True, signals={}, extra={})
    s.put_item(it)
    s.put_response("ev_1", {"issues": [1]})
    s.add_keys("ev_1", ["cve:CVE-1"])
    s.begin_run()
    calls = {"n": 0}
    real_get, real_q = table.get_item, table.query
    table.get_item = lambda **kw: (calls.__setitem__("n", calls["n"] + 1), real_get(**kw))[1]
    table.query = lambda **kw: (calls.__setitem__("n", calls["n"] + 1), real_q(**kw))[1]
    assert s.event_ids_for_key("cve:CVE-1") == ["ev_1"] and s.event_ids_for_key("cve:CVE-1") == ["ev_1"]
    assert s.get_response("ev_1") == {"issues": [1]} and s.get_response("ev_1") == {"issues": [1]}
    assert calls["n"] == 2                                     # one query, one get — repeats from the cache
    s.add_keys("ev_2", ["cve:CVE-1"])
    assert sorted(s.event_ids_for_key("cve:CVE-1")) == ["ev_1", "ev_2"]      # own write visible
    s.put_response("ev_1", {"issues": []})
    assert s.get_response("ev_1") == {"issues": []}
    r = s.get_response("ev_1"); r["issues"].append(9)
    assert s.get_response("ev_1") == {"issues": []}             # callers never share objects
    s.put_event(Event(event_id="ev_9", domain="vuln", title="t", first_seen="2026-11-10T00:00:00Z",
                      last_updated="2026-11-10T00:00:00Z", item_ids=[], keys=[]))
    assert s.get_event("ev_9").title == "t"


def test_a_station_run_reads_each_source_state_row_once(table):
    """Live 2026-11-11: Publish read the triage / retitle / duplabels ledgers once per event page (500 × 3 rows of up
    to 300 KB) and the full rebuild ran past 600 s."""
    s = DynamoStore(table)
    s.put_source_state("__triage__", {"ev_1": {"v": 1}})
    s.begin_run()
    n = {"get": 0}
    real = table.get_item
    table.get_item = lambda **kw: (n.__setitem__("get", n["get"] + 1), real(**kw))[1]
    a = s.get_source_state("__triage__"); s.get_source_state("__triage__")
    assert n["get"] == 1 and a == {"ev_1": {"v": 1}}
    a["ev_1"]["v"] = 9                                          # callers mutate their copy …
    assert s.get_source_state("__triage__") == {"ev_1": {"v": 1}}
    s.put_source_state("__triage__", a)                         # … and the run sees what it wrote
    assert s.get_source_state("__triage__") == {"ev_1": {"v": 9}} and n["get"] == 1
