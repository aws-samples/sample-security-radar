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
    s.get_item("x"); s.get_items(["x"]); s.event_ids_for_key("cve:CVE-1")
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
