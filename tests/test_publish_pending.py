"""R5.2 (audit 05 1.5): a Publish that dies keeps the cycle's change list for the next run; one that finishes clears it."""
import importlib
from datetime import UTC, datetime

import boto3
import pytest
from test_store_contract import table as _table  # noqa: F401  (fixture)

from radar import publish, timeutil
from radar.model import Event

NOW = datetime(2026, 11, 15, 3, 0, tzinfo=UTC)


@pytest.fixture
def h(monkeypatch, _table):  # noqa: F811
    for k, v in {"TABLE": "radar", "RAW_BUCKET": "raw", "SITE_BUCKET": "site", "SITE_URL": "https://site",
                 "AWS_DEFAULT_REGION": "ap-northeast-1"}.items():
        monkeypatch.setenv(k, v)
    boto3.client("s3", region_name="ap-northeast-1").create_bucket(
        Bucket="site", CreateBucketConfiguration={"LocationConstraint": "ap-northeast-1"})
    from radar import handlers
    handlers = importlib.reload(handlers)
    monkeypatch.setattr(timeutil, "now", lambda: NOW)
    at = "2026-11-15T02:00:00Z"
    handlers._store.put_event(Event(event_id="ev_0000000000000001", domain="vuln", title="x", first_seen=at,
                                    last_updated=at, item_ids=[], keys=[], severity="P1"))
    return handlers


def test_a_publish_that_dies_keeps_the_change_list_and_the_next_one_publishes_it(h, monkeypatch):
    real = publish.build
    monkeypatch.setattr(publish, "build", lambda *a, **k: (_ for _ in ()).throw(TimeoutError("300 s")))
    with pytest.raises(TimeoutError):
        h.publish_site({"changed": ["ev_0000000000000001"]})
    assert h._store.get_source_state(publish.PENDING_KEY)["ids"] == ["ev_0000000000000001"]
    seen = []
    monkeypatch.setattr(publish, "build", lambda store, now, changed, **k: seen.append(changed) or real(store, now, changed, **k))
    h.publish_site({"changed": []})
    assert seen == [{"ev_0000000000000001"}]
    assert h._store.get_source_state(publish.PENDING_KEY)["ids"] == []


def test_a_full_publish_that_dies_makes_the_next_one_full(h, monkeypatch):
    real = publish.build
    monkeypatch.setattr(publish, "build", lambda *a, **k: (_ for _ in ()).throw(TimeoutError("300 s")))
    with pytest.raises(TimeoutError):
        h.publish_site({"full": True})
    seen = []
    monkeypatch.setattr(publish, "build", lambda store, now, changed, **k: seen.append(changed) or real(store, now, changed, **k))
    h.publish_site({"changed": []})
    assert seen == [None]                                          # None = full
    assert not h._store.get_source_state(publish.PENDING_KEY).get("full")
