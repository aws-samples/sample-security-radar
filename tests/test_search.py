"""Static search index (radar.search, handlers._publish_search): every published event stays findable after it
leaves the 60-day window (research/19 B7)."""
import importlib
import json
from datetime import UTC, datetime

import boto3
import pytest
from test_store_contract import table as _table  # noqa: F401  (fixture)

from radar import search
from radar.model import Event


def ev(i, first, last=None, title=None):
    return Event(event_id=f"ev_{i}", domain="vuln", title=title or f"Event {i}", first_seen=first,
                 last_updated=last or first, item_ids=[], keys=[], cves=[f"CVE-2026-{i}"])


def test_a_month_shard_keeps_its_older_events_when_the_window_moves():
    old = [search.record(ev(1, "2026-09-02T00:00:00Z")), search.record(ev(2, "2026-09-20T00:00:00Z"))]
    fresh = [search.record(ev(2, "2026-09-20T00:00:00Z", title="Event 2 (updated)"))]
    rows = search.merge(old, fresh)
    assert {r["id"] for r in rows} == {"ev_1", "ev_2"} and next(r for r in rows if r["id"] == "ev_2")["t"].endswith("(updated)")


def test_events_land_in_the_month_they_were_first_seen():
    got = search.shards([ev(1, "2026-09-30T23:00:00Z", last="2026-11-01T00:00:00Z"), ev(2, "2026-11-02T00:00:00Z")])
    assert set(got) == {"2026-09", "2026-11"}


@pytest.fixture
def env(monkeypatch, _table):  # noqa: F811
    monkeypatch.setenv("TABLE", "radar")
    monkeypatch.setenv("RAW_BUCKET", "raw")
    monkeypatch.setenv("SITE_BUCKET", "site")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-northeast-1")
    s3 = boto3.client("s3", region_name="ap-northeast-1")
    s3.create_bucket(Bucket="site", CreateBucketConfiguration={"LocationConstraint": "ap-northeast-1"})
    import radar.handlers as h
    h = importlib.reload(h)
    return h, s3


def test_publishing_twice_with_a_moving_window_keeps_every_event(env):
    h, s3 = env
    h._publish_search("site", datetime(2026, 11, 10, tzinfo=UTC), events=[ev(1, "2026-08-01T00:00:00Z"), ev(2, "2026-11-01T00:00:00Z")])
    h._publish_search("site", datetime(2026, 11, 10, tzinfo=UTC), events=[ev(3, "2026-11-05T00:00:00Z")])
    idx = json.loads(s3.get_object(Bucket="site", Key="data/search/index.json")["Body"].read())
    nov = json.loads(s3.get_object(Bucket="site", Key="data/search/2026-11.json")["Body"].read())
    assert idx["total"] == 3 and [m["month"] for m in idx["months"]] == ["2026-11", "2026-08"]
    assert {r["id"] for r in nov["events"]} == {"ev_2", "ev_3"}


def test_a_row_says_whether_its_event_has_a_detail_page_and_keeps_saying_it():
    """Detail docs (events/<id>.json) exist only for the top PUBLISH_MAX_EVENTS of the window; the search shards hold
    every event. Live: most search hits opened 「事件不存在」 (research/action/06 B1). A row is marked once Publish has
    written its detail doc; detail docs are never deleted, so the mark survives later merges that do not rewrite it."""
    a, b = ev(1, "2026-09-02T00:00:00Z"), ev(2, "2026-09-03T00:00:00Z")
    first = search.shards([a, b], published={"ev_1"})["2026-09"]
    assert {r["id"]: r.get("p", False) for r in first} == {"ev_1": True, "ev_2": False}
    later = search.merge(first, search.shards([a, b])["2026-09"])
    assert {r["id"]: r.get("p", False) for r in later} == {"ev_1": True, "ev_2": False}


def test_publish_marks_the_events_whose_detail_doc_it_wrote(env, monkeypatch):
    h, s3 = env
    monkeypatch.setattr(h.publish, "build", lambda *a, **k: {"events.json": {"events": []}, "events/ev_1.json": {}})
    monkeypatch.setattr(h._store, "events_updated_since",
                        lambda since: [ev(1, "2026-11-01T00:00:00Z"), ev(2, "2026-11-02T00:00:00Z")])
    h.publish_site({"full": True})
    nov = json.loads(s3.get_object(Bucket="site", Key="data/search/2026-11.json")["Body"].read())
    assert {r["id"]: r.get("p", False) for r in nov["events"]} == {"ev_1": True, "ev_2": False}


def test_search_documents_validate_against_the_site_schema():
    from pathlib import Path

    import jsonschema
    schema = json.loads((Path(__file__).parents[1] / "schemas" / "site-data.schema.json").read_text())
    v = jsonschema.Draft202012Validator(schema)
    rows = [search.record(ev(1, "2026-09-02T00:00:00Z")), search.record(ev(2, "2026-09-03T00:00:00Z"), published=True)]
    for doc in (search.shard_doc("2026-09", rows, "2026-11-10T00:00:00Z"), search.index_doc({"2026-09": 1}, "2026-11-10T00:00:00Z")):
        assert not list(v.iter_errors(doc))


def test_the_index_states_the_publish_cap_so_the_ui_never_hardcodes_it():
    """The page explains an unlinked hit with the cap (「未进入发布的前 N 条」); a copy of 500 in the UI goes stale
    silently when Limits.PUBLISH_MAX_EVENTS changes. The index carries it; the UI only reads it."""
    from radar.limits import Limits
    assert search.index_doc({"2026-09": 1}, "2026-11-10T00:00:00Z")["detail_cap"] == Limits.PUBLISH_MAX_EVENTS


def _seed_script():
    from pathlib import Path
    spec = importlib.util.spec_from_file_location("seed_search", Path(__file__).parents[1] / "scripts" / "seed-search.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_backfill_marks_every_event_whose_detail_doc_is_already_in_the_bucket(env):
    """Shards built before the "p" mark carry none, and Publish marks only the detail docs it writes in that run: an
    event that left the top PUBLISH_MAX_EVENTS or the 60-day window keeps its data/events/<id>.json (never deleted)
    yet read 「无详情页」 forever. The one-off backfill lists data/events/ (every listing page) and marks those ids."""
    _, s3 = env
    for i in (1, 2, 3):
        s3.put_object(Bucket="site", Key=f"data/events/ev_{i}.json", Body=b"{}")
    s3.put_object(Bucket="site", Key="data/events.json", Body=b"{}")   # the list doc, not a detail page
    seed = _seed_script()
    assert seed.published_ids(s3, "site", page_size=2) == {"ev_1", "ev_2", "ev_3"}
    seed.seed(s3, "site", [ev(i, f"2026-08-0{i}T00:00:00Z") for i in (1, 2, 3, 4)], apply=True)
    aug = json.loads(s3.get_object(Bucket="site", Key="data/search/2026-08.json")["Body"].read())
    assert {r["id"]: r.get("p", False) for r in aug["events"]} == {"ev_1": True, "ev_2": True, "ev_3": True, "ev_4": False}


# --- removed events leave the site (radar.removals); the row carries the displayed title -----------------------------

def test_a_removed_events_row_and_page_leave_the_site_and_a_live_again_id_keeps_its_own(env):
    """Live 2026-11-12: 38 search rows (and their detail pages) pointed at events a merge or a recluster repair had
    deleted — a Binance search still listed the pre-repair events, an old link opened the pre-repair page."""
    from radar import removals
    h, s3 = env
    now = datetime(2026, 11, 12, tzinfo=UTC)
    h._publish_search("site", now, events=[ev(1, "2026-11-01T00:00:00Z"), ev(2, "2026-11-02T00:00:00Z"),
                                           ev(3, "2026-10-05T00:00:00Z"), ev(4, "2026-11-03T00:00:00Z")])
    for i in (1, 2, 3, 4):
        s3.put_object(Bucket="site", Key=f"data/events/ev_{i}.json", Body=b"{}")
    h._store.put_event(ev(4, "2026-11-03T00:00:00Z"))          # a repair re-seeded this id: it exists again
    removals.record(h._store, [("ev_2", "2026-11", "ev_1"), ("ev_3", "2026-10", None), ("ev_4", "2026-11", None)],
                    "2026-11-12T00:00:00Z")
    h._publish_search("site", now, events=[ev(1, "2026-11-01T00:00:00Z")])      # ev_3's month is not in the window
    nov = json.loads(s3.get_object(Bucket="site", Key="data/search/2026-11.json")["Body"].read())
    octo = json.loads(s3.get_object(Bucket="site", Key="data/search/2026-10.json")["Body"].read())
    idx = json.loads(s3.get_object(Bucket="site", Key="data/search/index.json")["Body"].read())
    assert {r["id"] for r in nov["events"]} == {"ev_1", "ev_4"} and octo["events"] == []
    assert idx["total"] == 2
    pages = {o["Key"] for o in s3.list_objects_v2(Bucket="site", Prefix="data/events/").get("Contents", [])}
    assert pages == {"data/events/ev_1.json", "data/events/ev_4.json"}
    assert removals.pending(h._store) == {}                    # pruned once, not every run


def test_the_removed_events_ledger_is_capped():
    from radar import removals
    from radar.limits import Limits
    from radar.store import MemoryStore
    store = MemoryStore()
    removals.record(store, [(f"ev_{i}", "2026-11", None) for i in range(Limits.REMOVED_EVENTS_MAX + 5)], "2026-11-12T00:00:00Z")
    removals.record(store, [("ev_new", "2026-11", None)], "2026-11-12T01:00:00Z")
    led = store.get_source_state(removals.REMOVED_KEY)
    assert len(led) == Limits.REMOVED_EVENTS_MAX and "ev_new" in led


def test_a_search_row_carries_the_title_the_page_shows(env):
    """An operator's sourced root-cause title (radar.retitle) is what the page shows; the search row said the old one."""
    from radar import retitle
    h, s3 = env
    e = ev(1, "2026-11-01T00:00:00Z", title="Binance — Key Leaked")
    e.event_id = "ev_0a4e5c3e0fce8be9"
    h._store.put_event(e)
    retitle.set_title(h._store, e.event_id, "Binance CEX — Hot Wallets Drained via Compromised DevOps Laptop",
                      "https://example.com/postmortem", "post-mortem", "ops", datetime(2026, 11, 11, tzinfo=UTC))
    h._publish_search("site", datetime(2026, 11, 12, tzinfo=UTC), events=[e])
    nov = json.loads(s3.get_object(Bucket="site", Key="data/search/2026-11.json")["Body"].read())
    assert nov["events"][0]["t"] == "Binance CEX — Hot Wallets Drained via Compromised DevOps Laptop"


def test_the_backfill_finds_rows_whose_event_is_gone():
    prune = _script("prune-search.py")
    rows = {"2026-11": [f"ev_{i}" for i in range(150)], "2026-10": ["ev_x"]}
    gone = prune.orphans(rows, lambda ids: {e for e in ids if e != "ev_7" and e != "ev_x"})
    assert sorted(gone) == [("ev_7", "2026-11", None), ("ev_x", "2026-10", None)]


def test_a_merge_records_the_absorbed_event_for_publish_to_prune():
    from test_pipeline_replay import _raw

    from radar import pipeline, removals
    from radar.store import MemoryStore
    store = MemoryStore()
    t = datetime(2026, 11, 1, tzinfo=UTC)
    pipeline.ingest([_raw("bleepingcomputer", "Acme VPN flaw CVE-2026-90001 exploited", "actively exploited",
                          when="2026-10-31T10:00:00Z")], store, t)
    pipeline.ingest([_raw("securityweek", "Acme gateway bug CVE-2026-90002 exploited", "exploited in the wild",
                          when="2026-10-31T11:00:00Z")], store, t)
    assert len(store.events) == 2
    pipeline.ingest([_raw("bleepingcomputer", "Acme: CVE-2026-90001 and CVE-2026-90002 are one bug chain", "exploited chain",
                          when="2026-10-31T12:00:00Z")], store, t)
    (survivor,) = store.events
    (gone,) = removals.pending(store)
    assert gone != survivor and removals.pending(store)[gone]["to"] == survivor


def _script(name):
    import importlib.util
    from pathlib import Path
    p = Path(__file__).resolve().parents[1] / "scripts" / name
    spec = importlib.util.spec_from_file_location(name.replace("-", "_").removesuffix(".py"), p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_a_page_that_could_not_be_deleted_is_retried_next_run(env, monkeypatch):
    """delete_objects reports per-key failures (AccessDenied) in its response, it does not raise: publish must not mark
    those events pruned, or their stale pages stay for good."""
    from radar import removals
    h, _ = env
    removals.record(h._store, [("ev_9", "2026-11", None)], "2026-11-12T00:00:00Z")
    monkeypatch.setattr(h._s3, "delete_objects", lambda **k: {"Errors": [{"Key": "data/events/ev_9.json", "Code": "AccessDenied"}]})
    h._publish_search("site", datetime(2026, 11, 12, tzinfo=UTC), events=[ev(1, "2026-11-01T00:00:00Z")])
    assert "ev_9" in removals.pending(h._store)
