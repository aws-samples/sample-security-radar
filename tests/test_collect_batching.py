"""Incremental, batched collection (research/17 P0 + P1).

Live 24 h before (28 sources): Process got 101,584 raw entries, 835 new or changed (0.82 %). Now the collector hands
over only new or edited entries (per-source SEEN record), sources are collected in batches (~15 invocations for 167
sources), and Process reads only the batches after its watermark."""
import importlib
import json
from datetime import UTC, datetime, timedelta

import boto3
import pytest
from test_store_contract import table as _table  # noqa: F401  (fixture)

from radar import collect, timeutil
from radar.limits import Limits
from radar.model import RawItem
from radar.registry import BY_ID

NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)


def _r(guid, title="t", days_ago=0.0, text="x"):
    return RawItem(source_id="s", url=f"https://x/{guid}", title=title, text=text,
                   published_at=NOW - timedelta(days=days_ago), guid=guid, author=None, links=[])


# ---------------------------------------------------------------- collect.incremental
def test_the_second_run_of_an_unchanged_feed_hands_over_nothing():
    feed = [_r("a"), _r("b")]
    first, seen = collect.incremental(feed, {}, NOW, brand_new=False)
    assert len(first) == 2
    again, _ = collect.incremental(feed, seen, NOW, brand_new=False)
    assert again == []


def test_an_edited_entry_is_handed_over_again():
    """DeFiLlama revises amounts in place — the edit is how the new figure arrives."""
    _, seen = collect.incremental([_r("a", title="Hack $10M")], {}, NOW, brand_new=False)
    out, _ = collect.incremental([_r("a", title="Hack $12M")], seen, NOW, brand_new=False)
    assert [r.title for r in out] == ["Hack $12M"]


def test_a_brand_new_source_hands_over_only_its_last_days_not_its_archive():
    feed = [_r("new", days_ago=1), _r("old", days_ago=Limits.FIRST_RUN_DAYS + 5)]
    out, seen = collect.incremental(feed, {}, NOW, brand_new=True)
    assert [r.guid for r in out] == ["new"] and len(seen) == 2       # the archive is remembered, not replayed
    out, _ = collect.incremental(feed, {}, NOW, brand_new=False)   # an existing source switching over: everything once
    assert len(out) == 2


def test_seen_is_bounded():
    big = {f"{i:016x}": "00000000" for i in range(Limits.SEEN_CAP * 2)}
    _, seen = collect.incremental([_r("a")], big, NOW, brand_new=False)
    assert len(seen) <= Limits.SEEN_CAP + 1


# ---------------------------------------------------------------- collect.batches
def test_batches_cover_every_due_source_once_and_respect_the_size():
    ids = list(BY_ID)
    got = collect.batches(ids)
    flat = [s for b in got for s in b]
    assert sorted(flat) == sorted(ids) and len(flat) == len(set(flat))
    assert all(len(b) <= Limits.COLLECT_BATCH or len({collect._host(BY_ID[s]) for s in b}) == 1 for b in got)
    assert len(got) < len(ids) / 4                                  # 167 sources ⇒ far fewer invocations


def test_heavy_sources_run_alone_and_a_host_stays_in_one_batch():
    got = collect.batches(list(BY_ID))
    for b in got:
        if any(BY_ID[s].parser in collect.HEAVY_PARSERS or BY_ID[s].via != "direct" for s in b):
            assert len(b) == 1
    hosts = {}
    for i, b in enumerate(got):
        for s in b:
            if len(b) > 1 or BY_ID[s].parser not in collect.HEAVY_PARSERS and BY_ID[s].via == "direct":
                hosts.setdefault(collect._host(BY_ID[s]), set()).add(i)     # light sources: one batch per host
    assert all(len(v) == 1 for v in hosts.values())


def test_the_stack_cycle_is_the_limits_cycle():
    import ast
    from pathlib import Path
    tree = ast.parse((Path(__file__).parents[1] / "infra" / "stack.py").read_text())
    [v] = [n.value.value for n in tree.body if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "CYCLE_MINUTES"]
    assert v == Limits.CYCLE_MINUTES


def test_the_docs_state_the_limits_cycle():
    """README / the roadmap / the diagram sources said 10 minutes a cycle while the code ran 5 (research/action/06 B6):
    the advertised freshness is a trust signal. Every 'N-minute cycle' they state must be the real one."""
    import re
    from pathlib import Path
    root = Path(__file__).parents[1]
    said = []
    # cycle phrasings only — 「每 60 分钟轮询」 is one source's own interval, not the cycle
    cycle = r"(\d+)-minute cycle|(?<!\d)(\d+) 分钟一轮|周期（每 (\d+) 分钟）|每 (\d+) 分钟触发|\"label\": \"每 (\d+) 分钟\""
    for f in ("README.md", "docs/ROADMAP.md", "docs/assets/cycle-flow.json", "docs/assets/architecture.json",
              "docs/assets/respond-loop.json"):
        if f == "docs/ROADMAP.md" and not (root / f).exists():
            continue   # the public sample ships without the internal roadmap
        said += [(f, int(n)) for g in re.findall(cycle, (root / f).read_text()) for n in g if n]
    assert said and all(n == Limits.CYCLE_MINUTES for _, n in said), said


# ---------------------------------------------------------------- stations (moto)
@pytest.fixture
def env(monkeypatch, _table):  # noqa: F811
    monkeypatch.setenv("TABLE", "radar")
    monkeypatch.setenv("RAW_BUCKET", "raw")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-northeast-1")
    s3 = boto3.client("s3", region_name="ap-northeast-1")
    s3.create_bucket(Bucket="raw", CreateBucketConfiguration={"LocationConstraint": "ap-northeast-1"})
    import radar.handlers as h
    h = importlib.reload(h)
    monkeypatch.setattr(timeutil, "now", lambda: NOW)
    return h, s3


RSS = """<?xml version="1.0"?><rss version="2.0"><channel><title>x</title>
<item><title>Hackers exploit zero-day CVE-2026-1111</title><link>https://k/1</link><guid>1</guid>
<pubDate>Tue, 10 Nov 2026 10:00:00 GMT</pubDate></item></channel></rss>"""


def _feed(monkeypatch, body=RSS):
    from radar import fetch
    monkeypatch.setattr(fetch, "http_get", lambda url, **k: fetch.Response(200, body, None, None))


def test_a_batch_writes_new_entries_once_and_nothing_the_second_time(env, monkeypatch):
    h, _ = env
    _feed(monkeypatch)
    out = h.collect_batch({"source_ids": ["krebs"], "slot": "2026-11-10T12:00:00Z"})["results"]
    assert out[0]["count"] == 1 and out[0]["key"]
    again = h.collect_batch({"source_ids": ["krebs"], "slot": "2026-11-10T12:05:00Z"})["results"]
    assert again[0]["count"] == 0 and again[0]["key"] is None


def test_seen_is_not_advanced_when_the_raw_batch_cannot_be_written(env, monkeypatch):
    """SEEN ahead of S3 would lose the entries forever: the next run must hand them over again."""
    h, _ = env
    _feed(monkeypatch)
    monkeypatch.setattr(h._s3, "put_object", lambda **k: (_ for _ in ()).throw(RuntimeError("s3 down")))
    out = h.collect_batch({"source_ids": ["krebs"], "slot": "2026-11-10T12:00:00Z"})["results"]
    assert out[0]["ok"] is False
    assert not h._store.get_source_state(h.SEEN_PREFIX + "krebs")


def test_one_crashing_source_does_not_drop_its_batch_mates(env, monkeypatch):
    h, _ = env
    _feed(monkeypatch)
    real = h._collect_source
    monkeypatch.setattr(h, "_collect_source", lambda st, sid, slot: (_ for _ in ()).throw(KeyError("boom"))
                        if sid == "schneier" else real(st, sid, slot))
    out = {r["source_id"]: r for r in h.collect_batch({"source_ids": ["krebs", "schneier"], "slot": "2026-11-10T12:00:00Z"})["results"]}
    assert out["krebs"]["count"] == 1 and out["schneier"]["ok"] is False


def test_sources_after_the_deadline_are_skipped_visibly_and_stay_due(env, monkeypatch):
    h, _ = env
    _feed(monkeypatch)
    monkeypatch.setattr(Limits, "COLLECT_DEADLINE_S", -1)
    out = h.collect_batch({"source_ids": ["krebs"], "slot": "2026-11-10T12:00:00Z"})["results"]
    assert out[0]["skipped"] == "batch_deadline"
    assert "krebs" in collect.due({"krebs": h._store.get_source_state("krebs")}, NOW)


def _raw(s3, key):
    s3.put_object(Bucket="raw", Key=key, Body=json.dumps({"source_id": "krebs", "url": f"https://k/{key[-30:]}",
        "title": "Hackers exploit zero-day CVE-2026-2222", "text": "x", "published_at": "2026-11-10T10:00:00Z",
        "guid": key, "author": None, "links": [], "extra": {}}).encode())


def test_process_reads_only_batches_after_its_watermark_and_up_to_its_slot(env):
    h, s3 = env
    _raw(s3, "raw/2026-11-10/2026-11-10T11:50:00Z/krebs.jsonl")
    _raw(s3, "raw/2026-11-10/2026-11-10T11:55:00Z/krebs.jsonl")
    _raw(s3, "raw/2026-11-10/2026-11-10T12:05:00Z/krebs.jsonl")     # a later cycle's batch: not this run's
    h._store.put_source_state(h.WATERMARK_KEY, {"key": "raw/2026-11-10/2026-11-10T11:50:00Z/~"})
    assert h._pending_raw_keys(NOW, "2026-11-10T12:00:00Z") == ["raw/2026-11-10/2026-11-10T11:55:00Z/krebs.jsonl"]
    h.process({"results": [], "slot": "2026-11-10T12:00:00Z"})
    assert h._store.get_source_state(h.WATERMARK_KEY)["key"] == "raw/2026-11-10/2026-11-10T12:00:00Z/~"
    assert h._pending_raw_keys(NOW, "2026-11-10T12:10:00Z") == ["raw/2026-11-10/2026-11-10T12:05:00Z/krebs.jsonl"]


def test_a_failed_process_run_leaves_the_watermark_behind(env, monkeypatch):
    h, s3 = env
    _raw(s3, "raw/2026-11-10/2026-11-10T11:55:00Z/krebs.jsonl")
    monkeypatch.setattr(h.pipeline, "ingest", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError):
        h.process({"results": [], "slot": "2026-11-10T12:00:00Z"})
    assert not h._store.get_source_state(h.WATERMARK_KEY)
    assert h._pending_raw_keys(NOW, "2026-11-10T12:05:00Z") == ["raw/2026-11-10/2026-11-10T11:55:00Z/krebs.jsonl"]


# ---------------------------------------------------------------- reporters are not victims (dry run 2026-11-10)
def test_a_reporters_own_name_is_not_a_clustering_key():
    """ChainCatcher's name in every body glued Binance, Keplr, Drift and ACryptoS reports into one event."""
    from radar import pipeline
    toks = pipeline.web3_text_keys("Keplr 钱包安全事件", "Keplr 钱包安全事件 ChainCatcher 消息，GoPlus 称 Keplr 被盗")
    assert "tok:chaincatcher" not in toks and "tok:keplr" in toks


def test_an_exchange_is_never_a_reporter_token():
    from radar.registry import REPORTER_TOKENS
    assert {"binance", "okx", "bybit", "kraken", "coinbase"}.isdisjoint(REPORTER_TOKENS)
    assert {"chaincatcher", "secaffairs", "cryptoslate"} <= REPORTER_TOKENS


def test_google_news_titles_lose_the_outlet_suffix():
    from radar import parsers
    body = """<?xml version="1.0"?><rss version="2.0"><channel><title>g</title><item>
<title>币安63亿美元黑客攻击事件始末 - 早晨报</title><link>https://news.google.com/rss/articles/x</link>
<source url="https://zcb.example">早晨报</source><pubDate>Mon, 09 Nov 2026 10:00:00 GMT</pubDate></item></channel></rss>"""
    [r] = parsers.PARSERS["feed"](body, "gn_exchange_zh")
    assert r.title == "币安63亿美元黑客攻击事件始末"


# ---------------------------------------------------------------- overlap guard (live 2026-11-10 00:50)
def test_a_cycle_skips_while_an_earlier_one_runs_but_a_full_publish_does_not(env, monkeypatch):
    h, _ = env
    me = "arn:aws:states:ap-northeast-1:1:execution:Cycle-X:b"
    earlier = {"executionArn": "arn:aws:states:ap-northeast-1:1:execution:Cycle-X:a", "startDate": NOW - timedelta(minutes=2)}
    later = {"executionArn": "arn:aws:states:ap-northeast-1:1:execution:Cycle-X:c", "startDate": NOW + timedelta(minutes=1)}
    seen = {}

    class SFN:
        def list_executions(self, **kw):
            seen.update(kw)
            return {"executions": runs}
    monkeypatch.setattr(h.boto3, "client", lambda name, **k: SFN())
    started = timeutil.iso(NOW)
    runs = [earlier, {"executionArn": me, "startDate": NOW}]
    assert h.plan({"input": {}, "execution": me, "started": started})["skip"] is True
    assert seen["stateMachineArn"] == "arn:aws:states:ap-northeast-1:1:stateMachine:Cycle-X"
    assert h.plan({"input": {"full": True}, "execution": me, "started": started})["skip"] is False
    runs = [later, {"executionArn": me, "startDate": NOW}]       # only a later one: this cycle runs
    assert h.plan({"input": {}, "execution": me, "started": started})["skip"] is False


# ---------------------------------------------------------------- event rows never reach 400 KB (live 2026-11-10)
def test_an_oversized_event_row_is_compacted_not_rejected(env):
    h, _ = env
    from radar.model import Event
    flips = [{"at": f"2026-11-0{1 + i % 9}T00:00:00Z", "kind": "amount_change", "from": a, "to": b, "item_id": "it_x"}
             for i, (a, b) in enumerate([("980000.0", "4900000.0"), ("4900000.0", "980000.0")] * 1500)]
    pts = [{"value": v, "source_id": "defillama_hacks", "observed_at": "2026-11-01T00:00:00Z", "kind": "loss"}
           for v in [980000.0, 4900000.0] * 1500]
    ev = Event(event_id="ev_flip", domain="web3", title="OcelotDex", first_seen="2024-09-20T00:00:00Z",
               last_updated="2026-11-10T00:00:00Z", item_ids=["it_x"], keys=["ent:ocelotdex"],
               timeline=[{"at": "2024-09-20T00:00:00Z", "kind": "created", "from": None, "to": "V1", "item_id": "it_x"}, *flips],
               amount_history=pts)
    assert len(json.dumps(ev.to_dict())) > 400_000          # DynamoDB would reject this row (moto does too)
    h._store.put_event(ev)
    got = h._store.get_event("ev_flip")
    assert len(got.timeline) == 3 and len(got.amount_history) == 2


def test_a_huge_event_of_distinct_reports_still_fits_the_row(env):
    h, _ = env
    from radar.model import Event
    n = 4500
    tl = [{"at": "2026-10-29T00:00:00Z", "kind": "created", "from": None, "to": "V1", "item_id": "it_0"},
          {"at": "2026-10-30T00:00:00Z", "kind": "level_change", "from": "V1", "to": "V2", "item_id": "it_9"}]
    tl += [{"at": f"2026-11-01T00:{i % 60:02d}:00Z", "kind": "item_added", "from": None, "to": None, "item_id": f"it_{i:06d}"}
           for i in range(n)]
    ah = [{"value": 1e9 + i, "source_id": f"s{i}", "observed_at": "2026-11-01T00:00:00Z", "kind": "loss"} for i in range(n)]
    ev = Event(event_id="ev_big", domain="web3", title="Binance", first_seen="2026-10-29T00:00:00Z",
               last_updated="2026-11-10T00:00:00Z", item_ids=[f"it_{i:06d}" for i in range(n)], keys=["ent:binance"],
               timeline=tl, amount_history=ah)
    assert len(json.dumps(ev.to_dict())) > 400_000
    h._store.put_event(ev)
    got = h._store.get_event("ev_big")
    assert len(got.item_ids) == n                                       # every report still listed
    assert [x["kind"] for x in got.timeline[:2]] == ["created", "level_change"]   # every state change kept
    assert got.timeline[-1]["item_id"] == f"it_{n - 1:06d}" and got.amount_history[0]["value"] == 1e9


def test_raw_batches_are_kept_not_expired():
    """research/19 B8: raw/ is the evidence and the replay source; the 90-day expiry deleted it."""
    from pathlib import Path
    src = (Path(__file__).parents[1] / "infra" / "stack.py").read_text()
    raw_line = next(ln for ln in src.splitlines() if 'bucket("RawBucket"' in ln)
    assert "expiration" not in raw_line and "INTELLIGENT_TIERING" in src


# ---------------------------------------------------------------- one event-window read per station run (research/19 B3)
def test_a_station_run_reads_the_event_window_once_and_sees_its_own_writes(env):
    h, _ = env
    from radar.model import Event
    st = h._store
    def ev(i, at):
        return Event(event_id=f"ev_{i}", domain="vuln", title=f"t{i}", first_seen=at, last_updated=at, item_ids=[], keys=[])
    for i, at in enumerate(["2026-11-01T00:00:00Z", "2026-11-05T00:00:00Z", "2026-11-09T00:00:00Z"]):
        st.put_event(ev(i, at))
    st.begin_run()
    assert len(st.events_updated_since("2026-10-01T00:00:00Z")) == 3
    assert [e.event_id for e in st.events_updated_since("2026-11-04T00:00:00Z")] == ["ev_1", "ev_2"]
    a = st.events_updated_since("2026-10-01T00:00:00Z")[0]
    a.title = "mutated by a caller"
    assert st.events_updated_since("2026-10-01T00:00:00Z")[0].title == "t0"      # callers never share objects
    st.put_event(ev(3, "2026-11-10T00:00:00Z"))                                   # a write in the same run
    assert "ev_3" in {e.event_id for e in st.events_updated_since("2026-11-04T00:00:00Z")}
    st.delete_event("ev_2")
    assert "ev_2" not in {e.event_id for e in st.events_updated_since("2026-10-01T00:00:00Z")}
    assert st.window_queries == 1 and st.window_hits >= 4
    st.begin_run()
    st.events_updated_since("2026-10-01T00:00:00Z")
    assert st.window_queries == 1 and st.window_hits == 0                          # a new run queries again


def test_a_station_run_starts_with_a_fresh_window(env, monkeypatch):
    h, _ = env
    from radar.model import Event
    h._store.events_updated_since("2026-10-01T00:00:00Z")                         # a previous invocation's window
    h._store.t.put_item(Item={"pk": "EVENT#ev_x", "sk": "META", "gsi1pk": "EVENT", "gsi1sk": "2026-11-09T00:00:00Z",
                              "d": json.dumps(Event(event_id="ev_x", domain="vuln", title="x", first_seen="2026-11-09T00:00:00Z",
                                                    last_updated="2026-11-09T00:00:00Z", item_ids=[], keys=[]).to_dict())})
    seen = []
    monkeypatch.setattr(h.pipeline, "ingest", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("stop")))
    monkeypatch.setattr(h, "_pending_raw_keys", lambda *a, **k: seen.append(
        [e.event_id for e in h._store.events_updated_since("2026-10-01T00:00:00Z")]) or [])
    try:
        h.process({"results": [], "slot": "2026-11-10T12:00:00Z"})
    except RuntimeError:
        pass
    assert seen and "ev_x" in seen[0]                       # written by another station between runs: visible


def test_a_feed_served_in_two_versions_is_not_handed_over_again(monkeypatch):
    """alas2023 (live 2026-11-10): the CDN serves two versions of 1,135 entries with different guids; a total-capped
    SEEN dropped one version and every other run handed over all of it again (funnel ratio 5.9 instead of ≤ 3)."""
    monkeypatch.setattr(Limits, "SEEN_CAP", 1500)
    a = [_r(f"a{i}") for i in range(1135)]
    b = [_r(f"b{i}") for i in range(1135)]
    seen = {}
    for feed in (a, b):
        _, seen = collect.incremental(feed, seen, NOW, brand_new=False)
    for feed in (a, b, a, b):
        out, seen = collect.incremental(feed, seen, NOW, brand_new=False)
        assert out == []
