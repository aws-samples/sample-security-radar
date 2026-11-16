"""P3 pull: data/feeds/ JSON Feed 1.1 + Atom per radar.feeds.FEEDS filter, and schema_version on every root document
the publish station writes."""

import importlib
import json
import xml.etree.ElementTree as ET  # nosec B405 — parses the radar's own output in a test
from datetime import UTC, datetime
from pathlib import Path

import boto3
import jsonschema
import pytest
from test_store_contract import table as _table  # noqa: F401  (fixture)

from radar import feeds, notify, timeutil
from radar.model import SITE_SCHEMA_VERSION, Event

NOW = datetime(2026, 11, 11, 4, tzinfo=UTC)
CANARY = "CANARY-internal-feed-51c2"
SCHEMA = json.loads((Path(__file__).parents[1] / "schemas" / "site-data.schema.json").read_text())
A = {"ns": feeds.ATOM_NS}


def row(eid, sev, domain, title, at, **kw):
    return {"event_id": eid, "title": title, "severity": sev, "domain": domain, "level": "V2", "level_reason": "r",
            "summary": f"summary of {title}", "first_seen": at, "last_updated": at, "cves": [], "chains": [],
            "entities": [], "impact": None, **kw}


ROWS = [row("ev_1", "P0", "vuln", "Ivanti RCE", "2026-11-10T01:00:00Z"),
        row("ev_2", "P1", "web3", "Bybit cold wallet drained", "2026-11-10T03:00:00Z", chains=["ethereum"]),
        row("ev_3", "P2", "web3", "small DEX rug", "2026-11-10T02:00:00Z"),
        row("ev_4", "P2", "incident", "Ransomware at a hospital", "2026-11-10T04:00:00Z")]
MIT = {"ev_1": {"plans": [{"group": "g"}]}}


def _docs(rows=ROWS, skip=None):
    return feeds.documents(rows, MIT, NOW, "https://site", skip)


def _ids(docs, name):
    return [i["id"] for i in json.loads(docs[f"feeds/{name}.json"][0])["items"]]


def test_each_feed_holds_exactly_its_matching_events_newest_first():
    d = _docs()
    assert _ids(d, "all") == ["ev_4", "ev_2", "ev_3", "ev_1"]
    assert _ids(d, "p0") == ["ev_1"] and _ids(d, "web3") == ["ev_2", "ev_3"] and _ids(d, "vuln") == ["ev_1"]
    assert _ids(d, "exchanges") == ["ev_2"] and _ids(d, "has-waf-pack") == ["ev_1"]


def test_json_feed_is_version_1_1_with_stable_ids_and_absolute_links():
    doc = json.loads(_docs()["feeds/p0.json"][0])
    assert doc["version"] == "https://jsonfeed.org/version/1.1" and doc["_radar"]["schema_version"] == SITE_SCHEMA_VERSION
    [it] = doc["items"]
    assert it["id"] == "ev_1" and it["url"] == "https://site/#/events/ev_1" and it["title"] == "[P0] Ivanti RCE"
    assert it["_radar"]["has_waf_pack"] is True and doc["feed_url"] == "https://site/data/feeds/p0.json"
    assert _docs()["feeds/p0.json"][1] == "application/feed+json" and _docs()["feeds/p0.atom"][1] == "application/atom+xml"


def test_atom_parses_and_carries_tag_ids_and_the_schema_version():
    root = ET.fromstring(_docs()["feeds/web3.atom"][0])   # nosec B314 — our own output
    assert root.tag == f"{{{feeds.ATOM_NS}}}feed"
    assert [e.findtext("ns:id", namespaces=A) for e in root.findall("ns:entry", A)] == [
        "tag:security-radar,2026:event:ev_2", "tag:security-radar,2026:event:ev_3"]
    assert root.findtext(f"{{{feeds.RADAR_NS}}}schema_version") == SITE_SCHEMA_VERSION
    assert root.findtext("ns:updated", namespaces=A) == "2026-11-10T03:00:00Z"


def test_a_title_with_markup_is_escaped_in_atom():
    d = _docs([row("ev_9", "P0", "vuln", "<script>alert(1)</script> & co", "2026-11-10T01:00:00Z")])
    body = d["feeds/p0.atom"][0].decode()
    assert "<script>" not in body and "&lt;script&gt;" in body
    assert ET.fromstring(d["feeds/p0.atom"][0]).find("ns:entry/ns:title", A).text.startswith("[P0] <script>")  # nosec B314


def test_a_control_character_in_collected_text_does_not_break_the_atom():
    """A feed title / summary carrying a C0 control (\\x01, an ANSI \\x1b[31m) made all.atom not well-formed XML —
    every reader failed on it silently. Characters outside XML 1.0 Char are dropped; the JSON Feed keeps the text."""
    bad = row("ev_9", "P0", "vuln", "bad\x01title\x1b[31m\ufffe", "2026-11-10T01:00:00Z")
    bad["summary"] = "sum\x00mary\x0b"
    d = _docs([bad])
    for n in feeds.FEEDS:
        ET.fromstring(d[f"feeds/{n}.atom"][0])  # nosec B314 — raises ParseError on a not-well-formed document
    entry = ET.fromstring(d["feeds/all.atom"][0]).find("ns:entry", A)  # nosec B314
    assert entry.find("ns:title", A).text == "[P0] badtitle[31m" and entry.find("ns:summary", A).text == "summary"
    assert "\x01" in json.loads(d["feeds/all.json"][0])["items"][0]["title"]


def test_a_deferred_page_is_not_in_any_feed():
    assert "ev_1" not in {i for n in feeds.FEEDS for i in _ids(_docs(skip={"ev_1"}), n)}


def test_the_index_is_generated_from_the_one_feed_table_and_validates():
    idx = json.loads(_docs()["feeds/index.json"][0])
    assert [f["name"] for f in idx["feeds"]] == list(feeds.FEEDS)
    assert {f["name"]: f["filters"] for f in idx["feeds"]} == {k: v[1] for k, v in feeds.FEEDS.items()}
    assert not list(jsonschema.Draft202012Validator(SCHEMA).iter_errors(idx))


def test_every_feed_filter_is_a_valid_subscription_filter():
    """Same fields, same matcher: a feed and a subscription with the same filter can never disagree."""
    for name, (_, f) in feeds.FEEDS.items():
        if "severity" in f:     # the push window is P0/P1; the feed table may only narrow it
            assert set(f["severity"]) <= set(notify.NOTIFY_SEVERITIES)
        got, err = notify._filters(f, name)
        assert err is None and got == f, (name, err)


def test_feed_size_is_bounded():
    from radar.limits import Limits
    many = [row(f"ev_{i}", "P2", "vuln", f"t{i}", f"2026-11-{1 + i % 9:02d}T00:00:00Z") for i in range(Limits.FEED_MAX_ITEMS + 7)]
    assert len(_ids(_docs(many), "all")) == Limits.FEED_MAX_ITEMS


# ---------------------------------------------------------------- the publish station, end to end (moto)

@pytest.fixture
def env(monkeypatch, _table):  # noqa: F811
    monkeypatch.setenv("TABLE", "radar")
    monkeypatch.setenv("RAW_BUCKET", "raw")
    monkeypatch.setenv("SITE_BUCKET", "site")
    monkeypatch.setenv("SITE_URL", "https://site")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-northeast-1")
    s3 = boto3.client("s3", region_name="ap-northeast-1")
    s3.create_bucket(Bucket="site", CreateBucketConfiguration={"LocationConstraint": "ap-northeast-1"})
    import radar.handlers as h
    h = importlib.reload(h)
    monkeypatch.setattr(timeutil, "now", lambda: NOW)
    return h, s3


def _objects(s3):
    keys = [o["Key"] for o in s3.list_objects_v2(Bucket="site", Prefix="data/")["Contents"]]
    return {k: s3.get_object(Bucket="site", Key=k)["Body"].read() for k in keys}


def test_publish_writes_the_feeds_and_every_root_document_carries_schema_version(env):
    h, s3 = env
    at = "2026-11-11T03:00:00Z"
    h._store.put_event(Event(event_id="ev_0000000000000001", domain="web3", title="Bybit drained", first_seen=at,
                             last_updated=at, item_ids=[], keys=[], severity="P0",
                             analysis={"status": "ok", "input_hash": CANARY, "bluf": []}))
    from radar import triage
    triage.set_status(h._store, "ev_0000000000000001", "tracking", CANARY, "ops", NOW)   # a note is the page's, not the feed's
    h.publish_site({"full": True})
    objs = _objects(s3)
    assert {f"data/feeds/{n}.{x}" for n in feeds.FEEDS for x in ("json", "atom")} | {"data/feeds/index.json"} <= set(objs)
    for k, body in objs.items():
        if k.endswith(".atom"):
            assert ET.fromstring(body).findtext(f"{{{feeds.RADAR_NS}}}schema_version") == SITE_SCHEMA_VERSION, k  # nosec B314
            continue
        doc = json.loads(body)
        assert (doc.get("schema_version") or doc.get("_radar", {}).get("schema_version")) == SITE_SCHEMA_VERSION, k
        if "kind" in doc:    # the version is a known property of every root shape (full shapes: test_publish)
            br = next(b for b in SCHEMA["oneOf"] if b["properties"]["kind"]["const"] == doc["kind"])
            assert br["properties"]["schema_version"] == {"$ref": "#/$defs/SchemaVersion"}, k
    assert not list(jsonschema.Draft202012Validator(SCHEMA).iter_errors(json.loads(objs["data/feeds/index.json"])))
    # R3.3: the freshness beacon every page polls — written by every run, valid against the contract
    status = json.loads(objs["data/status.json"])
    assert status["kind"] == "status" and status["generated_at"] == timeutil.iso(NOW)
    assert not list(jsonschema.Draft202012Validator(SCHEMA).iter_errors(status))
    for k, body in objs.items():
        if k.startswith("data/feeds/"):
            assert CANARY.encode() not in body, k                    # internal state never reaches a feed
    assert _ids({"feeds/p0.json": (objs["data/feeds/p0.json"], "")}, "p0") == ["ev_0000000000000001"]
    head = s3.head_object(Bucket="site", Key="data/feeds/p0.atom")
    assert head["ContentType"] == "application/atom+xml"
