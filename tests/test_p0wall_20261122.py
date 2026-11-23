"""The P0 wall (Neo 2026-11-22): every P0 on its product tile, many fine tiles in a few groups, click a tile for its
vulnerabilities. One taxonomy (radar.p0class) — the team channel's cloud prefilter is the group's flag."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jsonschema
import pytest

from radar import cloudstack, p0class, publish, retitle, send_judge, timeutil
from radar.model import Event
from radar.store import MemoryStore

NOW = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
SCHEMA = json.loads((Path(__file__).parents[1] / "schemas" / "site-data.schema.json").read_text())

# (title, entities, expected tile) — the 2026-11-22 replay's P0 titles where the rule had to choose
CASES = [
    ("Critical RCE Vulnerability in Apache HTTP Server: Everything You Need To Know", ["VMware", "vSphere"], "apache"),
    ("CVE-2026-133045 - JetBrains TeamCity VMware vSphere Cloud Profiles plugin", [], "jetbrains"),
    ("ICSA-26-237-03 Siemens SIMATIC IoT2050 Advanced", [], "siemens"),
    ("CVE-2026-124990 Masteriyo LMS <= 3.5.1 - Unauthenticated PHP Object Injection via 'file' Parameter", [], "wordpress"),
    ("CVE-2026-76466 Cisco Expressway Series: Use of Hard-coded Credentials in a Java service", [], "cisco"),
    ("CVE-2026-1 Apache Log4j JNDI lookup RCE", [], "java"),
    ("CVE-2026-90436 Apache Axis: Apache Axis Unsafe Reflection", [], "apacheproj"),
    ("Use-after-free in magic method backtraces can lead to RCE", ["PHP Group", "PHP"], "php"),
    ("Geth DoS via a crafted p2p message", [], "geth"),
    ("CVE-2026-4 Apache Axis: unsafe reflection", ["Java"], "apacheproj"),     # a fallback product in the title wins
    ("CVE-2026-5 PHP Object Injection in Acme Forms", [], "x-acme-forms"),       # a flaw class is not the product
]


@pytest.mark.parametrize("title,entities,tile", CASES)
def test_the_product_the_title_names_first_is_the_tile(title, entities, tile):
    assert p0class.place(title, entities).product == tile


@pytest.mark.parametrize("title,name", [
    ("CVE-2026-77367 Daptin: Unauthenticated SQL Injection via the aggregate API", "Daptin"),
    ("CVE-2026-114713 UnrealIRCd UnrealIRCd: UnrealIRCd Improper Neutralization", "UnrealIRCd"),
    ("CVE-2026-131852 OwnTracks Recorder before 1.0.5 Format String", "OwnTracks Recorder"),
    ("CVE-2026-133968 monailabel (aka MONAI Label) through 0.8.5 allows", "MONAI Label"),
    ("CVE-2026-14914 RCE in TEGSOFT Management's Tegsoft Contact Center", "Tegsoft Contact Center"),
    ("CVE-2026-120681 Mang Board <= 2.4.7 - Missing Authorization", "Mang Board"),
])
def test_an_unregistered_product_gets_its_own_tile_named_from_the_title(title, name):
    """The vendor slug (「ontola」「kitae-park」) and a flaw word (「RCE」) were tile names in the first trial."""
    pl = p0class.place(title, ["vendor-slug"])
    assert (pl.label, pl.group, pl.product.startswith("x-")) == (name, "other", True)


def test_nothing_falls_off_the_wall():
    assert p0class.place("", []).product == "x-unknown"
    assert p0class.place("", ["Acme"]).label == "Acme"


def test_the_registry_is_well_formed():
    ids = [p.id for p in p0class.PRODUCTS]
    labels = [p.label for p in p0class.PRODUCTS]
    assert len(ids) == len(set(ids)) and len(labels) == len(set(labels))
    assert {p.group for p in p0class.PRODUCTS} <= set(p0class.GROUP)
    assert all(not i.startswith("x-") for i in ids)          # x- is the unregistered namespace
    assert len(p0class.PRODUCTS) >= 80                       # 「类目要更多一些」: a wall, not a handful of buckets


@pytest.mark.parametrize("title,entities,_", CASES)
def test_the_team_channels_cloud_flag_is_the_walls_group(title, entities, _):
    assert cloudstack.is_cloud_stack(title, entities) is p0class.place(title, entities).cloud


def _ev(n, title, sev="P0", domain="vuln", hours=5, became_p0=None, exploitation="none", entities=None):
    at = timeutil.iso(NOW - timedelta(hours=hours))
    tl = [{"at": became_p0, "kind": "severity_change", "from": "P1", "to": "P0", "item_id": None}] if became_p0 else []
    return Event(event_id=f"ev_{n:016x}", domain=domain, title=title, first_seen=at, last_updated=at, item_ids=[], keys=[],
                 severity=sev, exploitation=exploitation, entities=entities or [], timeline=tl)


def test_the_document_places_every_p0_and_validates():
    s = MemoryStore()
    later = timeutil.iso(NOW - timedelta(hours=1))
    evs = [_ev(1, "CVE-2026-114952 Vulnerability in the MySQL Server", exploitation="poc"),
           _ev(2, "CVE-2026-2 MySQL Server crash", sev="P1", became_p0=later),              # was P0, demoted since
           _ev(3, "CVE-2026-77367 Daptin: Unauthenticated SQL Injection", exploitation="confirmed"),
           _ev(4, "CVE-2026-3 Windows Audio Service EoP", sev="P1"),                         # never P0: not on the wall
           _ev(5, "Exchange X drained of $40M", domain="web3")]                              # thefts: #/web3
    for e in evs:
        s.put_event(e)
    s.put_source_state(send_judge.key(evs[0].event_id), {"send": True, "reason": "MySQL 未认证 RCE"})
    s.put_source_state(retitle.KEY, {evs[2].event_id: {"title": "Daptin: aggregate API SQL injection", "source": "u",
                                                      "at": timeutil.iso(NOW)}})
    doc = publish.p0_doc(s, NOW, publish.publish_window(s, NOW))
    assert not list(jsonschema.Draft202012Validator(SCHEMA).iter_errors({**doc, "schema_version": "1"}))
    assert [x["event_id"] for x in doc["events"]] == [evs[1].event_id, evs[0].event_id, evs[2].event_id]  # newest P0 first
    assert (doc["total"], doc["now_p0"], doc["cloud"], doc["team_send"]) == (3, 2, 2, 1)
    by = {x["event_id"]: x for x in doc["events"]}
    assert by[evs[0].event_id]["team_send"] is True and by[evs[1].event_id]["team_send"] is None
    assert by[evs[1].event_id]["p0_at"] == later and by[evs[1].event_id]["severity"] == "P1"
    assert by[evs[2].event_id]["title"] == "Daptin: aggregate API SQL injection"        # the operator's title is placed
    tiles = {t["product"]: t for g in doc["groups"] for t in g["tiles"]}
    assert (tiles["mysql"]["count"], tiles["mysql"]["now_p0"], tiles["mysql"]["poc"]) == (2, 1, 1)
    assert tiles["x-daptin"]["exploited"] == 1 and tiles["x-daptin"]["registered"] is False
    assert tiles["windows"]["count"] == 0                     # registered tiles are listed empty too
    assert len(tiles) == len(p0class.PRODUCTS) + 1
    assert sum(g["count"] for g in doc["groups"]) == doc["total"]
    assert [g["id"] for g in doc["groups"]] == [g.id for g in p0class.GROUPS]
    db = next(g for g in doc["groups"] if g["id"] == "database")
    assert db["tiles"][0]["product"] == "mysql"               # the busiest tile leads its group


def test_the_build_publishes_it():
    s = MemoryStore()
    s.put_event(_ev(1, "CVE-2026-114952 Vulnerability in the MySQL Server"))
    docs = publish.build(s, NOW)
    assert docs["p0.json"]["kind"] == "p0" and docs["p0.json"]["total"] == 1
