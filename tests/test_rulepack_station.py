"""P2 rule pack in the mitigate station: one row per event, read-only CheckCapacity with a budget and a cache, PoC
outages visible, and the published pack (rulepack.public) valid against schemas/site-data.schema.json $defs/RulePack."""

from __future__ import annotations

import dataclasses
import json
from datetime import timedelta
from pathlib import Path

import jsonschema
from test_mitigate_station import ACL, FX, NOW, FakeWaf, _seed

from radar import mitigate_station, pocs, rulepack
from radar.limits import Limits
from radar.model import Event
from radar.store import MemoryStore

ROOT = Path(__file__).resolve().parents[1]
NUCLEI = ROOT / "tests" / "fixtures" / "nuclei"
SHA = "5cf0e5cf09" + "1" * 30
SCHEMA = json.loads((ROOT / "schemas" / "site-data.schema.json").read_text())


def _valid(doc: dict) -> list:
    return list(jsonschema.Draft202012Validator({"$defs": SCHEMA["$defs"], "$ref": "#/$defs/RulePack"}).iter_errors(doc))


class PocWaf(FakeWaf):
    """FakeWaf + a GitHub that serves nuclei templates for the given CVEs."""

    def __init__(self, refs, cves=("CVE-2026-42018",)):
        super().__init__(refs)
        self.poc_index = "".join(json.dumps({"ID": c, "file_path": f"http/cves/2026/{c}.yaml"}) + "\n" for c in cves)
        self.poc_down = False
        self.capacity_answer: dict | None = None

    def poc_get(self, url):
        if self.poc_down:
            raise OSError("github unreachable")
        if url.startswith(pocs.COMMITS_URL):
            return json.dumps([{"sha": SHA}])
        if url.startswith(pocs.RAW_URL + SHA + "/"):
            return (NUCLEI / url.rsplit("/", 1)[-1]).read_text()
        return super().poc_get(url)

    def check_capacity(self, rules):
        super().check_capacity(rules)
        return self.capacity_answer or {"capacity": 3 * len(rules)}


def _seed_cve(store, eid="ev_648fcb1c979faa78", cves=("CVE-2026-42018",)):
    ev = json.loads(FX.read_text())["event"]
    fields = set(Event.__dataclass_fields__)
    store.put_event(Event(**{**{k: v for k, v in ev.items() if k in fields}, "event_id": eid, "cves": list(cves),
                             "title": "JFrog Artifactory auth bypass"}, item_ids=[], keys=[]))
    return eid


def test_php2shell_gets_a_pack_with_the_managed_group_and_no_located_target_needed():
    store = MemoryStore()
    eid = _seed(store)
    out = mitigate_station.run(store, PocWaf({"demo-shop": {"name": ACL, "id": "a1"}}, cves=()), NOW)
    row = store.get_source_state(rulepack.key(eid))
    assert eid in out["events"]
    assert [m["group"] for m in row["managed"] if m["tier"] == "cve"] == ["AWSManagedRulesPHPRuleSet"]
    assert row["capacity"]["state"] == "pass" and row["capacity"]["wcu"] == 0
    pub = rulepack.public(row)
    assert not _valid(pub), _valid(pub)[:2]
    assert [r["id"] for r in pub["renderings"]] == ["wafv2_json", "cloudformation", "terraform", "cli", "markdown"]


def test_a_nuclei_cve_yields_a_custom_rule_checked_once_then_cached():
    store, waf = MemoryStore(), PocWaf({})
    eid = _seed_cve(store)
    out = mitigate_station.run(store, waf, NOW)
    row = store.get_source_state(rulepack.key(eid))
    assert eid in out["events"]
    [r] = row["custom"]
    assert r["extractor"] == "trailing_slash" and r["source_quotes"][0]["sha"] == SHA
    assert row["capacity"] == {"state": "pass", "wcu": 3, "checked_on": "2026-10-23", "detail": "CheckCapacity 3 WCU"}
    assert len(waf.capacity_calls) == 1 and waf.capacity_calls[0][0]["Action"] == {"Count": {}}
    assert not _valid(rulepack.public(row))
    out2 = mitigate_station.run(store, waf, NOW + timedelta(minutes=5))
    assert len(waf.capacity_calls) == 1 and eid not in out2["events"]       # same pack: no call, no write, no rebuild


def test_check_capacity_rejection_and_outage_read_differently():
    store, waf = MemoryStore(), PocWaf({})
    eid = _seed_cve(store)
    waf.capacity_answer = {"invalid": "WAFInvalidParameterException: duplicate TextTransformation type"}
    mitigate_station.run(store, waf, NOW)
    row = store.get_source_state(rulepack.key(eid))
    assert row["capacity"]["state"] == "fail" and row["capacity"]["wcu"] is None and "duplicate" in row["capacity"]["detail"]
    assert any(e["what"].startswith("CheckCapacity") for e in store.get_source_state(mitigate_station.MITIGATE_KEY)["errors"])
    store2, waf2 = MemoryStore(), PocWaf({})
    _seed_cve(store2)
    waf2.capacity_answer = {"error": "ThrottlingException"}
    mitigate_station.run(store2, waf2, NOW)
    cap = store2.get_source_state(rulepack.key(eid))["capacity"]
    assert cap["state"] == "unchecked" and cap["wcu"] is None              # never 0, never "pass"
    mitigate_station.run(store2, waf2, NOW + timedelta(minutes=5))
    assert len(waf2.capacity_calls) == 2                                     # an outage is retried next run


def test_a_pack_over_the_wcu_budget_says_so_with_actual_and_limit():
    store, waf = MemoryStore(), PocWaf({})
    eid = _seed_cve(store)
    waf.capacity_answer = {"capacity": Limits.RULEPACK_MAX_WCU + 1}
    mitigate_station.run(store, waf, NOW)
    cap = store.get_source_state(rulepack.key(eid))["capacity"]
    assert (cap["state"], cap["wcu"], cap["max_wcu"]) == ("over_budget", Limits.RULEPACK_MAX_WCU + 1, Limits.RULEPACK_MAX_WCU)


def test_capacity_checks_are_budgeted_per_run(monkeypatch):
    monkeypatch.setattr(Limits, "RULEPACK_CAPACITY_CHECKS_PER_RUN", 1)
    store, waf = MemoryStore(), PocWaf({})
    a, b = _seed_cve(store, "ev_a"), _seed_cve(store, "ev_b")
    mitigate_station.run(store, waf, NOW)
    states = sorted(store.get_source_state(rulepack.key(e))["capacity"]["state"] for e in (a, b))
    assert states == ["pass", "unchecked"] and len(waf.capacity_calls) == 1


def test_a_poc_outage_is_an_error_and_reads_unavailable_not_no_template():
    store, waf = MemoryStore(), PocWaf({})
    eid = _seed_cve(store)
    waf.poc_down = True
    mitigate_station.run(store, waf, NOW)
    row = store.get_source_state(rulepack.key(eid))
    assert [p["state"] for p in row["poc"]] == ["unavailable"]
    assert any(e["what"] == "nuclei-templates" for e in store.get_source_state(mitigate_station.MITIGATE_KEY)["errors"])


class BadTemplateWaf(PocWaf):
    """GitHub serves a template whose `info` is a scalar (review of p1/rulepack: AttributeError, ledger lost)."""

    def poc_get(self, url):
        if url.startswith(pocs.RAW_URL + SHA + "/"):
            return "id: x\ninfo: oops\nhttp:\n  - raw:\n      - |\n        GET /a HTTP/1.1\n"
        return super().poc_get(url)


def test_a_malformed_template_is_a_rejected_row_and_the_ledger_is_still_written():
    store = MemoryStore()
    eid = _seed_cve(store)
    mitigate_station.run(store, BadTemplateWaf({}), NOW)
    assert store.get_source_state(mitigate_station.MITIGATE_KEY).get("run_at")
    assert [r["reason"] for r in store.get_source_state(rulepack.key(eid))["rejected"]] == ["unparseable"]


def test_a_build_that_raises_writes_a_failed_pack_and_the_run_goes_on(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("extractor exploded")
    monkeypatch.setattr(rulepack, "build", boom)
    store = MemoryStore()
    eid = _seed_cve(store)
    mitigate_station.run(store, PocWaf({}), NOW)
    row = store.get_source_state(rulepack.key(eid))
    assert [(r["source"], r["reason"]) for r in row["rejected"]] == [("pack", "unparseable")]
    assert "RuntimeError: extractor exploded" in row["rejected"][0]["detail"] and not _valid(rulepack.public(row))
    assert row["capacity"]["state"] == "unchecked" and row["capacity"]["wcu"] is None     # not "pass, 0 WCU"
    led = store.get_source_state(mitigate_station.MITIGATE_KEY)
    assert any(e["what"] == f"rule pack {eid}" for e in led["errors"])


def test_a_rule_pack_stage_failure_is_an_error_and_the_m3_ledger_is_still_written(monkeypatch):
    def down(*a, **k):
        raise OSError("store throttled")
    monkeypatch.setattr(pocs, "refresh", down)
    store = MemoryStore()
    _seed_cve(store)
    out = mitigate_station.run(store, PocWaf({}), NOW)
    led = store.get_source_state(mitigate_station.MITIGATE_KEY)
    assert led.get("run_at") and out["errors"] == len(led["errors"])
    assert [e["error"] for e in led["errors"] if e["what"] == "rule packs"] == ["OSError: store throttled"]


def test_check_reads_stored_packs_back_against_the_stored_pinned_bytes_and_the_items(capsys):
    """W5 --check, wired (scripts/rulepack_check.py → rulepack.cli; scripts/verify.sh runs it): the station's packs read
    back clean; a stored template row whose bytes changed under the same SHA, or an edited item, fails — exit 1."""
    store, waf = MemoryStore(), PocWaf({})
    eid = _seed_cve(store)
    from radar.model import Item
    it = Item(item_id="it_ev", source_id="s", tier="T2", org="o", domain="web", url="https://e.x/a", canonical_url="https://e.x/a",
              title="Requests carrying X-Middleware-Subrequest: middleware skip auth", text="Patch.",
              published_at=NOW.isoformat(), fetched_at=NOW.isoformat(), content_hash="h", keys=[], links=[], entity=None,
              eventful=True, signals={}, extra={})
    store.put_item(it)
    ev = store.get_event(eid)
    store.put_event(dataclasses.replace(ev, item_ids=["it_ev"]))
    mitigate_station.run(store, waf, NOW)
    row = store.get_source_state(rulepack.key(eid))
    assert {r["extractor"] for r in row["custom"]} == {"trailing_slash", "evidence_header"}
    assert rulepack.cli(["--check"], store, NOW) == 0 and '"failures": 0' in capsys.readouterr().out
    tpl = store.get_source_state(pocs.TPL_KEY + "CVE-2026-42018")
    store.put_source_state(pocs.TPL_KEY + "CVE-2026-42018", {**tpl, "text": tpl["text"].replace("aws/token/", "aws/tok/")})
    store.put_item(dataclasses.replace(it, title="Requests carrying X-Other-Header: thing skip auth"))
    n, bad = rulepack.check_store(store, NOW)
    assert n == 1 and sorted((b["reason"], b["rule_id"].split("-")[2]) for b in bad) == [
        ("not_verbatim", "evidence"), ("not_verbatim", "trailing")]
    assert rulepack.cli(["--check"], store, NOW) == 1
    # --refetch reads the pinned SHA from GitHub instead of the stored row (here: the fixture, unchanged)
    _, bad = rulepack.check_store(store, NOW, waf.poc_get)
    assert [b["reason"] for b in bad] == ["not_verbatim"] and "evidence" in bad[0]["rule_id"]
    assert rulepack.cli(["--check"], MemoryStore(), NOW) == 1                  # nothing checked is not "ok"
    assert "scripts/rulepack_check.py --check" in (ROOT / "scripts" / "verify.sh").read_text()


def test_the_station_never_writes_a_customer_resource():
    """The only new AWS call is CheckCapacity (read-only): no create/update of a rule group, IP set or web ACL."""
    src = (ROOT / "src" / "radar" / "rulepack.py").read_text() + (ROOT / "src" / "radar" / "packrender.py").read_text()
    assert "boto3" not in src and "_waf()" not in src
    store, waf = MemoryStore(), PocWaf({})
    _seed_cve(store)
    mitigate_station.run(store, waf, NOW)
    assert waf.writes == []


UI_SAMPLE = ROOT / "ui" / "src" / "test" / "fixtures" / "rule-pack.json"


def _ui_sample() -> dict:
    """The UI's sample pack, built by the backend from the nuclei fixtures (never hand-written)."""
    from types import SimpleNamespace
    cves = ("CVE-2026-87902", "CVE-2026-9586", "CVE-2026-104935", "CVE-2026-42018", "CVE-2026-96655", "CVE-2026-35273")
    poc = {c: {"state": "found", "path": f"http/cves/2026/{c}.yaml", "sha": SHA, "text": (NUCLEI / f"{c}.yaml").read_text()}
           for c in cves}
    poc["CVE-2026-0001"] = {"state": "unavailable", "path": None, "sha": None}
    items = [SimpleNamespace(item_id="it_1", url="https://example.com/advisory", title="Credential stuffing against the login",
                             text="The origin server was exposed to the internet. Infrastructure at 8.8.8[.]8 was seen.")]
    d = rulepack.build({"event_id": "ev_40bbda4fb2090dde", "cves": [*cves, "CVE-2026-0001"]}, items, poc, {}, {}).to_dict()
    d["capacity"] = {"state": "pass", "wcu": 41, "checked_on": "2026-11-11", "detail": "CheckCapacity 41 WCU"}
    d["updated_at"] = "2026-11-11T03:00:00Z"
    return rulepack.public(d)


def test_ui_sample_pack_is_generated_from_the_backend():
    """--check for the UI fixture: RADAR_REGEN=1 rewrites it; otherwise it must equal what the code builds today."""
    import os
    want = _ui_sample()
    assert not _valid(want), _valid(want)[:2]
    if os.environ.get("RADAR_REGEN") == "1":
        UI_SAMPLE.parent.mkdir(parents=True, exist_ok=True)
        UI_SAMPLE.write_text(json.dumps(want, ensure_ascii=False, indent=1) + "\n")
    assert json.loads(UI_SAMPLE.read_text()) == want, "UI sample out of date: RADAR_REGEN=1 uv run pytest -k ui_sample"


def test_schema_enums_are_the_code_registries():
    """Single source: the schema restates four registries — it must equal them (regenerate with the code, never by hand)."""
    from radar import packrender
    d = SCHEMA["$defs"]
    assert d["RulePackRule"]["properties"]["kind"]["enum"] == list(rulepack.KINDS)
    assert d["RulePackRule"]["properties"]["confidence"]["enum"] == list(rulepack.CONFIDENCE)
    assert d["RulePackPoc"]["properties"]["state"]["enum"] == list(pocs.STATES)
    assert d["RulePackRendering"]["properties"]["id"]["enum"] == [r[0] for r in packrender.RENDERINGS]
    event_doc = next(v for v in SCHEMA["oneOf"] if v.get("properties", {}).get("kind", {}).get("const") == "event")
    assert event_doc["properties"]["rule_pack"]["oneOf"][0] == {"$ref": "#/$defs/RulePack"}
