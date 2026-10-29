"""Mitigate station wiring (M3.2): a real PHP2Shell response (respond.decide over the shipped demo targets) → WAF
plans → staged apply on the radar-owned web ACL only → human promotion → blocking; downstream failures stay visible."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path

import jsonschema

from radar import mitigate, mitigate_station, respond
from radar.model import Event, Item
from radar.store import MemoryStore

ROOT = Path(__file__).resolve().parents[1]
FX = ROOT / "tests" / "fixtures" / "events" / "php2shell.json"
SNAP = ROOT / "tests" / "fixtures" / "snapshots" / "2026-10-29"
DEMO = ROOT / "integrations" / "continuum" / "targets"
GROUPS = {g["name"]: g for g in map(json.loads, (SNAP / "waf-groups.jsonl").read_text().splitlines())}
NOW = datetime(2026, 10, 23, 18, 0, tzinfo=UTC)
ACL = "security-radar-waf-demo"
FOREIGN_ACL = {"Name": "n8n-waf", "Id": "f1", "DefaultAction": {"Allow": {}}, "Rules": [],
               "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "n"}}


class FakeWaf:
    def __init__(self, refs):
        self.refs = refs
        self.acls = {ACL: {"Name": ACL, "Id": "a1", "DefaultAction": {"Allow": {}}, "Rules": [],
                           "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "d"}},
                     "n8n-waf": copy.deepcopy(FOREIGN_ACL)}
        self.writes, self.fail, self.scans, self.dns, self.dns_writes, self.hub = [], set(), [], None, [], None

    def web_acls(self):
        return self.refs

    def changelog_rows(self):
        if "changelog" in self.fail:
            return {"error": "changelog: http_error 503"}
        return mitigate.parse_waf_changelog((SNAP / "waf-changelog.html").read_text())

    def group_meta(self, group):
        return {"labels": GROUPS[group]["labels"], "default_version": "Version_2.5"}

    def get_acl(self, ref):
        if "get" in self.fail:
            return {"error": "AccessDenied"}
        return {"acl": copy.deepcopy(self.acls[ref["name"]]), "lock": "L"}

    def dns_config(self):
        return {"rule_group_id": "rg", "domain_list_id": "dl"} if self.dns is not None else None

    def dns_state(self, cfg):
        if "dns" in self.fail:
            return {"error": "AccessDenied"}
        return {"domains": list(self.dns["domains"]), "rules": [dict(r) for r in self.dns["rules"]],
                "managed": {n: f"m-{n}" for n in mitigate.DNS_MANAGED_LISTS}}

    def dns_put(self, cfg, domains, create, update):
        self.dns_writes.append((domains, [r["Name"] for r in create], [r["Name"] for r in update]))
        if domains is not None:
            self.dns["domains"] = list(domains)
        for r in create:
            self.dns["rules"].append(dict(r))
        for u in update:
            for r in self.dns["rules"]:
                if r["FirewallDomainListId"] == u["FirewallDomainListId"]:
                    r.update(u)
                    r.pop("BlockResponse", None) if u["Action"] == "ALERT" else None
        return {}

    def security_hub(self):
        return {"account": "123456789012", "region": "ap-northeast-1"} if self.hub is not None else None

    def security_hub_import(self, findings):
        self.hub += findings
        return {"failed": []}

    def load_targets(self):
        insp = ROOT / "tests" / "fixtures" / "inspector"   # lockfiles as scanned (paired with the scan fixture)
        files = {"security-radar/uv.lock": (insp / "uv-2026-10-29.lock").read_text(),
                 "security-radar/ui/package-lock.json": (insp / "ui-package-lock-2026-10-29.json").read_text()}
        return [respond.Target("security-radar", "security-radar", "self", files),
                respond.Target("demo-shop", "demo-shop", "d", {"demo-shop/composer.json": (DEMO / "demo-shop" / "composer.json").read_text()})]

    def scan_sbom(self, doc):
        self.scans.append(doc["metadata"]["component"]["name"])
        if "scan" in self.fail:
            return {"error": "ThrottlingException"}
        return json.loads((ROOT / "tests" / "fixtures" / "inspector" / "scan-radar-2026-10-29.json").read_text())

    def put_rules(self, ref, acl, lock, rules):
        self.writes.append(ref["name"])
        self.acls[ref["name"]]["Rules"] = copy.deepcopy(rules)
        return {"lock": "L2"}


def _seed(store):
    d = json.loads(FX.read_text())
    ev = d["event"]
    fields = set(Event.__dataclass_fields__)
    items = [Item(item_id=i["item_id"], source_id=i["source_id"], tier=i["tier"], org=i["source_name"], domain=ev["domain"],
                  url=i["url"], canonical_url=i["url"], title=i["title"], text=i.get("excerpt") or "", published_at=i["published_at"],
                  fetched_at=i["published_at"], content_hash=i["item_id"], keys=[], links=[], entity=None, eventful=True,
                  signals=i.get("signals") or {}, extra={"cves": ev["cves"]}) for i in d["items"]]
    for it in items:
        store.put_item(it)
    store.put_event(Event(**{k: v for k, v in ev.items() if k in fields}, item_ids=[i.item_id for i in items], keys=[],
                          analysis=d.get("analysis")))
    files = {f"demo-shop/{p.relative_to(DEMO / 'demo-shop')}": p.read_text()
             for p in sorted((DEMO / "demo-shop").rglob("*")) if p.is_file()}
    st, _ = respond.decide(ev, d["items"], d.get("analysis"), None, [respond.Target("demo-shop", "demo-shop", "d", files)],
                           respond.Budget(0, False, "2026-10-23"))
    store.put_response(ev["event_id"], st)
    return ev["event_id"]


def _run(store, waf):
    return mitigate_station.run(store, waf, NOW)


def test_station_stages_php2shell_on_the_radar_acl_and_reports_it():
    store = MemoryStore()
    eid = _seed(store)
    waf = FakeWaf({"demo-shop": {"name": ACL, "id": "a1"}})
    out = _run(store, waf)
    assert eid in out["events"]
    assert out["errors"] == 0
    assert waf.writes == [ACL]
    (plan,) = store.get_source_state(mitigate_station.MITIGATE_KEY)["events"][eid]["plans"]
    assert (plan["tier"], plan["group"], plan["state"], plan["web_acl"]) == ("cve", "AWSManagedRulesPHPRuleSet", "staged", ACL)
    assert set(plan["labels"]) == {"awswaf:managed:aws:php-app:PHP2Shell_Body", "awswaf:managed:aws:php-app:PHP2Shell_Body_Extended"}
    assert "Count" in json.dumps(plan["rule_json"])
    schema = json.loads((ROOT / "schemas" / "site-data.schema.json").read_text())
    mit = store.get_source_state(mitigate_station.MITIGATE_KEY)["events"][eid]
    errs = list(jsonschema.Draft202012Validator({"$defs": schema["$defs"], "$ref": "#/$defs/Mitigation"}).iter_errors(mit))
    assert not errs, errs[:2]
    # second cycle: nothing changes ⇒ no write (idempotent)
    _run(store, waf)
    assert waf.writes == [ACL]


def test_foreign_web_acls_are_never_written():
    store = MemoryStore()
    _seed(store)
    waf = FakeWaf({"demo-shop": {"name": ACL, "id": "a1"}})
    _run(store, waf)
    assert waf.acls["n8n-waf"] == FOREIGN_ACL and "n8n-waf" not in waf.writes


def test_promotion_by_a_human_makes_it_blocking_and_it_is_never_demoted():
    store = MemoryStore()
    eid = _seed(store)
    waf = FakeWaf({"demo-shop": {"name": ACL, "id": "a1"}})
    _run(store, waf)
    store.put_source_state(mitigate_station.PROMOTE_KEY,
                           {"waf": {ACL: {mitigate.rule_name("AWSManagedRulesPHPRuleSet"): {"by": "human", "at": "x"}}}})
    _run(store, waf)
    _run(store, waf)
    (plan,) = store.get_source_state(mitigate_station.MITIGATE_KEY)["events"][eid]["plans"]
    assert plan["state"] == "blocking" and plan["promoted"] is True
    assert waf.writes == [ACL, ACL]   # staged once, promoted once, then stable


def test_a_target_without_web_acl_gets_the_rule_as_advice_only():
    store = MemoryStore()
    eid = _seed(store)
    waf = FakeWaf({})
    _run(store, waf)
    (plan,) = store.get_source_state(mitigate_station.MITIGATE_KEY)["events"][eid]["plans"]
    assert plan["state"] == "no_web_acl" and plan["rule_json"]["Statement"] and waf.writes == []


def test_failures_are_recorded_not_silent():
    store = MemoryStore()
    eid = _seed(store)
    waf = FakeWaf({"demo-shop": {"name": ACL, "id": "a1"}})
    waf.fail = {"get"}
    out = _run(store, waf)
    led = store.get_source_state(mitigate_station.MITIGATE_KEY)
    assert out["errors"] == 1 and led["errors"][0]["what"] == f"web ACL {ACL}"
    assert led["events"][eid]["plans"][0]["state"] == "unchecked"
    # changelog down on a new day ⇒ yesterday's catalog keeps working, and the outage is on record
    waf.fail = {"changelog"}
    led["catalog"]["fetched_on"] = "2026-10-22"
    store.put_source_state(mitigate_station.MITIGATE_KEY, led)
    out = _run(store, waf)
    led = store.get_source_state(mitigate_station.MITIGATE_KEY)
    assert any(e["what"] == "changelog" for e in led["errors"]) and led["events"][eid]["plans"]


def test_inspector_scans_lockfile_targets_once_a_day_and_runtime_targets_never():
    store = MemoryStore()
    _seed(store)
    waf = FakeWaf({})
    _run(store, waf)
    _run(store, waf)
    assert waf.scans == ["security-radar"]            # one call; demo-shop pins only the PHP runtime
    insp = store.get_source_state(mitigate_station.MITIGATE_KEY)["inspector"]
    assert insp["demo-shop"]["state"] == "no_packages" and insp["security-radar"]["state"] == "scanned"
    crit = [f for f in insp["security-radar"]["findings"] if f["severity"] == "critical"]
    assert crit[0]["purl"] == "pkg:npm/vitest@2.1.9" and crit[0]["file"] == "security-radar/ui/package-lock.json"


def test_an_event_naming_a_package_cve_gets_the_inspector_verdict():
    store = MemoryStore()
    _seed(store)
    ev = store.get_event(json.loads(FX.read_text())["event"]["event_id"])
    ev.cves = [*ev.cves, "CVE-2026-47429"]
    store.put_event(ev)
    waf = FakeWaf({})
    _run(store, waf)
    m = store.get_source_state(mitigate_station.MITIGATE_KEY)["events"][ev.event_id]
    assert [(h["target_id"], h["purl"]) for h in m["inspector"]] == [("security-radar", "pkg:npm/vitest@2.1.9")]


def test_a_failed_scan_is_recorded_and_not_reported_clean():
    store = MemoryStore()
    _seed(store)
    waf = FakeWaf({})
    waf.fail = {"scan"}
    _run(store, waf)
    led = store.get_source_state(mitigate_station.MITIGATE_KEY)
    assert led["inspector"]["security-radar"]["state"] == "error"
    assert any(e["what"] == "ScanSbom security-radar" for e in led["errors"])


def _with_ioc(store, eid):
    it = store.get_items(store.get_event(eid).item_ids)[0]
    it.text += " Exfiltration endpoint: hxxps://php2shell-loader[.]top/x — also see php.net"
    store.put_item(it)


def test_dns_lists_defanged_iocs_alerts_first_and_is_idempotent():
    store = MemoryStore()
    eid = _seed(store)
    _with_ioc(store, eid)
    waf = FakeWaf({})
    waf.dns = {"domains": [], "rules": []}
    _run(store, waf)
    assert waf.dns["domains"] == ["php2shell-loader.top", mitigate.DNS_CANARY]
    assert {r["Action"] for r in waf.dns["rules"]} == {"ALERT"} and len(waf.dns["rules"]) == 1 + len(mitigate.DNS_MANAGED_LISTS)
    m = store.get_source_state(mitigate_station.MITIGATE_KEY)["events"][eid]
    assert m["dns"] == {"domains": ["php2shell-loader.top"], "state": "in_place", "action": "ALERT"}
    _run(store, waf)
    assert len(waf.dns_writes) == 1     # nothing changed ⇒ no write


def test_dns_promotion_blocks_only_the_promoted_rule():
    store = MemoryStore()
    eid = _seed(store)
    _with_ioc(store, eid)
    waf = FakeWaf({})
    waf.dns = {"domains": [], "rules": []}
    _run(store, waf)
    store.put_source_state(mitigate_station.PROMOTE_KEY, {"dns": {mitigate.DNS_RADAR_RULE: {"by": "h", "at": "t"}}})
    _run(store, waf)
    acts = {r["Name"]: r["Action"] for r in waf.dns["rules"]}
    assert acts[mitigate.DNS_RADAR_RULE] == "BLOCK" and {v for k, v in acts.items() if k != mitigate.DNS_RADAR_RULE} == {"ALERT"}
    assert store.get_source_state(mitigate_station.MITIGATE_KEY)["events"][eid]["dns"]["action"] == "BLOCK"


def test_dns_failure_is_recorded_as_unchecked():
    store = MemoryStore()
    eid = _seed(store)
    _with_ioc(store, eid)
    waf = FakeWaf({})
    waf.dns = {"domains": [], "rules": []}
    waf.fail = {"dns"}
    _run(store, waf)
    led = store.get_source_state(mitigate_station.MITIGATE_KEY)
    assert led["events"][eid]["dns"]["state"] == "unchecked" and any(e["channel"] == "dns" for e in led["errors"])


def test_security_hub_gets_one_finding_per_affected_target_and_only_on_change():
    store = MemoryStore()
    eid = _seed(store)
    waf = FakeWaf({"demo-shop": {"name": ACL, "id": "a1"}})
    waf.hub = []
    _run(store, waf)
    ids = [f["Id"] for f in waf.hub]
    assert ids == [f"security-radar/{eid}/demo-shop"] and waf.hub[0]["RecordState"] == "ACTIVE"
    assert "staged" in waf.hub[0]["Description"]
    _run(store, waf)
    assert len(waf.hub) == 1                     # unchanged ⇒ not re-imported
    led = store.get_source_state(mitigate_station.MITIGATE_KEY)["security_hub"]
    assert (led["state"], led["active"]) == ("in_place", 1)


def test_a_group_someone_else_already_runs_on_the_acl_is_reported_not_duplicated():
    store = MemoryStore()
    eid = _seed(store)
    waf = FakeWaf({"demo-shop": {"name": ACL, "id": "a1"}})
    theirs = {"Name": "ops-team-php", "Priority": 0, "OverrideAction": {"None": {}},
              "Statement": {"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "AWSManagedRulesPHPRuleSet"}},
              "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "o"}}
    waf.acls[ACL]["Rules"] = [theirs]
    _run(store, waf)
    assert waf.writes == [] and waf.acls[ACL]["Rules"] == [theirs]
    (plan,) = store.get_source_state(mitigate_station.MITIGATE_KEY)["events"][eid]["plans"]
    assert plan["state"] == "blocking" and plan["rule"] == "ops-team-php"   # reported as what is really there
