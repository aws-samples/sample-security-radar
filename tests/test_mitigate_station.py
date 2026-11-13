"""Mitigate station wiring (M3.2): a real PHP2Shell response (respond.decide over the shipped demo targets) → WAF
plans → staged apply on the radar-owned web ACL only → human promotion → blocking; downstream failures stay visible."""

from __future__ import annotations

import copy
import dataclasses
import json
from datetime import UTC, datetime
from pathlib import Path

import jsonschema

from radar import mitigate, mitigate_aws, mitigate_station, respond
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
        self.meta_calls = []

    def web_acls(self):
        return self.refs

    def changelog_rows(self):
        if "changelog" in self.fail:
            return {"error": "changelog: http_error 503"}
        return mitigate.parse_waf_changelog((SNAP / "waf-changelog.html").read_text())

    def group_meta(self, group):
        self.meta_calls.append(group)
        if "meta" in self.fail:
            return {"error": "ThrottlingException"}
        return {"labels": GROUPS[group]["labels"], "rules": GROUPS[group]["rules"], "default_version": "Version_2.5"}

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

    # P2 rule pack: nuclei-templates (an empty index unless a test serves one) and the read-only CheckCapacity
    poc_index = ""
    capacity_calls: list | None = None

    def poc_get(self, url):
        import hashlib

        from radar import pocs
        if url == pocs.CHECKSUM_URL:
            return hashlib.md5(self.poc_index.encode(), usedforsecurity=False).hexdigest()
        if url == pocs.INDEX_URL:
            return self.poc_index
        raise AssertionError(f"unexpected PoC URL {url}")

    def check_capacity(self, rules):
        if self.capacity_calls is None:
            self.capacity_calls = []
        self.capacity_calls.append(rules)
        return {"capacity": 3 * len(rules)}

    def put_rules(self, ref, acl, lock, rules):
        """Through the REAL adapter (radar.mitigate_aws.put_rules, its prefix guard included) with a stub wafv2 client:
        only what reaches UpdateWebACL counts as a write."""
        class Client:
            def update_web_acl(_, **kw):
                self.writes.append(kw["Name"])
                self.acls[kw["Name"]]["Rules"] = copy.deepcopy(kw["Rules"])
                return {"NextLockToken": "L2"}
        saved = mitigate_aws._clients.get("waf")
        mitigate_aws._clients["waf"] = Client()
        try:
            return mitigate_aws.put_rules(ref, acl, lock, rules)
        finally:
            if saved is None:
                mitigate_aws._clients.pop("waf", None)
            else:
                mitigate_aws._clients["waf"] = saved


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


THEIR_RULE = {"Name": "ops-rate-limit", "Priority": 3, "Action": {"Block": {}},
              "Statement": {"RateBasedStatement": {"Limit": 100, "AggregateKeyType": "IP"}},
              "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "r"}}


def test_foreign_web_acls_are_never_written():
    """B3 at station level. Before 2026-11-11 the fake listed only the radar ACL, so the station never even reached a
    foreign one and every guard could be deleted with this test still green (01-waf.md Bug-3)."""
    store = MemoryStore()
    _seed(store)
    # a mis-registered ACL (no radar prefix) behind an affected target: the station wants to write it — the adapter refuses
    waf = FakeWaf({"demo-shop": {"name": "n8n-waf", "id": "f1"}})
    _run(store, waf)
    led = store.get_source_state(mitigate_station.MITIGATE_KEY)
    assert waf.acls["n8n-waf"] == FOREIGN_ACL and "n8n-waf" not in waf.writes
    assert any(e["what"] == "update n8n-waf" and "refusing" in e["error"] for e in led["errors"])
    # the radar's own ACL shared with someone else's rule: written, and their rule kept byte-for-byte
    store = MemoryStore()
    _seed(store)
    waf = FakeWaf({"demo-shop": {"name": ACL, "id": "a1"}})
    waf.acls[ACL]["Rules"] = [copy.deepcopy(THEIR_RULE)]
    _run(store, waf)
    assert waf.writes == [ACL] and waf.acls[ACL]["Rules"][0] == THEIR_RULE
    assert [r["Name"] for r in waf.acls[ACL]["Rules"]] == ["ops-rate-limit", "radar-AWSManagedRulesPHPRuleSet"]


def test_w1_the_staged_rule_on_the_acl_and_on_the_page_blocks_nothing():
    """Live bug (01-waf.md Bug-1): the staged PHP rule on the demo ACL — and the rule_json users copy — counted only the
    two PHP2Shell rules; the group's 4 PHPHighRiskMethodsVariables_* rules blocked without anyone promoting them."""
    store = MemoryStore()
    eid = _seed(store)
    waf = FakeWaf({"demo-shop": {"name": ACL, "id": "a1"}})
    _run(store, waf)
    (written,) = waf.acls[ACL]["Rules"]
    (plan,) = store.get_source_state(mitigate_station.MITIGATE_KEY)["events"][eid]["plans"]
    for rule in (written, plan["rule_json"]):
        assert rule["OverrideAction"] == {"Count": {}}
        assert "RuleActionOverrides" not in rule["Statement"]["ManagedRuleGroupStatement"]
    # promoted: only the plan's rules block; every other PHP rule stays at Count
    store.put_source_state(mitigate_station.PROMOTE_KEY,
                           {"waf": {ACL: {mitigate.rule_name("AWSManagedRulesPHPRuleSet"): {"by": "human", "at": "x"}}}})
    _run(store, waf)
    (written,) = waf.acls[ACL]["Rules"]
    every = GROUPS["AWSManagedRulesPHPRuleSet"]["rules"]
    counted = {o["Name"] for o in written["Statement"]["ManagedRuleGroupStatement"]["RuleActionOverrides"]
               if "Count" in o["ActionToUse"]}
    assert written["OverrideAction"] == {"None": {}}
    assert set(every) - counted == set(plan["rules"]) & set(every) and set(every) - counted


def _seed_twin(store, eid, new_id, cves):
    """Another event with the same located response (same affected targets) but other CVEs."""
    ev = store.get_event(eid)
    store.put_event(dataclasses.replace(ev, event_id=new_id, cves=list(cves)))
    store.put_response(new_id, copy.deepcopy(store.get_response(eid)))


def test_w2_two_events_on_one_acl_and_group_share_one_rule_and_both_are_checked():
    """Live bug (01-waf.md Bug-2): `wanted = {p.group: p …}` kept the last plan per group — the earlier event's rules were
    not the ones rendered, so after a promotion the earlier plan read as not blocking (and, before W1, as blocking
    while staged)."""
    store = MemoryStore()
    eid = _seed(store)
    _seed_twin(store, eid, "ev_kbi_a", ["CVE-2022-42889"])
    _seed_twin(store, eid, "ev_kbi_b", ["CVE-2023-22515"])
    waf = FakeWaf({"demo-shop": {"name": ACL, "id": "a1"}})
    _run(store, waf)
    kbi = "AWSManagedRulesKnownBadInputsRuleSet"
    assert [r["Name"] for r in waf.acls[ACL]["Rules"]].count(mitigate.rule_name(kbi)) == 1
    events = store.get_source_state(mitigate_station.MITIGATE_KEY)["events"]
    plans = [p for e in ("ev_kbi_a", "ev_kbi_b") for p in events[e]["plans"] if p["group"] == kbi]
    assert len(plans) == 2 and {p["state"] for p in plans} == {"staged"}
    # approved as the whole group ("rules": []): the rule renders the merged plan itself. A promotion that names rules
    # is pinned to them (mitigate.pinned) whatever the merge says — with that, last-one-wins rendered the same rule
    # and this test could not tell (CI 2026-11-13: M505 survived)
    store.put_source_state(mitigate_station.PROMOTE_KEY,
                           {"waf": {ACL: {mitigate.rule_name(kbi): {"by": "human", "at": "x", "rules": []}}}})
    _run(store, waf)
    events = store.get_source_state(mitigate_station.MITIGATE_KEY)["events"]
    plans = [p for e in ("ev_kbi_a", "ev_kbi_b") for p in events[e]["plans"] if p["group"] == kbi]
    assert {p["state"] for p in plans} == {"blocking"}, [(p["rules"], p["state"]) for p in plans]
    (written,) = [r for r in waf.acls[ACL]["Rules"] if r["Name"] == mitigate.rule_name(kbi)]
    every = set(GROUPS[kbi]["rules"])
    counted = {o["Name"] for o in written["Statement"]["ManagedRuleGroupStatement"].get("RuleActionOverrides") or []}
    assert every - counted == {r for p in plans for r in p["rules"]} & every
    assert all(p["rule_json"] == written for p in plans)   # the page shows the rule that is really there


def test_w4_rule_json_priority_is_the_real_one_on_the_radar_acl_and_a_distinct_placeholder_otherwise():
    store = MemoryStore()
    eid = _seed(store)
    waf = FakeWaf({"demo-shop": {"name": ACL, "id": "a1"}})
    waf.acls[ACL]["Rules"] = [copy.deepcopy(THEIR_RULE)]
    _run(store, waf)
    (plan,) = store.get_source_state(mitigate_station.MITIGATE_KEY)["events"][eid]["plans"]
    assert plan["rule_json"]["Priority"] == waf.acls[ACL]["Rules"][1]["Priority"] == 4
    store, waf = MemoryStore(), FakeWaf({})
    eid = _seed(store)
    _run(store, waf)
    (plan,) = store.get_source_state(mitigate_station.MITIGATE_KEY)["events"][eid]["plans"]
    assert plan["rule_json"]["Priority"] == mitigate.paste_priority(plan["group"]) != 0


def test_w4_priority_placeholder_flag_follows_the_real_priority_not_the_web_acl():
    """The page notes a placeholder Priority from this flag: web_acl alone is not enough (an advisory cwe plan behind a
    radar ACL, a group someone else runs, a rule not written yet all carry web_acl and a 10000+ placeholder)."""
    store = MemoryStore()
    eid = _seed(store)
    waf = FakeWaf({"demo-shop": {"name": ACL, "id": "a1"}})
    _run(store, waf)
    (plan,) = store.get_source_state(mitigate_station.MITIGATE_KEY)["events"][eid]["plans"]
    assert plan["web_acl"] == ACL and plan["priority_placeholder"] is False
    assert plan["rule_json"]["Priority"] != mitigate.paste_priority(plan["group"])
    # (b) a group someone else already runs: the radar rule is never written => the shown Priority is a placeholder
    store = MemoryStore()
    eid = _seed(store)
    waf = FakeWaf({"demo-shop": {"name": ACL, "id": "a1"}})
    waf.acls[ACL]["Rules"] = [{"Name": "ops-team-php", "Priority": 0, "OverrideAction": {"None": {}},
                               "Statement": {"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "AWSManagedRulesPHPRuleSet"}},
                               "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "o"}}]
    _run(store, waf)
    (plan,) = store.get_source_state(mitigate_station.MITIGATE_KEY)["events"][eid]["plans"]
    assert plan["web_acl"] == ACL and plan["priority_placeholder"] is True
    assert plan["rule_json"]["Priority"] == mitigate.paste_priority(plan["group"])
    # (a) an advisory cwe plan behind a radar ACL whose radar rule for the group is there: still a placeholder
    ref = {"name": ACL, "id": "a1"}
    cwe = mitigate.WafPlan("demo-shop", "cwe", plan["group"], (), None, "CWE-94")
    acl = {"Rules": [{"Name": mitigate.rule_name(plan["group"]), "Priority": 4}]}
    row = mitigate_station._row(cwe, ref, False, {"state": "staged", "detail": ""}, acl, {}, {})
    assert row["web_acl"] == ACL and row["priority_placeholder"] is True
    assert row["rule_json"]["Priority"] == mitigate.paste_priority(plan["group"])
    # (c) a radar ACL whose rule is not there (put_rules failed / get_acl unchecked): placeholder
    cve = mitigate.WafPlan("demo-shop", "cve", plan["group"], (), None, "CVE")
    row = mitigate_station._row(cve, ref, False, {"state": "unchecked", "detail": ""}, None, {}, {})
    assert row["web_acl"] == ACL and row["priority_placeholder"] is True
    # no web ACL at all: placeholder
    store, waf = MemoryStore(), FakeWaf({})
    eid = _seed(store)
    _run(store, waf)
    (plan,) = store.get_source_state(mitigate_station.MITIGATE_KEY)["events"][eid]["plans"]
    assert plan["web_acl"] is None and plan["priority_placeholder"] is True


def test_group_meta_cached_without_the_rule_list_is_refetched_the_same_day():
    """Ledgers written before W1 cached {labels, default_version} only; promotion needs the group's rule list."""
    store = MemoryStore()
    _seed(store)
    waf = FakeWaf({"demo-shop": {"name": ACL, "id": "a1"}})
    _run(store, waf)
    led = store.get_source_state(mitigate_station.MITIGATE_KEY)
    for g in led["groups"].values():
        g.pop("rules")
    store.put_source_state(mitigate_station.MITIGATE_KEY, led)
    waf.meta_calls.clear()
    _run(store, waf)
    assert waf.meta_calls and all(g.get("rules") for g in store.get_source_state(mitigate_station.MITIGATE_KEY)["groups"].values())


def test_a_promotion_without_the_group_rule_list_keeps_what_is_there_and_says_so():
    store = MemoryStore()
    _seed(store)
    waf = FakeWaf({"demo-shop": {"name": ACL, "id": "a1"}})
    waf.fail = {"meta"}
    _run(store, waf)
    staged = copy.deepcopy(waf.acls[ACL]["Rules"])
    store.put_source_state(mitigate_station.PROMOTE_KEY,
                           {"waf": {ACL: {mitigate.rule_name("AWSManagedRulesPHPRuleSet"): {"by": "human", "at": "x"}}}})
    out = _run(store, waf)
    led = store.get_source_state(mitigate_station.MITIGATE_KEY)
    assert waf.acls[ACL]["Rules"] == staged and waf.writes == [ACL]   # neither a blind Block nor a demotion
    assert out["errors"] >= 1 and any("AWSManagedRulesPHPRuleSet" in e["what"] and "promot" in e["what"] for e in led["errors"])


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


def test_the_station_blocks_what_was_approved_and_reports_what_the_plan_gained_since():
    """R4.1 end to end: a promotion recorded for ONE of the plan's rules — the web ACL rule lets only that one block, the
    rest of the plan's rules stay at Count, and the ledger (⇒ #/ops) names them as waiting for a decision."""
    store = MemoryStore()
    eid = _seed(store)
    waf = FakeWaf({"demo-shop": {"name": ACL, "id": "a1"}})
    _run(store, waf)
    (plan,) = store.get_source_state(mitigate_station.MITIGATE_KEY)["events"][eid]["plans"]
    assert len(plan["rules"]) >= 2, "the fixture plan names several rules"
    first, rest = plan["rules"][0], set(plan["rules"][1:])
    name = mitigate.rule_name(plan["group"])
    store.put_source_state(mitigate_station.PROMOTE_KEY, {"waf": {ACL: {name: {"by": "human", "at": "x", "rules": [first]}}}})
    _run(store, waf)
    rule = next(r for r in waf.acls[ACL]["Rules"] if r["Name"] == name)
    counted = {o["Name"] for o in rule["Statement"]["ManagedRuleGroupStatement"].get("RuleActionOverrides") or []}
    assert rule["OverrideAction"] == {"None": {}} and first not in counted and rest <= counted
    led = store.get_source_state(mitigate_station.MITIGATE_KEY)
    (g,) = led["waf_grown"]
    assert g["group"] == plan["group"] and set(g["beyond"].split(", ")) == rest and g["approved"] == [first]
    from radar import ops
    assert any("计划扩大了" in i["title"] for i in ops.attention({"mitigate": led}) if i["code"] == "mitigate")


def test_a_promoted_dns_rule_blocks_the_domains_approved_and_a_domain_found_later_waits():
    """Audit 04 §6.3 (reproduced): the promotion was per rule and the list is rewritten every run from every defanged
    domain in the window — after a promotion, one report writing `partner-api[.]example` made it NXDOMAIN in the VPC."""
    store = MemoryStore()
    eid = _seed(store)
    _with_ioc(store, eid)
    waf = FakeWaf({})
    waf.dns = {"domains": [], "rules": []}
    _run(store, waf)
    listed = list(waf.dns["domains"])
    assert "php2shell-loader.top" in listed and "partner-api.example" not in listed
    store.put_source_state(mitigate_station.PROMOTE_KEY,
                           {"dns": {mitigate.DNS_RADAR_RULE: {"by": "h", "at": "t", "domains": listed}}})
    it = store.get_items(store.get_event(eid).item_ids)[0]
    it.text += " A later report also names partner-api[.]example as contacted."
    store.put_item(it)
    _run(store, waf)
    led = store.get_source_state(mitigate_station.MITIGATE_KEY)
    assert waf.dns["domains"] == listed, "a domain nobody approved entered a blocking list"
    assert led["dns"]["waiting"] == ["partner-api.example"]
    from radar import ops
    assert any("partner-api.example" in i["detail"] for i in ops.attention({"mitigate": led}) if i["code"] == "mitigate")
    # a promotion from before pinning: the list is frozen at what it holds
    store.put_source_state(mitigate_station.PROMOTE_KEY, {"dns": {mitigate.DNS_RADAR_RULE: {"by": "h", "at": "t"}}})
    _run(store, waf)
    assert waf.dns["domains"] == listed
    # not promoted (ALERT only): every domain is listed, as before
    store.put_source_state(mitigate_station.PROMOTE_KEY, {})
    _run(store, waf)
    assert set(waf.dns["domains"]) == {*listed, "partner-api.example"}
