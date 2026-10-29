"""Mitigate station (M3): located, affected targets → mitigation plans → read-only check → staged apply on radar-owned
resources. Runs after the respond station, reads what it found (store responses), and writes one ledger
(MITIGATE_KEY, single writer: this station). Human promotions are read from PROMOTE_KEY (single writer:
scripts/promote.py) — the station renders a promoted plan as blocking and never demotes it.

`aws` is radar.mitigate_aws in Lambda and a fake in tests; every downstream failure is recorded in the ledger
(`errors`), so "not checked" never looks like "checked, nothing to do" (degradation-and-guards §1)."""

from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta
from typing import Any

from radar import inspector, mitigate, patterns, respond, securityhub, timeutil
from radar.limits import Limits
from radar.store import Store
from radar.targets import NAMES

MITIGATE_KEY = "__mitigate__"
PROMOTE_KEY = "__mitigate_promotions__"


def _cwes(store: Store, item_ids: list[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for it in store.get_items(item_ids):
        for c in it.extra.get("cves") or []:
            out.setdefault(c, [])
            out[c] += [w for w in it.extra.get("cwes") or [] if w not in out[c]]
    return out


def _catalog(led: dict[str, Any], aws: Any, today: str, errors: list[dict[str, str]]) -> dict[str, list[mitigate.CveRules]]:
    cat = led.setdefault("catalog", {})
    if cat.get("fetched_on") != today:
        rows = aws.changelog_rows()
        if isinstance(rows, dict):   # keep yesterday's rows, visibly
            errors.append({"channel": "waf", "what": "changelog", "error": rows["error"]})
        else:
            cat.update({"fetched_on": today, "rows": [dataclasses.asdict(r) for r in rows]})
    rows = [mitigate.ChangelogRow(**{**r, "rules": tuple(r["rules"]), "cves": tuple(r["cves"])}) for r in cat.get("rows") or []]
    return mitigate.waf_catalog(rows)


def _group(led: dict[str, Any], aws: Any, group: str, today: str, errors: list[dict[str, str]]) -> dict[str, Any]:
    groups = led.setdefault("groups", {})
    g = groups.get(group) or {}
    if g.get("on") != today:
        meta = aws.group_meta(group)
        if "error" in meta:
            errors.append({"channel": "waf", "what": f"group {group}", "error": meta["error"]})
        else:
            g = groups[group] = {**meta, "on": today}
    return g


def _inspector(led: dict[str, Any], aws: Any, today: str, errors: list[dict[str, str]]) -> dict[str, list[dict[str, Any]]]:
    """Once a day per target: lockfiles → SBOM → ScanSbom. Results kept per target (the dependency baseline the page
    shows); a failed scan keeps the previous result and is recorded. Capped by Limits.INSPECTOR_SCANS_PER_DAY."""
    insp = led.setdefault("inspector", {})
    targets = None
    budget = Limits.INSPECTOR_SCANS_PER_DAY - sum(1 for r in insp.values() if r.get("called_on") == today)
    for tid in NAMES:
        row = insp.setdefault(tid, {})
        if row.get("scanned_on") == today or row.get("tried_on") == today:
            continue
        if targets is None:
            targets = {t.target_id: t for t in aws.load_targets()}
        t = targets.get(tid)
        comps = inspector.components(t.files) if t else []
        row.update({"components": len(comps), "tried_on": today})
        if not comps:   # nothing Inspector can judge (runtime-only target) — recorded as such, not as "clean"
            row.update({"scanned_on": today, "state": "no_packages", "findings": []})
            continue
        if budget <= 0:
            row["state"] = "deferred"
            continue
        budget -= 1
        row["called_on"] = today
        res = aws.scan_sbom(inspector.sbom(comps, tid))
        if "error" in res:
            errors.append({"channel": "inspector", "what": f"ScanSbom {tid}", "error": res["error"]})
            row["state"] = "error"
            continue
        found = inspector.findings(res)
        files = {c["purl"]: c["file"] for c in comps}
        row.update({"scanned_on": today, "state": "scanned",
                    "findings": [{**f, "file": files.get(f["purl"])} for f in found][:200]})
    return {tid: r.get("findings") or [] for tid, r in insp.items()}


def _dns(led: dict[str, Any], aws: Any, by_event: dict[str, list[str]], promoted: set[str],
         errors: list[dict[str, str]]) -> dict[str, Any] | None:
    """Make the radar's DNS Firewall list + rules match the evidence; returns what is in place (None = not configured)."""
    cfg = aws.dns_config()
    if not cfg:
        return None
    st = aws.dns_state(cfg)
    if "error" in st:
        errors.append({"channel": "dns", "what": "DNS Firewall state", "error": st["error"]})
        return {"state": "unchecked"}
    want_domains = mitigate.dns_domains(by_event)
    missing = [n for n in mitigate.DNS_MANAGED_LISTS if n not in st["managed"]]
    if missing:
        errors.append({"channel": "dns", "what": "managed domain lists", "error": f"not in this Region: {missing}"})
    rules = mitigate.dns_rules(cfg["domain_list_id"], st["managed"], promoted)
    create, update = mitigate.dns_diff(st["rules"], rules)
    domains = want_domains if want_domains != st["domains"] else None
    if domains is not None or create or update:
        put = aws.dns_put(cfg, domains, create, update)
        if "error" in put:
            errors.append({"channel": "dns", "what": "DNS Firewall update", "error": put["error"]})
            return {"state": "unchecked"}
    return {"state": "in_place", "domains": want_domains, "rules": [{"name": r["Name"], "action": r["Action"]} for r in rules]}


def _security_hub(led: dict[str, Any], aws: Any, affected: dict[str, Any], out_events: dict[str, Any], nowi: str,
                  errors: list[dict[str, str]]) -> None:
    hub = aws.security_hub()
    if not hub:
        led["security_hub"] = {"state": "not_configured"}
        return
    current = {}
    for eid, (ev, targets) in affected.items():
        view = {"event_id": eid, "title": ev.title, "severity": ev.severity, "cves": ev.cves, "first_seen": ev.first_seen}
        for t in targets:
            f = securityhub.asff(view, t, out_events.get(eid), hub["account"], hub["region"], nowi, hub.get("site_url", ""))
            current[f["Id"]] = f
    prev = (led.get("security_hub") or {}).get("exported") or {}
    send, exported = securityhub.plan(current, prev, hub["account"], hub["region"], nowi)
    res = aws.security_hub_import(send) if send else {"failed": []}
    if "error" in res:
        errors.append({"channel": "security_hub", "what": "BatchImportFindings", "error": res["error"]})
        exported = prev   # nothing confirmed ⇒ retry the same set next cycle
    else:
        for fid in res.get("failed") or []:
            exported.pop(fid, None)
            errors.append({"channel": "security_hub", "what": f"import {fid}", "error": "rejected"})
    led["security_hub"] = {"state": "in_place", "exported": exported, "active": sum(1 for r in exported.values() if r["state"] == "ACTIVE"),
                           "last_sent": len(send) if "error" not in res else 0}


def run(store: Store, aws: Any, now: datetime) -> dict[str, Any]:
    nowi, today = timeutil.iso(now), timeutil.iso(now)[:10]
    led = store.get_source_state(MITIGATE_KEY)
    promoted = (store.get_source_state(PROMOTE_KEY).get("waf") or {})
    errors: list[dict[str, str]] = []
    catalog = _catalog(led, aws, today, errors)
    by_target = _inspector(led, aws, today, errors)
    acl_refs = aws.web_acls()
    since = timeutil.iso(now - timedelta(days=Limits.MITIGATE_WINDOW_DAYS))
    plans_by_event: dict[str, list[mitigate.WafPlan]] = {}
    affected: dict[str, tuple[Any, list[dict[str, Any]]]] = {}   # event_id → (event, affected targets) for Security Hub
    for ev in store.events_updated_since(since):
        resp = respond.to_response(store.get_response(ev.event_id), NAMES, nowi)
        if not resp or not resp.get("targets"):
            continue
        hit = [t for t in resp["targets"] if t.get("verdict") == "affected"]
        if hit:
            affected[ev.event_id] = (ev, hit)
        view = {"event_id": ev.event_id, "cves": ev.cves, "product": resp.get("product")}
        plans = mitigate.waf_plans(view, resp["targets"], catalog, _cwes(store, ev.item_ids))
        if plans:
            plans_by_event[ev.event_id] = plans
    dns_by_event: dict[str, list[str]] = {}
    for ev in store.events_updated_since(since):
        ds = patterns.indicators([ev.title, *(f"{i.title} {i.text}" for i in store.get_items(ev.item_ids))]).domains
        if ds:
            dns_by_event[ev.event_id] = ds
    dns = _dns(led, aws, dns_by_event, set(store.get_source_state(PROMOTE_KEY).get("dns") or {}), errors)
    insp_by_event: dict[str, list[dict[str, Any]]] = {}
    for ev in store.events_updated_since(since):
        hits = [{"target_id": tid, **f} for tid, fs in sorted(by_target.items()) for f in inspector.for_event(ev.cves, fs)]
        if hits:
            insp_by_event[ev.event_id] = hits
    used = {p.group for ps in plans_by_event.values() for p in ps}
    meta = {g: _group(led, aws, g, today, errors) for g in sorted(used)}
    labels = {g: m.get("labels") or [] for g, m in meta.items()}

    # one write per web ACL: every appliable plan of every target behind it, staged unless a human promoted it
    acl_state: dict[str, dict[str, Any]] = {}
    for ref in {r["name"]: r for r in acl_refs.values()}.values():
        got = aws.get_acl(ref)
        if "error" in got:
            errors.append({"channel": "waf", "what": f"web ACL {ref['name']}", "error": got["error"]})
            continue
        acl = got["acl"]
        behind = {t for t, r in acl_refs.items() if r["name"] == ref["name"]}
        wanted = {p.group: p for ps in plans_by_event.values() for p in ps if p.appliable and p.target_id in behind}
        foreign = {(r.get("Statement") or {}).get("ManagedRuleGroupStatement", {}).get("Name")
                   for r in acl.get("Rules") or [] if not r["Name"].startswith(mitigate.RADAR_RULE_PREFIX)}
        pairs = [(p, mitigate.rule_name(g) in promoted.get(ref["name"], {})) for g, p in sorted(wanted.items())
                 if g not in foreign]   # someone else already runs this group here ⇒ report it, do not duplicate it
        new_rules = mitigate.merge_acl_rules(acl.get("Rules") or [], pairs)
        if new_rules is not None:
            put = aws.put_rules(ref, acl, got["lock"], new_rules)
            if "error" in put:
                errors.append({"channel": "waf", "what": f"update {ref['name']}", "error": put["error"]})
            else:
                acl = {**acl, "Rules": new_rules}
                led.setdefault("applied", []).append({"at": nowi, "web_acl": ref["name"],
                                                      "rules": [p.group for p, _ in pairs]})
                led["applied"] = led["applied"][-50:]
        acl_state[ref["name"]] = acl

    out_events: dict[str, Any] = {}
    for eid in sorted(set(plans_by_event) | set(insp_by_event) | set(dns_by_event)):
        plans = plans_by_event.get(eid, [])
        rows = []
        for p in plans:
            p = dataclasses.replace(p, labels=mitigate.labels_for(p.group, p.rules, labels))
            ref = acl_refs.get(p.target_id)
            acl = acl_state.get(ref["name"]) if ref else None
            if ref is None:
                chk = {"state": "no_web_acl", "detail": "这个目标前面没有登记 web ACL —— 只给出规则，由你决定挂在哪里"}
            elif acl is None:
                chk = {"state": "unchecked", "detail": "web ACL 读取失败，本轮没查（见运维页）"}
            else:
                chk = mitigate.waf_check(p, acl, meta.get(p.group, {}).get("default_version"))
            block = bool(ref) and mitigate.rule_name(p.group) in promoted.get(ref["name"], {})
            rows.append({"channel": "waf", "key": p.key, "target_id": p.target_id, "tier": p.tier, "group": p.group,
                         "group_label": mitigate.WAF_GROUPS[p.group].label, "rules": list(p.rules),
                         "min_version": p.min_version, "reason": p.reason, "cves": list(p.cves), "labels": list(p.labels),
                         "appliable": p.appliable, "web_acl": ref["name"] if ref else None, "promoted": block,
                         **chk, "rule_json": mitigate.waf_rule(p, 0, block=block)})
        out_events[eid] = {"note": mitigate.MITIGATION_NOTE, "updated_at": nowi, "plans": rows,
                           "inspector": insp_by_event.get(eid, []),
                           "dns": ({"domains": dns_by_event[eid],
                                    "state": (dns or {}).get("state", "no_dns_firewall"),
                                    "action": next((r["action"] for r in (dns or {}).get("rules") or []
                                                    if r["name"] == mitigate.DNS_RADAR_RULE), None)}
                                   if eid in dns_by_event else None)}
    led["dns"] = dns
    _security_hub(led, aws, affected, out_events, nowi, errors)
    led.update({"events": out_events, "errors": errors, "run_at": nowi,
                "web_acls": [{"target_id": t, **r} for t, r in sorted(acl_refs.items())]})
    store.put_source_state(MITIGATE_KEY, led)
    return {"events": sorted(out_events), "errors": len(errors)}
