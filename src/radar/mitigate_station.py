"""Mitigate station (M3): located, affected targets → mitigation plans → read-only check → staged apply on radar-owned
resources. Runs after the respond station, reads what it found (store responses), and writes one ledger
(MITIGATE_KEY, single writer: this station). Human promotions are read from PROMOTE_KEY (single writer:
scripts/promote.py) — the station renders a promoted plan as blocking and never demotes it.

`aws` is radar.mitigate_aws in Lambda and a fake in tests; every downstream failure is recorded in the ledger
(`errors`), so "not checked" never looks like "checked, nothing to do" (degradation-and-guards §1)."""

from __future__ import annotations

import dataclasses
import json
import logging
from datetime import datetime, timedelta
from typing import Any

from radar import decisions, inspector, mitigate, patterns, respond, securityhub, timeutil
from radar.limits import Limits
from radar.store import Store
from radar.targets import NAMES

MITIGATE_KEY = "__mitigate__"
PROMOTE_KEY = "__mitigate_promotions__"
log = logging.getLogger(__name__)


def _cwes(store: Store, item_ids: list[str]) -> dict[str, list[str]]:
    return _cwes_of(store.get_items(item_ids))


def _cwes_of(items: list[Any]) -> dict[str, list[str]]:
    """CVE → CWE ids (KEV items carry both) — from items already read (the rule pack reads them once per event)."""
    out: dict[str, list[str]] = {}
    for it in items:
        for c in it.extra.get("cves") or []:
            out.setdefault(c, [])
            out[c] += [w for w in it.extra.get("cwes") or [] if w not in out[c]]
    return out


def _catalog(led: dict[str, Any], aws: Any, today: str, errors: list[dict[str, str]],
             now: datetime | None = None) -> dict[str, list[mitigate.CveRules]]:
    """AWS's managed-rule changelog, re-read every Limits.WAF_CHANGELOG_REFRESH_H hours (R4.5: it was once a day, so a
    rule AWS added for a CVE in the morning was not planned until the next day)."""
    cat = led.setdefault("catalog", {})
    at = timeutil.parse(cat.get("fetched_at"))
    stale = (cat.get("fetched_on") != today if now is None
             else at is None or now - at >= timedelta(hours=Limits.WAF_CHANGELOG_REFRESH_H))
    if stale:
        rows = aws.changelog_rows()
        if isinstance(rows, dict):   # keep yesterday's rows, visibly
            errors.append({"channel": "waf", "what": "changelog", "error": rows["error"]})
        else:
            cat.update({"fetched_on": today, "fetched_at": timeutil.iso(now) if now else None,
                        "rows": [dataclasses.asdict(r) for r in rows]})
    rows = [mitigate.ChangelogRow(**{**r, "rules": tuple(r["rules"]), "cves": tuple(r["cves"])}) for r in cat.get("rows") or []]
    return mitigate.waf_catalog(rows)


def _group(led: dict[str, Any], aws: Any, group: str, today: str, errors: list[dict[str, str]]) -> dict[str, Any]:
    groups = led.setdefault("groups", {})
    g = groups.get(group) or {}
    if g.get("on") != today or "rules" not in g:   # ledgers before 2026-11-11 cached no rule list (needed to promote)
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


def _dns(led: dict[str, Any], aws: Any, by_event: dict[str, list[str]], promotions: dict[str, Any],
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
    # A promoted radar list blocks the domains that were approved (scripts/promote.py records them); a domain found
    # later is not added to a blocking list — it waits, named on #/ops, for a decision. Before pinning the promotion was
    # per rule: any domain any report defanged afterwards became NXDOMAIN in the VPC (audit 04 §6.3). A promotion from
    # before pinning has no "domains": the list is frozen at what it holds now.
    waiting: list[str] = []
    if (pin := promotions.get(mitigate.DNS_RADAR_RULE)) is not None:
        approved = (set(pin["domains"]) if "domains" in pin else set(st["domains"])) | {mitigate.DNS_CANARY}   # the probe's own
        waiting = [d for d in want_domains if d not in approved]
        want_domains = [d for d in want_domains if d in approved]
    missing = [n for n in mitigate.DNS_MANAGED_LISTS if n not in st["managed"]]
    if missing:
        errors.append({"channel": "dns", "what": "managed domain lists", "error": f"not in this Region: {missing}"})
    rules = mitigate.dns_rules(cfg["domain_list_id"], st["managed"], set(promotions))
    create, update = mitigate.dns_diff(st["rules"], rules)
    domains = want_domains if want_domains != st["domains"] else None
    if domains is not None or create or update:
        put = aws.dns_put(cfg, domains, create, update)
        if "error" in put:
            errors.append({"channel": "dns", "what": "DNS Firewall update", "error": put["error"]})
            return {"state": "unchecked"}
    return {"state": "in_place", "domains": want_domains, "waiting": waiting,
            "rules": [{"name": r["Name"], "action": r["Action"]} for r in rules]}


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
    catalog = _catalog(led, aws, today, errors, now)
    by_target = _inspector(led, aws, today, errors)
    acl_refs = aws.web_acls()
    since = decisions.window_start("waf_stage", "M_OUT_OF_WINDOW", now)   # the decision table's window (page reads it too)
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
    dns = _dns(led, aws, dns_by_event, store.get_source_state(PROMOTE_KEY).get("dns") or {}, errors)
    insp_by_event: dict[str, list[dict[str, Any]]] = {}
    for ev in store.events_updated_since(since):
        hits = [{"target_id": tid, **f} for tid, fs in sorted(by_target.items()) for f in inspector.for_event(ev.cves, fs)]
        if hits:
            insp_by_event[ev.event_id] = hits
    used = {p.group for ps in plans_by_event.values() for p in ps}
    meta = {g: _group(led, aws, g, today, errors) for g in sorted(used)}
    labels = {g: m.get("labels") or [] for g, m in meta.items()}
    group_rules = {g: m.get("rules") or [] for g, m in meta.items()}

    # one write per web ACL: every appliable plan of every target behind it, staged unless a human promoted it
    acl_state: dict[str, dict[str, Any]] = {}
    grown: list[dict[str, Any]] = []    # promoted rules whose plan now asks for more than was approved
    merged: dict[tuple[str, str], mitigate.WafPlan] = {}   # (web ACL, group) → the one plan its radar rule renders
    for ref in {r["name"]: r for r in acl_refs.values()}.values():
        got = aws.get_acl(ref)
        if "error" in got:
            errors.append({"channel": "waf", "what": f"web ACL {ref['name']}", "error": got["error"]})
            continue
        acl = got["acl"]
        behind = {t for t, r in acl_refs.items() if r["name"] == ref["name"]}
        by_group: dict[str, list[mitigate.WafPlan]] = {}
        for ps in plans_by_event.values():
            for p in ps:
                if p.appliable and p.target_id in behind:
                    by_group.setdefault(p.group, []).append(p)
        wanted = {g: mitigate.merge_plans(ps) for g, ps in by_group.items()}   # union, never last-one-wins (Bug-2)
        merged.update({(ref["name"], g): p for g, p in wanted.items()})
        foreign = {(r.get("Statement") or {}).get("ManagedRuleGroupStatement", {}).get("Name")
                   for r in acl.get("Rules") or [] if not r["Name"].startswith(mitigate.RADAR_RULE_PREFIX)}
        # a promoted rule blocks what was approved, not what the merged plan has become since (mitigate.pinned)
        approvals = promoted.get(ref["name"], {})
        for g in sorted(wanted):
            if (promo := approvals.get(mitigate.rule_name(g))) is not None:
                named = tuple(dict.fromkeys(r for p in by_group[g] for r in p.rules))
                wanted[g], beyond = mitigate.pinned(wanted[g], promo, named)
                merged[(ref["name"], g)] = wanted[g]
                if beyond:
                    grown.append({"web_acl": ref["name"], "group": g, "beyond": beyond,
                                  "approved": list(wanted[g].rules), "by": promo.get("by"), "at": promo.get("at")})
        pairs = [(p, mitigate.rule_name(g) in approvals) for g, p in sorted(wanted.items())
                 if g not in foreign]   # someone else already runs this group here ⇒ report it, do not duplicate it
        # promoted, but the group's rule list is unknown ⇒ cannot keep the unnamed rules at Count: leave the rule as it is
        # (no blind Block, no demotion) and say so
        blind = {p.group for p, b in pairs if b and p.rules and not group_rules.get(p.group)}
        for g in sorted(blind):
            errors.append({"channel": "waf", "what": f"promote {g} on {ref['name']}",
                           "error": "rule list of the group unavailable (DescribeManagedRuleGroup) — left as is"})
        pairs = [(p, b) for p, b in pairs if p.group not in blind]
        new_rules = mitigate.merge_acl_rules(acl.get("Rules") or [], pairs, group_rules,
                                             {g: m.get("default_version") for g, m in meta.items()})
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
            rows.append(_row(p, ref, block, chk, acl, merged, group_rules))
        out_events[eid] = {"note": mitigate.MITIGATION_NOTE, "updated_at": nowi, "plans": rows,
                           "inspector": insp_by_event.get(eid, []),
                           "dns": ({"domains": dns_by_event[eid],
                                    "state": (dns or {}).get("state", "no_dns_firewall"),
                                    "action": next((r["action"] for r in (dns or {}).get("rules") or []
                                                    if r["name"] == mitigate.DNS_RADAR_RULE), None)}
                                   if eid in dns_by_event else None)}
    led["dns"] = dns
    _security_hub(led, aws, affected, out_events, nowi, errors)
    try:   # P2: WAF rule pack per event (own rows) — a failure there must not cost this run its M3 ledger
        packs_changed = _rule_packs(store, aws, now, catalog, labels, errors)
    except Exception as e:   # noqa: BLE001 — recorded in errors (the ledger below), never swallowed
        packs_changed = []
        errors.append({"channel": "waf", "what": "rule packs", "error": f"{type(e).__name__}: {str(e)[:280]}"})
        log.warning(json.dumps({"station": "mitigate", "degraded": "rule_packs_failed", "error": str(e)[:200]}))
    led.update({"events": out_events, "errors": errors, "run_at": nowi, "waf_grown": grown,
                "web_acls": [{"target_id": t, **r} for t, r in sorted(acl_refs.items())]})
    store.put_source_state(MITIGATE_KEY, led)
    return {"events": sorted(set(out_events) | set(packs_changed)), "errors": len(errors)}


def _capacity(pack: dict[str, Any], aws: Any, budget: list[int], today: str, prev: dict[str, Any]) -> dict[str, Any]:
    """CheckCapacity (read-only) for one pack → its `capacity` field. Re-checked only when the pack changed (hash) or
    the last call failed; a pack with no rule needs none. States: pass | over_budget (WCU above Limits.RULEPACK_MAX_WCU)
    | fail (AWS rejects a statement: the reason is shown) | unchecked (not called / call failed — never shown as 0).
    IP-set rules reference an ARN that only exists in the reader's account ⇒ left out of the call, 1 WCU each (AWS:
    an IPSetReferenceStatement costs 1 WCU)."""
    from radar import packrender
    old = prev.get("capacity") or {}
    if prev.get("hash") == pack["hash"] and old.get("state") in ("pass", "over_budget", "fail"):
        return old
    rules = packrender.rules(pack)
    if not rules:
        return {"state": "pass", "wcu": 0, "detail": "规则包只有托管规则组，无自定义规则组", "checked_on": today}
    ipset = [r for r in rules if "IPSetReferenceStatement" in r["Statement"]]
    send = [r for r in rules if r not in ipset]
    if budget[0] <= 0:
        return {"state": "unchecked", "wcu": None, "detail": "本轮 CheckCapacity 预算已用完，下一轮再查"}
    budget[0] -= 1
    res = aws.check_capacity(send) if send else {"capacity": 0}
    if "capacity" in res:
        wcu = res["capacity"] + len(ipset)
        if wcu > Limits.RULEPACK_MAX_WCU:
            return {"state": "over_budget", "wcu": wcu, "max_wcu": Limits.RULEPACK_MAX_WCU, "checked_on": today,
                    "detail": f"{wcu} WCU 超过规则包上限 {Limits.RULEPACK_MAX_WCU}（默认 web ACL 共 1,500）"}
        return {"state": "pass", "wcu": wcu, "checked_on": today, "detail": f"CheckCapacity {wcu} WCU"}
    if "invalid" in res:
        return {"state": "fail", "wcu": None, "checked_on": today, "detail": f"AWS 拒绝了规则：{res['invalid']}"}
    return {"state": "unchecked", "wcu": None, "detail": f"CheckCapacity 调用失败（下一轮重试）：{res.get('error')}"}


def _rule_packs(store: Store, aws: Any, now: datetime, catalog: dict[str, list[mitigate.CveRules]],
                labels: dict[str, list[str]], errors: list[dict[str, str]]) -> list[str]:
    """P2: one customer-owned RulePack per windowed event (radar.rulepack), written to its own row only when it changed;
    returns the event ids whose pack changed (their pages are rebuilt). nuclei templates come from radar.pocs (budgeted,
    allowlisted); a PoC outage is an error here and `unavailable` on the page, never 「无模板」."""
    from radar import pocs, rulepack
    since = timeutil.iso(now - timedelta(days=Limits.MITIGATE_WINDOW_DAYS))
    evs = store.events_updated_since(since)
    stats: dict[str, Any] = {}
    poc = pocs.refresh(store, sorted({c for ev in evs for c in ev.cves}), now, aws.poc_get, stats=stats)
    if stats.get("poc_degraded"):
        errors.append({"channel": "waf", "what": "nuclei-templates", "error": str(stats["poc_degraded"])})
    old = store.get_source_states([rulepack.key(ev.event_id) for ev in evs]) if evs else {}
    budget, today, changed = [Limits.RULEPACK_CAPACITY_CHECKS_PER_RUN], timeutil.iso(now)[:10], []
    nowi = timeutil.iso(now)
    for ev in evs:
        resp = respond.to_response(store.get_response(ev.event_id), NAMES, nowi) or {}
        items = store.get_items(ev.item_ids)
        event = {"event_id": ev.event_id, "cves": ev.cves, "product": resp.get("product")}
        ev_poc = {c: poc[c] for c in ev.cves if c in poc}
        built = True
        try:
            pack = rulepack.build(event, items, ev_poc, catalog, _cwes_of(items), labels)
        except Exception as e:   # noqa: BLE001 — this event's pack says why (rejected row) + errors; the run goes on
            pack, built = rulepack.failed(event, ev_poc, e), False
            errors.append({"channel": "waf", "what": f"rule pack {ev.event_id}", "error": f"{type(e).__name__}: {str(e)[:280]}"})
        prev = old.get(rulepack.key(ev.event_id)) or {}
        if pack.empty and not prev:
            continue
        d = pack.to_dict()
        # a failed build has no rule: _capacity would read "pass, 0 WCU, managed only" — a success it is not
        d["capacity"] = (_capacity(d, aws, budget, today, prev) if built else
                         {"state": "unchecked", "wcu": None, "detail": "规则包生成失败（原因见未生成的规则），未调用 CheckCapacity"})
        if d["capacity"]["state"] == "fail":
            errors.append({"channel": "waf", "what": f"CheckCapacity {d['name']}", "error": d["capacity"]["detail"][:300]})
        d["updated_at"] = prev.get("updated_at") if {**prev, "updated_at": None} == {**d, "updated_at": None} else nowi
        if d != prev:
            store.put_source_state(rulepack.key(ev.event_id), d)
            changed.append(ev.event_id)
    return changed


def _row(p: mitigate.WafPlan, ref: dict[str, str] | None, block: bool, chk: dict[str, Any], acl: dict[str, Any] | None,
         merged: dict[tuple[str, str], mitigate.WafPlan], group_rules: dict[str, list[str]]) -> dict[str, Any]:
    """One plan as the page shows it. rule_json: on a radar web ACL it is the rule the ACL carries for the group (the
    merged plan, at its real priority); for a target without one it is this plan alone at a paste placeholder priority
    (mitigate.paste_priority — the user's own ACL decides). A promoted render needing an unknown rule list falls back to
    the staged render — the station recorded the error and did not write it. Advisory (cwe) plans always show their own.
    priority_placeholder is True whenever the Priority is not one a radar rule really has on the ACL — web_acl alone does
    not say that (cwe plans, a group someone else runs, a rule not written yet all carry web_acl)."""
    on_acl = bool(ref) and p.appliable
    shown = merged.get((ref["name"], p.group), p) if ref and on_acl else p
    have = next((r for r in (acl or {}).get("Rules") or [] if r.get("Name") == mitigate.rule_name(p.group)), None)
    real_prio = bool(have) and on_acl   # the one test for "Priority is real"; the page's placeholder note reads it (W4)
    prio = have["Priority"] if real_prio else mitigate.paste_priority(p.group)
    render_block = block and (not shown.rules or bool(group_rules.get(p.group)))
    rule_json = mitigate.waf_rule(shown, prio, block=render_block, group_rules=group_rules.get(p.group) or ())
    return {"channel": "waf", "key": p.key, "target_id": p.target_id, "tier": p.tier, "group": p.group,
            "group_label": mitigate.WAF_GROUPS[p.group].label, "rules": list(p.rules),
            "min_version": p.min_version, "reason": p.reason, "cves": list(p.cves), "labels": list(p.labels),
            "appliable": p.appliable, "web_acl": ref["name"] if ref else None, "promoted": block,
            "priority_placeholder": not real_prio, **chk, "rule_json": rule_json}

