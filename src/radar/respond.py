"""Respond station logic — radar event → AWS Security Agent + AWS Continuum, and the results back.

Pure (no AWS, no clock): `decide` turns (event, evidence, state, targets, budget) into a list of operations,
`apply` folds an operation's observed result into the state, `to_response` renders the public block
(schemas/site-data.schema.json#/$defs/Response). The adapter (radar.continuum_aws) only executes operations.
Harness split: *when* to scan, *what* rule to push and *where* the affected pin is are code; *whether the
code is exploitable and how to fix it* is judged inside the AWS agents."""

from __future__ import annotations

import copy
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from radar import patterns, products
from radar.limits import Limits

SA, CN = "security_agent", "continuum"
TERMINAL_JOB = {"COMPLETED", "FAILED", "STOPPED", "CANCELLED", "TIMED_OUT"}
TERMINAL_SCAN = {"SUCCEEDED", "FAILED"}
TERMINAL_FINDING = {"CONFIRMED", "DISCARDED"}
REQ_PREFIX = "radar-"
REVIEW_PARSER = 3  # bump when the reading of Security Agent findings changes ⇒ finished reviews are re-read once
# Security Agent prefixes the pack name: "[Requirement: security-radar/radar-cve-…] …" (live); the PoC pack had none
_REQ_HIT = re.compile(r"^\[Requirement:\s*(?:[^\]/]+/)?" + re.escape(REQ_PREFIX))


def requirement_hit(finding_name: str) -> bool:
    """A Security Agent finding raised against a radar-generated requirement."""
    return bool(_REQ_HIT.match(finding_name or ""))


@dataclass(frozen=True)
class Target:
    target_id: str
    name: str
    description: str
    files: dict[str, str]           # path (prefixed with name/) → text, read from the uploaded zip
    uploaded_at: str | None = None

    def pins(self) -> list[products.Pin]:
        return products.inventory(self.files)


# Repository channels: Continuum environments on a code host, which deliver patches natively (GitHub PRs, GitLab
# MRs). Same flow for each; state key = channel name, op suffix kept short (existing states / ledgers use "_gh").
REPO_CHANNELS = {"github": {"op": "gh", "label": "GitHub", "change": "PR", "web": "https://github.com", "tree": "tree"},
                 "gitlab": {"op": "gl", "label": "GitLab", "change": "MR", "web": "https://gitlab.com", "tree": "-/tree"}}
# derived, never hand-listed: the scan op per channel, and every op that needs a reachable Continuum
SCAN_OPS = {"s3": "request_scan", **{ch: f"request_scan_{m['op']}" for ch, m in REPO_CHANNELS.items()}}
CONTINUUM_OPS = frozenset({"write_context", "submit_finding", "request_scan", "poll_continuum"} | {
    f"{k}_{m['op']}" for m in REPO_CHANNELS.values() for k in ("submit_finding", "request_scan", "poll_continuum")})


@dataclass
class Budget:
    """Spend guards for the paid steps. `reviews_left` = Security Agent code reviews still allowed today."""
    reviews_left: int
    scan_allowed: bool
    today: str = ""  # YYYY-MM-DD; drives the daily requirement re-assert
    github_targets: tuple[str, ...] = ()  # targets mirrored to the Continuum GitHub environment (PR delivery)
    github_scan_allowed: bool = False
    gitlab_targets: tuple[str, ...] = ()  # targets in the Continuum GitLab environment (MR delivery)
    gitlab_scan_allowed: bool = False
    s3_targets: tuple[str, ...] | None = None  # targets the S3 environment validates (targets.CHANNEL); None = all

    def channel(self, target_id: str) -> str | None:
        """The ONE Continuum environment that validates this target (s3 | github | gitlab), None = not sent.
        Single answer for every channel: a target in two environments is validated and scanned twice (cost x2)."""
        for ch in REPO_CHANNELS:  # a repository channel wins over the S3 fallback
            if target_id in getattr(self, f"{ch}_targets"):
                return ch
        return "s3" if self.s3_targets is None or target_id in self.s3_targets else None


@dataclass
class Op:
    kind: str                       # sync_requirement | write_context | submit_finding | request_scan |
                                    # start_review | poll_review | poll_continuum
    target_id: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------- eligibility + requirement (D-class)

def texts(items: list[dict[str, Any]]) -> list[str]:
    return [f"{it.get('title', '')} {it.get('excerpt', it.get('text', ''))}" for it in items]


def eligibility(ev: dict[str, Any], items: list[dict[str, Any]]) -> dict[str, Any]:
    """Which events the station acts on, and why not — every 'no' carries its reason (降级留痕).
    kind 'product' = a vulnerable runtime/library (registry radar.products);
    kind 'web3' = an incident whose IOCs or attack class can be located in contract code (radar.patterns)."""
    sev, expl = ev["severity"], ev["exploitation"]
    if ev["domain"] not in ("vuln", "web3"):
        return {"eligible": False, "reason": f"{ev['domain']} 事件不涉及代码依赖，不做代码侧响应"}
    if not (sev == "P0" or (sev == "P1" and expl in ("confirmed", "poc"))):
        return {"eligible": False, "reason": f"{sev}/{expl}：只对 P0，或已利用/有 PoC 的 P1 做代码侧响应"}
    tx = texts(items)
    if ev["domain"] == "web3":
        classes = [c.class_id for c in patterns.classes_for([ev["title"], *tx])]
        addrs = patterns.indicators([ev["title"], *tx]).addresses
        if not classes and not addrs:
            return {"eligible": False, "reason": "攻击手法不在登记表、证据中也没有地址类 IOC，无法在代码中定位"}
        names = [patterns.BY_CLASS[c].name for c in classes]
        return {"eligible": True, "kind": "web3", "product": None, "classes": classes, "iocs": addrs,
                "fixed": [], "affected": [],
                "reason": f"{sev} · Web3 事件 · " + " · ".join(
                    ([f"攻击手法：{'、'.join(names)}"] if names else []) +
                    ([f"证据中 {len(addrs)} 个地址 IOC（逐字抽取）"] if addrs else []))}
    prod = products.match(ev["title"], ev.get("entities") or [])
    if not prod:
        return {"eligible": False, "reason": "产品不在登记表（网络设备/闭源产品不在代码里），无法定位代码"}
    fixed, affected = products.versions(prod, tx)
    return {"eligible": True, "kind": "product", "product": prod.product_id, "fixed": fixed, "affected": affected,
            "reason": f"{sev} · 产品 {prod.name} 命中登记表 · " + (
                f"修复版本 {'/'.join(fixed)} 从证据逐字抽取" if fixed else
                f"证据未给修复版本；受影响版本 {'/'.join(affected) or '未知'}")}


def subject(elig: dict[str, Any]) -> str:
    if elig.get("kind") == "web3":
        return "、".join(patterns.BY_CLASS[c].name for c in elig["classes"]) or "事件 IOC"
    return products.BY_PRODUCT[elig["product"]].name


def requirement_name(ev: dict[str, Any]) -> str:
    """Stable and API-safe (live constraint: [a-z0-9][a-z0-9-]*, ≤64 — no underscores): CVEs if any, else event id."""
    base = "-".join(c.lower() for c in ev["cves"]) if ev["cves"] else ev["event_id"].lower()
    return re.sub(r"[^a-z0-9-]", "-", f"{REQ_PREFIX}{base}")[:64].rstrip("-")


def requirement(ev: dict[str, Any], elig: dict[str, Any]) -> dict[str, str]:
    desc = (f"Security Radar {ev['severity']}/{ev['level']} ({ev['exploitation']}): {ev['title']}. "
            f"Independent sources: {ev['independent_sources']}. Event {ev['event_id']}.")[:500]  # CFN/API max 500
    if elig.get("kind") == "web3":
        cls = [patterns.BY_CLASS[c] for c in elig["classes"]]
        ioc = (f" Also fail if the code references any address named in the incident evidence: {', '.join(elig['iocs'])}."
               if elig["iocs"] else "")
        return {"name": requirement_name(ev), "domain": "Smart contract security", "description": desc,
                "evaluation": (f"Incident: {ev['title']} (chains: {', '.join(ev.get('chains') or []) or 'n/a'}). "
                               + " ".join(c.evaluation for c in cls) + ioc)[:2000],
                "remediation": (" ".join(c.remediation for c in cls) or
                                "Remove trust in the listed addresses and review every integration with them.")[:2000]}
    prod = products.BY_PRODUCT[elig["product"]]
    fixed, affected = elig["fixed"], elig["affected"]
    cves = ", ".join(ev["cves"]) or "(no CVE id yet)"
    if fixed:
        rule = (f"Fail if any {prod.name} version is below the fixed release of its branch "
                f"({', '.join('>= ' + v for v in fixed)}) or its branch is not listed.")
        fix = f"Upgrade {prod.name} to a fixed release of the same branch ({', '.join(fixed)})."
    else:
        rule = (f"Fail if the code base runs {prod.name} " +
                (f"at an affected version ({', '.join(affected)}) " if affected else "") +
                "and processes untrusted input on the vulnerable path described in the event; "
                "fixed versions are not yet stated in the evidence — flag every such usage for review.")
        fix = f"Follow the vendor advisory for {cves}; until a fix is available, remove or isolate the vulnerable path."
    return {
        "name": requirement_name(ev), "domain": "Vulnerability management", "description": desc,
        "evaluation": (f"Find every {prod.name} runtime/dependency the code base builds or runs on (container base "
                       f"images, CI images, runtime config, lock files). {rule} Affected: {cves}.")[:2000],
        "remediation": f"{fix} Rebuild and redeploy."[:2000],
    }


def locations(target: Target, elig: dict[str, Any]) -> list[dict[str, Any]]:
    """Code lines tied to the event. match=exact ⇒ the line itself is the exposure (affected pin, IOC, public key);
    match=heuristic ⇒ a candidate shape that only the AWS agents can confirm."""
    if elig.get("kind") == "web3":
        return [{"file": h["file"], "line": h["line"], "found_version": h["what"], "fixed_version": None,
                 "kind": "smart contract", "match": h["match"]}
                for h in patterns.scan(target.files, elig["classes"], elig["iocs"])]
    out = []
    for pin in target.pins():
        if pin.product_id != elig["product"]:
            continue
        v, fixed_for = products.verdict(pin.version, elig["fixed"], elig["affected"])
        if v == "affected":
            out.append({"file": pin.file, "line": pin.line, "found_version": pin.version,
                        "fixed_version": fixed_for, "kind": pin.kind, "match": "exact"})
    return out


def relevant(target: Target, elig: dict[str, Any]) -> bool:
    if elig.get("kind") == "web3":
        return patterns.relevant(target.files)
    return any(p.product_id == elig["product"] for p in target.pins())


def context_doc(ev: dict[str, Any], analysis: dict[str, Any] | None, items: list[dict[str, Any]]) -> str:
    """Radar → Continuum knowledge document (markdown). Only grounded analyst sentences are included."""
    lines = [f"# Security Radar threat intel: {ev['title']}", "",
             (f"- Event: {ev['event_id']} · severity {ev['severity']} · verification {ev['level']} "
              f"· exploitation {ev['exploitation']}"),
             f"- CVEs: {', '.join(ev['cves']) or 'none yet'}",
             f"- Independent sources: {ev['independent_sources']} · first seen {ev['first_seen']}", ""]
    for key, title in (("bluf", "Bottom line"), ("what", "What happened"), ("impact", "Impact"),
                       ("exploitation", "Exploitation"), ("actions", "Recommended actions"), ("unknowns", "Unknowns")):
        sents = [s["text"] for s in (analysis or {}).get(key, []) if s.get("grounded")]
        if sents:
            lines += [f"## {title}", *[f"- {s}" for s in sents], ""]
    lines += ["## Evidence", *[f"- {it.get('source_name', it.get('source', ''))}: {it['title']} <{it.get('url', '')}>"
                               for it in items[:20]]]
    return "\n".join(lines) + "\n"


def ocsf(ev: dict[str, Any], items: list[dict[str, Any]], loc: dict[str, Any], region: str, now_ms: int) -> dict[str, Any]:
    """OCSF 1.9 Vulnerability Finding (class 2002) pinned to one code location; evidence URLs as osint.
    Field set = what Continuum's validator demanded live (metadata.version 1.9.0, cloud, osint, finding_info.uid,
    vulnerabilities[0].affected_code[0].file)."""
    elig = eligibility(ev, items)
    web3 = elig.get("kind") == "web3"
    name = subject(elig)
    pkg = [] if web3 else [{"name": elig["product"], "version": loc["found_version"],
                            **({"fixed_in_version": loc["fixed_version"]} if loc.get("fixed_version") else {})}]
    vuln_title = (f"{loc['found_version']} in {loc['file']}: {ev['title']}" if web3 else
                  f"{name} {loc['found_version']} is affected by {', '.join(ev['cves']) or ev['title']}")[:240]
    remediation = (" ".join(patterns.BY_CLASS[c].remediation for c in elig["classes"]) or
                   "Remove trust in the incident addresses.") if web3 else (
        f"Upgrade to {name} {loc['fixed_version']}." if loc.get("fixed_version") else "Follow the vendor advisory.")
    return {
        "class_uid": 2002, "category_uid": 2, "type_uid": 200201, "activity_id": 1,
        "severity_id": 5 if ev["severity"] == "P0" else 4, "status_id": 1, "time": now_ms,
        "cloud": {"provider": "AWS", "region": region},
        "osint": [{"type_id": 5, "value": it["url"], "src_url": it["url"], "name": it.get("source_name", "")}
                  for it in items[:10] if it.get("url")],
        "metadata": {"version": "1.9.0", "product": {"name": "Security Radar", "vendor_name": "aws-gcr-web3"}},
        "finding_info": {"uid": finding_uid(ev, loc),
                         "title": f"{name} · {loc['found_version']} @ {loc['file']}:{loc['line']} · {ev['title']}"[:240],
                         "desc": (f"Security Radar {ev['severity']}/{ev['level']} ({ev['exploitation']}), "
                                  f"{ev['independent_sources']} independent sources; CVEs {', '.join(ev['cves']) or 'n/a'}."),
                         "first_seen_time": now_ms},
        "vulnerabilities": [{
            "title": vuln_title,
            "desc": (f"{loc.get('match', 'exact')} match ({loc['kind']}) at {loc['file']}:{loc['line']}" if web3 else
                     f"{loc['kind']} pinned to {loc['found_version']}" + (
                         f", below fixed release {loc['fixed_version']}." if loc.get("fixed_version") else ".")),
            **({"cve": {"uid": ev["cves"][0]}} if ev["cves"] else
               {"cwe": {"uid": (patterns.BY_CLASS[elig["classes"][0]].cwe if web3 and elig["classes"] else "1357")}}),
            "severity": "Critical" if ev["severity"] == "P0" else "High",
            "affected_code": [{"file": {"name": loc["file"].rsplit("/", 1)[-1], "path": loc["file"], "type_id": 1},
                               "start_line": loc["line"], "end_line": loc["line"]}],
            **({"affected_packages": pkg} if pkg else {}),
            "remediation": {"desc": remediation},
        }],
    }


def client_token(uid: str, doc: dict[str, Any]) -> str:
    """Idempotency token per document *content*: Continuum keeps a token 8 h even after a rejected request, so
    reusing the uid for a corrected document is a ConflictException (live). Timestamps are excluded so an
    identical retry stays idempotent."""
    stable = {k: v for k, v in doc.items() if k != "time"}
    stable["finding_info"] = {k: v for k, v in doc["finding_info"].items() if k != "first_seen_time"}
    h = hashlib.sha256(repr(sorted(stable.items(), key=lambda kv: kv[0])).encode()).hexdigest()[:16]
    return f"{uid[-40:]}-{h}"


def finding_uid(ev: dict[str, Any], loc: dict[str, Any]) -> str:
    h = hashlib.sha256(f"{ev['event_id']}|{loc['file']}|{loc['line']}|{loc['found_version']}".encode()).hexdigest()[:16]
    return f"radar-{ev['event_id']}-{h}"


def scan_token(prefix: str, ev: dict[str, Any], finding_uids: set[str]) -> str:
    """CreateCodeScan idempotency token. It must change whenever the set of findings to validate changes: with a
    per-event token, a rescan for newly submitted findings replays the event's first scan instead of starting one
    (live 2026-10-25 23:19: the request returned the finished 10-24 scan, nothing ran). Same set ⇒ same token, so a
    retried request still cannot start a second paid scan."""
    h = hashlib.sha256("|".join(sorted(finding_uids)).encode()).hexdigest()[:10]
    return f"{prefix}-{ev['event_id']}-{trigger_key(ev)}-{h}"[:64]


def _repo_op(kind: str) -> tuple[str, str] | None:
    """'submit_finding_gl' → ('gitlab', 'submit_finding'); None for non-channel ops."""
    for ch, meta in REPO_CHANNELS.items():
        for verb in ("submit_finding", "request_scan", "poll_continuum"):
            if kind == f"{verb}_{meta['op']}":
                return ch, verb
    return None


def scan_action_status(status: str) -> str:
    """CreateCodeScan can answer with an already-finished run (idempotent replay); poll never revisits a terminal scan,
    so mapping it to 'running' would leave the action — and the event — running forever (live 2026-10-25)."""
    return {"SUCCEEDED": "done", "FAILED": "failed"}.get(status, "running")


def trigger_key(ev: dict[str, Any]) -> str:
    """A paid review re-runs only when the event escalates (severity/level/exploitation change)."""
    return f"{ev['severity']}|{ev['level']}|{ev['exploitation']}"


# ---------------------------------------------------------------- decide / apply

def decide(ev: dict[str, Any], items: list[dict[str, Any]], analysis: dict[str, Any] | None,
           state: dict[str, Any] | None, targets: list[Target], budget: Budget) -> tuple[dict[str, Any], list[Op]]:
    st = copy.deepcopy(state or {})  # the caller compares old vs new to decide whether to persist
    elig = eligibility(ev, items)
    st["eligibility"] = elig
    if elig["eligible"]:
        st["last_eligibility"] = elig  # what the results below were produced under (kept when the event cools down)
    if not elig["eligible"]:
        return st, [op for op in _polls(st)]  # still drain anything already running
    ops: list[Op] = []
    req = requirement(ev, elig)
    synced = st.get("requirement") or {}
    # re-assert daily: the pack is a CloudFormation resource and a stack update must not silently drop rules
    if synced.get("hash") != _h(req) or synced.get("synced_day") != budget.today:
        ops.append(Op("sync_requirement", payload={"requirement": req, "hash": _h(req)}))
    doc = context_doc(ev, analysis, items)
    if (st.get("context") or {}).get("hash") != _h(doc):
        ops.append(Op("write_context", payload={"key": f"context/radar-{ev['event_id']}.md", "body": doc, "hash": _h(doc)}))
    tstate = st.setdefault("targets", {})
    for t in targets:
        ts = tstate.setdefault(t.target_id, {})
        ts["relevant"] = relevant(t, elig)
        ts["locations"] = locations(t, elig)
        live = {finding_uid(ev, loc) for loc in ts["locations"]}
        _rekey_by_location(ev, ts)
        _retire(ts, "cn_findings", live, budget.today)
        if not ts["locations"] and not ts.get("cn_findings"):
            st.get("actions", {}).pop(f"code_finding:{t.target_id}", None)  # nothing left to report for it
        for loc in ts["locations"]:
            uid = finding_uid(ev, loc)
            if uid not in (ts.get("cn_findings") or {}) and budget.channel(t.target_id) == "s3":
                ops.append(Op("submit_finding", t.target_id, {"uid": uid, "location": loc}))
        review = ts.get("review") or {}
        # paid review: P0, or exploited in the wild — and only where the target actually uses the product
        wants_review = ts["relevant"] and (ev["severity"] == "P0" or ev["exploitation"] == "confirmed")
        if wants_review and review.get("trigger") != trigger_key(ev) and review.get("status") not in ("SUBMITTED", "RUNNING", "IN_PROGRESS"):
            # a request, not a start: the station batches requests per target (plan_reviews) because one review
            # evaluates every requirement in the pack — N events on one repo cost one review, not N
            ops.append(Op("start_review", t.target_id, {"trigger": trigger_key(ev), "requirement": req["name"]}))
    for ch, meta in REPO_CHANNELS.items():
        chan_targets = getattr(budget, f"{ch}_targets")
        gst = st.setdefault(ch, {}) if chan_targets else st.get(ch) or {}
        mine = [t.target_id for t in targets if budget.channel(t.target_id) == ch]
        for tid in mine:  # R9: line drift is the same exposure on every channel
            _rekey_by_location(ev, st["targets"][tid], store=gst, key="findings", only=lambda f, x=tid: f.get("target_id") == x)
        if mine:  # R12: the same "removed from the code" bookkeeping as the S3 path, for this channel's targets only
            live = {finding_uid(ev, loc) for tid in mine for loc in st["targets"][tid].get("locations") or []}
            _retire(gst, "findings", live, budget.today, only=lambda f, m=frozenset(mine): f.get("target_id") in m)
        for tid in mine:
            for loc in (st["targets"][tid].get("locations") or []):
                uid = finding_uid(ev, loc)
                if uid not in (gst.get("findings") or {}):
                    ops.append(Op(f"submit_finding_{meta['op']}", tid, {"uid": uid, "location": loc}))
        # a scan is triggered by findings that WERE submitted (status SUBMITTED, after the last scan request), never by
        # a submit op merely being issued: while CreateCodeFinding was disabled (10-26 03:38Z → 10-27) every cycle
        # re-issued the submit, each looked "new", and a full paid environment scan ran every 6 h for nothing
        if chan_targets and _scan_due((gst.get("findings") or {}).values(), gst.get("scan")) \
                and getattr(budget, f"{ch}_scan_allowed"):
            ops.append(Op(f"request_scan_{meta['op']}", payload={"token": scan_token(f"radar-{meta['op']}", ev, set(
                gst.get("findings") or {}) | {o.payload["uid"] for o in ops if o.kind == f"submit_finding_{meta['op']}"})}))
            setattr(budget, f"{ch}_scan_allowed", False)
    s3_findings = [f for ts in tstate.values() for f in (ts.get("cn_findings") or {}).values()]
    if _scan_due(s3_findings, st.get("scan")) and budget.scan_allowed:
        uids = {u for ts in tstate.values() for u in (ts.get("cn_findings") or {})} | {
            o.payload["uid"] for o in ops if o.kind == "submit_finding"}
        ops.append(Op("request_scan", payload={"token": scan_token("radar", ev, uids)}))
        budget.scan_allowed = False  # one environment scan per cycle covers every event
    return st, ops + _polls(st)


def prune_plan(pack_names: list[str], seen: dict[str, str], today: str, ttl_days: int) -> tuple[list[str], dict[str, str]]:
    """R6: which radar-* rules leave the Security Agent pack. `seen` = name → last day it was re-asserted (every
    eligible event re-asserts its rule daily) or first observed in the pack. Older than ttl_days ⇒ delete: the rule of an
    event that was merged away (its name changed with the CVE set — live 10-28: the wrong PHP2Shell + Node2Shell merge
    left `radar-cve-…-111497-…`) or that stopped being eligible. A name first seen today gets the full grace period, so a
    rule is never deleted by the deploy that introduces this. Non-radar rules are never touched."""
    from datetime import date
    mine = [n for n in pack_names if n.startswith(REQ_PREFIX)]
    out = {n: seen.get(n, today) for n in mine}
    gone = [n for n in mine if (date.fromisoformat(today) - date.fromisoformat(out[n])).days > ttl_days]
    return sorted(gone), {n: d for n, d in out.items() if n not in gone}


def _cn_title(f: dict[str, Any]) -> str:
    """Stored title, else the location: repository-channel findings submitted before 10-28 were stored without one."""
    return f.get("title") or (f"{f['file']}:{f['line']}" if f.get("file") else "")


def _retire(store: dict[str, Any], key: str, live: set[str], today: str, only: Any = None) -> None:
    """One rule for every channel: a stored finding whose location is no longer in the uploaded code moves to
    resolved_findings (radar-side evidence of the fix — R3: Continuum has no finding/issue update API, 33 operations,
    none Update*Finding / *Issue, checked 2026-10-27). Revival (the line came back) is _rekey_by_location's job — it
    runs first on every channel; a second copy here was dead code (M95 inactive in CI 3854167). `only` limits it to
    findings this caller owns."""
    own = only or (lambda _f: True)
    for u in [u for u, f in (store.get(key) or {}).items() if u not in live and own(f)]:
        store.setdefault("resolved_findings", {})[u] = {**store[key].pop(u), "resolved_on": today}
    if not store.get("resolved_findings"):
        store.pop("resolved_findings", None)


def _scan_due(findings: Any, scan: dict[str, Any] | None) -> bool:
    """The one scan rule, every channel (S3 / GitHub / GitLab): scan only to validate radar findings that WERE
    submitted after the last scan request, and only once that scan has finished.
    - A submitted finding is validated only by the next successful build (Continuum API doc); without a rescan it
      waits for the schedule, which is off (PT0H) — live: Node2Shell stuck SUBMITTED 2 days.
    - Counting findings, not submit ops: while CreateCodeFinding was disabled (10-26 03:38Z → 10-27) every cycle
      re-issued the submit, each looked new, and a paid full scan ran every 6 h (≈ $1.4k/day).
    - No "P0 without a scan yet" trigger: it scanned events with nothing located in our code (live: Adobe Commerce,
      ≈ $450 at 10-28 01:11Z). The 24 h per-environment debounce is the caller's budget flag."""
    scan = scan or {}
    last_req = scan.get("requested_at") or ""
    waiting = any(f.get("status") == "SUBMITTED" and f.get("submitted_at", "") > last_req for f in findings)
    return waiting and (not scan or scan.get("status") in TERMINAL_SCAN)


def plan_reviews(requests: list[tuple[str, Op]], budget: Budget) -> tuple[dict[str, list[str]], list[tuple[str, str]]]:
    """[(event_id, start_review op)] in priority order → ({target_id: [event_ids sharing one review]}, blocked).
    Budget is spent per target review; events on an already-started target ride along for free."""
    start: dict[str, list[str]] = {}
    blocked: list[tuple[str, str]] = []
    for event_id, op in requests:
        tid = op.target_id or ""
        if tid in start:
            start[tid].append(event_id)
        elif budget.reviews_left > 0:
            budget.reviews_left -= 1
            start[tid] = [event_id]
        else:
            blocked.append((event_id, tid))
    return start, blocked


def block_review(st: dict[str, Any], target_id: str) -> dict[str, Any]:
    st.setdefault("targets", {}).setdefault(target_id, {})["review_blocked"] = \
        f"今日 Security Agent 评审额度已用完（{Limits.SA_REVIEWS_PER_DAY}/天），明天自动补做"
    return st


def _rekey_by_location(ev: dict[str, Any], ts: dict[str, Any], store: dict[str, Any] | None = None,
                       key: str = "cn_findings", only: Any = None) -> None:
    """A stored finding whose (file, line) is still a live location is the same exposure, whatever its key says.
    Keys drift: scripts/rehydrate_response.py keyed restored findings by Continuum findingId, so when PHP2Shell turned
    eligible again (live 2026-10-26 ~19:00Z) all 3 CONFIRMED findings looked 'gone', were moved to resolved and
    resubmitted — and the new finding set started a paid scan. Same for resolved findings whose line came back.
    R9 — lines drift too: an edit above the pin moves it (Dockerfile:1 → :2). A stored finding whose line is gone is
    re-pointed to the ONLY unclaimed live location in the same file with the same found version; ambiguous ⇒ left
    alone (retired + resubmitted, as before). `store` / `key` / `only`: repository channels keep findings elsewhere."""
    store = ts if store is None else store
    own = only or (lambda _f: True)
    locs = ts.get("locations") or []
    by_line = {(loc["file"], loc["line"]): finding_uid(ev, loc) for loc in locs}
    for bucket in (key, "resolved_findings"):
        for u, f in list((store.get(bucket) or {}).items()):
            want = by_line.get((f.get("file"), f.get("line")))
            if own(f) and want and (bucket != key or u != want):
                store[bucket].pop(u)
                f.pop("resolved_on", None)
                f.pop("issues_done", None)  # re-fetch its issues on the next poll (they may have been erased)
                store.setdefault(key, {}).setdefault(want, f)
    claimed = {(f.get("file"), f.get("line")) for f in (store.get(key) or {}).values()}
    free = [loc for loc in locs if (loc["file"], loc["line"]) not in claimed]
    for u, f in list((store.get(key) or {}).items()):
        if not own(f) or (f.get("file"), f.get("line")) in by_line:
            continue
        fits = [loc for loc in free if loc["file"] == f.get("file")
                and loc.get("found_version") == f.get("found_version", loc.get("found_version"))]
        if len(fits) == 1:
            free.remove(fits[0])
            store[key].pop(u)
            f.update(moved_from=f.get("line"), line=fits[0]["line"])
            store[key].setdefault(finding_uid(ev, fits[0]), f)
    if not store.get("resolved_findings"):
        store.pop("resolved_findings", None)


def _merge_issues(old: list[dict[str, Any]] | None, new: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Poll results only cover live findings: replacing the list would erase issues (and their patches / PR links)
    of findings resolved or re-keyed since (live 2026-10-26: PHP2Shell's 3 issues vanished). New wins per issue_id."""
    fresh = {i.get("issue_id"): i for i in new}
    return [fresh.pop(i.get("issue_id"), i) for i in old or []] + list(fresh.values())


def merge_states(survivor_id: str, survivor: dict[str, Any] | None, absorbed_id: str,
                 absorbed: dict[str, Any]) -> dict[str, Any]:
    """Respond state of an event absorbed by a merge, folded into the survivor's (roadmap R2: it used to be orphaned —
    AWS job records, Continuum findings, issues and delivered PRs vanished from the merged event's page).

    Survivor wins on conflicts; everything recomputed each cycle (eligibility, locations) is the survivor's. Absorbed
    Continuum findings are re-keyed to the uid the survivor will compute for the same location — otherwise decide()
    sees them as 'gone', drops them and resubmits (new findings ⇒ a new paid scan)."""
    out = copy.deepcopy(survivor or {})
    # requirement / context are named after the absorbed event: the survivor syncs its own on the next cycle
    if absorbed.get("last_eligibility") and not out.get("last_eligibility"):
        out["last_eligibility"] = copy.deepcopy(absorbed["last_eligibility"])
    for tid, ats in (absorbed.get("targets") or {}).items():
        ts = out.setdefault("targets", {}).setdefault(tid, {})
        by_line = {(loc["file"], loc["line"]): loc for loc in ats.get("locations") or []}
        cf = ts.setdefault("cn_findings", {})
        for uid, f in (ats.get("cn_findings") or {}).items():
            loc = by_line.get((f.get("file"), f.get("line")))
            new_uid = finding_uid({"event_id": survivor_id}, loc) if loc else uid
            cf.setdefault(new_uid, copy.deepcopy(f))
        if not cf:
            ts.pop("cn_findings")
        for uid, f in (ats.get("resolved_findings") or {}).items():
            ts.setdefault("resolved_findings", {}).setdefault(uid, copy.deepcopy(f))
        if ats.get("review") and not ts.get("review"):
            ts["review"] = copy.deepcopy(ats["review"])
    for k, v in (absorbed.get("actions") or {}).items():
        out.setdefault("actions", {}).setdefault(k, copy.deepcopy(v))
    for k, v in (absorbed.get("delivered_prs") or {}).items():
        out.setdefault("delivered_prs", {}).setdefault(k, v)
    have = {i.get("issue_id") for i in out.get("issues") or []}
    extra = [copy.deepcopy(i) for i in absorbed.get("issues") or [] if i.get("issue_id") not in have]
    if extra:
        out["issues"] = (out.get("issues") or []) + extra
    a_scan, s_scan = absorbed.get("scan") or {}, out.get("scan") or {}
    if a_scan.get("requested_at", "") > s_scan.get("requested_at", ""):
        out["scan"] = copy.deepcopy(a_scan)
    for ch in REPO_CHANNELS:  # was S3-only: a merge dropped the absorbed event's GitHub / GitLab findings and PRs
        a_ch = absorbed.get(ch) or {}
        if not a_ch:
            continue
        o_ch = out.setdefault(ch, {})
        for bucket in ("findings", "resolved_findings"):
            for uid, f in (a_ch.get(bucket) or {}).items():
                loc = next((x for x in ((absorbed.get("targets") or {}).get(f.get("target_id")) or {}).get("locations") or []
                            if (x["file"], x["line"]) == (f.get("file"), f.get("line"))), None)
                new_uid = finding_uid({"event_id": survivor_id}, loc) if loc and bucket == "findings" else uid
                o_ch.setdefault(bucket, {}).setdefault(new_uid, copy.deepcopy(f))
        have_ch = {i.get("issue_id") for i in o_ch.get("issues") or []}
        extra_ch = [copy.deepcopy(i) for i in a_ch.get("issues") or [] if i.get("issue_id") not in have_ch]
        if extra_ch:
            o_ch["issues"] = (o_ch.get("issues") or []) + extra_ch
        if (a_ch.get("scan") or {}).get("requested_at", "") > (o_ch.get("scan") or {}).get("requested_at", ""):
            o_ch["scan"] = copy.deepcopy(a_ch["scan"])
    out.setdefault("merged_from", []).append(absorbed_id)
    return out


def has_open_jobs(st: dict[str, Any] | None) -> bool:
    return bool(st) and bool(_polls(st))  # type: ignore[arg-type]


def _polls(st: dict[str, Any]) -> list[Op]:
    ops = []
    for tid, ts in (st.get("targets") or {}).items():
        r = ts.get("review") or {}
        # parser bump ⇒ re-read finished reviews once (e.g. pack-prefixed requirement titles, 2026-10-23)
        if r.get("job_id") and (r.get("status") not in TERMINAL_JOB or not r.get("findings_fetched")
                                or r.get("parser") != REVIEW_PARSER):
            ops.append(Op("poll_review", tid, {"job_id": r["job_id"], "code_review_id": r.get("code_review_id")}))
    open_findings = [f for ts in (st.get("targets") or {}).values() for f in (ts.get("cn_findings") or {}).values()
                     if f.get("status") not in TERMINAL_FINDING or not f.get("issues_done")]
    scan = st.get("scan") or {}
    if open_findings or (scan.get("scan_run_id") and scan.get("status") not in TERMINAL_SCAN):
        ops.append(Op("poll_continuum"))
    for ch, meta in REPO_CHANNELS.items():
        gh = st.get(ch) or {}
        gscan = gh.get("scan") or {}
        if any(f.get("status") not in TERMINAL_FINDING or not f.get("issues_done") for f in (gh.get("findings") or {}).values()) \
                or (gscan.get("scan_run_id") and gscan.get("status") not in TERMINAL_SCAN) \
                or any(not i.get("pr_url") and i.get("status") not in ("FAILED",) for i in gh.get("issues") or []):
            ops.append(Op(f"poll_continuum_{meta['op']}"))
    return ops


def _h(x: Any) -> str:
    return hashlib.sha256(repr(x).encode()).hexdigest()[:16]


def apply(st: dict[str, Any], op: Op, result: dict[str, Any], now: str) -> dict[str, Any]:
    """Fold one executed operation's result into the state. `result['error']` ⇒ recorded, never raised."""
    acts = st.setdefault("actions", {})
    err = result.get("error")
    ts = (st.setdefault("targets", {}).setdefault(op.target_id, {}) if op.target_id else None)
    if op.kind == "sync_requirement":
        if not err:
            st["requirement"] = {"name": op.payload["requirement"]["name"], "hash": op.payload["hash"], "synced_at": now,
                                 "synced_day": now[:10]}
        _act(acts, "requirement", SA, None, "failed" if err else "done",
             err or f"规则 {op.payload['requirement']['name']} 已写入 requirement pack", now, op.payload["requirement"]["name"])
    elif op.kind == "write_context":
        if not err:
            st["context"] = {"key": op.payload["key"], "hash": op.payload["hash"], "written_at": now}
        _act(acts, "context", CN, None, "failed" if err else "done", err or "事件与分析卡写入 context/ 作为知识文档", now, None)
    elif op.kind == "submit_finding" and ts is not None:
        if not err:
            ts.setdefault("cn_findings", {})[op.payload["uid"]] = {
                "finding_id": result["finding_id"], "status": result["status"], "title": result.get("title", ""),
                "file": op.payload["location"]["file"], "line": op.payload["location"]["line"],
                "found_version": op.payload["location"].get("found_version"), "submitted_at": now}
        _act(acts, f"code_finding:{op.target_id}", CN, op.target_id, "failed" if err else "submitted",
             err or f"OCSF 2002 已提交（{op.payload['location']['file']}:{op.payload['location']['line']}）", now,
             result.get("finding_id"), kind="code_finding")
    elif op.kind == "request_scan":
        if not err:
            st["scan"] = {"scan_run_id": result["scan_run_id"], "status": result["status"], "requested_at": now}
        _act(acts, "code_scan", CN, None, "failed" if err else scan_action_status(result["status"]),
             err or f"环境扫描 {result.get('status', '')}", now,
             result.get("scan_run_id"))
    elif op.kind == "start_review" and ts is not None:
        if not err:
            ts["review"] = {"trigger": op.payload["trigger"], "code_review_id": result["code_review_id"],
                            "job_id": result["job_id"], "status": "RUNNING", "started_at": now}
        _act(acts, f"code_review:{op.target_id}", SA, op.target_id, "failed" if err else "running",
             err or "代码评审已发起（含雷达规则）", now, result.get("job_id"), kind="code_review")
    elif op.kind == "poll_review" and ts is not None:
        r = ts.setdefault("review", {})
        if err:
            r["last_error"] = err
        else:
            r["status"] = result["status"]
            if result.get("findings") is not None:
                r["findings"], r["findings_fetched"] = result["findings"], result["status"] in TERMINAL_JOB
                r["parser"] = REVIEW_PARSER
            if result.get("patches"):
                r["patches"] = result["patches"]
            done = result["status"] in TERMINAL_JOB
            hits = [f for f in r.get("findings") or [] if f.get("requirement_hit")]
            _act(acts, f"code_review:{op.target_id}", SA, op.target_id,
                 ("done" if result["status"] == "COMPLETED" else "failed") if done else "running",
                 f"{result['status']} · {len(r.get('findings') or [])} 个 finding（命中雷达规则 {len(hits)}）", now,
                 op.payload["job_id"], kind="code_review")
            if r.get("patches"):
                _act(acts, f"remediation:{op.target_id}", SA, op.target_id, "done",
                     f"自动修复 diff：{len(r['patches'])} 份，涉及 {len({f for p in r['patches'] for f in p['files_changed']})} 个文件", now, None, kind="remediation")
    elif (rc := _repo_op(op.kind)) is not None:
        ch, verb = rc
        meta = REPO_CHANNELS[ch]
        gh = st.setdefault(ch, {})
        if verb == "submit_finding":
            if not err:
                gh.setdefault("findings", {})[op.payload["uid"]] = {
                    "finding_id": result["finding_id"], "status": result["status"], "title": result.get("title", ""),
                    "target_id": op.target_id,
                    "file": op.payload["location"]["file"], "line": op.payload["location"]["line"],
                    "found_version": op.payload["location"].get("found_version"), "submitted_at": now}
            _act(acts, f"{ch}_finding:{op.target_id}", CN, op.target_id, "failed" if err else "submitted",
                 err or f"{meta['label']} 仓库环境：OCSF 已提交（{op.payload['location']['file']}:{op.payload['location']['line']}）",
                 now, result.get("finding_id"), kind="code_finding")
        elif verb == "request_scan":
            if not err:
                gh["scan"] = {"scan_run_id": result["scan_run_id"], "status": result["status"], "requested_at": now}
            _act(acts, f"{ch}_scan", CN, None, "failed" if err else scan_action_status(result["status"]),
                 err or f"{meta['label']} 仓库环境扫描 {result.get('status', '')}", now, result.get("scan_run_id"), kind="code_scan")
        elif err:
            gh["error"] = err
        else:
            gh.pop("error", None)
            if result.get("scan") and gh.get("scan"):
                gh["scan"].update(status=result["scan"]["status"])
                _act(acts, f"{ch}_scan", CN, None, scan_action_status(gh["scan"]["status"]),
                     f"{meta['label']} 仓库环境扫描 {gh['scan']['status']}", now, gh["scan"]["scan_run_id"], kind="code_scan")
            by_id = {f["finding_id"]: f for f in result.get("findings") or []}
            for f in (gh.get("findings") or {}).values():
                if f["finding_id"] in by_id:
                    f["status"] = by_id[f["finding_id"]]["status"]
                f["issues_done"] = f["status"] in TERMINAL_FINDING and result.get("issues_complete", False)
            if result.get("issues") is not None:
                gh["issues"] = _merge_issues(gh.get("issues"), result["issues"])
            for i in gh.get("issues") or []:
                if i.get("pr_url"):
                    _act(acts, f"pull_request:{i['issue_id']}", CN, None, "done",
                         f"Continuum 已在 {meta['label']} 开出补丁 {meta['change']}：{i['pr_url'].rsplit('/', 1)[-1]} · {i['name'][:80]}",
                         now, i["issue_id"], kind="remediation")
                    acts[f"pull_request:{i['issue_id']}"]["console_url"] = i["pr_url"]
    elif op.kind == "poll_continuum":
        if err:
            st["continuum_error"] = err
        else:
            st.pop("continuum_error", None)
            if result.get("scan") and st.get("scan"):
                st["scan"].update(status=result["scan"]["status"], failure=result["scan"].get("failureMessage"))
                sc = st["scan"]
                _act(acts, "code_scan", CN, None, scan_action_status(sc["status"]),
                     f"环境扫描 {sc['status']}" + (f"：{sc['failure']}" if sc.get("failure") else ""), now, sc["scan_run_id"])
            by_id = {f["finding_id"]: f for f in result.get("findings") or []}
            for tid, t in (st.get("targets") or {}).items():
                for f in (t.get("cn_findings") or {}).values():
                    if f["finding_id"] in by_id:
                        f.update(status=by_id[f["finding_id"]]["status"], verdict=by_id[f["finding_id"]].get("verdict"))
                    f["issues_done"] = f["status"] in TERMINAL_FINDING and result.get("issues_complete", False)
                    stt = {"CONFIRMED": "done", "DISCARDED": "failed"}.get(f["status"], "running")
                    _act(acts, f"code_finding:{tid}", CN, tid, stt, f"Continuum 验证：{f['status']}"
                         + (f" · {f['verdict']}" if f.get("verdict") not in (None, f["status"]) else ""), now, f["finding_id"],
                         kind="code_finding")
            if result.get("issues") is not None:
                st["issues"] = _merge_issues(st.get("issues"), result["issues"])
    return st


def _act(acts: dict[str, Any], key: str, service: str, target_id: str | None, status: str, detail: str, now: str,
         external_id: str | None, kind: str | None = None) -> None:
    prev = acts.get(key) or {}
    acts[key] = {"kind": kind or key.split(":")[0], "service": service, "target_id": target_id, "status": status,
                 "detail": detail[:300], "external_id": external_id or prev.get("external_id"),
                 "console_url": None, "started_at": prev.get("started_at") or now, "updated_at": now}


# ---------------------------------------------------------------- public rendering

def to_response(st: dict[str, Any] | None, names: dict[str, str], now: str) -> dict[str, Any] | None:
    """names = target_id → display name (radar.targets)."""
    if not st:
        return None
    elig = st.get("eligibility") or {}
    history = not elig.get("eligible") and st.get("targets") and st.get("last_eligibility")
    if history:  # cooled-down event: show what was done, and say why nothing new is started
        cooled = elig.get("reason", "")
        elig = st["last_eligibility"]
    if not elig.get("eligible"):
        return {"status": "not_eligible", "reason": elig.get("reason", ""), "product": None, "requirement_name": None,
                "updated_at": now, "targets": [], "actions": [], "findings": [], "issues": [], "patches": []}
    out_targets, findings, patches = [], [], []
    for tid, ts in (st.get("targets") or {}).items():
        r = ts.get("review") or {}
        hits = [f for f in r.get("findings") or [] if f.get("requirement_hit")]
        repo_live = [(REPO_CHANNELS[ch]["label"], f) for ch in REPO_CHANNELS
                     for f in ((st.get(ch) or {}).get("findings") or {}).values() if f.get("target_id") == tid]
        repo_gone = [(REPO_CHANNELS[ch]["label"], f) for ch in REPO_CHANNELS
                     for f in ((st.get(ch) or {}).get("resolved_findings") or {}).values() if f.get("target_id") == tid]
        cn = list((ts.get("cn_findings") or {}).values()) + [f for _, f in repo_live]
        exact = [loc for loc in ts.get("locations") or [] if loc.get("match", "exact") == "exact"]
        cands = len(ts.get("locations") or []) - len(exact)
        if not ts.get("relevant"):
            verdict, detail = "skipped", ("不含智能合约代码，不评审" if elig.get("kind") == "web3"
                                          else f"清单中无 {subject(elig)}，不评审")
        elif exact or hits or any(f["status"] == "CONFIRMED" for f in cn):
            verdict = "affected"
            detail = (f"{len(exact)} 处精确命中" + ("（受影响版本）" if elig.get("kind") != "web3" else "（IOC / 公开密钥）")
                      if exact else "AWS 侧确认命中雷达规则") + (f"，另有 {cands} 处候选待验证" if cands else "")
        elif r.get("status") == "COMPLETED" and r.get("findings_fetched"):
            verdict, detail = "not_affected", "Security Agent 评审完成，未命中雷达规则"
        elif r.get("job_id") or cn:
            verdict, detail = "pending", "评审/验证进行中" + (f"（{cands} 处候选代码）" if cands else "")
        else:
            verdict, detail = "unknown", ts.get("review_blocked") or "版本无法比较（未钉死），未发起评审"
        out_targets.append({"target_id": tid, "name": names.get(tid, tid), "relevant": bool(ts.get("relevant")),
                            "verdict": verdict, "detail": detail,
                            "locations": [{**{k: loc[k] for k in ("file", "line", "found_version", "fixed_version")},
                                           "match": loc.get("match", "exact")}
                                          for loc in ts.get("locations") or []]})
        if not ts.get("relevant"):
            continue  # skipped targets contribute no findings/patches (e.g. a review of an archive later corrected)
        findings += [{"service": SA, "finding_id": f["finding_id"], "title": f["title"], "severity": f["severity"],
                      "status": f["status"], "target_id": tid, "file": f.get("file"), "line": f.get("line"),
                      "requirement_hit": bool(f.get("requirement_hit"))} for f in r.get("findings") or []]
        labelled = [("", f) for f in (ts.get("cn_findings") or {}).values()] + [(f" · {lb}", f) for lb, f in repo_live]
        findings += [{"service": CN, "finding_id": f["finding_id"], "title": _cn_title(f), "severity": "HIGH",
                      "status": f["status"] + (f" · {f['verdict']}" if f.get("verdict") not in (None, f["status"]) else "") + lb,
                      "target_id": tid,
                      "file": f.get("file"), "line": f.get("line"), "requirement_hit": True} for lb, f in labelled]
        findings += [{"service": CN, "finding_id": f["finding_id"], "title": _cn_title(f), "severity": "HIGH",
                      "status": f"{f['status']} · 代码中已移除（{f['resolved_on']}，雷达判定；Continuum 无回写 API）",
                      "target_id": tid, "file": f.get("file"), "line": f.get("line"), "requirement_hit": True}
                     for f in (ts.get("resolved_findings") or {}).values()]
        findings += [{"service": CN, "finding_id": f["finding_id"], "title": _cn_title(f), "severity": "HIGH",
                      "status": f"{f['status']} · 代码中已移除（{f['resolved_on']}，雷达判定；Continuum 无回写 API）· {label}",
                      "target_id": tid, "file": f.get("file"), "line": f.get("line"), "requirement_hit": True}
                     for label, f in repo_gone]
        patches += [{**p, "target_id": tid} for p in r.get("patches") or []]
    findings.sort(key=lambda f: (not f["requirement_hit"], f["service"], f["finding_id"]))
    skipped = {tid for tid, ts in (st.get("targets") or {}).items() if not ts.get("relevant")}
    acts = sorted((a for a in (st.get("actions") or {}).values() if a.get("target_id") not in skipped),
                  key=lambda a: a["started_at"])
    running = any(a["status"] in ("running", "submitted") for a in acts)
    failed = any(a["status"] == "failed" for a in acts)
    status = "running" if running else ("failed" if failed and not out_targets else ("done" if acts else "queued"))
    issues = [{**i} for i in (st.get("issues") or []) + [x for ch in REPO_CHANNELS for x in (st.get(ch) or {}).get("issues") or []]]
    for i in issues:  # PRs the radar opened for Continuum patches (scripts/deliver_prs.py) — native PRs win
        i["pr_url"] = i.get("pr_url") or (st.get("delivered_prs") or {}).get(i["issue_id"])
    patches += [{"source": CN, "target_id": None, "path": i["patch_path"], "files_changed": i.get("patch_files") or [],
                 "summary": i["name"], "pr_url": i.get("pr_url")} for i in issues if i.get("patch_path")]
    for i in issues:
        i.pop("patch_files", None)
    affected = sum(1 for t in out_targets if t["verdict"] == "affected")
    reason = elig["reason"] + (f" ⇒ {affected}/{len(out_targets)} 个目标受影响" if out_targets else "")
    if history:
        reason = f"已退出触发条件（{cooled}），不再发起新工作；以下为此前的结果 · " + reason
    return {"status": status, "reason": reason, "product": elig["product"],
            "requirement_name": (st.get("requirement") or {}).get("name"), "updated_at": now,
            "targets": out_targets, "actions": acts, "findings": findings, "issues": issues, "patches": patches}


def impact(resp: dict[str, Any] | None) -> dict[str, Any] | None:
    if not resp:
        return None
    if resp["status"] == "not_eligible":
        return {"status": "not_eligible", "affected": 0, "checked": 0}
    ts = resp["targets"]
    affected = sum(1 for t in ts if t["verdict"] == "affected")
    if affected:
        status = "affected"
    elif any(t["verdict"] in ("pending",) for t in ts) or resp["status"] in ("running", "queued"):
        status = "running"
    elif resp["status"] == "failed":
        status = "failed"
    else:
        status = "not_affected"
    return {"status": status, "affected": affected, "checked": len(ts)}
