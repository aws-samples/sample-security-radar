"""Lambda entrypoints = harness stations. Step Functions owns order, retries and fan-out; each station is
short-lived, reads inputs by S3 key / table, writes outputs the same way, and returns a small JSON."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from radar import collect, cost, keys, notify, pipeline, prsync, publish, timeutil
from radar.dynamo import DynamoStore
from radar.model import RawItem
from radar.registry import BY_ID

log = logging.getLogger()
log.setLevel(logging.INFO)

_s3 = boto3.client("s3")
_store = DynamoStore(boto3.resource("dynamodb").Table(os.environ["TABLE"])) if os.environ.get("TABLE") else None
MAX_CHANGED_IDS = 2000  # keeps the Step Functions payload far below 256 KB
FUNNEL_KEY = "__funnel__"  # not a registered source; sources_doc only iterates the registry
MAX_ANALYSES_PER_CYCLE = 6  # ~30 s each (2026-10-23 probe) ⇒ bounded station time


def plan(event: dict[str, Any], _ctx: Any = None) -> dict[str, Any]:
    now = timeutil.now()
    states = {sid: _store.get_source_state(sid) for sid in BY_ID}
    # `full` (manual full republish) must survive to Publish: Plan's output is the state every later step reads
    return {"slot": timeutil.iso(now), "sources": [{"source_id": s} for s in collect.due(states, now)],
            "full": bool(event.get("full", False))}


def collect_one(event: dict[str, Any], _ctx: Any = None) -> dict[str, Any]:
    sid, slot = event["source_id"], event["slot"]
    now = timeutil.now()
    source = BY_ID[sid]
    raws, state = collect.collect(source, _store.get_source_state(sid), now,
                                  known_item=lambda s, g: _store.get_item(keys.item_id(s, g)) is not None)
    _store.put_source_state(sid, state)
    key = None
    if raws:
        key = f"raw/{slot[:10]}/{slot}/{sid}.jsonl"
        _s3.put_object(Bucket=os.environ["RAW_BUCKET"], Key=key, ContentType="application/x-ndjson",
                       Body="\n".join(json.dumps(r.to_dict(), ensure_ascii=False) for r in raws).encode())
    ok = state.get("consecutive_failures", 0) == 0
    log.info(json.dumps({"station": "collect", "source": sid, "items": len(raws), "ok": ok,
                         "error": None if ok else state.get("last_error")}))
    return {"source_id": sid, "key": key, "count": len(raws), "ok": ok}


def _pending_raw_keys(now: Any) -> list[str]:
    """Every raw batch from today/yesterday not yet marked processed — not just this cycle's. A failed
    process run therefore loses nothing: collectors already advanced their cursors, the batches wait in S3."""
    bucket, keys_ = os.environ["RAW_BUCKET"], []
    for day in sorted({timeutil.iso(now)[:10], timeutil.iso(now - timedelta(days=1))[:10]}):
        for page in _s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=f"raw/{day}/"):
            keys_ += [o["Key"] for o in page.get("Contents", [])]
    return sorted(k for k in keys_ if not _store.is_raw_processed(k))


def process(event: dict[str, Any], _ctx: Any = None) -> dict[str, Any]:
    now = timeutil.now()
    pending = _pending_raw_keys(now)
    raws: list[RawItem] = []
    for key in pending:
        body = _s3.get_object(Bucket=os.environ["RAW_BUCKET"], Key=key)["Body"].read().decode()
        raws += [RawItem.from_dict(json.loads(line)) for line in body.splitlines() if line.strip()]
    raws.sort(key=lambda x: x.published_at or now)
    res = pipeline.ingest(raws, _store, now)
    for key in pending:  # only after a successful ingest
        _store.mark_raw_processed(key, timeutil.iso(now))
    # rolling counters for the funnel ("how much work the system did"); kept beside source states
    st = _store.get_source_state(FUNNEL_KEY)
    day_ago = timeutil.iso(now - timedelta(days=1))
    st["runs"] = [r for r in st.get("runs", []) if r[0] >= day_ago] + \
        [[timeutil.iso(now), len(raws), res.new_items + res.updated_items]]
    _store.put_source_state(FUNNEL_KEY, st)
    # age-driven recompute (V4 finalization) only needs to run hourly, not every 10-minute cycle
    refreshed = pipeline.refresh(_store, now) if now.minute < 10 or event.get("full") else []
    onchain = pipeline.verify_onchain(_store, now)   # C6: ≤ CHAIN_CHECKS_PER_CYCLE public-RPC calls, never raises
    changed = set(res.changes) | set(refreshed) | set(onchain)
    log.info(json.dumps({"station": "process", "batches": len(pending), "raw": len(raws), "new": res.new_items,
                         "updated": res.updated_items, "unchanged": res.unchanged_items,
                         "events_changed": len(changed)}))
    ids = sorted(changed)
    return {"changed": ids[:MAX_CHANGED_IDS], "full": len(ids) > MAX_CHANGED_IDS or bool(event.get("full"))}


def _evidence(ev: Any) -> list[dict[str, Any]]:
    items = sorted(_store.get_items(ev.item_ids), key=lambda i: (i.published_at, i.source_id, i.item_id))
    return [{"item_id": i.item_id, "source": BY_ID[i.source_id].name if i.source_id in BY_ID else i.source_id,
             "tier": i.tier, "published_at": i.published_at, "title": i.title, "text": i.text} for i in items]


def analyze_events(event: dict[str, Any], _ctx: Any = None) -> dict[str, Any]:
    """Analyst station: P0/P1 events whose evidence changed get a (re)generated, code-validated brief."""
    from radar import analyst
    now = timeutil.now()
    since = timeutil.iso(now - timedelta(days=publish.Limits.PUBLISH_WINDOW_DAYS))
    todo = []
    for ev in _store.events_updated_since(since):
        if ev.severity not in ("P0", "P1"):
            continue
        ev_in = analyst.trim_evidence(_evidence(ev))
        if (ev.analysis or {}).get("input_hash") != analyst.input_hash(ev_in):
            todo.append((0 if ev.severity == "P0" else 1, ev.last_updated, ev, ev_in))
    todo.sort(key=lambda t: (t[0], -_ts(t[1])))
    done = []
    for _, _, ev, ev_in in todo[:MAX_ANALYSES_PER_CYCLE]:
        ev.analysis = analyst.analyze(ev_in, timeutil.iso(now))
        _store.put_event(ev)
        done.append(ev.event_id)
        log.info(json.dumps({"station": "analyze", "event": ev.event_id, "status": ev.analysis["status"],
                             "reason": ev.analysis.get("reason")}))
    _daily_digest(now)
    dup = _cluster_judge(now)
    changed = sorted(set(event.get("changed") or []) | set(done) | set(dup))
    return {"changed": changed[:MAX_CHANGED_IDS], "full": bool(event.get("full")), "analysis_backlog": len(todo) - len(done)}


DIGEST_KEY = "__digest__"  # C7: the latest daily digest (single writer: the analyze station)
DUP_KEY = "__cluster_judge__"  # C4: {"pairs": {pair_key: verdict row}} (single writer: the analyze station)


def _cluster_judge(now: datetime) -> list[str]:
    """C4: judge new candidate pairs (≤ MAX_PAIRS_PER_CYCLE Haiku calls); returns the events whose possible-duplicate
    list changed, so publish rebuilds their pages. Advisory only — nothing is merged."""
    from radar import cluster_judge
    st = _store.get_source_state(DUP_KEY)
    before = {k: v.get("verdict") for k, v in (st.get("pairs") or {}).items()}
    evs = _store.events_updated_since(timeutil.iso(now - timedelta(days=publish.Limits.PUBLISH_WINDOW_DAYS)))
    pairs, calls = cluster_judge.run(evs, st.get("pairs") or {}, timeutil.iso(now))
    _store.put_source_state(DUP_KEY, {"pairs": pairs})
    touched = sorted({e for k, v in pairs.items() if v.get("verdict") == "same" and before.get(k) != "same"
                      for e in (v["a"], v["b"])})
    if calls or touched:
        log.info(json.dumps({"station": "analyze", "cluster_judge_calls": calls, "possible_duplicates_new": len(touched) // 2}))
    return touched


def _daily_digest(now: datetime) -> None:
    """C7: once a day after 08:00 HKT (digest.due), ≤ MAX_ATTEMPTS tries; the outcome — ok, partial, failed with
    a reason, or a quiet day — is stored and published as is."""
    from radar import digest
    st = _store.get_source_state(DIGEST_KEY)
    if not digest.due(st, now):
        return
    d = digest.generate(_store.events_updated_since(timeutil.iso(now - timedelta(hours=24))), now)
    d["attempts"] = int(st.get("attempts", 0)) + 1 if st.get("day") == d["day"] else 1
    _store.put_source_state(DIGEST_KEY, d)
    log.info(json.dumps({"station": "analyze", "digest": d["day"], "status": d["status"], "reason": d.get("reason"),
                         "events": d["header"]["events"], "attempt": d["attempts"]}))


def _ts(iso: str) -> float:
    t = timeutil.parse(iso)
    return t.timestamp() if t else 0.0


def _epss(cves: list[str]) -> dict[str, dict[str, float]]:
    """FIRST EPSS for the CVEs we publish. Failure ⇒ empty (UI shows '—'), logged as degraded, never fatal."""
    from radar import fetch
    out: dict[str, dict[str, float]] = {}
    for i in range(0, len(cves), 100):
        try:
            d = json.loads(fetch.http_get("https://api.first.org/data/v1/epss?cve=" + ",".join(cves[i:i + 100])).body)
            for row in d.get("data", []):
                out[row["cve"]] = {"epss": float(row["epss"]), "percentile": float(row["percentile"])}
        except (fetch.FetchError, ValueError, KeyError) as e:
            log.warning(json.dumps({"station": "publish", "degraded": "epss_unavailable", "error": str(e)[:200]}))
    return out


def publish_site(event: dict[str, Any], _ctx: Any = None) -> dict[str, Any]:
    now = timeutil.now()
    changed = None if event.get("full") else set(event.get("changed") or [])
    evs = [e for e in (_store.get_event(x) for x in (changed or [])) if e]
    cves = sorted({c for e in evs for c in e.cves})
    docs = publish.build(_store, now, changed, _epss(cves) if cves else {})
    bucket = os.environ["SITE_BUCKET"]
    for path, doc in docs.items():
        _s3.put_object(Bucket=bucket, Key=f"data/{path}", Body=json.dumps(doc, ensure_ascii=False).encode(),
                       ContentType="application/json", CacheControl="max-age=60")
    log.info(json.dumps({"station": "publish", "docs": len(docs)}))
    return {"docs": len(docs)}


CONTINUUM_KEY = "__continuum__"  # respond ledger (counters, review timestamps, inventory, resources)
_COUNT = {"sync_requirement": "requirements_synced", "write_context": "contexts_written",
          "submit_finding": "findings_submitted", "request_scan": "scans_requested", "start_review": "code_reviews_started",
          "submit_finding_gh": "github_findings_submitted", "request_scan_gh": "github_scans_requested",
          "submit_finding_gl": "gitlab_findings_submitted", "request_scan_gl": "gitlab_scans_requested"}
# per-environment scan clock (24 h debounce), one ledger key per channel; keys predate the channel table, kept as-is
SCAN_CLOCK = {"s3": "last_scan_at", "github": "last_gh_scan_at", "gitlab": "last_gl_scan_at"}


def _scan_open(led: dict[str, Any], channel: str, now: datetime) -> bool:
    """≤ 1 paid scan per environment per CONTINUUM_SCAN_MIN_INTERVAL_H — the same rule for every channel."""
    last = led.get(SCAN_CLOCK[channel])
    return not last or last < timeutil.iso(now - timedelta(hours=publish.Limits.CONTINUUM_SCAN_MIN_INTERVAL_H))


def _respond_view(ev: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    items = sorted(_store.get_items(ev.item_ids), key=lambda i: (i.published_at, i.source_id, i.item_id))
    view = {"event_id": ev.event_id, "domain": ev.domain, "title": ev.title, "severity": ev.severity, "level": ev.level,
            "exploitation": ev.exploitation, "cves": ev.cves, "entities": ev.entities,
            "independent_sources": ev.independent_sources, "first_seen": ev.first_seen}
    refs = [{"title": i.title, "excerpt": i.text[:2000], "url": i.url,
             "source_name": BY_ID[i.source_id].name if i.source_id in BY_ID else i.source_id} for i in items]
    return view, refs


def _tally(led: dict[str, Any], op: Any, res: dict[str, Any], nowi: str) -> None:
    """Ledger counters = the evidence behind radar.coverage 'live' statuses."""
    c = led.setdefault("counters", {})
    if op.kind in _COUNT:
        c[_COUNT[op.kind]] = c.get(_COUNT[op.kind], 0) + 1
    if op.kind == "start_review":
        led.setdefault("reviews", []).append(nowi)
    if op.kind == "sync_requirement":   # R6: the day each radar rule was last re-asserted
        led.setdefault("requirements", {})[op.payload["requirement"]["name"]] = nowi[:10]
    from radar import respond  # lazy, like every respond-station import (other stations never load it)
    for ch, kind in respond.SCAN_OPS.items():
        if op.kind == kind:
            led[SCAN_CLOCK[ch]] = nowi
    if op.kind == "poll_continuum_gh":
        prs = sorted({i["pr_url"] for i in res.get("issues") or [] if i.get("pr_url")} | set(led.get("prs", [])))
        led["prs"] = prs
        c["github_prs"] = len(prs)
    if op.kind == "poll_continuum_gl":
        mrs = sorted({i["pr_url"] for i in res.get("issues") or [] if i.get("pr_url")} | set(led.get("mrs", [])))
        led["mrs"] = mrs
        c["gitlab_mrs"] = len(mrs)
    if op.kind == "poll_review" and res.get("status") == "COMPLETED" and res.get("findings") is not None:
        c["code_reviews_completed"] = c.get("code_reviews_completed", 0) + 1
        c["sa_patches"] = c.get("sa_patches", 0) + len(res.get("patches") or [])
    if op.kind == "poll_continuum":
        c["finding_verdicts"] = max(c.get("finding_verdicts", 0), sum(1 for f in res.get("findings") or [] if f.get("verdict")))
        c["issues_seen"] = max(c.get("issues_seen", 0), len(res.get("issues") or []))


NOTIFY_KEY = "__notify__"  # {event_id: {channel: {keys, thread}}} — single writer: this station


def _notify(led: dict[str, Any], now: datetime) -> None:
    """C3: P0 / affected / PR-link messages to Slack and Lark, one thread per event. Status per channel goes to the
    ledger (not_configured / baseline / ok / error) — a broken channel never blocks the station or the other channel.
    The first configured run only records what already exists (baseline): enabling push must not replay a week."""
    arn = os.environ.get("NOTIFY_SECRET_ARN")
    if not arn:
        return
    from radar import respond
    nowi = timeutil.iso(now)
    status = led.setdefault("notify", {})
    try:
        raw = boto3.client("secretsmanager").get_secret_value(SecretId=arn)["SecretString"]
        cfg = json.loads(raw) if raw.strip().startswith("{") else {}
    except (ClientError, BotoCoreError, ValueError) as e:
        status["error"] = str(e)[:300]
        return
    channels = notify.configured(cfg)
    for c in notify.CHANNELS:
        if c not in channels:
            status[c] = {"status": "not_configured", "at": nowi}
    if not channels:
        return
    site = os.environ.get("SITE_URL", "")
    state = _store.get_source_state(NOTIFY_KEY)
    since = timeutil.iso(now - timedelta(days=publish.Limits.RESPOND_WINDOW_DAYS))
    evs = [e for e in _store.events_updated_since(since) if e.severity in ("P0", "P1")]
    state = {e.event_id: state[e.event_id] for e in evs if e.event_id in state}  # prune to the window
    for c in channels:
        baseline = not (status.get(c) or {}).get("baselined")
        sent_n, err = 0, None
        for e in sorted(evs, key=lambda x: (x.severity != "P0", x.first_seen)):
            resp = publish._response(e, _store, now)
            row = {"event_id": e.event_id, "title": e.title, "severity": e.severity, "level_reason": e.level_reason}
            mine = state.setdefault(e.event_id, {}).setdefault(c, {})
            for m in notify.plan(row, resp, respond.impact(resp), mine, site):
                if baseline:
                    mine = notify.record(mine, m["key"], None)
                    continue
                if err or sent_n >= publish.Limits.NOTIFY_MAX_PER_CYCLE:
                    break
                try:
                    mine = notify.record(mine, m["key"], notify.SENDERS[c](cfg, m["text"], mine.get("thread")))
                    sent_n += 1
                except (OSError, ValueError, KeyError) as ex:  # urllib errors are OSError; in-band API errors ValueError
                    err = str(ex)[:300]
            state[e.event_id][c] = mine
        status[c] = {"status": "error" if err else ("baseline" if baseline else "ok"), "at": nowi, "sent": sent_n,
                     "baselined": True, **({"error": err} if err else {})}
        if err:
            log.warning(json.dumps({"station": "respond", "degraded": f"notify_{c}", "error": err}))
    _store.put_source_state(NOTIFY_KEY, state)


def _sync_prs(led: dict[str, Any], now: datetime) -> list[str]:
    """C2c: links of the PRs opened by the scheduled deliver_prs.py → delivered_prs of their events (single writer).
    Not configured / failing ⇒ recorded in the ledger (pr_sync), never raised: the station must still publish."""
    arn = os.environ.get("DEMO_FLEET_RO_SECRET_ARN")
    last = timeutil.parse((led.get("pr_sync") or {}).get("at"))
    if not arn or (last and now - last < timedelta(hours=publish.Limits.PR_SYNC_H)):
        return []
    nowi = timeutil.iso(now)
    try:
        token = boto3.client("secretsmanager").get_secret_value(SecretId=arn)["SecretString"].strip()
        if not token.startswith(("github_pat_", "ghp_")):  # CDK creates a placeholder; the value is set out of band
            led["pr_sync"] = {"at": nowi, "status": "not_configured"}
            return []
        pulls = prsync.fetch_pulls(os.environ.get("FLEET_REPO", "your-org/security-radar-demo-fleet"), token)
    except (ClientError, BotoCoreError, OSError, ValueError) as e:  # OSError covers urllib's HTTPError / URLError
        led["pr_sync"] = {"at": nowi, "status": "error", "error": str(e)[:300]}
        log.warning(json.dumps({"station": "respond", "degraded": "pr_sync", "error": str(e)[:300]}))
        return []
    by_prefix = prsync.links(pulls)
    touched = []
    since = timeutil.iso(now - timedelta(days=publish.Limits.PUBLISH_WINDOW_DAYS))
    for ev in _store.events_updated_since(since):
        urls = by_prefix.get(ev.event_id[:11])
        st = _store.get_response(ev.event_id) if urls else None
        if st is not None and prsync.apply(st, urls):
            _store.put_response(ev.event_id, st)
            touched.append(ev.event_id)
    prs = sorted(p["html_url"] for p in pulls if prsync.BRANCH.match((p.get("head") or {}).get("ref", "")))
    led["prs"] = prs
    led.setdefault("counters", {})["github_prs"] = len(prs)
    led["pr_sync"] = {"at": nowi, "status": "ok", "prs": len(prs), "events_updated": len(touched)}
    return touched


def respond_events(event: dict[str, Any], _ctx: Any = None) -> dict[str, Any]:
    """Respond station: eligible events → AWS Security Agent (rule + code review + auto-fix) and AWS Continuum
    (context, located finding, scan); running jobs are polled every cycle. Waiting is a data row, not a sleep."""
    from radar import continuum_aws as aws
    from radar import respond
    from radar import targets as targets_mod
    from radar.targets import TARGETS
    passthrough = {"changed": event.get("changed") or [], "full": bool(event.get("full"))}
    if not os.environ.get("SA_AGENT_SPACE_ID"):
        log.warning(json.dumps({"station": "respond", "degraded": "not_configured"}))
        return passthrough
    now = timeutil.now()
    nowi = timeutil.iso(now)
    led = _store.get_source_state(CONTINUUM_KEY)
    counters = led.setdefault("counters", {})
    day_ago = timeutil.iso(now - timedelta(days=1))
    led["reviews"] = [t for t in led.get("reviews", []) if t >= day_ago]
    scan_ok = _scan_open(led, "s3", now)
    per_day = int(os.environ.get("SA_REVIEWS_PER_DAY", publish.Limits.SA_REVIEWS_PER_DAY))  # stage override (CDK context)
    # R10 (Neo 2026-10-28: a budget line to show, not a brake): a billed day above the budget is recorded and logged —
    # it never stops a scan. Spend is kept down by the scan rules (only to validate radar findings, one environment
    # per repo, ≤ 1 per day per environment, no Continuum schedule), not by refusing work.
    over = cost.over_cap(led)
    if over:
        led["over_budget"] = {**over, "at": nowi}
        log.warning(json.dumps({"station": "respond", "warning": "over_budget", **over}))
    else:
        led.pop("over_budget", None)
    led.pop("spend_cap", None)
    budget = respond.Budget(per_day - len(led["reviews"]), scan_ok, nowi[:10], s3_targets=targets_mod.on("s3"))
    try:
        # GitHub environment failures back off to hourly (a service-side 500 must not be retried every cycle)
        gh_retry = not led.get("github_retry_at") or led["github_retry_at"] <= nowi
        env = aws.ensure_environment([t[0] for t in TARGETS], github_retry=gh_retry)
        # the backoff clock covers both repository channels (one ensure call reaches both)
        repo_err = {k: env[k] for k in ("github_error", "gitlab_error") if env.get(k)}
        if repo_err:
            led["github_retry_at"] = timeutil.iso(now + timedelta(hours=1))
            led.update(repo_err)
        if gh_retry:
            for k in ("github_error", "gitlab_error"):
                if k not in repo_err:
                    led.pop(k, None)
            if not repo_err:
                led.pop("github_retry_at", None)
        if not gh_retry:  # backing off ⇒ keep the repository environments already known
            env.update({k: v for k, v in (led.get("env") or {}).items() if k.startswith(("github_", "gitlab_"))})
        led["env"] = env
        counters["environment_ensured"] = counters.get("environment_ensured", 0) + 1
    except (ClientError, BotoCoreError, KeyError) as e:  # Continuum outage ⇒ Security-Agent-only, visibly
        log.warning(json.dumps({"station": "respond", "degraded": "continuum_unavailable", "error": str(e)[:300]}))
        env = None
    for ch in respond.REPO_CHANNELS:  # a repository channel is live once its integration + environment exist
        if env and env.get(f"{ch}_environment_id"):
            setattr(budget, f"{ch}_targets", targets_mod.on(ch))
            setattr(budget, f"{ch}_scan_allowed", _scan_open(led, ch, now))
    targets = aws.load_targets(list(TARGETS))
    led["targets"] = []
    for t in targets:
        ch = targets_mod.CHANNEL.get(t.target_id, "none")
        where, url = aws.target_location(t.target_id, ch, env)
        led["targets"].append({"target_id": t.target_id, "name": t.name, "description": t.description, "prefix": where,
                               "channel": ch, "channel_url": url, "uploaded_at": t.uploaded_at,
                               "inventory": [{"product": p.product_id, "version": p.version, "file": p.file, "line": p.line}
                                             for p in t.pins()]})
    counters["inventory_scans"] = counters.get("inventory_scans", 0) + 1
    since = timeutil.iso(now - timedelta(days=publish.Limits.RESPOND_WINDOW_DAYS))
    cands = [e for e in _store.events_updated_since(since) if e.domain in ("vuln", "web3") and e.severity in ("P0", "P1")]
    cands.sort(key=lambda e: (e.severity != "P0", -_ts(e.last_updated)))
    touched, acted = [], 0
    work = []  # (ev, view, refs, prev, st) — phase 1 runs everything except review starts
    review_requests: list[tuple[str, Any]] = []

    def run(op: Any, view: dict[str, Any], refs: list[dict[str, Any]], st: dict[str, Any]) -> dict[str, Any]:
        if env is None and op.kind in respond.CONTINUUM_OPS:
            res: dict[str, Any] = {"error": "continuum_unavailable"}
        else:
            res = aws.execute(op, view, refs, st, env or {})
        st = respond.apply(st, op, res, nowi)
        if not res.get("error"):
            _tally(led, op, res, nowi)
        return st

    for ev in cands:
        if acted >= publish.Limits.RESPOND_MAX_EVENTS:
            break
        view, refs = _respond_view(ev)
        prev = _store.get_response(ev.event_id)
        # an event that cools down (P0 → P1 after 72 h) keeps its results: only never-acted-on events are short-cut
        # (live 2026-10-25: the PHP2Shell response — reviews, Continuum issues, patches — was overwritten here)
        if not respond.eligibility(view, refs)["eligible"] and not respond.has_open_jobs(prev) \
                and not (prev or {}).get("targets"):
            if (prev or {}).get("eligibility", {}).get("eligible") is not False:  # record the reason once
                _store.put_response(ev.event_id, {"eligibility": respond.eligibility(view, refs)})
                touched.append(ev.event_id)
            continue
        acted += 1
        st, ops = respond.decide(view, refs, ev.analysis, prev, targets, budget)
        counters["events_considered"] = counters.get("events_considered", 0) + 1
        for op in ops:
            if op.kind == "start_review":
                review_requests.append((ev.event_id, op))
            else:
                st = run(op, view, refs, st)
        work.append((ev, view, refs, prev, st))
        log.info(json.dumps({"station": "respond", "event": ev.event_id, "ops": [o.kind for o in ops],
                             "eligible": st["eligibility"]["eligible"]}))
    # phase 2: one review per target covers every requirement synced in phase 1
    start, blocked = respond.plan_reviews(review_requests, budget)
    by_id = {w[0].event_id: i for i, w in enumerate(work)}
    for tid, event_ids in start.items():
        first = work[by_id[event_ids[0]]]
        op = next(o for e, o in review_requests if e == event_ids[0] and o.target_id == tid)
        res = aws.execute(op, first[1], first[2], first[4], env or {})
        if not res.get("error"):
            _tally(led, op, res, nowi)
        for eid in event_ids:
            i = by_id[eid]
            ev_, view_, refs_, prev_, st_ = work[i]
            own = next(o for e, o in review_requests if e == eid and o.target_id == tid)
            work[i] = (ev_, view_, refs_, prev_, respond.apply(st_, own, res, nowi))
        log.info(json.dumps({"station": "respond", "review": tid, "events": event_ids, "error": res.get("error")}))
    for eid, tid in blocked:
        i = by_id[eid]
        work[i] = (*work[i][:4], respond.block_review(work[i][4], tid))
    for ev, _view, _refs, prev, st in work:
        if st != prev:
            _store.put_response(ev.event_id, st)
            touched.append(ev.event_id)
    if env:
        led["resources"] = aws.resources(env)
    if led.get("requirements_pruned_on") != nowi[:10]:  # R6, once a day
        try:
            before = dict(led.get("requirements") or {})
            gone, led["requirements"] = respond.prune_plan(aws.requirement_names(), led.get("requirements") or {},
                                                           nowi[:10], publish.Limits.REQUIREMENT_TTL_DAYS)
            failed = aws.delete_requirements(gone) if gone else []
            for n in failed:   # refused ⇒ keep its clock, so it is retried tomorrow instead of getting a fresh grace period
                led["requirements"][n] = before.get(n, nowi[:10])
            led["requirements_pruned_on"] = nowi[:10]
            counters["requirements_pruned"] = counters.get("requirements_pruned", 0) + len(gone) - len(failed)
            if gone:
                log.info(json.dumps({"station": "respond", "pruned_requirements": gone, "failed": failed}))
        except (ClientError, BotoCoreError, KeyError) as e:   # never blocks the station; retried next cycle
            log.warning(json.dumps({"station": "respond", "degraded": "requirement_prune_failed", "error": str(e)[:300]}))
    touched += _sync_prs(led, now)
    _notify(led, now)
    if cost.due(led, now):  # R4: spend on #/continuum; a failed read keeps the last numbers, visibly
        try:
            led["cost"] = cost.summarize(aws.fetch_costs(*cost.window(now)), now)
            led.pop("cost_error", None)
        except (ClientError, BotoCoreError) as e:
            led["cost_error"] = {"at": nowi, "error": str(e)[:300]}
            log.warning(json.dumps({"station": "respond", "degraded": "cost_unavailable", "error": str(e)[:300]}))
    _store.put_source_state(CONTINUUM_KEY, led)
    changed = sorted(set(passthrough["changed"]) | set(touched))
    return {"changed": changed[:MAX_CHANGED_IDS], "full": passthrough["full"], "responded": len(touched)}


def mitigate_events(event: dict[str, Any], _ctx: Any = None) -> dict[str, Any]:
    """Mitigate station (M3): affected targets → WAF plans → read-only check → staged apply on radar-owned web ACLs.
    Its own Lambda and role (UpdateWebACL scoped to the radar prefix); a failure never blocks publish."""
    from radar import mitigate_aws, mitigate_station
    out = mitigate_station.run(_store, mitigate_aws, timeutil.now())
    log.info(json.dumps({"station": "mitigate", **out}))
    changed = sorted(set(event.get("changed") or []) | set(out["events"]))
    return {"changed": changed[:MAX_CHANGED_IDS], "full": bool(event.get("full"))}


def dns_probe(event: dict[str, Any], _ctx: Any = None) -> dict[str, Any]:
    """M3 B5: resolve one name from inside the DNS demo VPC, so Route 53 Resolver DNS Firewall sees (and logs) the
    query. Only names under the radar's canary are allowed — this function is not a general resolver."""
    import socket

    from radar.mitigate import DNS_CANARY
    name = str(event.get("name") or DNS_CANARY)
    if name != DNS_CANARY:
        return {"name": name, "error": "only the radar canary may be probed"}
    try:
        return {"name": name, "answers": sorted({a[4][0] for a in socket.getaddrinfo(name, 443)})}
    except OSError as e:   # NXDOMAIN for .invalid (and a BLOCK rule) — live it surfaces as gaierror OR OSError(EBUSY)
        return {"name": name, "error": f"{type(e).__name__} {e.errno}: {e.strerror}"}
