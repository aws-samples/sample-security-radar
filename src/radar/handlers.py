"""Lambda entrypoints = harness stations. Step Functions owns order, retries and fan-out; each station is
short-lived, reads inputs by S3 key / table, writes outputs the same way, and returns a small JSON."""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from radar import (
    announcements,
    anomaly,
    attacktx,
    chain,
    collect,
    cost,
    digest,
    fetch,
    keys,
    latency,
    pipeline,
    prsync,
    publish,
    removals,
    retitle,
    search,
    timeutil,
    triage,
)
from radar import onchain as onchain_station
from radar.dynamo import DynamoStore
from radar.limits import Limits
from radar.model import RawItem
from radar.registry import BY_ID

log = logging.getLogger()
log.setLevel(logging.INFO)

_s3 = boto3.client("s3")
_store = DynamoStore(boto3.resource("dynamodb").Table(os.environ["TABLE"])) if os.environ.get("TABLE") else None
MAX_CHANGED_IDS = 2000  # keeps the Step Functions payload far below 256 KB
FUNNEL_KEY = "__funnel__"  # not a registered source; sources_doc only iterates the registry
MAX_ANALYSES_PER_CYCLE = 6  # ~30 s each (2026-10-23 probe) ⇒ bounded station time


def _bedrock_gate(model: str) -> bool:
    """R5.6: one atomic count per Bedrock call per UTC day; past llm.daily_cap the call is not made. The counter
    failing lets the call through (the station's other table writes would fail first) and says so."""
    from radar import llm
    if _store is None:                       # installed only with a store (below); a test calling it bare is ungated
        return True
    try:
        return _store.add_count(timeutil.iso(timeutil.now())[:10], f"bedrock:{model}") <= llm.daily_cap(model)
    except (BotoCoreError, ClientError) as e:
        log.warning(json.dumps({"ledger": "llm", "degraded": "daily_cap_unchecked", "error": str(e)[:200]}))
        return True


if _store is not None:
    from radar import llm as _llm
    _llm.gate = _bedrock_gate


def _record_row_sizes(station: str) -> None:
    """Rows this run wrote above Limits.ROW_WARN_BYTES (DynamoStore._sized) ⇒ the newest 50 in one small ledger, read
    by #/ops row_near_limit — a row creeping toward 400 KB is seen days before it fails a cycle (R5.3)."""
    from radar.dynamo import ROW_SIZES_KEY
    near = getattr(_store, "near_limit", None)
    if not near:
        return
    at = timeutil.iso(timeutil.now())
    led = _store.get_source_state(ROW_SIZES_KEY)
    led.update({k: {"bytes": n, "station": station, "at": at} for k, n in near.items()})
    _store.put_source_state(ROW_SIZES_KEY, dict(sorted(led.items(), key=lambda kv: kv[1]["at"], reverse=True)[:50]))
    near.clear()


def _timed(station: str):
    """Record each run of a single-writer station in its run-time ledger (radar.stationtime ⇒ #/ops station_slow).
    Recording never breaks the station: a failed write is logged as degraded."""
    import functools
    import time

    def wrap(fn):
        @functools.wraps(fn)
        def run(event: dict[str, Any], _ctx: Any = None) -> dict[str, Any]:
            t0 = time.monotonic()
            if _store is not None and hasattr(_store, "begin_run"):
                _store.begin_run()                  # a warm container must not serve last run's event window
            left = _time_left(_ctx)
            limit = round(left()) if left else None    # remaining at the start ≈ the function's timeout
            ok = False
            try:
                out = fn(event, _ctx)
                ok = True
                return out
            finally:
                from radar import stationtime
                el = time.monotonic() - t0
                if _store is not None and hasattr(_store, "window_queries"):
                    log.info(json.dumps({"station": station, "window_queries": _store.window_queries,
                                         "window_hits": _store.window_hits}))
                try:
                    if _store is not None:
                        stationtime.record(_store, station, el, limit, timeutil.now(), ok=ok)
                        _record_row_sizes(station)
                except (BotoCoreError, ClientError) as e:
                    log.warning(json.dumps({"station": station, "degraded": "timing_not_recorded", "error": str(e)[:200]}))
        return run
    return wrap


# the states after collection: an earlier cycle in one of them no longer collects, so this one may (roadmap R2.2)
POST_COLLECT_STATES = frozenset({"Process", "Analyze", "Respond", "Mitigate", "Publish", "Notify",
                                 "AnalyzeFailed", "RespondFailed", "MitigateFailed", "NotifyFailed"})


def _earlier_cycle_running(execution: str | None, started: str | None) -> str:
    """What earlier executions of this state machine are doing: "none", "past_collect" (every earlier one is in
    Process or later — this cycle may collect, and stops before Process: one writer of events at a time), or
    "collecting" (one is still collecting — this cycle ends here: two collections of one source would race on its
    state). Live 2026-11-10 00:50: two cycles 6 s apart, the second's Process throttled and failed. Measured
    2026-11-15: half of the 5-minute triggers were skipped this way, so the site published every 10 minutes and a
    report waited up to two cycles to be fetched. The state machine ARN is derived from the execution ARN. A failed
    check is logged and the cycle runs in full — the stations' throttle retry is the second line."""
    if not execution or not started:
        return "none"
    sm = execution.replace(":execution:", ":stateMachine:").rsplit(":", 1)[0]
    me = timeutil.parse(started)
    sfn = boto3.client("stepfunctions")
    try:
        running = sfn.list_executions(stateMachineArn=sm, statusFilter="RUNNING", maxResults=20)["executions"]
        earlier = [x for x in running if x["executionArn"] != execution and x["startDate"] < me]
        if not earlier:
            return "none"
        for x in earlier:
            hist = sfn.get_execution_history(executionArn=x["executionArn"], reverseOrder=True, maxResults=100)["events"]
            entered = {(e.get("stateEnteredEventDetails") or {}).get("name") for e in hist}
            if not entered & POST_COLLECT_STATES:
                return "collecting"
        return "past_collect"
    except (BotoCoreError, ClientError) as e:
        log.warning(json.dumps({"station": "plan", "degraded": "overlap_check_unavailable", "error": str(e)[:200]}))
        return "none"


def plan(event: dict[str, Any], _ctx: Any = None) -> dict[str, Any]:
    now = timeutil.now()
    inp = event.get("input", event) or {}            # the cycle passes {input, execution, started}; manual calls the input
    full = bool(inp.get("full", False))
    other = "none" if full else _earlier_cycle_running(event.get("execution"), event.get("started"))
    if other == "collecting":
        log.info(json.dumps({"station": "plan", "skipped": "earlier_cycle_collecting"}))
        return {"skip": True, "collect_only": False, "slot": timeutil.iso(now), "sources": [], "full": False}
    if other == "past_collect":
        # the raw batches this cycle writes are picked up by the next full cycle's Process (it reads every batch after
        # its watermark, up to its own slot)
        log.info(json.dumps({"station": "plan", "collect_only": "earlier_cycle_past_collect"}))
    states = _store.get_source_states([*BY_ID, collect.SURGE_KEY])   # one BatchGetItem per 100 sources (research/17 §0)
    # `full` (manual full republish) must survive to Publish: Plan's output is the state every later step reads
    return {"skip": False, "collect_only": other == "past_collect", "slot": timeutil.iso(now),
            "sources": [{"source_ids": b} for b in collect.batches(collect.due(states, now))], "full": full}


SEEN_PREFIX = "__seen__#"          # per-source SEEN record (collect.incremental) — its own item, not read by Plan


def _collect_source(store: Any, sid: str, slot: str) -> dict[str, Any]:
    now = timeutil.now()
    source = BY_ID[sid]
    state = store.get_source_state(sid)
    seen = dict((store.get_source_state(SEEN_PREFIX + sid) or {}).get("h") or {})
    before = dict(seen)
    with fetch.source_budget(Limits.SOURCE_BUDGET_S):     # R2.5: one source cannot hold its host's thread past this
        raws, state = collect.collect(source, state, now, seen=seen,
                                      known_item=lambda s, g: store.get_item(keys.item_id(s, g)) is not None)
    key = None
    if raws:
        key = f"raw/{slot[:10]}/{slot}/{sid}.jsonl"
        _s3.put_object(Bucket=os.environ["RAW_BUCKET"], Key=key, ContentType="application/x-ndjson",
                       Body="\n".join(json.dumps(r.to_dict(), ensure_ascii=False) for r in raws).encode())
    if seen != before:              # only after the batch is safely in S3: a SEEN ahead of S3 would lose entries forever
        store.put_source_state(SEEN_PREFIX + sid, {"h": seen})
    store.put_source_state(sid, state)
    ok = state.get("consecutive_failures", 0) == 0
    log.info(json.dumps({"station": "collect", "source": sid, "items": len(raws), "ok": ok,
                         "error": None if ok else state.get("last_error")}))
    return {"source_id": sid, "key": key, "count": len(raws), "ok": ok}


def collect_batch(event: dict[str, Any], _ctx: Any = None) -> dict[str, Any]:
    """One Map iteration = a batch of sources (collect.batches). Host groups run concurrently, a host's sources
    serially; a source not started before COLLECT_DEADLINE_S is skipped — logged, its state untouched, so it is due
    again next cycle — instead of the whole invocation timing out and losing every result of the batch."""
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor
    t_end = time.monotonic() + Limits.COLLECT_DEADLINE_S
    slot, local = event["slot"], threading.local()

    def store() -> Any:      # boto3 resources are not thread-safe: one per worker thread
        if not hasattr(local, "s"):
            local.s = DynamoStore(boto3.session.Session().resource("dynamodb").Table(os.environ["TABLE"])) \
                if os.environ.get("TABLE") else _store
        return local.s

    def run_group(ids: list[str]) -> list[dict[str, Any]]:
        out, failed_in_row = [], 0
        for sid in ids:
            # R2.5 host breaker: a host's sources run serially here (24 WeChat feeds on wechat2rss, 21 Telegram channels
            # on t.me). After HOST_BREAKER_AFTER failures in a row the host is down for this run — the rest are skipped,
            # their state untouched, so they are due next cycle instead of each waiting out its own timeout now.
            if failed_in_row >= Limits.HOST_BREAKER_AFTER:
                log.warning(json.dumps({"station": "collect", "source": sid, "skipped": "host_breaker",
                                        "host": collect._host(BY_ID[sid])}))
                out.append({"source_id": sid, "key": None, "count": 0, "ok": False, "skipped": "host_breaker"})
                continue
            if time.monotonic() > t_end:
                log.warning(json.dumps({"station": "collect", "source": sid, "skipped": "batch_deadline"}))
                out.append({"source_id": sid, "key": None, "count": 0, "ok": False, "skipped": "batch_deadline"})
                continue
            try:
                out.append(_collect_source(store(), sid, slot))
                failed_in_row = 0 if out[-1]["ok"] else failed_in_row + 1
            except Exception as e:  # noqa: BLE001 — logged + reported per source; batch-mates' results must survive
                log.error(json.dumps({"station": "collect", "source": sid, "error": f"{type(e).__name__}: {e}"[:300]}))
                try:      # the failure goes on the source's record, or #/sources keeps saying ok
                    s = store()
                    s.put_source_state(sid, collect.crashed(s.get_source_state(sid), timeutil.now(), e))
                except (BotoCoreError, ClientError) as e2:
                    log.error(json.dumps({"station": "collect", "source": sid, "degraded": "crash_not_recorded",
                                          "error": str(e2)[:200]}))
                out.append({"source_id": sid, "key": None, "count": 0, "ok": False, "error": type(e).__name__})
                failed_in_row += 1
        return out
    groups: dict[str, list[str]] = {}
    for sid in event["source_ids"]:
        groups.setdefault(collect._host(BY_ID[sid]), []).append(sid)
    with ThreadPoolExecutor(min(Limits.COLLECT_THREADS, len(groups) or 1)) as ex:
        results = [r for rs in ex.map(run_group, groups.values()) for r in rs]
    return {"results": results}


WATERMARK_KEY = "__raw_watermark__"
RAW_BAD_KEY = "__raw_bad__"  # {batch key: {lines, first_line, error, at}} — the newest 50; #/ops raw_lines_skipped
REFRESH_KEY = "__refresh__"  # {"at": the last time-driven refresh} — single writer: the process station


def _refresh_due(now: datetime) -> bool:
    """Hourly by ledger, not by clock phase: `now.minute < CYCLE_MINUTES` gave an hour two refreshes or none, since
    rate(5 min) is not aligned to the hour, Process's `now` drifts with Collect's duration and an overlap-skipped cycle
    takes its slot (research 07 B8). No ledger yet (first run) ⇒ due."""
    last = timeutil.parse((_store.get_source_state(REFRESH_KEY) or {}).get("at"))
    return last is None or now - last >= timedelta(minutes=Limits.REFRESH_EVERY_MINUTES)


def _pending_raw_keys(now: Any, slot: str | None = None) -> list[str]:
    """Raw batches not yet processed. With a cycle slot: only keys after the watermark (the last processed slot) and
    not later than this slot — O(batches since the last successful run), not O(two days of batches) (research/17 §4.1:
    the old listing grows linearly, ~43k GetItems per run at 150 sources). A failed run leaves the watermark behind, so
    the next run picks its batches up. Without a slot (manual runs): every unprocessed key of today and yesterday."""
    bucket, keys_ = os.environ["RAW_BUCKET"], []
    wm = (_store.get_source_state(WATERMARK_KEY) or {}).get("key", "") if slot else ""
    for day in sorted({timeutil.iso(now)[:10], timeutil.iso(now - timedelta(days=1))[:10]}):
        kw = {"Bucket": bucket, "Prefix": f"raw/{day}/", **({"StartAfter": wm} if wm else {})}
        for page in _s3.get_paginator("list_objects_v2").paginate(**kw):
            keys_ += [o["Key"] for o in page.get("Contents", [])]
    if slot:
        cap = f"raw/{slot[:10]}/{slot}/~"
        keys_ = [k for k in keys_ if k <= cap]
    return sorted(k for k in keys_ if not _store.is_raw_processed(k))


@_timed("process")
def process(event: dict[str, Any], _ctx: Any = None) -> dict[str, Any]:
    now = timeutil.now()
    slot = event.get("slot")
    pending = _pending_raw_keys(now, slot)
    raws: list[RawItem] = []
    bad: dict[str, dict[str, Any]] = {}
    for key in pending:
        body = _s3.get_object(Bucket=os.environ["RAW_BUCKET"], Key=key)["Body"].read().decode("utf-8", "replace")
        for n, line in enumerate(body.splitlines(), 1):
            if not line.strip():
                continue
            # one line that does not parse used to fail the whole run; the watermark stayed behind, every later run
            # re-read and failed on it, and after two days the batch fell out of the listing unprocessed — everything
            # in it lost without a word (audit 05 1.6). Now the line is skipped and counted; the batch is processed.
            try:
                raws.append(RawItem.from_dict(json.loads(line)))
            except (ValueError, TypeError, KeyError) as e:
                b = bad.setdefault(key, {"lines": 0, "first_line": n, "error": f"{type(e).__name__}: {str(e)[:120]}"})
                b["lines"] += 1
    if bad:
        log.error(json.dumps({"station": "process", "degraded": "raw_lines_skipped", "batches": len(bad),
                              "lines": sum(b["lines"] for b in bad.values())}))
        led = _store.get_source_state(RAW_BAD_KEY)
        led.update({k: {**v, "at": timeutil.iso(now)} for k, v in bad.items()})
        _store.put_source_state(RAW_BAD_KEY, dict(sorted(led.items(), key=lambda kv: kv[1]["at"])[-50:]))
    raws.sort(key=lambda x: x.published_at or now)
    res = pipeline.ingest(raws, _store, now)
    latency.record(_store, res.held, now)     # published → held, for #/ops collect_latency (roadmap R0.5)
    if res.anomalies:     # an event changed shape this cycle (radar.anomaly): #/ops error + the owner's ops push
        anomaly.record(_store, res.anomalies, now)
        log.error(json.dumps({"station": "process", "degraded": "event_anomaly", "count": len(res.anomalies),
                              "first": res.anomalies[0]}, ensure_ascii=False))
    if any(BY_ID.get(r.source_id) and BY_ID[r.source_id].board for r in raws):     # exchange notices ⇒ the board
        _store.put_source_state(announcements.BOARD_KEY, announcements.board_add(
            _store.get_source_state(announcements.BOARD_KEY), raws, BY_ID, timeutil.iso(now)))
    for key in pending:  # only after a successful ingest
        _store.mark_raw_processed(key, timeutil.iso(now))
    if slot:
        _store.put_source_state(WATERMARK_KEY, {"key": f"raw/{slot[:10]}/{slot}/~", "at": timeutil.iso(now)})
    # rolling counters for the funnel ("how much work the system did"); kept beside source states
    st = _store.get_source_state(FUNNEL_KEY)
    day_ago = timeutil.iso(now - timedelta(days=1))
    st["runs"] = [r for r in st.get("runs", []) if r[0] >= day_ago] + \
        [[timeutil.iso(now), len(raws), res.new_items + res.updated_items]]
    _store.put_source_state(FUNNEL_KEY, st)
    # age-driven recompute (V4 finalization) only needs to run hourly, not every cycle
    refreshed = []
    if event.get("full") or _refresh_due(now):
        refreshed = pipeline.refresh(_store, now)
        _store.put_source_state(REFRESH_KEY, {"at": timeutil.iso(now)})      # only after it ran
    chain.start_cycle()                              # one wall-clock RPC budget for the three on-chain steps below
    onchain = pipeline.verify_onchain(_store, now)   # C6: ≤ CHAIN_CHECKS_PER_CYCLE public-RPC calls, never raises
    traced = onchain_station.cycle(_store, now)       # M4 D6: P0 web3 reconstruction, ≤ ONCHAIN_CALLS_PER_CYCLE calls
    decoded = attacktx.cycle(_store, now)            # M4.1 E3: attack-tx breakdown, ≤ ATTACKTX_CALLS_PER_CYCLE calls
    disposed = triage.changed(_store)                 # D: operator dispositions (scripts/triage.py) ⇒ republish
    retitled = retitle.changed(_store)                # root-cause title corrections (scripts/retitle.py) ⇒ republish
    changed = set(res.changes) | set(refreshed) | set(onchain) | set(traced) | set(decoded) | set(disposed) | set(retitled)
    log.info(json.dumps({"station": "process", "batches": len(pending), "raw": len(raws), "new": res.new_items,
                         "updated": res.updated_items, "unchanged": res.unchanged_items,
                         "events_changed": len(changed)}))
    ids = sorted(changed)
    return {"changed": ids[:MAX_CHANGED_IDS], "full": len(ids) > MAX_CHANGED_IDS or bool(event.get("full"))}


def _evidence(ev: Any) -> list[dict[str, Any]]:
    items = sorted(_store.get_items(ev.item_ids), key=lambda i: (i.published_at, i.source_id, i.item_id))
    return [{"item_id": i.item_id, "source": BY_ID[i.source_id].name if i.source_id in BY_ID else i.source_id,
             "tier": i.tier, "published_at": i.published_at, "title": i.title, "text": i.text} for i in items]


def _structured_ids(ev: Any) -> set[str]:
    """Reports from hack databases / KEV (Source.always_eventful): a brief keeps them whatever its size (R1.8)."""
    return {it.item_id for it in _store.get_items(ev.item_ids)
            if BY_ID.get(it.source_id) and BY_ID[it.source_id].always_eventful}


@_timed("analyze")
def analyze_events(event: dict[str, Any], _ctx: Any = None) -> dict[str, Any]:
    """Analyst station: P0/P1 events whose evidence changed get a (re)generated, code-validated brief."""
    from radar import analyst
    now = timeutil.now()
    since = timeutil.iso(now - timedelta(days=publish.Limits.PUBLISH_WINDOW_DAYS))
    store = _store
    if store is None:          # the station runs with its table; no table is a wiring fault, said — never a silent skip
        raise RuntimeError("analyze: no store (TABLE is not set)")
    todo, kept, stamped, reasons = [], 0, 0, {}
    now_iso = timeutil.iso(now)
    for ev in store.events_updated_since(since):
        if ev.severity not in ("P0", "P1"):
            continue
        ev_in = analyst.trim_evidence(_evidence(ev), _structured_ids(ev))
        facts = analyst.facts_of(ev)
        why = analyst.needs_rewrite(ev.analysis, ev_in, facts, now_iso)
        if why is None:
            if ev.analysis and "facts" not in ev.analysis and stamped < Limits.BRIEF_FACT_STAMPS_PER_RUN:
                # a brief from before the facts rule, still current: record its facts, no model call (else each of
                # the 817 live 11-19 would be rewritten once on its next report — the wave seen after deploy)
                ev.analysis = {**ev.analysis, "facts": facts}
                store.put_event(ev)
                stamped += 1
            elif (ev.analysis or {}).get("input_hash") != analyst.input_hash(ev_in):
                kept += 1                   # evidence moved but no code-decided fact did: the brief stays
            continue
        reasons[why] = reasons.get(why, 0) + 1
        todo.append((0 if ev.severity == "P0" else 1, ev.last_updated, ev, ev_in))
    todo.sort(key=lambda t: (t[0], -_ts(t[1])))
    left = _time_left(_ctx)
    # attack paths first: ≤ ATTACK_PATHS_PER_CYCLE calls, and before 11-19 the briefs filled the run (avg 448 s of 600) so
    # the paths after them rarely started — 36 events built in 14 h while 660 P1s had none
    log.info(json.dumps({"station": "analyze", "to_rewrite": len(todo), "why": reasons, "kept_not_material": kept,
                         "facts_stamped": stamped}))
    paths = _attack_paths(now, since, left)
    done, deferred = [], 0
    for _, _, ev, ev_in in todo[:MAX_ANALYSES_PER_CYCLE]:
        if left is not None and left() < Limits.MODEL_CALL_RESERVE_S:   # briefs: no call started without the reserve
            deferred = min(len(todo), MAX_ANALYSES_PER_CYCLE) - len(done)   # said, not timed out: the next run takes them
            log.info(json.dumps({"station": "analyze", "deferred": deferred, "reason": "time_left", "left_s": round(left())}))
            break
        ev.analysis = {**analyst.analyze(ev_in, timeutil.iso(now)), "facts": analyst.facts_of(ev)}
        store.put_event(ev)
        done.append(ev.event_id)
        log.info(json.dumps({"station": "analyze", "event": ev.event_id, "status": ev.analysis["status"],
                             "reason": ev.analysis.get("reason")}))
    _daily_digest(now)
    dup = _cluster_judge(now)
    try:
        aliased = _ghsa_alias(now)
    except Exception as ex:  # noqa: BLE001 — a third-party lookup never fails the Analyze step (security review 2026-11-20)
        aliased = []
        log.warning(json.dumps({"station": "analyze", "warning": "ghsa_alias_failed", "error": type(ex).__name__}))
        store_ = _store
        if store_ is not None:                               # "__ghsa_alias__" = ghsa_alias.KEY (lazy module)
            st_ = dict(store_.get_source_state("__ghsa_alias__") or {})
            store_.put_source_state("__ghsa_alias__", {**st_, "last_error": {"at": timeutil.iso(now), "error": type(ex).__name__}})
    _retitle_shadow(now)
    changed = sorted(set(event.get("changed") or []) | set(done) | set(dup) | set(paths) | set(aliased))
    return {"changed": changed[:MAX_CHANGED_IDS], "full": bool(event.get("full")), "analysis_backlog": len(todo) - len(done),
            "analysis_deferred": deferred}


def _attack_paths(now: datetime, since: str, left: Any = None) -> list[str]:
    """R9.5: (re)build the attack path of P0 / P1 vulnerability events whose evidence changed, P0 first, at most
    Limits.ATTACK_PATHS_PER_CYCLE model calls (the brief keeps its own budget). Returns the events whose page changed."""
    from radar import analyst, attack_path
    if _store is None:
        raise RuntimeError("attack_path: no store (TABLE is not set)")
    todo = []
    for ev in _store.events_updated_since(since):
        if ev.domain != "vuln" or ev.severity not in ("P0", "P1"):
            continue
        path_in = analyst.trim_evidence(_evidence(ev), _structured_ids(ev))
        row = _store.get_source_state(attack_path.key(ev.event_id)) or {}
        if row.get("input_hash") != attack_path.input_hash(path_in):
            todo.append((0 if ev.severity == "P0" else 1, -_ts(ev.last_updated), ev.event_id, path_in))
    done = []
    for _, _, eid, path_in in sorted(todo)[:Limits.ATTACK_PATHS_PER_CYCLE]:
        if left is not None and left() < Limits.MODEL_CALL_RESERVE_S:
            log.info(json.dumps({"station": "attack_path", "deferred": len(todo) - len(done), "reason": "time_left"}))
            break
        row = attack_path.build(path_in, timeutil.iso(now))
        _store.put_source_state(attack_path.key(eid), row)
        done.append(eid)
        log.info(json.dumps({"station": "attack_path", "event": eid, "status": row["status"], "reason": row.get("reason"),
                             "dropped_defenses": row.get("dropped_defenses", 0)}))
    log.info(json.dumps({"station": "attack_path", "backlog": len(todo) - len(done)}))   # coverage is measured, not guessed
    return done


DIGEST_KEY = digest.KEY  # C7: the latest daily digest (single writer: the analyze station)
DUP_KEY = "__cluster_judge__"  # C4: {"pairs": {pair_key: verdict row}} (single writer: the analyze station)


def _cluster_judge(now: datetime) -> list[str]:
    """C4: judge new candidate pairs (≤ MAX_PAIRS_PER_CYCLE Haiku calls; reports read only for the events of the pairs
    judged); returns the events whose possible-duplicate list changed, or that a merge touched, so publish rebuilds
    their pages. SHADOW unless Limits.CLUSTER_AUTO_MERGE: would_merge rows only show in #/ops."""
    from radar import cluster_judge
    store = _store
    if store is None:      # the station runs with its table; no table is a wiring fault, said — never a silent skip
        raise RuntimeError("cluster judge: no store")
    held = cluster_judge.load(store, DUP_KEY)
    before = {k: v.get("verdict") for k, v in held.items()}
    evs = store.events_updated_since(timeutil.iso(now - timedelta(days=publish.Limits.PUBLISH_WINDOW_DAYS)))
    pairs, calls = cluster_judge.run(evs, held, timeutil.iso(now), get_items=store.get_items)
    merged = cluster_judge.merge(store, pairs, now)        # [] while Limits.CLUSTER_AUTO_MERGE is False
    cluster_judge.save(store, DUP_KEY, pairs)
    touched = sorted({e for k, v in pairs.items() if v.get("verdict") == "same" and before.get(k) != "same"
                      for e in (v["a"], v["b"])} | {e for m in merged for e in (m["into"], m["from"])})
    would = sum(1 for v in pairs.values() if v.get("would_merge") and not v.get("merged"))
    if calls or touched or merged:
        log.info(json.dumps({"station": "analyze", "cluster_judge_calls": calls, "possible_duplicates_new": len(touched) // 2,
                             "would_merge": would, "auto_merge": Limits.CLUSTER_AUTO_MERGE}))
    for m in merged:                 # the ledger row leaves with the smaller event: the log keeps the undo
        log.info(json.dumps({"station": "analyze", "cluster_merge": m}, ensure_ascii=False))
    _judge_truth(store, pairs, evs, now)
    return touched


def _ghsa_alias(now: datetime, get: Callable[[str], tuple[int, Any]] | None = None) -> list[str]:
    """R12: link GitHub advisory ids to CVEs (radar.ghsa_alias) for vulnerability events that name a GHSA and no CVE;
    a new link gives the event's reports naming that GHSA the CVE key and re-attaches them (pipeline.attach: the two
    events of one flaw become one). Bounded: ≤ GHSA_ALIAS_PER_RUN lookups, ≤ 1 unreviewed scan per GHSA_ALIAS_SCAN_MIN.
    No token ⇒ the state says not_configured (never a silent skip). Returns the events whose page changed."""
    from radar import ghsa_alias, pipeline
    store = _store
    if store is None:
        raise RuntimeError("ghsa alias: no store")
    st = dict(store.get_source_state(ghsa_alias.KEY) or {})
    amap, checked = dict(st.get("map") or {}), dict(st.get("checked") or {})
    nowi = timeutil.iso(now)
    evs = [e for e in store.events_updated_since(timeutil.iso(now - timedelta(days=30)))
           if e.domain == "vuln" and not e.cves and any(k.startswith("ghsa:") for k in e.keys)]
    pending = {k[5:] for e in evs for k in e.keys if k.startswith("ghsa:")} - set(amap)
    if not pending:
        return []
    if get is None:
        arn = os.environ.get("GHSA_TOKEN_SECRET_ARN")
        try:
            token = boto3.client("secretsmanager").get_secret_value(SecretId=arn)["SecretString"].strip() if arn else ""
        except (ClientError, BotoCoreError) as e:
            # the published state (#/ops, readable with a radar/read token) carries the error code only: an AccessDenied
            # message names the account id and the role ARN (security review 2026-11-20). The full text goes to the private log.
            code = (getattr(e, "response", None) or {}).get("Error", {}).get("Code") or type(e).__name__
            log.warning(json.dumps({"station": "analyze", "degraded": "ghsa_token_unreadable", "error": str(e)[:300]}))
            store.put_source_state(ghsa_alias.KEY, {**st, "status": "error", "error": code, "at": nowi})
            return []
        if not token.startswith("github_pat_"):     # CDK creates a placeholder; scripts/set-ghsa-token.sh sets the value
            store.put_source_state(ghsa_alias.KEY, {**st, "status": "not_configured", "pending": len(pending), "at": nowi})
            return []
        get = ghsa_alias.github_get(token)
    due = sorted(g for g in pending if not checked.get(g) or
                 now - (timeutil.parse(checked[g]) or now) >= timedelta(hours=Limits.GHSA_ALIAS_RECHECK_H))
    texts = [f"{i.title}\n{i.text}\n" + " ".join(i.links) for e in evs for i in store.get_items(e.item_ids[:40])]
    repos = ghsa_alias.repo_advisories(texts)
    found: dict[str, dict[str, Any]] = {}
    for g in due[:Limits.GHSA_ALIAS_PER_RUN]:
        r = ghsa_alias.resolve(g, repos, get)
        checked[g] = nowi
        if r["cve"]:
            found[g] = {"cve": r["cve"], "via": r["via"], "at": nowi}
    last_scan = timeutil.parse(st.get("scan_at") or "")
    if not last_scan or now - last_scan >= timedelta(minutes=Limits.GHSA_ALIAS_SCAN_MIN):
        since = timeutil.iso(last_scan - timedelta(minutes=5)) if last_scan else timeutil.iso(now - timedelta(days=2))
        for g, cve in ghsa_alias.scan_unreviewed(pending - set(found), since, get).items():
            found[g] = {"cve": cve, "via": "unreviewed_reference", "at": nowi}
        st["scan_at"] = nowi
    touched: set[str] = set()
    res = pipeline.IngestResult()
    for g, row in found.items():
        amap[g] = row
        for e in evs:
            if f"ghsa:{g}" not in e.keys:
                continue
            for it in store.get_items(e.item_ids):
                if f"ghsa:{g}" in it.keys and f"cve:{row['cve']}" not in it.keys:
                    it.keys = sorted({*it.keys, f"cve:{row['cve']}"})
                    store.put_item(it)
                    pipeline.attach(it, store, nowi, now, res)
                    touched.add(e.event_id)
    exp = (getattr(get, "seen", None) or {}).get("token_expires") or st.get("token_expires")
    store.put_source_state(ghsa_alias.KEY, {**st, "map": amap, "checked": checked, "status": "ok", "at": nowi,
                                            "pending": len(pending - set(found)), **({"token_expires": exp} if exp else {})})
    if found:
        log.info(json.dumps({"station": "analyze", "ghsa_alias": {g: r["cve"] for g, r in found.items()},
                             "events": sorted(touched)}))
    return sorted(touched)


JUDGE_TRUTH_KEY = "__judge_truth__"   # once a day: the judge's verdicts scored against delayed truth (#/ops)


def _judge_truth(store: Any, pairs: dict[str, Any], evs: list[Any], now: datetime) -> None:
    """Step 2 of measuring the shadow judge without a person (Neo 11-19): once a day, model verdicts ≥ 2 days old are
    scored against facts read now — shared attack tx / attacker / CVE, contradictions, hack-database records
    (cluster_judge.delayed_truth). Reads reports only of the judged events (≤ 60 each), once a day."""
    from radar import cluster_judge
    day = timeutil.iso(now)[:10]
    if (store.get_source_state(JUDGE_TRUTH_KEY) or {}).get("day") == day:
        return
    by_id = {e.event_id: e for e in evs}
    ids = {v[k] for v in pairs.values() for k in ("a", "b") if v.get(k) in by_id}
    db = {sid for sid, s in BY_ID.items() if s.always_eventful}
    records = {}
    for eid in ids:
        recs = {(i.source_id, i.item_id) for i in store.get_items(by_id[eid].item_ids[:60]) if i.source_id in db}
        if recs:
            records[eid] = recs
    rep = cluster_judge.truth_report(pairs, by_id, {e: e for e in ids}, timeutil.iso(now), records=records)
    store.put_source_state(JUDGE_TRUTH_KEY, {"day": day, "at": timeutil.iso(now),
                                             **{k: v for k, v in rep.items() if k != "rows"}, "rows": rep["rows"][:50]})
    log.info(json.dumps({"station": "analyze", "judge_truth": {k: v for k, v in rep.items() if k != "rows"}}))


def _retitle_shadow(now: datetime) -> None:
    """Root-cause title proposals (≤ 2 Sonnet calls/cycle), shadow only: rows land in #/ops for an operator to adopt
    with scripts/retitle.py; no published title changes here."""
    from radar import retitle, retitle_judge
    evs = _store.events_updated_since(timeutil.iso(now - timedelta(days=retitle_judge.RECENT_DAYS)))
    stored = _store.get_source_state(retitle_judge.KEY)
    st, calls = retitle_judge.run(evs, _store.get_items, stored, _store.get_source_state(retitle.KEY), now)
    if calls or st != stored:            # an adopted proposal leaves (and is tallied) without a model call
        _store.put_source_state(retitle_judge.KEY, st)
        log.info(json.dumps({"station": "analyze", "retitle_shadow_calls": calls,
                             "proposals": sum(1 for v in st.values() if v.get("verdict") == "propose")}))


def _daily_digest(now: datetime) -> None:
    """C7: once a day after 08:00 HKT (digest.due), ≤ MAX_ATTEMPTS tries; the outcome — ok, partial, failed with
    a reason, or a quiet day — is stored and published as is."""
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


def _enrich(cves: list[str], now: datetime, left: Any = None) -> tuple[dict[str, dict[str, float]], set[str]]:
    """radar.enrich over every published CVE: CVE records (budget shrinks with the invocation's remaining time: pages
    first, backfill with spare time) + daily EPSS; returns (EPSS, touched CVEs ⇒ their pages are rebuilt)."""
    from radar import enrich, fetch
    lim = publish.Limits
    budget = lim.CVE_META_BUDGET_S if left is None else min(lim.CVE_META_BUDGET_S, max(0.0, left() - 180))
    epss, touched, stats = enrich.run(_store, cves, now, lambda url: fetch.http_get(url, {"Accept": "application/json"}).body,
                                      budget)
    _store.put_source_state(publish.ENRICH_KEY, stats)    # before ops.json is built ⇒ this run's health is shown
    return epss, touched


def _aws_fix(cves: list[str], now: datetime) -> set[str]:
    """radar.awsfix for the CVEs of P0 / P1 vulnerability events (publish.build picks them): AWS's own fix status, read from
    the Amazon Linux Security Center (only that host). Its health joins the enrich stats on #/ops."""
    from radar import awsfix, fetch
    if _store is None:      # installed at import when TABLE is set; a publish without a table is a wiring error
        raise RuntimeError("aws_fix: no store (TABLE is not set)")
    stats = dict(_store.get_source_state(publish.ENRICH_KEY) or {})
    touched = awsfix.refresh(_store, cves, now, lambda url: fetch.http_get(url, {"Accept": "text/html"},
                                                                        allow_hosts=frozenset({awsfix.HOST})).body,
                             stats=stats)
    _store.put_source_state(publish.ENRICH_KEY, stats)
    return touched


def _timeout_watchdog(station: str, left: Any, timings: dict[str, Any]) -> Callable[[], None]:
    """Live 2026-11-11: Publish hit the Lambda timeout with nothing logged after its first line — which phase hung was
    unknowable. Shortly before the deadline, log the phase timings so far and the main thread's stack; returns stop()."""
    import sys
    import threading
    import traceback
    if left is None:
        return lambda: None
    done = threading.Event()
    main = threading.get_ident()

    def watch() -> None:
        if done.wait(max(0.0, left() - Limits.TIMEOUT_WATCHDOG_S)):
            return
        frame = sys._current_frames().get(main)
        stack = traceback.format_stack(frame)[-12:] if frame else []
        log.error(json.dumps({"station": station, "degraded": "about_to_time_out", "phases": dict(timings),
                              "seconds_left": round(left(), 1), "stack": [ln.strip() for ln in stack]}))
    threading.Thread(target=watch, daemon=True).start()
    return done.set


def _time_left(ctx: Any):
    """Seconds left in this invocation (None outside Lambda: tests and scripts have no deadline)."""
    if ctx is None or not hasattr(ctx, "get_remaining_time_in_millis"):
        return None
    return lambda: ctx.get_remaining_time_in_millis() / 1000


PENDING_KEY = publish.PENDING_KEY


def _read_site_json(bucket: str, key: str) -> dict[str, Any] | None:
    try:
        return json.loads(_s3.get_object(Bucket=bucket, Key=key)["Body"].read())
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") in ("NoSuchKey", "404"):
            return None
        raise


def _publish_search(bucket: str, now: Any, events: list[Any] | None = None, published: set[str] | None = None) -> int:
    """Merge the window's events (or `events`, for a backfill) into their month shards and refresh the index
    (radar.search). The window read is the station's cached one (DynamoStore.events_updated_since).
    published = ids whose detail doc this run wrote: their rows are marked linkable (search.record "p").
    Events that stopped existing (radar.removals) leave their shard and their detail page here."""
    if _store is None:      # installed at import when TABLE is set; a publish without a table is a wiring error
        raise RuntimeError("publish: no store (TABLE is not set)")
    if events is None:
        events = _store.events_updated_since(timeutil.iso(now - timedelta(days=Limits.PUBLISH_WINDOW_DAYS)))
    at = timeutil.iso(now)
    fixes = _store.get_source_state(retitle.KEY)
    titles = {e.event_id: f["title"] for e in events if (f := retitle.public(fixes.get(e.event_id), e.title))}
    # an id the ledger lists may be live again (a repair re-seeds ids) — that one keeps its row and page
    gone = {eid: r for eid, r in removals.pending(_store).items() if _store.get_event(eid) is None}
    idx = _read_site_json(bucket, "data/search/index.json") or {"months": []}
    counts = {m["month"]: m["events"] for m in idx.get("months") or []}
    fresh_by_month = search.shards(events, published or set(), titles)
    by_id = {e.event_id: e for e in events}
    reads = 0
    # newest month first: during the R3.5 backfill the per-run read cap goes to the rows readers search most
    for m in sorted(set(fresh_by_month) | {r.get("m") for r in gone.values() if r.get("m")}, reverse=True):
        old = (_read_site_json(bucket, f"data/search/{m}.json") or {}).get("events") or []
        if m not in fresh_by_month and not {r["id"] for r in old} & gone.keys():
            continue                                  # a removed event's month that never had its row
        # R3.5: a row without a detail page gets its source URL ("r"), read once — merge keeps it after that. Capped per
        # run: the first runs after this change backfill the window a few hundred rows at a time.
        had = {r["id"] for r in old if r.get("r") or r.get("p")}
        need = [r for r in fresh_by_month.get(m, []) if not r.get("p") and r["id"] not in had]
        need = need[:max(0, Limits.SEARCH_URL_READS_PER_RUN - reads)]
        first = {r["id"]: fid for r in need if (fid := search.first_item_id(by_id[r["id"]]))}
        if first:
            reads += len(first)
            urls = {it.item_id: search.source_url(it.url) for it in _store.get_items(sorted(set(first.values())))}
            for r in need:
                if (u := urls.get(first.get(r["id"], ""))):
                    r["r"] = u
        rows = search.merge(old, fresh_by_month.get(m, []), drop=gone.keys())
        counts[m] = len(rows)
        if rows == old:
            continue                                  # R2.6: same rows ⇒ no rewrite (≈ 50 shards, 2+ MB every cycle)
        _s3.put_object(Bucket=bucket, Key=f"data/search/{m}.json", ContentType="application/json",
                       CacheControl="max-age=300", Body=json.dumps(search.shard_doc(m, rows, at), ensure_ascii=False).encode())
    _s3.put_object(Bucket=bucket, Key="data/search/index.json", ContentType="application/json", CacheControl="max-age=60",
                   Body=json.dumps(search.index_doc(counts, at)).encode())
    ids, failed = sorted(gone), []
    for i in range(0, len(ids), 1000):                # an old link to a removed event must not open its stale page
        r = _s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": f"data/events/{e}.json"} for e in ids[i:i + 1000]],
                                                      "Quiet": True})
        failed += r.get("Errors") or []               # per-key failures (AccessDenied …) come back here, not as raises
    if failed:
        # not marked pruned ⇒ retried next run; the rows are already gone, only the pages remain
        log.error(json.dumps({"station": "publish", "degraded": "removed_event_pages_not_deleted", "count": len(failed),
                              "first": failed[0]}))
    else:
        removals.mark_pruned(_store, list(removals.pending(_store)), at)
    if ids:
        log.info(json.dumps({"station": "publish", "pruned_removed_events": len(ids), "page_delete_errors": len(failed)}))
    return len(counts)


def _publish_feeds(bucket: str, rows: list[dict[str, Any]], now: datetime, deferred: set[str]) -> None:
    """P3 pull: JSON Feed + Atom per radar.feeds.FEEDS filter, under data/ (behind the site's Basic Auth)."""
    from radar import feeds
    mit = _store.get_source_state("__mitigate__").get("events") or {}
    for path, (body, ctype) in feeds.documents(rows, mit, now, os.environ.get("SITE_URL", ""), deferred).items():
        _s3.put_object(Bucket=bucket, Key=f"data/{path}", Body=body, ContentType=ctype, CacheControl="max-age=60")


def _surge(rows: list[dict[str, Any]], now: datetime) -> None:
    """R2.3: an event that BECAME P0 within Limits.SURGE_HOURS (first seen as one, or escalated) ⇒ T1 sources run at
    half cadence until SURGE_HOURS after that moment (collect.cadence). Not "a P0 updated": big P0s update every cycle,
    which would make the surge permanent (measured: +30 % runs, 22.8k → 29.8k a day). Written only when it changes;
    Plan reads it with the source states."""
    if _store is None:
        return
    became: dict[str, datetime] = {}
    for r in rows:
        ev = _store.get_event(r["event_id"]) if r.get("severity") == "P0" else None
        at = timeutil.parse(max(ev.first_seen or "", ev.escalated_at or "")) if ev else None
        if at is not None and at >= now - timedelta(hours=Limits.SURGE_HOURS):
            became[r["event_id"]] = at
    hot = sorted(became)
    until = timeutil.iso(max(became.values()) + timedelta(hours=Limits.SURGE_HOURS)) if became else None
    old = _store.get_source_state(collect.SURGE_KEY)
    new = {"until": until, "events": hot} if hot else {}
    if new != old:
        _store.put_source_state(collect.SURGE_KEY, new)


@_timed("publish")
def publish_site(event: dict[str, Any], _ctx: Any = None) -> dict[str, Any]:
    now = timeutil.now()
    left = _time_left(_ctx)
    led = _store.get_source_state(PENDING_KEY)
    pending = set(led.get("ids") or [])
    full = bool(event.get("full") or led.get("full"))
    incoming = set(event.get("changed") or [])
    changed = None if full else incoming | pending
    # R5.2 (audit 05 1.5): the cycle's change list lived only in this invocation's input — a Publish that timed out or
    # failed lost it, and those events' pages stayed stale until they changed again. Recorded before the build; a run
    # that finishes replaces it with what it deferred (below), a run that dies leaves it for the next one.
    if (full and not led.get("full")) or incoming - pending:
        _store.put_source_state(PENDING_KEY, {"ids": sorted(pending | incoming), "full": full, "at": timeutil.iso(now)})
        pending |= incoming
    import time
    from concurrent.futures import ThreadPoolExecutor
    deferred: list[str] = []
    timings: dict[str, float] = {}
    stop = _timeout_watchdog("publish", left, timings)
    t = [time.monotonic()]
    try:
        docs = publish.build(_store, now, changed, enrich=lambda cves: _enrich(cves, now, left),
                             aws_fix=lambda cves: _aws_fix(cves, now), time_left=left,
                             deferred=deferred, timings=timings)
    finally:
        stop()
    t.append(time.monotonic())
    bucket = os.environ["SITE_BUCKET"]

    def put(item: tuple[str, Any]) -> None:
        _s3.put_object(Bucket=bucket, Key=f"data/{item[0]}", Body=json.dumps(item[1], ensure_ascii=False).encode(),
                       ContentType="application/json", CacheControl="max-age=60")
    # one at a time, ~400 pages took tens of seconds after the build had already used its time (live 2026-11-11:
    # publish timed out at 300 s every 15 min); the S3 client is thread-safe, a failed put still raises here
    with ThreadPoolExecutor(16) as ex:
        list(ex.map(put, docs.items()))
    t.append(time.monotonic())
    _surge(docs["events.json"]["events"], now)
    if deferred or pending or led.get("full") or full:
        _store.put_source_state(PENDING_KEY, {"ids": deferred, "at": timeutil.iso(now)})
    _publish_feeds(bucket, docs["events.json"]["events"], now, set(deferred))
    # only these events have a page; the shards hold the whole window (live: most search hits were 「事件不存在」)
    months = _publish_search(bucket, now, published={p[len("events/"):-len(".json")] for p in docs if p.startswith("events/")})
    t.append(time.monotonic())
    log.info(json.dumps({"station": "publish", "docs": len(docs), "deferred": len(deferred), "search_months": months,
                         "seconds": {"build": round(t[1] - t[0], 1), "write": round(t[2] - t[1], 1),
                                     "search": round(t[3] - t[2], 1)}, "build_phases": timings}))
    return {"docs": len(docs), "deferred": len(deferred)}


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


def _open_job_ids(led: dict[str, Any], now: datetime, in_window: set[str]) -> list[str]:
    """Events whose response still has open jobs (respond.has_open_jobs), kept in the ledger by respond_events.
    A ledger written before the list existed is bootstrapped once from the last RESPOND_OPEN_JOBS_BOOTSTRAP_DAYS —
    the live rows already stuck outside the window would otherwise never be found again."""
    if "open_jobs" in led:
        return list(led["open_jobs"])
    from radar import respond
    since = timeutil.iso(now - timedelta(days=publish.Limits.RESPOND_OPEN_JOBS_BOOTSTRAP_DAYS))
    return [e.event_id for e in _store.events_updated_since(since)
            if e.event_id not in in_window and e.domain in ("vuln", "web3") and e.severity in ("P0", "P1")
            and respond.has_open_jobs(_store.get_response(e.event_id))]


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


def _sync_prs(led: dict[str, Any], now: datetime) -> list[str]:
    """C2c: links of the PRs opened by the scheduled deliver_prs.py → delivered_prs of their events (single writer).
    Not configured / failing ⇒ recorded in the ledger (pr_sync), never raised: the station must still publish."""
    arn = os.environ.get("DEMO_FLEET_RO_SECRET_ARN")
    last = timeutil.parse((led.get("pr_sync") or {}).get("at"))
    if not arn or (last and now - last < timedelta(hours=publish.Limits.PR_SYNC_H)):
        return []
    nowi = timeutil.iso(now)
    repo = os.environ.get("FLEET_REPO", "your-org/security-radar-demo-fleet")
    try:
        token = boto3.client("secretsmanager").get_secret_value(SecretId=arn)["SecretString"].strip()
        if not token.startswith(("github_pat_", "ghp_")):  # CDK creates a placeholder; the value is set out of band
            led["pr_sync"] = {"at": nowi, "status": "not_configured"}
            return []
        pulls = prsync.fetch_pulls(repo, token)
    except (ClientError, BotoCoreError, OSError, ValueError) as e:  # OSError covers urllib's HTTPError / URLError
        led["pr_sync"] = {"at": nowi, "status": "error", "error": str(e)[:300]}
        log.warning(json.dumps({"station": "respond", "degraded": "pr_sync", "error": str(e)[:300]}))
        return []
    by_prefix = prsync.links(pulls, repo)
    touched = []
    since = timeutil.iso(now - timedelta(days=publish.Limits.PUBLISH_WINDOW_DAYS))
    for ev in _store.events_updated_since(since):
        urls = by_prefix.get(ev.event_id[:11])
        st = _store.get_response(ev.event_id) if urls else None
        if st is not None and prsync.apply(st, urls):
            _store.put_response(ev.event_id, st)
            touched.append(ev.event_id)
    prs = sorted(p["html_url"] for p in pulls if prsync.ours(p, repo))
    led["prs"] = prs
    led.setdefault("counters", {})["github_prs"] = len(prs)
    led["pr_sync"] = {"at": nowi, "status": "ok", "prs": len(prs), "events_updated": len(touched)}
    return touched


def reason_changed(prev: dict[str, Any] | None, elig: dict[str, Any]) -> bool:
    """An ineligible event's reason is re-recorded whenever it changes, not once: an event that escalated P1 → P0 but
    stays ineligible for another reason kept showing "P1/reported：只对 P0…" on a P0 page (live 2026-11-01: Polymarket,
    PHP2Shell). Unchanged ⇒ no write, so a quiet event is not republished every cycle."""
    return (prev or {}).get("eligibility") != elig


@_timed("respond")
def respond_events(event: dict[str, Any], _ctx: Any = None) -> dict[str, Any]:
    """Respond station: eligible events → AWS Security Agent (rule + code review + auto-fix) and AWS Continuum
    (context, located finding, scan); running jobs are polled every cycle. Waiting is a data row, not a sleep."""
    from radar import continuum_aws as aws
    from radar import decisions, respond
    from radar import targets as targets_mod
    from radar.targets import TARGETS
    passthrough = {"changed": event.get("changed") or [], "full": bool(event.get("full"))}
    now = timeutil.now()
    nowi = timeutil.iso(now)
    if not os.environ.get("SA_AGENT_SPACE_ID"):
        log.warning(json.dumps({"station": "respond", "degraded": "not_configured"}))
        # recorded in the ledger (N_STATION_OFF reads it): an existing ledger must not keep last cycle's rows looking
        # live. Written on the change only; the change republishes every page once (full), so no page keeps them
        off = _store.get_source_state(CONTINUUM_KEY)
        if (off.get(decisions.STATION_KEY) or {}).get("status") != decisions.STATION_OFF_STATUS:
            off[decisions.STATION_KEY] = {"status": decisions.STATION_OFF_STATUS, "at": nowi}
            _store.put_source_state(CONTINUUM_KEY, off)
            return {**passthrough, "full": True}
        return passthrough
    led = _store.get_source_state(CONTINUUM_KEY)
    # configured: the same flip back republishes every page once, the not-evaluated rows must not linger either
    flipped = (led.get(decisions.STATION_KEY) or {}).get("status") != decisions.STATION_ON
    led[decisions.STATION_KEY] = {"status": decisions.STATION_ON, "at": nowi}
    led.pop("notify", None)   # pre-P3 push status (handlers._notify); push status is radar.notify_station.STATUS_KEY now
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
    budget = respond.Budget(per_day - len(led["reviews"]), scan_ok, nowi[:10], s3_targets=targets_mod.on("s3"),
                            routes=dict(targets_mod.CHANNEL), now=nowi,
                            event_reviews=respond.event_reviews_on(dict(os.environ)))
    cn_down = "continuum_unavailable"   # the error every Continuum op records while env is None
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
    except aws.TooManyTargets as e:  # config outgrew one environment ⇒ same degradation, with the numbers (B8)
        log.warning(json.dumps({"station": "respond", "degraded": "too_many_targets", "message": str(e),
                                "actual": e.actual, "max": e.limit}))
        env, cn_down = None, f"continuum_unavailable: {e}"
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
    since = decisions.window_start("sa_requirement", "N_OUT_OF_WINDOW", now)   # the table's window (page reads it too)
    cands = [e for e in _store.events_updated_since(since) if e.domain in ("vuln", "web3") and e.severity in ("P0", "P1")]
    # B4: put_response never moves last_updated, so an event quiet for 7 days left the window with a review / finding /
    # scan still open and stayed 检查中 forever. The ledger keeps every event with open jobs; those are polled too.
    open_ids = set(_open_job_ids(led, now, {e.event_id for e in cands}))
    seen_ids = {e.event_id for e in cands}
    cands += [e for e in (_store.get_event(i) for i in sorted(open_ids - seen_ids)) if e]
    evaluated = {k: v for k, v in (led.get("evaluated") or {}).items() if k in {e.event_id for e in cands}}
    cands = respond.order(cands, evaluated)      # a queue, not a fixed order: the cap must not starve the tail
    touched, acted = [], 0
    work = []  # (ev, view, refs, prev, st) — phase 1 runs everything except review starts
    review_requests: list[tuple[str, Any]] = []

    def run(op: Any, view: dict[str, Any], refs: list[dict[str, Any]], st: dict[str, Any]) -> dict[str, Any]:
        if env is None and op.kind in respond.CONTINUUM_OPS:
            res: dict[str, Any] = {"error": cn_down}
        else:
            res = aws.execute(op, view, refs, st, env or {})
        st = respond.apply(st, op, res, nowi)
        if not res.get("error"):
            _tally(led, op, res, nowi)
        return st

    cap = publish.Limits.RESPOND_MAX_EVENTS
    for ev in cands:
        view, refs = _respond_view(ev)
        prev = _store.get_response(ev.event_id)
        # an event that cools down (P0 → P1 after 72 h) keeps its results: only never-acted-on events are short-cut
        # (live 2026-10-25: the PHP2Shell response — reviews, Continuum issues, patches — was overwritten here)
        elig = respond.eligibility(view, refs)
        if not elig["eligible"] and not respond.has_open_jobs(prev) and not (prev or {}).get("targets"):
            open_ids.discard(ev.event_id)
            if reason_changed(prev, elig):
                _store.put_response(ev.event_id, {"eligibility": elig})
                touched.append(ev.event_id)
            continue
        if acted >= cap:   # B5: the cap used to `break` — the rest left no trace (未轮到 looked like 不合格)
            note = respond.cycle_cap_note(cap, nowi)
            counters["events_not_evaluated"] = counters.get("events_not_evaluated", 0) + 1
            if ((prev or {}).get("not_evaluated") or {}).get("code") != note["code"]:   # written once, not every cycle
                _store.put_response(ev.event_id, {**(prev or {"eligibility": elig}), "not_evaluated": note})
                touched.append(ev.event_id)
            log.info(json.dumps({"station": "respond", "event": ev.event_id, "not_evaluated": note["code"], "max": cap}))
            continue
        acted += 1
        evaluated[ev.event_id] = nowi
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
        work[i] = (*work[i][:4], respond.block_review(work[i][4], tid, per_day, nowi, work[i][3]))
    for ev, _view, _refs, prev, st in work:
        if st != prev:
            _store.put_response(ev.event_id, st)
            touched.append(ev.event_id)
    # an event the cap skipped keeps its entry; an evaluated one is in iff it still has open jobs; a deleted one leaves
    open_ids &= {e.event_id for e in cands}
    for ev, *_rest, st in work:
        (open_ids.add if respond.has_open_jobs(st) else open_ids.discard)(ev.event_id)
    led["open_jobs"] = sorted(open_ids)
    led["evaluated"] = evaluated
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
    if cost.due(led, now):  # R4: spend on #/continuum; a failed read keeps the last numbers, visibly
        try:
            led["cost"] = cost.summarize(aws.fetch_costs(*cost.window(now)), now)
            led.pop("cost_error", None)
        except (ClientError, BotoCoreError) as e:
            led["cost_error"] = {"at": nowi, "error": str(e)[:300]}
            log.warning(json.dumps({"station": "respond", "degraded": "cost_unavailable", "error": str(e)[:300]}))
    _store.put_source_state(CONTINUUM_KEY, led)
    changed = sorted(set(passthrough["changed"]) | set(touched))
    return {"changed": changed[:MAX_CHANGED_IDS], "full": passthrough["full"] or flipped, "responded": len(touched)}


@_timed("notify")
def notify_events(event: dict[str, Any], _ctx: Any = None) -> dict[str, Any]:
    """Notify station (P3, radar.notify_station): after Publish, so a message never links to a page not written yet.
    Not configured / unreadable secret ⇒ a status row #/ops shows, never raised: push must not fail the cycle."""
    from radar import notify_station
    now = timeutil.now()
    arn = os.environ.get("NOTIFY_SECRET_ARN")
    if not arn:
        st = {"at": timeutil.iso(now), "status": "not_configured", "invalid": [], "subscriptions": {}}
        _store.put_source_state(notify_station.STATUS_KEY, st)
        return {"status": st["status"]}
    try:
        raw = boto3.client("secretsmanager").get_secret_value(SecretId=arn)["SecretString"]
        cfg = json.loads(raw) if raw.strip().startswith("{") else {}   # CDK's placeholder is not JSON ⇒ not configured
    except (ClientError, BotoCoreError, ValueError) as e:
        st = {"at": timeutil.iso(now), "status": "error", "invalid": [], "subscriptions": {},
              "error": {"error": "secret_unreadable", "message": str(e)[:300]}}
        _store.put_source_state(notify_station.STATUS_KEY, st)
        log.warning(json.dumps({"station": "notify", "degraded": "secret_unreadable", "error": str(e)[:300]}))
        return {"status": "error"}
    # self-service webhooks (R7.3) live in their own secret; unreadable ⇒ the operator's subscriptions still go out
    # and the failure is an invalid row on #/ops — "could not read" must not look like "nobody subscribed"
    if os.environ.get("SELF_SUBSCRIPTIONS_ARN") and isinstance(cfg, dict) and cfg:
        from radar import subscribe_api
        try:
            raw = boto3.client("secretsmanager").get_secret_value(SecretId=os.environ["SELF_SUBSCRIPTIONS_ARN"])["SecretString"]
            cfg = subscribe_api.merge(cfg, json.loads(raw) if raw.strip().startswith("{") else {})
        except (ClientError, BotoCoreError, ValueError) as e:
            cfg = {**cfg, "self_service_error": str(e)[:200]}
            log.warning(json.dumps({"station": "notify", "degraded": "self_subscriptions_unreadable", "error": str(e)[:300]}))
    st = notify_station.run(_store, cfg, now, os.environ.get("SITE_URL", ""), time_left=_time_left(_ctx))
    sent = {k: v.get("sent", 0) for k, v in st["subscriptions"].items()}
    log.info(json.dumps({"station": "notify", "status": st["status"], "sent": sent, "invalid": len(st["invalid"])}))
    if st["status"] == "degraded":
        log.warning(json.dumps({"station": "notify", "degraded": "send_failed",
                                "subscriptions": sorted(k for k, v in st["subscriptions"].items() if v["status"] == "error")}))
    return {"status": st["status"], "sent": sum(sent.values())}


@_timed("mitigate")
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


def alert(event: dict[str, Any], _ctx: Any = None) -> dict[str, Any]:
    """AlertFn (roadmap R0.2): a CloudWatch alarm's SNS record → the owner's chat subscriptions (radar.alert). Outside
    the cycle on purpose — the cycle may be what is down. An unreadable secret or a delivery that reached nobody raises:
    the invocation is retried by Lambda and counted by the AlertFnErrors alarm."""
    from radar import alert as alert_
    raw = boto3.client("secretsmanager").get_secret_value(SecretId=os.environ["NOTIFY_SECRET_ARN"])["SecretString"]
    cfg = json.loads(raw) if raw.strip().startswith("{") else {}
    out = alert_.deliver(cfg, alert_.messages(event), os.environ.get("SITE_URL", ""))
    if out.get("degraded"):
        log.error(json.dumps({"station": "alert", "degraded": out["degraded"], "messages": out["messages"]}))
    log.info(json.dumps({"station": "alert", **{k: out[k] for k in ("messages", "sent", "errors")}}))
    return out
