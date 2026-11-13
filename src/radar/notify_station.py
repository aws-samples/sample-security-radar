"""Notify station (P3): its own Lambda, after Publish — so every link in a message points at a page that is written,
and WAF plans / verdicts of this cycle are already there (research/action/03 B1). It runs whether or not a Security
Agent space exists (the old push lived inside Respond, behind SA_AGENT_SPACE_ID).

State (research/action/03 B2, B5, B6):
- one row per (event, subscription), `__notify__#<event_id>#<sub_id>` = {keys, thread}, written RIGHT AFTER each send —
  a timeout or a crash after a send never repeats it, and no single row grows with the number of events or subscribers;
- rows are never pruned to a window: an event that drops to P2 and comes back keeps its keys and its thread;
- `__notify_status__` = what #/ops shows: top-level status, invalid subscriptions, per-subscription status. Rewritten
  whole every run, so a passing Secrets Manager error does not stay on the page forever (B3).

Single writer: reserved concurrency 1 (infra/stack.py NotifyFn) and the cycle's overlap rule (handlers.plan).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime
from typing import Any

from radar import decisions, fetch, latency, notify, publish, respond, retitle, timeutil
from radar.limits import Limits
from radar.model import SEVERITY_ORDER

STATE_PREFIX = "__notify__#"
STATUS_KEY = "__notify_status__"
# the pre-P3 single row {event_id: {channel: {keys, thread}}} (handlers._notify, up to the 400 KB item limit). Nothing
# reads it since the per-(event, subscription) rows; deleted on the first run that finds it, never re-created.
LEGACY_STATE_KEY = "__notify__"
# which subscriptions have had their baseline run: {sub_id: iso}. Its own row — it lived in the status row, which the
# station's error paths rewrite whole: one cycle with an unreadable secret erased every flag, and the next good cycle
# "baselined" again, recording a P0 that had arrived in between as sent without sending it (audit 04 §4.1).
BASELINED_KEY = "__notify_baselined__"


def state_key(event_id: str, sub_id: str) -> str:
    return f"{STATE_PREFIX}{event_id}#{sub_id}"


def views(store: Any, now: datetime) -> tuple[list[dict[str, Any]], list[str]]:
    """(event views to consider, ids held back because their page is not written yet). Most severe first, then oldest.
    A page publish deferred (time budget, publish.PENDING_KEY) is not linked to until a later run writes it."""
    pending = set(store.get_source_state(publish.PENDING_KEY).get("ids") or [])
    # the window and severities are the decision table's (N_NOTIFY_WINDOW) — the event page reads the same rule
    since = decisions.window_start("notify", "N_NOTIFY_WINDOW", now)
    evs = [e for e in store.events_updated_since(since) if decisions.notify_due(e.severity, e.last_updated, now)]
    evs.sort(key=lambda e: (-SEVERITY_ORDER[e.severity], e.first_seen, e.event_id))
    fixes = store.get_source_state(retitle.KEY)
    mit = store.get_source_state("__mitigate__").get("events") or {}
    out, held = [], []
    for e in evs:
        if e.event_id in pending:
            held.append(e.event_id)
            continue
        resp = publish._response(e, store, now)
        # the public summary row: the retitled title (an operator's sourced fix) is the one subscribers see
        row = publish._summary(e, {"title_override": retitle.public(fixes.get(e.event_id), e.title),
                                   "impact": respond.impact(resp)})
        prs = [i["pr_url"] for i in (resp or {}).get("issues") or [] if i.get("pr_url")]
        out.append(notify.view(row, bool((mit.get(e.event_id) or {}).get("plans")), prs))
    return out, held


def _safe(ex: BaseException) -> str:
    """A send failure as it may be stored and shown on #/ops: never the target. A FetchError's text carries the URL it
    was fetching and, for a refused redirect, where it pointed — a webhook URL is often a bearer secret (audit 04 §4.8).
    urllib's HTTPError / URLError and the adapters' own ValueErrors ("slack: channel_not_found") carry no address."""
    if isinstance(ex, fetch.FetchError):
        return f"{ex.code} (status={ex.status})"
    return f"{type(ex).__name__}: {ex}"[:300]


def _size(row: dict[str, Any]) -> int:
    return len(json.dumps(row).encode())


def run(store: Any, cfg: dict[str, Any], now: datetime, site_url: str,
        senders: dict[str, Callable[..., str]] | None = None,
        time_left: Callable[[], float] | None = None) -> dict[str, Any]:
    """One run: parse subscriptions, match, send, record. Returns (and stores) the status ledger."""
    senders = senders if senders is not None else notify.SENDERS
    nowi = timeutil.iso(now)
    prev = (store.get_source_state(STATUS_KEY).get("subscriptions") or {})
    based = store.get_source_state(BASELINED_KEY)
    based_before = dict(based)       # compared at the end: the row is written only when it changed
    # read-merged once: flags written by a run before this row existed are still in the status row
    based.update({sid: row.get("at") or nowi for sid, row in prev.items() if row.get("baselined") and sid not in based})
    conf = notify.parse_config(cfg)
    subs: dict[str, dict[str, Any]] = {}
    status: dict[str, Any] = {"at": nowi, "rollout": conf.rollout, "invalid": conf.invalid, "subscriptions": subs}
    if store.get_source_state(LEGACY_STATE_KEY):
        store.delete_source_state(LEGACY_STATE_KEY)
    for sid in conf.disabled:
        # like a gated one: no baseline kept, so re-enabling baselines then instead of replaying every fact of the pause
        subs[sid] = {"status": "disabled", "at": nowi, "baselined": False}
        based.pop(sid, None)
    if not conf.subscriptions:
        status["status"] = "legacy_config" if conf.legacy else ("invalid" if conf.invalid else "not_configured")
        store.put_source_state(STATUS_KEY, status)
        if based != based_before:
            store.put_source_state(BASELINED_KEY, based)
        return status
    vs, held = views(store, now)
    status.update(status="ok", held_unpublished=held)
    # per event, what this run decided — the event page's 「响应决策」 notify row reads it (radar.decisions._notify_row)
    events: dict[str, dict[str, Any]] = {i: {"held": True} for i in held}
    events.update({v["event_id"]: {"matched": 0, "has_message": bool(notify.plan(v, {}, site_url)), "pending": 0,
                                   "failed": 0} for v in vs})
    status["events"] = events
    active = []
    for s in conf.subscriptions:
        if notify.gated(s, conf.rollout):
            # visibly held back — never shown as ok (degradation §1); keeps no baseline, so opening the rollout
            # baselines it then (no replay of a week of events into a new subscriber)
            subs[s.id] = {"status": "gated_by_rollout", "channel": s.channel, "at": nowi, "sent": 0, "baselined": False}
            based.pop(s.id, None)
        else:
            active.append(s)
            # placeholder until its turn: the status row is written after every subscription, and a run killed
            # mid-way must not drop a later subscription's baseline (it would then swallow its pending facts)
            subs[s.id] = {"status": "not_reached", "channel": s.channel, "at": nowi, "sent": 0,
                          "baselined": s.id in based}
    hits = {s.id: [v for v in vs if notify.matches(s.filters, v)] for s in active}
    rows = store.get_source_states([state_key(v["event_id"], s.id) for s in active for v in hits[s.id]])
    cache: dict[str, Any] = {}    # per-run adapter cache (one Lark tenant token per run)
    pushed: list[list[Any]] = []  # latency samples of this run's P0 pushes
    for s in active:
        baseline = s.id not in based
        sent_n, err, stopped = 0, None, None
        after: dict[str, dict[str, Any]] = {}
        for v in hits[s.id]:
            k = state_key(v["event_id"], s.id)
            mine = rows.get(k) or {}
            msgs = notify.plan(v, mine, site_url)
            if not msgs:
                continue
            if baseline:     # the first run of a subscription records what exists — it does not replay a week
                for m in msgs:
                    mine = notify.record(mine, m["key"], None)
                store.put_source_state(k, mine)
                after[k] = mine
                continue
            for m in msgs:
                if sent_n >= Limits.NOTIFY_MAX_PER_CYCLE:
                    stopped = "cap"
                elif time_left is not None and time_left() < Limits.NOTIFY_RESERVE_S:
                    stopped = "time"
                if stopped:
                    break
                # refuse BEFORE sending: a row that could not be stored would make the message repeat every run
                if (n := _size(notify.record(mine, m["key"], "x" * 64))) > Limits.NOTIFY_STATE_ROW_MAX_BYTES:
                    err = {"error": "state_row_too_large", "message": "push state row would exceed the limit",
                           "actual": n, "limit": Limits.NOTIFY_STATE_ROW_MAX_BYTES, "event_id": v["event_id"]}
                    break
                try:
                    thread = senders[s.channel](cfg, s, {**m, "view": v}, mine.get("thread"), cache)
                # urllib errors are OSError; in-band API errors ValueError; a refused redirect (a webhook answering
                # 3xx: its allowlist is empty) is fetch.FetchError — a plain Exception, which escaped run() and
                # crashed the station for every later subscription, every cycle
                except (OSError, ValueError, KeyError, fetch.FetchError) as ex:
                    err = {"error": "send_failed", "message": _safe(ex)}
                    break
                mine = notify.record(mine, m["key"], thread)
                store.put_source_state(k, mine)   # right after the send: at most once, even if the run dies next
                if m["key"] == "p0" and (lag := latency.minutes(v.get("first_seen") or "", now)) is not None:
                    pushed.append(["P0", lag])    # first report published → this push (roadmap R0.5)
                after[k] = mine
                sent_n += 1
            if err or stopped:
                break
        for v in hits[s.id]:                      # what is still unsent for this subscription, per event
            row = events[v["event_id"]]
            row["matched"] += 1
            k = state_key(v["event_id"], s.id)
            if notify.plan(v, after.get(k, rows.get(k) or {}), site_url):
                if err:
                    row["failed"] += 1
                    row.setdefault("errors", []).append(f"{s.id}: {err.get('error')}")
                else:
                    row["pending"] += 1
        subs[s.id] = {"status": "error" if err else ("baseline" if baseline else "ok"), "channel": s.channel,
                      "at": nowi, "sent": sent_n, "baselined": True, "matched": len(hits[s.id]),
                      **({"stopped": stopped} if stopped else {}), **({"error": err} if err else {})}
        if s.id not in based:
            based[s.id] = nowi
            store.put_source_state(BASELINED_KEY, based)  # before the status row: a timeout must not lose the flag
            based_before = dict(based)
        store.put_source_state(STATUS_KEY, status)    # per subscription: a timeout keeps what already happened
    if any(r.get("status") == "error" for r in subs.values()):
        status["status"] = "degraded"
    store.put_source_state(STATUS_KEY, status)
    latency.record(store, pushed, now, latency.PUSH_KEY, latency.PUSH_HOURS)
    if based != based_before:
        store.put_source_state(BASELINED_KEY, based)
    return status
