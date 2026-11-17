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
from datetime import datetime, timedelta
from typing import Any

from radar import decisions, digest, fetch, latency, notify, publish, removals, respond, retitle, timeutil
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


LEDGER_ID = "__p0_sent__"   # state_key(LEDGER_ID, sub): the P0s a subscription sent (notify.gate G3 reads it)
DIGEST_ID = "__digest__"   # the digest's push row: state_key(DIGEST_ID, sub) — keys `digest:<day>`, no thread


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
        v = notify.view(row, bool((mit.get(e.event_id) or {}).get("plans")), prs)
        # when the event became what it is now (Event.escalated_at): the push latency is measured from there — an event
        # first reported days ago and raised to P0 an hour ago was pushed an hour late, not days late
        v["became_at"] = max(e.first_seen or "", e.escalated_at or "")
        out.append(v)
    return out, held


def moved(store: Any, now: datetime) -> dict[str, str | None]:
    """Events removed in the last NOTIFY_FOLLOW_HOURS → where their story is now: the last successor of the merge chain,
    or None (withdrawn, nothing took it over). An id that exists again (a replay re-created it) is not "removed"."""
    led = store.get_source_state(removals.REMOVED_KEY)
    floor = timeutil.iso(now - timedelta(hours=Limits.NOTIFY_FOLLOW_HOURS))
    out: dict[str, str | None] = {}
    for eid, r in led.items():
        if (r.get("at") or "") < floor or store.get_event(eid) is not None:
            continue
        to, hops = r.get("to"), 0
        while to in led and store.get_event(to) is None and hops < 5:     # a successor that was merged away in turn
            to, hops = led[to].get("to"), hops + 1
        out[eid] = to if to and store.get_event(to) is not None else None
    return out


def correction(eid: str, to: str | None, title: str | None, site_url: str) -> dict[str, str]:
    """The one message a subscriber gets in the thread of an event that no longer exists (roadmap R4.3)."""
    link = f"{site_url.rstrip('/')}/#/events/{to}" if to else site_url.rstrip("/") + "/"
    if to is None:
        text = "更正：这条推送对应的事件已撤下（与其他事件重复，或不再成立）。此前的链接不再有效。"
    else:
        text = f"更正：这条推送对应的事件已并入{f'「{title}」' if title else '另一个事件'}，后续更新在那里。\n{link}"
    # kind: a subscription's `kinds` filter decides whether it hears corrections (Neo 2026-11-17, the team channel: only
    # a withdrawal — a P0 that was wrong — gets its one line; a merge is silent there, the survivor stays quiet anyway)
    return {"key": f"moved:{to or 'withdrawn'}", "kind": "merged" if to else "withdrawn", "text": text, "link": link}


# what a send may raise without being a bug: urllib errors are OSError, in-band API errors ValueError, a refused redirect
# fetch.FetchError (a plain Exception — it once escaped run() and crashed the station for every later subscription)
SEND_ERRORS = (OSError, ValueError, KeyError, fetch.FetchError)


def _out_of_budget(sent_n: int, time_left: Callable[[], float] | None) -> str | None:
    """Why this subscription sends nothing more this run ("cap" / "time"), or None. One rule for messages and corrections."""
    if sent_n >= Limits.NOTIFY_MAX_PER_CYCLE:
        return "cap"
    if time_left is not None and time_left() < Limits.NOTIFY_RESERVE_S:
        return "time"
    return None


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
    blocked: list[dict[str, Any]] = []     # notices the send gate refused this run (shown on #/ops)
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
    # R4.3: pushes follow the story. An event a subscriber was told about and that has since been merged away or
    # withdrawn gets one correction in its thread; what was already said about it (the P0 notice) counts for the
    # survivor, whose later messages then continue in that thread instead of opening a second one.
    gone = moved(store, now)
    old_rows = store.get_source_states([state_key(e, s.id) for s in active for e in gone]) if gone else {}
    titles = {v["event_id"]: v["title"] for v in vs}
    # R4.4: today's digest, once per opted-in subscription (notify.wants_digest); None ⇒ nothing to send today
    dmsg = notify.digest_message(store.get_source_state(digest.KEY), digest.day_key(now), site_url)
    cache: dict[str, Any] = {}    # per-run adapter cache (one Lark tenant token per run)
    pushed: list[list[Any]] = []  # latency samples of this run's P0 pushes
    for s in active:
        baseline = s.id not in based
        sent_n, err, stopped = 0, None, None
        after: dict[str, dict[str, Any]] = {}
        for eid, to in ([] if baseline else sorted(gone.items())):
            ko = state_key(eid, s.id)
            was = old_rows.get(ko) or {}
            m = correction(eid, to, titles.get(to or ""), site_url)
            if not was.get("keys") or m["key"] in was["keys"]:
                continue                                    # never told about it, or already corrected
            if to and "p0" in was["keys"]:
                # before the send, and whether or not it succeeds: the survivor must not announce itself as a new P0
                ks = state_key(to, s.id)
                surv = rows.get(ks) or store.get_source_state(ks) or {}
                if "p0" not in (surv.get("keys") or []):
                    # with what the old notice said about loss and level: the survivor then updates only on a change
                    said = [k for k in was["keys"] if k == notify.STANDING or k.startswith(("loss:", "level:"))]
                    surv = notify.record(surv, "p0", was.get("thread"), said)
                    store.put_source_state(ks, surv)
                    rows[ks] = surv
            if not notify.wanted(s.filters, m):             # recorded as handled: not re-checked every run
                store.put_source_state(ko, notify.record(was, m["key"], was.get("thread")))
                continue
            stopped = _out_of_budget(sent_n, time_left)
            if stopped:
                break
            try:
                senders[s.channel](cfg, s, {**m, "view": {"event_id": eid, "merged_into": to}}, was.get("thread"), cache)
            except SEND_ERRORS as ex:
                err = {"error": "send_failed", "message": _safe(ex)}
                break
            store.put_source_state(ko, notify.record(was, m["key"], None))
            sent_n += 1
        kl = state_key(LEDGER_ID, s.id)
        ledger = list((store.get_source_state(kl) or {}).get("rows") or [])
        since = timeutil.iso(now - timedelta(hours=Limits.NOTIFY_P0_DEDUP_HOURS))
        recent = [r for r in ledger if (r.get("at") or "") >= since]
        for v in ([] if err or stopped else hits[s.id]):
            k = state_key(v["event_id"], s.id)
            mine = rows.get(k) or {}
            msgs = [m for m in notify.plan(v, mine, site_url) if notify.wanted(s.filters, m)]   # R4.4: kinds filter
            if not msgs:
                continue
            if baseline:     # the first run of a subscription records what exists — it does not replay a week
                for m in msgs:
                    mine = notify.record(mine, m["key"], None, m.get("also"))
                store.put_source_state(k, mine)
                after[k] = mine
                continue
            for m in msgs:
                stopped = _out_of_budget(sent_n, time_left)
                if stopped:
                    break
                # refuse BEFORE sending: a row that could not be stored would make the message repeat every run
                if (n := _size(notify.record(mine, m["key"], "x" * 64, m.get("also")))) > Limits.NOTIFY_STATE_ROW_MAX_BYTES:
                    err = {"error": "state_row_too_large", "message": "push state row would exceed the limit",
                           "actual": n, "limit": Limits.NOTIFY_STATE_ROW_MAX_BYTES, "event_id": v["event_id"]}
                    break
                # the send gate (notify.gate): a notice that fails any rule is not sent, never retried, and named on
                # #/ops — "blocked" must look unlike "sent" (degradation leaves a trace). No `also`: a blocked P0
                # opens no thread, so no update can follow it
                if probs := notify.gate(m, v, site_url, recent):
                    mine = notify.record(mine, m["key"], None)
                    store.put_source_state(k, mine)
                    after[k] = mine
                    blocked.append({"subscription": s.id, "event_id": v["event_id"], "key": m["key"],
                                    "problems": probs[:3]})
                    continue
                try:
                    thread = senders[s.channel](cfg, s, {**m, "view": v}, mine.get("thread"), cache)
                # urllib errors are OSError; in-band API errors ValueError; a refused redirect (a webhook answering
                # 3xx: its allowlist is empty) is fetch.FetchError — a plain Exception, which escaped run() and
                # crashed the station for every later subscription, every cycle
                except SEND_ERRORS as ex:
                    err = {"error": "send_failed", "message": _safe(ex)}
                    break
                mine = notify.record(mine, m["key"], thread, m.get("also"))
                store.put_source_state(k, mine)   # right after the send: at most once, even if the run dies next
                if m["key"] == "p0":   # gate G3's memory: CVEs and victim names of what this subscription announced
                    recent.append(notify.ledger_entry(v, nowi))
                    ledger = [*recent, *(r for r in ledger if r not in recent)][-Limits.NOTIFY_P0_LEDGER_MAX:]
                    store.put_source_state(kl, {"rows": ledger})
                if m["key"] == "p0" and (lag := latency.minutes(v.get("became_at") or v.get("first_seen") or "", now)) is not None:
                    pushed.append(["P0", lag])    # became P0 → this push (roadmap R0.5 / R8.8)
                after[k] = mine
                sent_n += 1
            if err or stopped:
                break
        if dmsg and not (err or stopped) and notify.wants_digest(s.filters):
            kd = state_key(DIGEST_ID, s.id)
            drow = store.get_source_state(kd)
            if dmsg["key"] not in (drow.get("keys") or []):
                if not baseline and not (stopped := _out_of_budget(sent_n, time_left)):
                    try:   # top level, never a thread: a digest is not about one event
                        senders[s.channel](cfg, s, {**dmsg, "view": {"event_id": DIGEST_ID}}, None, cache)
                        sent_n += 1
                    except SEND_ERRORS as ex:
                        err = {"error": "send_failed", "message": _safe(ex)}
                if not err and not stopped:   # baseline: today's digest counts as seen — the next one is sent
                    store.put_source_state(kd, {"keys": [dmsg["key"]]})   # only the latest day matters: one key, no growth
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
    if blocked:
        status["blocked"] = blocked[-20:]
    if any(r.get("status") == "error" for r in subs.values()):
        status["status"] = "degraded"
    store.put_source_state(STATUS_KEY, status)
    latency.record(store, pushed, now, latency.PUSH_KEY, latency.PUSH_HOURS)
    if based != based_before:
        store.put_source_state(BASELINED_KEY, based)
    return status
