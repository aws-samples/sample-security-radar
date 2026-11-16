"""P3 notify station: who receives what, exactly once, and only links to pages that exist."""

import dataclasses
from datetime import UTC, datetime

import pytest
from test_notify import loopback  # noqa: F401  (fixture: real loopback HTTP servers)

from radar import fetch, notify, notify_station, publish, retitle, triage
from radar.limits import Limits
from radar.model import Event
from radar.store import MemoryStore

NOW = datetime(2026, 11, 11, 4, 0, tzinfo=UTC)
AT = "2026-11-11T03:00:00Z"
CANARY = "CANARY-internal-7f3a9e"      # an internal string: must never reach a subscriber
HOOK_SECRET = "h" * 32 + CANARY        # the webhook HMAC key itself is internal too
CFG = {"slack_bot_token": "xoxb-" + CANARY, "rollout": "owner_only", "subscriptions": [
    {"id": "p0-only", "owner": True, "channel": "slack_channel", "target": "C-P0", "filters": {"severity": ["P0"]}},
    {"id": "web3-all", "owner": True, "channel": "webhook", "target": "https://hooks.example/r", "secret": HOOK_SECRET,
     "filters": {"domain": ["web3"]}}]}


def ev(eid, sev, domain, title, **kw):
    return Event(event_id=eid, domain=domain, title=title, first_seen=AT, last_updated=AT, item_ids=[], keys=[],
                 severity=sev, **kw)


RESP = {"ev_00000000000000b1": {"status": "done", "targets": [{"verdict": "affected"}], "issues": []}}


@pytest.fixture
def world(monkeypatch):
    store = MemoryStore()
    for e in (ev("ev_00000000000000a0", "P0", "vuln", "Ivanti EPMM RCE"), ev("ev_00000000000000b0", "P0", "web3", "Bybit drained"),
              ev("ev_00000000000000b1", "P1", "web3", "DEX oracle bug"), ev("ev_00000000000000a1", "P1", "vuln", "nginx bug"),
              ev("ev_00000000000000b2", "P2", "web3", "small rug")):
        store.put_event(e)
    monkeypatch.setattr(publish, "_response", lambda e, s, now: RESP.get(e.event_id))
    sent: list[tuple[str, str, str]] = []

    def sender(cfg, sub, msg, thread, cache):
        body = notify.webhook_body(sub, msg, msg["view"]).decode() if sub.channel == "webhook" else msg["text"]
        sent.append((sub.id, msg["view"]["event_id"], msg["key"], body))
        return thread or f"T-{sub.id}-{msg['view']['event_id']}"
    senders = {c: sender for c in notify.CHANNELS}
    return store, sent, senders


def _baseline(store, senders, cfg=CFG):
    """First run of each subscription records what exists without sending; then the backlog of the test is added."""
    empty = MemoryStore()
    notify_station.run(empty, cfg, NOW, "https://site", senders)
    store.put_source_state(notify_station.STATUS_KEY, empty.get_source_state(notify_station.STATUS_KEY))


def test_two_subscriptions_receive_exactly_their_matching_set_and_a_second_run_sends_nothing(world):
    store, sent, senders = world
    _baseline(store, senders)
    st = notify_station.run(store, CFG, NOW, "https://site", senders)
    got = {(s, e, k) for s, e, k, _ in sent}
    assert got == {("p0-only", "ev_00000000000000a0", "p0"), ("p0-only", "ev_00000000000000b0", "p0"),
                   ("web3-all", "ev_00000000000000b0", "p0"), ("web3-all", "ev_00000000000000b1", "affected:1")}
    assert len(sent) == len(got)
    assert st["status"] == "ok" and {k: v["sent"] for k, v in st["subscriptions"].items()} == {"p0-only": 2, "web3-all": 2}
    n = len(sent)
    again = notify_station.run(store, CFG, NOW, "https://site", senders)
    assert len(sent) == n and all(v["sent"] == 0 for v in again["subscriptions"].values())


def test_the_first_run_of_a_subscription_is_a_baseline_not_a_replay(world):
    store, sent, senders = world
    st = notify_station.run(store, CFG, NOW, "https://site", senders)
    assert sent == [] and {v["status"] for v in st["subscriptions"].values()} == {"baseline"}
    assert notify_station.run(store, CFG, NOW, "https://site", senders)["subscriptions"]["p0-only"]["status"] == "ok"
    assert sent == []


def test_state_is_saved_after_each_send_so_a_run_killed_halfway_neither_loses_nor_repeats(world):
    """research/action/03 B2: state was written once at the end — a timeout after some sends re-sent all of them."""
    store, sent, senders = world
    _baseline(store, senders)
    calls = {"n": 0}

    class Killed(BaseException):     # the Lambda timeout: nothing after it runs, no except clause sees it
        pass

    def dies_on_the_third(cfg, sub, msg, thread, cache):
        calls["n"] += 1
        if calls["n"] == 3:
            raise Killed
        return senders["slack_channel"](cfg, sub, msg, thread, cache)
    with pytest.raises(Killed):
        notify_station.run(store, CFG, NOW, "https://site", {c: dies_on_the_third for c in notify.CHANNELS})
    assert len(sent) == 2
    notify_station.run(store, CFG, NOW, "https://site", senders)
    keys = [(s, e, k) for s, e, k, _ in sent]
    assert len(keys) == len(set(keys)) == 4                     # every message once: none lost, none repeated


def test_one_state_row_per_event_and_subscription_threads_replies(world):
    store, _sent, senders = world
    _baseline(store, senders)
    notify_station.run(store, CFG, NOW, "https://site", senders)
    row = store.get_source_state(notify_station.state_key("ev_00000000000000b0", "web3-all"))
    assert row == {"keys": ["p0", "standing"], "thread": "T-web3-all-ev_00000000000000b0"}
    assert store.get_source_state(notify_station.state_key("ev_00000000000000a0", "p0-only"))["thread"] == "T-p0-only-ev_00000000000000a0"
    assert "__notify__" not in store.sources                     # no single row holds everybody's state (B6)


def test_a_state_row_that_would_pass_the_size_limit_is_refused_before_sending(world):
    store, sent, senders = world
    _baseline(store, senders)
    big = {"keys": [f"pr:https://example.com/{i:06d}/" + "x" * 90 for i in range(2100)]}
    store.put_source_state(notify_station.state_key("ev_00000000000000a0", "p0-only"), big)
    st = notify_station.run(store, CFG, NOW, "https://site", senders)
    err = st["subscriptions"]["p0-only"]["error"]
    assert err["error"] == "state_row_too_large" and err["actual"] > err["limit"] == Limits.NOTIFY_STATE_ROW_MAX_BYTES
    assert ("p0-only", "ev_00000000000000a0") not in {(s, e) for s, e, _, _ in sent} and st["status"] == "degraded"


def test_an_event_whose_page_publish_deferred_is_not_linked_until_it_is_written(world):
    """research/action/03 B1: the message linked #/events/<id> before Publish had written events/<id>.json."""
    store, sent, senders = world
    _baseline(store, senders)
    store.put_source_state(publish.PENDING_KEY, {"ids": ["ev_00000000000000a0"], "at": AT})
    st = notify_station.run(store, CFG, NOW, "https://site", senders)
    assert "ev_00000000000000a0" not in {e for _, e, _, _ in sent} and st["held_unpublished"] == ["ev_00000000000000a0"]
    store.put_source_state(publish.PENDING_KEY, {"ids": [], "at": AT})
    notify_station.run(store, CFG, NOW, "https://site", senders)
    assert ("p0-only", "ev_00000000000000a0", "p0") in {(s, e, k) for s, e, k, _ in sent}


def test_the_retitled_title_is_pushed(world):
    store, sent, senders = world
    _baseline(store, senders)
    retitle.set_title(store, "ev_00000000000000a0", "Ivanti EPMM auth bypass chain (CVE-2026-1)", "https://vendor.example/a",
                      "", "ops", NOW)
    notify_station.run(store, CFG, NOW, "https://site", senders)
    text = next(b for s, e, _, b in sent if s == "p0-only" and e == "ev_00000000000000a0")
    assert text.startswith("[P0] Ivanti EPMM auth bypass chain")


def test_the_rollout_gate_holds_back_non_owner_subscriptions_visibly(world):
    store, sent, senders = world
    cfg = {**CFG, "subscriptions": [{**s, "owner": s["id"] == "p0-only"} for s in CFG["subscriptions"]]}
    del cfg["rollout"]                                           # absent ⇒ owner_only
    _baseline(store, senders, cfg)
    st = notify_station.run(store, cfg, NOW, "https://site", senders)
    assert {s for s, *_ in sent} == {"p0-only"} and st["subscriptions"]["web3-all"]["status"] == "gated_by_rollout"
    st = notify_station.run(store, {**cfg, "rollout": "all"}, NOW, "https://site", senders)
    assert st["subscriptions"]["web3-all"]["status"] == "baseline"      # opening the gate does not replay a week
    assert {s for s, *_ in sent} == {"p0-only"}


def test_a_failing_subscription_does_not_block_the_other(world):
    store, sent, senders = world
    _baseline(store, senders)

    def down(cfg, sub, msg, thread, cache):
        raise OSError("connection reset")
    st = notify_station.run(store, CFG, NOW, "https://site", {**senders, "slack_channel": down})
    assert st["subscriptions"]["p0-only"]["status"] == "error" and st["status"] == "degraded"
    assert {s for s, *_ in sent} == {"web3-all"}


def test_a_webhook_answering_a_redirect_is_a_failed_send_not_a_crashed_station(world, loopback, monkeypatch):  # noqa: F811
    """A real 3xx: send_webhook refuses it with fetch.FetchError (a plain Exception). It escaped run(), so the
    station crashed every cycle, the subscriptions after the webhook never got a push and #/ops showed nothing."""
    store, sent, senders = world
    base, elsewhere = loopback
    monkeypatch.setattr(fetch, "_internal_host", lambda host: False)   # the loopback server stands for a public host
    cfg = {**CFG, "subscriptions": [CFG["subscriptions"][1], CFG["subscriptions"][0]]}   # the webhook first
    _baseline(store, senders, cfg)

    def real_webhook(c, sub, msg, thread, cache):
        return notify.send_webhook(c, dataclasses.replace(sub, target=base + "/redirect"), msg, thread, cache)
    st = notify_station.run(store, cfg, NOW, "https://site", {**senders, "webhook": real_webhook})
    hook = st["subscriptions"]["web3-all"]
    assert hook["status"] == "error" and hook["error"]["error"] == "send_failed" and "redirect_refused" in hook["error"]["message"]
    assert st["status"] == "degraded" and elsewhere == []
    assert {s for s, *_ in sent} == {"p0-only"} and st["subscriptions"]["p0-only"]["status"] == "ok"
    assert store.get_source_state(notify_station.STATUS_KEY)["subscriptions"]["web3-all"]["status"] == "error"


def test_re_enabling_a_paused_subscription_baselines_instead_of_replaying_the_pause(world):
    """Like the rollout gate: a disabled subscription keeps no baseline, so re-enabling it does not send every fact
    of the pause (it did: 5 P0 events added while paused ⇒ 5 messages on re-enable)."""
    store, sent, senders = world
    _baseline(store, senders)
    paused = {**CFG, "subscriptions": [{**CFG["subscriptions"][0], "enabled": False}, CFG["subscriptions"][1]]}
    st = notify_station.run(store, paused, NOW, "https://site", senders)
    assert st["subscriptions"]["p0-only"] == {"status": "disabled", "at": st["at"], "baselined": False}
    assert {s for s, *_ in sent} == {"web3-all"}
    st = notify_station.run(store, CFG, NOW, "https://site", senders)
    assert st["subscriptions"]["p0-only"]["status"] == "baseline" and {s for s, *_ in sent} == {"web3-all"}


def test_the_pre_p3_single_state_row_is_deleted(world):
    store, _sent, senders = world
    store.put_source_state(notify_station.LEGACY_STATE_KEY, {"ev_x": {"slack": {"keys": ["p0"], "thread": "T"}}})
    notify_station.run(store, {}, NOW, "https://site", senders)
    assert notify_station.LEGACY_STATE_KEY not in store.sources


def test_the_time_budget_stops_sending_and_the_next_run_continues(world):
    store, sent, senders = world
    _baseline(store, senders)
    st = notify_station.run(store, CFG, NOW, "https://site", senders, time_left=lambda: Limits.NOTIFY_RESERVE_S - 1)
    assert sent == [] and st["subscriptions"]["p0-only"]["stopped"] == "time"
    notify_station.run(store, CFG, NOW, "https://site", senders)
    assert len(sent) == 4


def test_a_legacy_secret_or_an_empty_table_pushes_nothing_and_says_why(world):
    store, sent, senders = world
    assert notify_station.run(store, {"slack_bot_token": "x", "slack_channel_id": "C"}, NOW, "s", senders)["status"] == "legacy_config"
    assert notify_station.run(store, {}, NOW, "s", senders)["status"] == "not_configured"
    bad = notify_station.run(store, {"subscriptions": [{"id": "x", "channel": "sms", "target": "1"}]}, NOW, "s", senders)
    assert bad["status"] == "invalid" and bad["invalid"][0]["error"] == "unknown_channel" and sent == []


def test_a_canary_internal_string_never_reaches_a_message(world):
    """Messages and webhook bodies are built from the public summary row only (notify.view): analysis cache keys,
    triage notes, operator notes, raw response fields, WAF rule bodies and the secrets themselves never get in."""
    store, sent, senders = world
    _baseline(store, senders)
    for e in store.events_updated_since("2000"):
        e.analysis = {"status": "ok", "input_hash": CANARY, "bluf": [{"text": "grounded", "grounded": True}]}
        store.put_event(e)
    triage.set_status(store, "ev_00000000000000b0", "tracking", CANARY, CANARY, NOW)
    retitle.set_title(store, "ev_00000000000000b0", "Bybit cold wallet drained", "https://x.example", CANARY, CANARY, NOW)
    store.put_source_state("__mitigate__", {"events": {"ev_00000000000000b0": {"plans": [{"rules": CANARY}]}}})
    RESP["ev_00000000000000b1"]["internal"] = CANARY
    try:
        notify_station.run(store, CFG, NOW, "https://site", senders)
    finally:
        RESP["ev_00000000000000b1"].pop("internal")
    assert len(sent) == 4 and not [b for *_, b in sent if CANARY in b]


def test_each_subscription_keeps_its_own_thread(world):
    """Two subscriptions on one event are two conversations: a reply must go to the subscription's own thread, never
    to another channel's message id (one row per (event, subscription); a shared row mixed them)."""
    store, _sent, senders = world
    _baseline(store, senders)
    threads = []

    def sender(cfg, sub, msg, thread, cache):
        threads.append((sub.id, msg["key"], thread))
        return senders["slack_channel"](cfg, sub, msg, thread, cache)
    spy = {c: sender for c in notify.CHANNELS}
    notify_station.run(store, CFG, NOW, "https://site", spy)
    RESP["ev_00000000000000b0"] = {"status": "done", "targets": [{"verdict": "affected"}], "issues": []}
    try:
        notify_station.run(store, CFG, NOW, "https://site", spy)
    finally:
        RESP.pop("ev_00000000000000b0")
    replies = {(s, t) for s, k, t in threads if k == "affected:1" and s in ("p0-only", "web3-all") and t}
    assert replies == {("p0-only", "T-p0-only-ev_00000000000000b0"), ("web3-all", "T-web3-all-ev_00000000000000b0")}


# ------------------------------------------------------------------ the event page's notify row reads this station

def _row(store, eid, sev="P0", at=AT):
    from radar import decisions
    led = {"notify": store.get_source_state(notify_station.STATUS_KEY)}
    ev_ = {"event_id": eid, "domain": "vuln", "severity": sev, "exploitation": "confirmed", "last_updated": at}
    return next(r for r in decisions.evaluate(ev_, None, led, NOW) if r["action"] == "notify")


def test_the_notify_decision_row_says_what_the_station_did_for_that_event(world):
    """Every gate of the table, decided from the station's own per-event record (P3: the filters are in the secret)."""
    store, _sent, senders = world
    assert _row(store, "ev_00000000000000a0")["gate"] == "N_NOTIFY_OFF"              # never ran
    notify_station.run(store, {}, NOW, "https://site", senders)
    assert _row(store, "ev_00000000000000a0")["gate"] == "N_NOTIFY_OFF"              # ran, nothing configured
    _baseline(store, senders)
    st = notify_station.run(store, CFG, NOW, "https://site", senders, time_left=lambda: Limits.NOTIFY_RESERVE_S - 1)
    assert st["subscriptions"]["p0-only"]["stopped"] == "time"
    r = _row(store, "ev_00000000000000a0")
    assert (r["outcome"], r["gate"]) == ("blocked", "B_NOTIFY_PENDING")              # matched, unsent: next run
    notify_station.run(store, CFG, NOW, "https://site", senders)
    r = _row(store, "ev_00000000000000a0")
    assert (r["outcome"], r["result"]) == ("fire", "ok")
    assert _row(store, "ev_00000000000000a1", "P1")["gate"] == "X_NO_SUBSCRIBER"     # vuln P1: neither filter
    assert _row(store, "ev_unknown")["gate"] == "N_NOTIFY_NOT_YET"
    old = "2026-09-01T00:00:00Z"
    assert _row(store, "ev_00000000000000a0", at=old)["gate"] == "N_NOTIFY_WINDOW"


def test_a_matched_event_with_nothing_to_say_is_not_fire(world):
    store, _sent, senders = world
    cfg = {**CFG, "subscriptions": [{"id": "all", "owner": True, "channel": "slack_channel", "target": "C",
                                      "filters": {}}]}
    _baseline(store, senders, cfg)
    notify_station.run(store, cfg, NOW, "https://site", senders)
    r = _row(store, "ev_00000000000000a1", "P1")                                     # P1, no impact, no PR
    assert (r["outcome"], r["gate"]) == ("not_fire", "X_NOTHING_TO_SAY")


def test_a_send_error_is_a_failed_send_on_the_row_not_a_budget_hold(world):
    store, _sent, senders = world
    _baseline(store, senders)

    def down(cfg, sub, msg, thread, cache):
        raise OSError("app not installed")
    notify_station.run(store, CFG, NOW, "https://site", {c: down for c in notify.CHANNELS})
    r = _row(store, "ev_00000000000000a0")
    assert (r["outcome"], r["gate"], r["result"]) == ("fire", None, "error") and "send_failed" in r["error"]


def test_a_page_not_written_yet_is_not_evaluated(world):
    store, _sent, senders = world
    _baseline(store, senders)
    store.put_source_state(publish.PENDING_KEY, {"ids": ["ev_00000000000000a0"]})
    notify_station.run(store, CFG, NOW, "https://site", senders)
    assert _row(store, "ev_00000000000000a0")["gate"] == "N_NOTIFY_NOT_YET"


def test_the_station_selects_with_the_tables_window_and_severities(world, monkeypatch):
    """Change the table, not the station: the station follows (one definition, the page reads it too)."""
    from radar import decisions
    store, _sent, _senders = world
    ids = lambda: {v["event_id"] for v in notify_station.views(store, NOW)[0]}
    assert ids() == {"ev_00000000000000a0", "ev_00000000000000b0", "ev_00000000000000b1", "ev_00000000000000a1"}
    monkeypatch.setattr(decisions, "NOTIFY_SEVERITIES", ("P0",))
    assert ids() == {"ev_00000000000000a0", "ev_00000000000000b0"}
    monkeypatch.setattr(decisions, "window_start", lambda action, code, n: "2026-11-11T03:30:00Z")
    assert ids() == set()
    # … and a WIDER table window reaches further back than the station's old hand-written 7 days. (CI 2026-11-14: the
    # narrowing above passes through notify_due alone, so a hand-restated query bound survived — it had only ever been
    # red because the mutant's `timedelta` was not imported.)
    old = dataclasses.replace(ev("ev_00000000000000d0", "P0", "vuln", "three weeks old"), last_updated="2026-10-21T00:00:00Z")
    store.put_event(old)
    monkeypatch.setattr(decisions, "window_start", lambda action, code, n: "2026-10-01T00:00:00Z")
    assert "ev_00000000000000d0" in ids()


def test_a_cycle_that_could_not_read_the_secret_does_not_make_the_next_one_swallow_messages(world):
    """Audit 04 §4.1 (reproduced): the error path rewrote the status row with `subscriptions: {}` — where the
    `baselined` flags lived. The next good run saw no flag, treated every subscription as new and recorded each
    pending fact as sent without sending: a P0 that arrived in between reached nobody."""
    store, sent, senders = world
    _baseline(store, senders)
    notify_station.run(store, CFG, NOW, "https://site", senders)
    n = len(sent)
    # exactly what handlers.notify_events stores when Secrets Manager cannot be read (or NOTIFY_SECRET_ARN is unset)
    store.put_source_state(notify_station.STATUS_KEY, {"at": AT, "status": "error", "invalid": [], "subscriptions": {},
                                                       "error": {"error": "secret_unreadable", "message": "x"}})
    store.put_event(ev("ev_00000000000000c0", "P0", "vuln", "A P0 that arrived while the secret was unreadable"))
    st = notify_station.run(store, CFG, NOW, "https://site", senders)
    assert ("p0-only", "ev_00000000000000c0", "p0") in {(s, e, k) for s, e, k, _ in sent[n:]}, "the P0 was recorded as sent, not sent"
    assert st["subscriptions"]["p0-only"]["status"] == "ok"


def test_a_subscription_is_baselined_once_and_the_record_is_its_own_row(world):
    store, sent, senders = world
    notify_station.run(store, CFG, NOW, "https://site", senders)                       # the baseline run
    assert set(store.get_source_state(notify_station.BASELINED_KEY)) == {"p0-only", "web3-all"} and sent == []
    paused = {**CFG, "subscriptions": [{**CFG["subscriptions"][0], "enabled": False}, CFG["subscriptions"][1]]}
    notify_station.run(store, paused, NOW, "https://site", senders)
    assert set(store.get_source_state(notify_station.BASELINED_KEY)) == {"web3-all"}  # a paused one baselines again later


def test_a_failed_send_never_puts_the_webhook_address_on_the_ops_page(world, loopback, monkeypatch):  # noqa: F811
    """Audit 04 §4.8: the error text of a refused redirect carries the redirect target and the webhook URL; it was stored
    in the status ledger and shown on #/ops. A webhook URL is often a bearer secret."""
    store, _sent, senders = world
    base, _elsewhere = loopback
    monkeypatch.setattr(fetch, "_internal_host", lambda host: False)   # the loopback server stands for a public host
    cfg = {**CFG, "subscriptions": [CFG["subscriptions"][1]]}
    _baseline(store, senders, cfg)

    def real_webhook(c, sub, msg, thread, cache):
        return notify.send_webhook(c, dataclasses.replace(sub, target=base + "/redirect"), msg, thread, cache)
    st = notify_station.run(store, cfg, NOW, "https://site", {**senders, "webhook": real_webhook})
    err = st["subscriptions"]["web3-all"]["error"]
    blob = str(store.get_source_state(notify_station.STATUS_KEY))
    assert err["error"] == "send_failed" and "redirect_refused" in err["message"]
    assert "127.0.0.1" not in blob, "the webhook address or the redirect target (both on 127.0.0.1) is in the ledger"
    bad = notify.parse_config({"subscriptions": [{"id": "h", "channel": "webhook", "secret": "s" * 32,
                                                  "target": "http://hooks.example/T000/SECRET-PATH-TOKEN"}]}).invalid
    assert bad and "SECRET-PATH-TOKEN" not in str(bad) and bad[0]["actual"] == "http"


# ---------------------------------------------------------------- R4.3: pushes follow the story

def _merge(store, old, to, at="2026-11-11T03:30:00Z"):
    from radar import removals
    first = store.get_event(old).first_seen
    store.delete_event(old)
    removals.record(store, [(old, first[:7], to)], at)


def test_a_merged_event_is_corrected_once_in_its_thread_and_the_survivor_does_not_announce_itself_again(world):
    store, sent, senders = world
    _baseline(store, senders)
    notify_station.run(store, CFG, NOW, "https://site", senders)                 # p0-only was told about a0 (and b0)
    thread = store.get_source_state(notify_station.state_key("ev_00000000000000a0", "p0-only"))["thread"]
    store.put_event(ev("ev_00000000000000a9", "P0", "vuln", "Ivanti EPMM RCE (the real one)"))
    _merge(store, "ev_00000000000000a0", "ev_00000000000000a9")
    del sent[:]
    notify_station.run(store, CFG, NOW, "https://site", senders)
    got = [(sid, eid, key) for sid, eid, key, _ in sent if sid == "p0-only"]
    assert got == [("p0-only", "ev_00000000000000a0", "moved:ev_00000000000000a9")]     # one correction, no second P0
    body = sent[0][3]
    assert "已并入「Ivanti EPMM RCE (the real one)」" in body and "https://site/#/events/ev_00000000000000a9" in body
    surv = store.get_source_state(notify_station.state_key("ev_00000000000000a9", "p0-only"))
    assert surv["keys"] == ["p0", "standing"] and surv["thread"] == thread       # later updates continue in the old thread
    del sent[:]
    notify_station.run(store, CFG, NOW, "https://site", senders)
    assert sent == []                                                            # said once


def test_a_withdrawn_event_is_said_withdrawn_and_someone_never_told_hears_nothing(world):
    store, sent, senders = world
    _baseline(store, senders)
    notify_station.run(store, CFG, NOW, "https://site", senders)
    _merge(store, "ev_00000000000000a0", None)                                   # p0-only was told; web3-all never was
    _merge(store, "ev_00000000000000b2", None)                                   # a P2: nobody was told
    del sent[:]
    notify_station.run(store, CFG, NOW, "https://site", senders)
    assert [(s, e, k) for s, e, k, _ in sent] == [("p0-only", "ev_00000000000000a0", "moved:withdrawn")]
    assert "已撤下" in sent[0][3]


def test_a_chain_of_merges_points_at_the_event_that_exists_and_old_removals_are_left_alone(world):
    from datetime import timedelta
    store, _, _ = world
    store.put_event(ev("ev_00000000000000c9", "P0", "vuln", "final"))
    _merge(store, "ev_00000000000000a0", "ev_00000000000000a1")
    _merge(store, "ev_00000000000000a1", "ev_00000000000000c9")
    _merge(store, "ev_00000000000000b0", "ev_00000000000000b1", at="2026-11-01T00:00:00Z")      # long ago
    got = notify_station.moved(store, NOW)
    assert got == {"ev_00000000000000a0": "ev_00000000000000c9", "ev_00000000000000a1": "ev_00000000000000c9"}
    store.put_event(ev("ev_00000000000000a0", "P0", "vuln", "re-created by a replay"))
    assert "ev_00000000000000a0" not in notify_station.moved(store, NOW)         # it exists again: not removed
    assert notify_station.moved(store, NOW + timedelta(hours=Limits.NOTIFY_FOLLOW_HOURS + 1)) == {}


def test_a_failed_correction_is_retried_and_still_keeps_the_survivor_quiet(world):
    store, sent, senders = world
    _baseline(store, senders)
    notify_station.run(store, CFG, NOW, "https://site", senders)
    store.put_event(ev("ev_00000000000000a9", "P0", "vuln", "survivor"))
    _merge(store, "ev_00000000000000a0", "ev_00000000000000a9")
    del sent[:]

    def broken(cfg, sub, msg, thread, cache):
        raise OSError("slack down")
    st = notify_station.run(store, CFG, NOW, "https://site", {**senders, "slack_channel": broken})
    assert st["subscriptions"]["p0-only"]["status"] == "error"
    assert "p0" in store.get_source_state(notify_station.state_key("ev_00000000000000a9", "p0-only"))["keys"]
    notify_station.run(store, CFG, NOW, "https://site", senders)
    assert [(s, k) for s, _, k, _ in sent if s == "p0-only"] == [("p0-only", "moved:ev_00000000000000a9")]


def test_r4_4_a_kinds_filter_is_applied_by_the_station(world):
    store, sent, senders = world
    cfg = {**CFG, "subscriptions": [{"id": "verdicts", "owner": True, "channel": "slack_channel", "target": "C-V",
                                     "filters": {"domain": ["web3"], "kinds": ["verdict"]}}]}
    _baseline(store, senders, cfg)
    notify_station.run(store, cfg, NOW, "https://site", senders)
    assert {(s, e, k) for s, e, k, _ in sent} == {("verdicts", "ev_00000000000000b1", "affected:1")}   # no P0 notice


DIGEST = {"day": "2026-11-11", "status": "partial", "header": {"events": 3, "p0": 1, "p1": 2, "new": 1, "escalated": 2},
          "summary": [{"text": "Ivanti EPMM 遭在野利用。", "cite": ["ev_00000000000000a0"], "grounded": True},
                      {"text": "损失已超过 9 亿美元。", "cite": ["ev_00000000000000b0"], "grounded": False}],
          "highlights": [{"text": "Bybit 被盗，资金仍在移动。", "cite": ["ev_00000000000000b0"], "grounded": True}],
          "watch": []}
DIGEST_SUB = {"id": "daily", "owner": True, "channel": "slack_channel", "target": "C-D",
              "filters": {"severity": ["P0"], "kinds": ["digest"]}}


def test_r4_4_an_opted_in_subscription_gets_todays_digest_once_with_only_its_grounded_sentences(world):
    store, sent, senders = world
    cfg = {**CFG, "subscriptions": [*CFG["subscriptions"], DIGEST_SUB]}
    _baseline(store, senders, cfg)
    store.put_source_state("__digest__", DIGEST)
    notify_station.run(store, cfg, NOW, "https://site", senders)
    got = [(s, k, body) for s, e, k, body in sent if k.startswith("digest:")]
    assert [(s, k) for s, k, _ in got] == [("daily", "digest:2026-11-11")]          # not p0-only / web3-all: opt-in
    body = got[0][2]
    assert "Ivanti EPMM 遭在野利用" in body and "Bybit 被盗" in body and "3 个事件 · P0 1 · P1 2" in body
    assert "9 亿" not in body and "1 句未通过核对" in body                          # an ungrounded sentence is never sent
    assert not [k for s, e, k, _ in sent if s == "daily" and not k.startswith("digest:")]  # kinds: digest only
    sent.clear()
    notify_station.run(store, cfg, NOW, "https://site", senders)
    assert sent == []                                                                # once a day


@pytest.mark.parametrize("d", [{**DIGEST, "day": "2026-11-10"}, {**DIGEST, "status": "failed"}, {}])
def test_r4_4_no_digest_is_sent_when_today_has_none_or_it_failed(world, d):
    store, sent, senders = world
    cfg = {**CFG, "subscriptions": [DIGEST_SUB]}
    _baseline(store, senders, cfg)
    store.put_source_state("__digest__", d)
    notify_station.run(store, cfg, NOW, "https://site", senders)
    assert sent == []


def test_r4_4_a_new_subscription_does_not_get_the_digest_that_was_already_out_and_a_failed_send_is_retried(world):
    store, sent, senders = world
    cfg = {**CFG, "subscriptions": [DIGEST_SUB]}
    store.put_source_state("__digest__", DIGEST)
    notify_station.run(store, cfg, NOW, "https://site", senders)                    # baseline run of "daily"
    assert sent == []
    store.put_source_state("__digest__", {**DIGEST, "day": "2026-11-12"})
    later = datetime(2026, 11, 12, 1, 0, tzinfo=UTC)

    def down(cfg_, sub, msg, thread, cache):
        raise OSError("slack is down")
    st = notify_station.run(store, cfg, later, "https://site", {c: down for c in notify.CHANNELS})
    assert st["subscriptions"]["daily"]["error"]["error"] == "send_failed"
    notify_station.run(store, cfg, later, "https://site", senders)
    assert [k for _, _, k, _ in sent] == ["digest:2026-11-12"]


def test_r4_4_a_quiet_day_digest_says_so():
    m = notify.digest_message({"day": "2026-11-11", "status": "ok", "header": {"events": 0}}, "2026-11-11", "https://site/")
    assert m["kind"] == "digest" and "没有 P0 / P1 事件" in m["text"] and m["text"].endswith("https://site/")
