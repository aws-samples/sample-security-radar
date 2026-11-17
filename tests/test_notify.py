"""P3 push, pure parts: subscriptions parse (or are reported invalid with the four error elements), the matcher, the
rollout gate, message planning (at most once per fact, threaded per event) and the channel adapters."""

import _socket
import dataclasses
import hashlib
import hmac
import http.server
import json
import socket
import threading
import urllib.error

import pytest

from radar import fetch, notify

ROW = {"event_id": "ev_1", "title": "PHP2Shell", "severity": "P0", "domain": "vuln", "level": "V3",
       "level_reason": "T1 confirmed", "summary": "s", "first_seen": "t0", "last_updated": "t1", "cves": ["CVE-2026-1"],
       "chains": [], "entities": ["PHP"], "impact": {"status": "affected", "affected": 2, "checked": 5}}
V = notify.view(ROW, False, ["https://x/pull/3", "https://x/pull/3"])
CFG = {"slack_bot_token": "xoxb-1", "lark_app_id": "a", "lark_app_secret": "s"}
SECRET = "w" * 40


def sub(**kw):
    return {"id": "ops", "owner": True, "channel": "slack_channel", "target": "C1", **kw}


# ---------------------------------------------------------------- planning (the existing idempotency design)

def test_plan_p0_affected_and_each_pr_once():
    ms = notify.plan(V, {}, "https://site/")
    assert [m["key"] for m in ms] == ["p0", "affected:2", "pr:https://x/pull/3"]
    assert "https://site/#/events/ev_1" in ms[0]["text"] and ms[1]["text"].endswith("?section=env")


def test_plan_skips_sent_keys_and_a_new_fact_is_new():
    sent = {"keys": ["p0", "affected:2", "pr:https://x/pull/3"]}
    assert notify.plan(V, sent, "s") == []
    v3 = notify.view({**ROW, "impact": {"status": "affected", "affected": 3, "checked": 5}}, False, ["https://x/pull/3"])
    assert [m["key"] for m in notify.plan(v3, sent, "s")] == ["affected:3"]
    assert notify.plan(notify.view({**ROW, "severity": "P1", "impact": {"status": "not_affected"}}, False), {}, "s") == []


def test_record_keeps_the_first_thread():
    s = notify.record({}, "p0", "T1")
    s = notify.record(s, "affected:2", "T1")
    assert s == {"keys": ["p0", "affected:2"], "thread": "T1"}


def test_the_message_uses_the_retitled_title():
    """research/action/03 B4: the page shows the operator's sourced fix; the push showed the raw feed title."""
    row = {**ROW, "title": "Fixed root-cause title"}     # publish._summary applies title_override
    first = notify.plan(notify.view(row, False), {}, "s")[0]["text"].splitlines()[0]
    assert first.startswith("🚨 [P0 · ") and first.endswith("] Fixed root-cause title")


# ---------------------------------------------------------------- subscriptions

def test_a_legacy_single_channel_secret_is_reported_not_translated():
    """Contract: the hard-coded single-channel path is gone. A secret still in the old shape pushes nothing and says so."""
    c = notify.parse_config({**CFG, "slack_channel_id": "C1"})
    assert c.subscriptions == [] and c.legacy


@pytest.mark.parametrize("raw,code", [
    (sub(id="Ops"), "bad_id"), (sub(id="ops\n"), "bad_id"), (sub(channel="sms"), "unknown_channel"),
    (sub(target=""), "no_target"), (sub(channel="webhook", target="http://h/x", secret=SECRET), "webhook_not_https"),
    (sub(channel="webhook", target="https://h/x", secret="short"), "webhook_secret_short"),
    (sub(filters={"severty": ["P0"]}), "unknown_filter"), (sub(filters={"severity": ["P2"]}), "filter_value"),
    (sub(filters={"domain": []}), "filter_not_list"), (sub(filters={"has_waf_pack": "yes"}), "filter_not_bool"),
    (sub(filters={"exchanges": ["Binanse"]}), "filter_value")])
def test_an_invalid_subscription_is_reported_with_code_actual_and_allowed(raw, code):
    c = notify.parse_config({**CFG, "subscriptions": [raw]})
    assert c.subscriptions == [] and [e["error"] for e in c.invalid] == [code]
    assert {"error", "message", "actual", "allowed"} <= set(c.invalid[0])


def test_missing_credentials_duplicate_ids_and_a_bad_rollout_are_reported():
    c = notify.parse_config({"rollout": "everyone", "subscriptions": [sub(), sub(channel="lark_chat")]})
    assert [e["error"] for e in c.invalid] == ["bad_rollout", "missing_credentials", "missing_credentials"]
    assert c.rollout == "owner_only"                               # an unreadable gate fails toward fewer recipients
    c = notify.parse_config({**CFG, "subscriptions": [sub(), sub(target="C2")]})
    assert [s.target for s in c.subscriptions] == ["C1"] and c.invalid[0]["error"] == "duplicate_id"


def test_the_rollout_gate_defaults_to_owner_only():
    c = notify.parse_config({**CFG, "subscriptions": [sub(), sub(id="team", owner=False)]})
    assert c.rollout == "owner_only"
    assert [s.id for s in c.subscriptions if not notify.gated(s, c.rollout)] == ["ops"]
    assert not any(notify.gated(s, "all") for s in c.subscriptions)


def test_a_disabled_subscription_is_listed_not_used():
    c = notify.parse_config({**CFG, "subscriptions": [sub(enabled=False)]})
    assert c.subscriptions == [] and c.disabled == ["ops"]


# ---------------------------------------------------------------- the matcher

@pytest.mark.parametrize("filters,hit", [
    ({}, True), ({"severity": ["P0"]}, True), ({"severity": ["P1"]}, False), ({"domain": ["web3"]}, False),
    ({"domain": ["web3", "vuln"]}, True), ({"products": ["php"]}, True), ({"products": ["nginx"]}, False),
    ({"vendors": ["php"]}, True), ({"vendors": ["Ivanti"]}, False), ({"chains": ["ethereum"]}, False),
    ({"has_waf_pack": True}, False), ({"has_waf_pack": False}, True), ({"has_verdict": True}, True),
    ({"severity": ["P0"], "domain": ["web3"]}, False)])
def test_matches_every_field_and_combines_fields_with_and(filters, hit):
    assert notify.matches(filters, V) is hit


def test_chains_and_exchanges_match_case_insensitively_from_the_registry():
    v = notify.view({**ROW, "domain": "web3", "title": "Bybit cold wallet drained", "entities": [], "chains": ["Ethereum"],
                     "impact": None}, True)
    assert v["exchanges"] == ["Bybit"] and notify.matches({"exchanges": ["Bybit"], "chains": ["ethereum"]}, v)
    assert notify.matches({"has_waf_pack": True}, v) and not notify.matches({"has_verdict": True}, v)
    assert not notify.matches({"exchanges": ["OKX"]}, v)


def test_the_filter_explanation_is_generated_from_the_one_table():
    text = notify.explain()
    assert all(f"`{k}`" in text for k in notify.FILTER_FIELDS) and text.count("\n") == len(notify.FILTER_FIELDS) + 1


# ---------------------------------------------------------------- adapters

def _capture(monkeypatch, reply):
    sent = []

    def post(url, body, headers):
        sent.append((url, body))
        return reply(url)
    monkeypatch.setattr(notify, "_post", post)
    return sent


def _sub(**kw):
    s, err = notify.parse_subscription(sub(**kw), CFG)
    assert err is None, err
    return s


def test_slack_text_escapes_control_characters_from_feed_titles(monkeypatch):
    """A third-party title must not ping the channel (<!channel>) or dress a phishing URL as a link (05 §3.6)."""
    sent = _capture(monkeypatch, lambda url: {"ok": True, "ts": "1.2"})
    notify.send_slack(CFG, _sub(), {"text": "[P0] <!channel> R&D <https://phish.example|官方补丁>"}, None, {})
    assert sent[0][1]["text"] == "[P0] &lt;!channel&gt; R&amp;D &lt;https://phish.example|官方补丁&gt;"
    assert sent[0][1]["channel"] == "C1"


def test_slack_dm_posts_to_the_user_id(monkeypatch):
    sent = _capture(monkeypatch, lambda url: {"ok": True, "ts": "1.2"})
    assert notify.send_slack(CFG, _sub(channel="slack_dm", target="U9"), {"text": "x"}, None, {}) == "1.2"
    assert sent[0][1]["channel"] == "U9"


def test_lark_text_cannot_mention_everyone_and_the_token_is_fetched_once_per_run(monkeypatch):
    """Lark text messages parse <at user_id="all"></at> as @所有人 — a title carrying it must reach the chat inert."""
    sent = _capture(monkeypatch, lambda url: {"code": 0, "tenant_access_token": "x", "data": {"message_id": "m1"}})
    cache: dict = {}
    s = _sub(channel="lark_chat", target="oc_1")
    notify.send_lark(CFG, s, {"text": '[P0] x <at user_id="all"></at> < AT  id="ou_1">y</ at> a < b'}, None, cache)
    notify.send_lark(CFG, s, {"text": "second"}, "m1", cache)
    text = json.loads(sent[1][1]["content"])["text"]
    squashed = text.lower().replace(" ", "")
    assert "<at" not in squashed and "</at" not in squashed
    assert text.endswith("a < b")                         # an ordinary "<" is left as written
    assert sum("tenant_access_token" in u for u, _ in sent) == 1 and sent[1][1]["receive_id"] == "oc_1"


class _Resp:
    status = 204

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_webhook_body_is_json_signed_over_timestamp_and_body(monkeypatch):
    got = {}

    def urlopen(req, timeout, allow_hosts=None):
        got.update(req=req, allow_hosts=allow_hosts)
        return _Resp()
    monkeypatch.setattr(notify.fetch, "urlopen", urlopen)
    s = _sub(channel="webhook", target="https://hooks.example/radar", secret=SECRET)
    m = {**notify.plan(V, {}, "https://site")[0], "view": V}
    assert notify.send_webhook(CFG, s, m, None, {}) == "ev_1:p0"
    req = got["req"]
    body, ts = req.data, req.get_header("X-radar-timestamp")
    expect = "sha256=" + hmac.new(SECRET.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    assert req.get_header("X-radar-signature") == expect
    assert req.get_header("X-radar-delivery") == "ev_1:p0"
    doc = json.loads(body)
    assert doc["event"]["event_id"] == "ev_1" and doc["key"] == "p0" and doc["url"] == "https://site/#/events/ev_1"
    assert SECRET not in body.decode() and got["allow_hosts"] == frozenset()       # redirects refused


@pytest.fixture(autouse=True)
def _dns(monkeypatch):
    """Names resolve without the network: public, except *.rebind.example → 10.0.0.5."""
    real = fetch.socket.getaddrinfo
    monkeypatch.setattr(fetch.socket, "getaddrinfo", lambda h, *a, **k: real(h, *a, **k) if str(h)[:1].isdigit() else [
        (2, 1, 6, "", ("10.0.0.5" if str(h).endswith(".rebind.example") else "93.184.215.14", 0))])


def test_a_chat_api_call_never_follows_a_redirect(monkeypatch):
    """Slack / Lark calls carry a bot or tenant token; urllib keeps Authorization across a redirect, so none is followed
    (an empty allowlist), and the answer is read with the size cap."""
    seen = {}

    class R:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n=-1):
            seen["n"] = n
            return b'{"ok": true}'

    def opener(req, timeout, allow_hosts=None):
        seen["allow"] = allow_hosts
        return R()
    monkeypatch.setattr(fetch, "urlopen", opener)
    assert notify._post("https://slack.com/api/chat.postMessage", {"a": 1}, {"Authorization": "Bearer x"}) == {"ok": True}
    assert seen["allow"] == frozenset() and seen["n"] == notify.Limits.HTTP_MAX_BYTES


def test_a_webhook_whose_name_now_resolves_internal_is_not_posted_to(monkeypatch):
    """Registered while public, re-pointed to 10.0.0.5 later: the send resolves again and refuses before any open."""
    opened = []
    monkeypatch.setattr(fetch, "urlopen", lambda *a, **k: opened.append(a))
    m = {**notify.plan(V, {}, "s")[0], "view": V}
    sub = webhook_to("https://hooks.rebind.example", "/x")
    with pytest.raises(fetch.FetchError, match="webhook_internal"):
        notify.send_webhook(CFG, sub, m, None, {})
    assert opened == []


@pytest.fixture
def loopback(monkeypatch):
    """Real HTTP servers on 127.0.0.1: /redirect answers 302 to a second server (which counts every request it gets),
    /fail answers 500. conftest denies every connect; this re-allows loopback only. A mocked urlopen returning a
    response with status 302 tested a path real urllib never takes: its redirect handler acts first."""
    def connect(self, addr):
        if addr[0] != "127.0.0.1":
            raise RuntimeError("tests must not open network connections")
        return _socket.socket.connect(self, addr)
    monkeypatch.setattr(socket.socket, "connect", connect)
    elsewhere: list[str] = []

    class Other(http.server.BaseHTTPRequestHandler):
        def _hit(self):
            elsewhere.append(self.command)
            self.send_response(204)
            self.end_headers()
        do_GET = do_POST = _hit

        def log_message(self, *a):
            pass
    other = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Other)

    class Hook(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{other.server_port}/stolen")
            else:
                self.send_response(500)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass
    hook = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Hook)
    for srv in (other, hook):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{hook.server_port}", elsewhere
    finally:
        for srv in (other, hook):
            srv.shutdown()
            srv.server_close()


def webhook_to(base: str, path: str) -> notify.Subscription:
    """A parsed webhook subscription pointed at a loopback URL (parse_subscription rightly refuses http://)."""
    return dataclasses.replace(_sub(channel="webhook", target="https://hooks.example/radar", secret=SECRET),
                               target=base + path)


def test_a_webhook_answering_non_2xx_is_a_failed_send_and_a_redirect_is_never_followed(loopback, monkeypatch):
    base, elsewhere = loopback
    # both test servers are on 127.0.0.1, which R2.8's general redirect policy refuses as internal; the 3xx target stands
    # for a public host here, so what must refuse the hop is the webhook's own empty allowlist (M1111 died without this)
    monkeypatch.setattr(fetch, "_internal_host", lambda host: False)
    m = {**notify.plan(V, {}, "s")[0], "view": V}
    with pytest.raises(fetch.FetchError, match="redirect_refused"):
        notify.send_webhook(CFG, webhook_to(base, "/redirect"), m, None, {})
    assert elsewhere == []                    # the signed body (or a request at all) never reached the 3xx target
    with pytest.raises(urllib.error.HTTPError, match="500"):
        notify.send_webhook(CFG, webhook_to(base, "/fail"), m, None, {})


# ---------------------------------------------------------------- R4.4: thresholds and ids a subscriber asks for

def _v(**row):
    return notify.view({**ROW, **row}, False)


@pytest.mark.parametrize(("filters", "row", "hit"), [
    ({"min_loss_usd": 1_000_000}, {"amount_usd_latest": 49_000_000.0}, True),
    ({"min_loss_usd": 1_000_000}, {"amount_usd_latest": 999_999}, False),
    ({"min_loss_usd": 1_000_000}, {"amount_usd_latest": None}, False),          # no figure is not "at least"
    ({"min_loss_usd": 0}, {"amount_usd_latest": None}, False),
    ({"min_level": "V2"}, {"level": "V2"}, True),
    ({"min_level": "V2"}, {"level": "V4"}, True),
    ({"min_level": "V2"}, {"level": "V1"}, False),
    ({"min_level": "V0"}, {"level": "X"}, False),                               # disputed: below every minimum
    ({"exploitation": ["confirmed", "reported"]}, {"exploitation": "reported"}, True),
    ({"exploitation": ["confirmed"]}, {"exploitation": "poc"}, False),
    ({"exploitation": ["none"]}, {}, True),                                     # absent on the row = none
    ({"cves": ["cve-2026-109618"]}, {"cves": ["CVE-2026-109618", "CVE-2026-1"]}, True),
    ({"cves": ["CVE-2026-2"]}, {"cves": ["CVE-2026-109618"]}, False),
    ({"min_level": "V2", "min_loss_usd": 1e6}, {"level": "V3", "amount_usd_latest": 5e5}, False),   # AND across fields
])
def test_threshold_and_id_filters(filters, row, hit):
    parsed, err = notify.parse_subscription(sub(filters=filters), CFG)
    assert err is None and notify.matches(parsed.filters, _v(**row)) is hit


@pytest.mark.parametrize(("filters", "code"), [
    ({"min_loss_usd": "1000000"}, "filter_not_number"), ({"min_loss_usd": -1}, "filter_not_number"),
    ({"min_loss_usd": True}, "filter_not_number"), ({"min_loss_usd": float("inf")}, "filter_not_number"),
    ({"min_level": "V9"}, "filter_value"), ({"min_level": ["V2"]}, "filter_value"),
    ({"exploitation": ["exploited"]}, "filter_value"), ({"cves": []}, "filter_not_list"),
])
def test_a_threshold_that_cannot_be_one_is_refused_with_a_code(filters, code):
    parsed, err = notify.parse_subscription(sub(filters=filters), CFG)
    assert parsed is None and err["error"] == code and "allowed" in err


def test_the_view_keeps_the_events_own_field_names():
    v = _v(level="V3", amount_usd_latest=5e6, exploitation="confirmed")
    assert (v["level"], v["amount_usd"], v["exploitation"]) == ("V3", 5e6, "confirmed")
    assert not any(k.startswith("min_") for k in v)            # a filter's name is not a field of what subscribers receive
    assert set(notify._BOUNDS) == {k for k, (t, _, _) in notify.FILTER_FIELDS.items() if t in ("atleast", "number")}


# ---------------------------------------------------------------- R4.3: updates in the thread of a P0

def test_the_loss_step_doubles_and_small_or_missing_figures_have_none():
    assert [notify.loss_rung(a) for a in (None, True, 999_999, 1e6, 1.9e6, 2e6, 5e6, 6.34e9)] == \
        [None, None, None, "loss:1M", "loss:1M", "loss:2M", "loss:4M", "loss:4096M"]


def _p0(**row):
    return notify.view({**ROW, "severity": "P0", "impact": None, **row}, False)


def test_a_p0_notice_records_what_it_says_and_only_a_later_change_is_an_update():
    first = _p0(amount_usd_latest=5e6, level="V2")
    [m] = notify.plan(first, {}, "https://s")
    assert m["key"] == "p0" and m["also"] == ["standing", "loss:4M"]
    sent = notify.record({}, m["key"], "T1", m["also"])
    assert notify.plan(first, sent, "https://s") == []                                    # nothing new: nothing said
    assert notify.plan(_p0(amount_usd_latest=7.9e6, level="V2"), sent, "https://s") == []   # same step: restated, not doubled
    ups = notify.plan(_p0(amount_usd_latest=1.2e7, level="V3"), sent, "https://s")
    assert [u["key"] for u in ups] == ["loss:8M", "level:V3"]
    assert "损失数字升至 $12.0M" in ups[0]["text"] and "已证实（V3）" in ups[1]["text"]
    sent = notify.record(notify.record(sent, "loss:8M", None), "level:V3", None)
    assert notify.plan(_p0(amount_usd_latest=1.2e7, level="V3"), sent, "https://s") == []
    assert [u["key"] for u in notify.plan(_p0(amount_usd_latest=6.34e9, level="V4"), sent, "https://s")] == ["loss:4096M", "level:V4"]


def test_a_notice_that_already_states_a_confirmed_level_does_not_follow_itself_with_an_update():
    v = _p0(amount_usd_latest=None, level="V4")
    [m] = notify.plan(v, {}, "https://s")
    assert m["also"] == ["standing", "level:V4"] and notify.plan(v, notify.record({}, "p0", "T", m["also"]), "https://s") == []


def test_updates_are_for_a_p0_thread_that_exists():
    assert notify.plan(notify.view({**ROW, "severity": "P1", "impact": None, "amount_usd_latest": 9e7, "level": "V4"}, False), {}, "https://s") == []
    assert [m["key"] for m in notify.plan(_p0(amount_usd_latest=9e7, level="V4"), {}, "https://s")] == ["p0"]   # the notice first, alone


def test_a_thread_opened_before_updates_existed_gets_none():
    """Deploying this must not "update" every open P0 thread with the state it has been in for days."""
    assert notify.plan(_p0(amount_usd_latest=6.34e9, level="V4"), {"keys": ["p0"], "thread": "T-old"}, "https://s") == []


def test_r4_3_an_attack_tx_confirmed_on_chain_updates_the_p0_thread_once_per_count():
    """R4.3: the push view had no transaction verdicts; a P0 thread never heard that the attack tx was read back."""
    first = _p0(amount_usd_latest=None, level="V2", tx_confirmed=0)
    [m] = notify.plan(first, {}, "https://s")
    sent = notify.record({}, m["key"], "T1", m["also"])
    [up] = notify.plan(_p0(amount_usd_latest=None, level="V2", tx_confirmed=1), sent, "https://s")
    assert up["key"] == "tx:1" and "攻击交易已在链上证实（1 笔）" in up["text"]
    sent = notify.record(sent, "tx:1", None)
    assert notify.plan(_p0(amount_usd_latest=None, level="V2", tx_confirmed=1), sent, "https://s") == []
    # a thread opened after the confirmation records it as standing, not as news
    v = _p0(amount_usd_latest=None, level="V2", tx_confirmed=2)
    [m2] = notify.plan(v, {}, "https://s")
    assert "tx:2" in m2["also"] and notify.plan(v, notify.record({}, "p0", "T", m2["also"]), "https://s") == []


def test_r4_3_the_published_row_counts_only_confirmed_attack_transactions():
    from radar import publish
    from radar.model import Event
    ev = Event(event_id="ev_1", domain="web3", title="x", first_seen="2026-11-15T00:00:00Z", last_updated="2026-11-15T00:00:00Z",
               item_ids=[], keys=[], severity="P0",
               tx=[{"hash": "0x1", "chain": "bsc", "verified": "confirmed"}, {"hash": "0x2", "chain": "bsc", "verified": "unchecked"},
                   {"hash": "0x3", "chain": "bsc", "verified": "failed"}])
    assert publish._summary(ev)["tx_confirmed"] == 1


def test_r4_4_waf_and_not_affected_reach_an_existing_p0_thread_once_and_kinds_filter_messages():
    v0 = _p0(amount_usd_latest=None, level="V2")
    [m] = notify.plan(v0, {}, "https://s")
    sent = notify.record({}, m["key"], "T1", m["also"])
    v = notify.view({**ROW, "severity": "P0", "amount_usd_latest": None, "level": "V2",
                     "impact": {"status": "not_affected", "affected": 0, "checked": 3}}, True)
    ups = notify.plan(v, sent, "https://s")
    assert [(u["key"], u["kind"]) for u in ups] == [("waf", "waf"), ("verdict:not_affected", "verdict")]
    assert "WAF 规则包已生成" in ups[0]["text"] and "已查 3 个" in ups[1]["text"]
    # a thread opened when the pack already existed: standing, not news (no burst for packs that predate the thread)
    [m2] = notify.plan(v, {}, "https://s")
    assert {"waf", "verdict:not_affected"} <= set(m2["also"])
    assert notify.plan(v, notify.record({}, "p0", "T", m2["also"]), "https://s") == []
    # the kinds filter is per message; matches() ignores it
    assert notify.wanted({"kinds": ["waf"]}, ups[0]) and not notify.wanted({"kinds": ["waf"]}, ups[1])
    assert notify.wanted({}, ups[1]) and notify.matches({"kinds": ["waf"]}, v)
    assert all(m.get("kind") for m in notify.plan(_p0(amount_usd_latest=9e7, level="V3"), sent, "https://s"))


def test_r4_4_a_lark_dm_goes_to_the_person_by_open_id_or_email_and_replies_in_its_thread(monkeypatch):
    sent = _capture(monkeypatch, lambda url: {"code": 0, "tenant_access_token": "x", "data": {"message_id": "m9"}})
    cache: dict = {}
    for target, kind in (("ou_7f3a", "open_id"), ("alice@example.com", "email")):
        sent.clear()
        assert notify.send_lark(CFG, _sub(channel="lark_dm", target=target), {"text": "x"}, None, cache) == "m9"
        url, body = next((u, b) for u, b in sent if "/im/v1/messages" in u)
        assert url.endswith(f"receive_id_type={kind}") and body["receive_id"] == target
    sent.clear()
    notify.send_lark(CFG, _sub(channel="lark_dm", target="ou_7f3a"), {"text": "y"}, "m9", cache)
    assert sent[-1][0].endswith("/im/v1/messages/m9/reply")
    assert notify.lark_receive_type("lark_chat", "oc_1") == "chat_id"


@pytest.mark.parametrize("target", ["oc_1", "alice", "alice@", "@example.com", "ou"])
def test_r4_4_a_lark_dm_target_that_is_not_a_person_is_refused_with_its_reason(target):
    s, err = notify.parse_subscription(sub(channel="lark_dm", target=target), CFG)
    assert s is None and err["error"] == "lark_dm_target"


def test_r4_4_an_owner_lark_dm_receives_alerts():
    from radar import alert
    assert "lark_dm" in alert.CHAT_CHANNELS and set(alert.CHAT_CHANNELS) == set(notify.CHANNELS) - {"webhook"}
