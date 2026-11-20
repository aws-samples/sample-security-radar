"""The P0 notice and its send gate (Neo 2026-11-16: the team Slack gets P0s only, once, about the event itself, with
emoji, a summary and the event page said for what it is — and the whole path is a harness: every notice passes coded
rules right before the send, a refused one is named on #/ops and never retried)."""
from datetime import UTC, datetime

import pytest

from radar import alert, notify, notify_station, ops
from radar.model import Event
from radar.store import MemoryStore

SITE = "https://site"
NOW = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
AT = "2026-11-16T11:00:00Z"
LIGHTER = {"event_id": "ev_0000000000000c01", "severity": "P0", "domain": "web3", "level": "V2",
           "title": "#PeckShieldAlert #Lighter has been exploited for ~$10M, the exploiter bridged 640 $ETH https:/",
           "summary": "Lighter 两个做市商账户疑因 API 密钥泄露损失约 1550 万美元，平台已暂停提款。",
           "amount_usd_latest": 10_000_000.0, "tx_confirmed": 2, "entities": ["Lighter"], "cves": [],
           "first_seen": "2026-11-16T03:05:00Z"}
VULN = {"event_id": "ev_0000000000000d01", "severity": "P0", "domain": "vuln", "level": "V3", "exploitation": "confirmed",
        "title": "CVE-2026-1 Acme Gateway: Auth Bypass", "summary": "Acme 网关认证绕过已被在野利用。",
        "cves": ["CVE-2026-1"], "entities": ["Acme"], "impact": {"status": "affected", "affected": 2, "checked": 5}}


def p0(row):
    v = notify.view(row, False, ["https://github.com/x/y/pull/3"])
    return v, notify.plan(v, {}, SITE)[0]


# ---------------------------------------------------------------- the notice itself

@pytest.mark.parametrize(("title", "want"), [
    ("#PeckShieldAlert #Lighter has been exploited for ~$10M https:/", "Lighter has been exploited for ~$10M"),
    ("https://t.co/agOq56biUi > We are actively investigating a security incident", "We are actively investigating a security incident"),
    ("Kava Lend — Arithmetic Error", "Kava Lend — Arithmetic Error"),
    ("#CertiKAlert #Foo drained", "Foo drained"),
])
def test_the_headline_has_no_link_quote_marker_or_alert_tag_and_keeps_the_victim(title, want):
    assert notify.headline(title) == want


def test_a_web3_p0_notice_has_emoji_the_summary_the_figures_and_the_event_page_said_for_what_it_is():
    v, m = p0(LIGHTER)
    lines = m["text"].splitlines()
    assert lines[0] == "🚨 [P0 · Web3 被盗] Lighter has been exploited for ~$10M, the exploiter bridged 640 $ETH"
    assert lines[1] == f"📝 {LIGHTER['summary']}"
    assert lines[2] == "🕐 首报 2026-11-16 11:05（UTC+8）"       # first report, on the team's clock
    assert lines[3] == "💰 损失 $10.0M ｜ ✅ V2 多方互证 ｜ ⛓️ 链上攻击交易已确认 2 笔"
    assert lines[4] == f"🔗 雷达事件页（原始来源 · 时间线 · 链上证据）：{SITE}/#/events/{LIGHTER['event_id']}"
    assert m["slack"].splitlines()[-1] == f"🔗 <{SITE}/#/events/{LIGHTER['event_id']}|雷达事件页（原始来源 · 时间线 · 链上证据）>"
    assert notify.gate(m, v, SITE, []) == []


def test_a_vulnerability_p0_notice_carries_no_facts_row_and_nothing_of_our_repositories():
    """Neo 2026-11-18: 「这两句也不要了」 — the CVE / exploitation / level row is gone from a vulnerability notice."""
    v, m = p0(VULN)
    assert "🧩" not in m["text"] and "🔥" not in m["text"] and "✅ V3" not in m["text"]
    assert "代码目标" not in m["text"] and "section=env" not in m["text"] and "pull/3" not in m["text"]
    assert notify.gate(m, v, SITE, []) == []


def test_slack_mrkdwn_escapes_every_third_party_piece_but_keeps_the_radars_own_link():
    _v, m = p0({**LIGHTER, "title": "<!channel> drained <https://phish|官方补丁>", "summary": "a & b"})
    s = m["slack"]
    assert "<!channel>" not in s and "&lt;!channel&gt;" in s and "a &amp; b" in s
    assert s.count("<") == 1 and s.splitlines()[-1].startswith(f"🔗 <{SITE}/#/events/")


def test_a_summary_with_a_broken_character_is_dropped_not_sent():
    v, m = p0({**LIGHTER, "summary": "可被串联,�蜜罐已出现扫描"})
    assert "📝" not in m["text"] and "�" not in m["text"] and notify.gate(m, v, SITE, []) == []


def test_slack_gets_its_mrkdwn_without_unfurling(monkeypatch):
    seen = {}
    monkeypatch.setattr(notify, "_post", lambda url, body, headers: seen.update(body) or {"ok": True, "ts": "1.2"})
    s, err = notify.parse_subscription({"id": "team", "owner": True, "channel": "slack_channel", "target": "C1"},
                                       {"slack_bot_token": "x"})
    assert err is None
    _v, m = p0(LIGHTER)
    notify.send_slack({"slack_bot_token": "x"}, s, m, None, {})
    assert seen["text"] == m["slack"] and seen["unfurl_links"] is False and seen["unfurl_media"] is False


# ---------------------------------------------------------------- the gate, rule by rule

@pytest.mark.parametrize(("change", "code"), [
    (lambda v, m: v.update(severity="P1"), "not_p0"),
    (lambda v, m: m["parts"].update(headline=""), "no_headline"),
    (lambda v, m: m["parts"].update(headline="see https://t.co/x"), "url_in_headline"),
    (lambda v, m: m["parts"].update(link="https://elsewhere/#/events/x"), "link_not_event_page"),
    (lambda v, m: m.update(text=m["text"] + "\n受影响：2/5 个代码目标命中"), "repository_content"),
    (lambda v, m: m.update(text=m["text"] + "\n…?section=env"), "repository_content"),
    (lambda v, m: m.update(text=m["text"] + "�"), "bad_characters"),
    (lambda v, m: m.update(text=m["text"] + "x" * 900), "too_long"),
])
def test_each_gate_rule_refuses_with_its_code(change, code):
    v, m = p0(LIGHTER)
    v, m = dict(v), {**m, "parts": dict(m["parts"])}
    change(v, m)
    assert code in {p["error"] for p in notify.gate(m, v, SITE, [])}


def test_the_first_report_time_is_always_said_and_the_gate_refuses_a_notice_without_it():
    v, m = p0(LIGHTER)
    assert "🕐 首报 2026-11-16 11:05（UTC+8）" in m["slack"]
    cut = {**m, "text": m["text"].replace("🕐 首报 2026-11-16 11:05（UTC+8）\n", "")}
    assert [p["error"] for p in notify.gate(cut, v, SITE, [])] == ["no_first_report_time"]
    v2, m2 = p0({**LIGHTER, "first_seen": None})
    assert "🕐 首报时间未知" in m2["text"] and notify.gate(m2, v2, SITE, []) == []     # unknown is said, not blocked


def test_a_problem_names_code_message_actual_and_limit():
    v, m = p0(LIGHTER)
    (p,) = notify.gate(m, {**v, "severity": "P1"}, SITE, [])
    assert p == {"error": "not_p0", "message": "a P0 notice for an event that is not P0", "actual": "P1", "limit": "P0"}


def test_the_same_victim_or_cve_within_the_window_is_a_duplicate_but_a_shared_word_is_not():
    v, m = p0(LIGHTER)
    other = notify.ledger_entry({**LIGHTER, "event_id": "ev_0000000000000c02"}, AT)
    assert [p["error"] for p in notify.gate(m, v, SITE, [other])] == ["duplicate_p0"]
    assert notify.gate(m, v, SITE, [notify.ledger_entry(LIGHTER, AT)]) == []          # its own earlier entry
    unrelated = notify.ledger_entry({**LIGHTER, "event_id": "ev_0000000000000c03", "entities": ["Kava Lend"]}, AT)
    assert notify.gate(m, v, SITE, [unrelated]) == []                                  # both say USDC / exploited
    vv, vm = p0(VULN)
    assert [p["error"] for p in notify.gate(vm, vv, SITE, [notify.ledger_entry(
        {**VULN, "event_id": "ev_0000000000000d02", "entities": []}, AT)])] == ["duplicate_p0"]


# ---------------------------------------------------------------- the station: once, gated, said

TEAM = {"slack_bot_token": "x", "rollout": "owner_only", "subscriptions": [
    {"id": "team", "owner": True, "channel": "slack_channel", "target": "C-TEAM",
     "filters": {"severity": ["P0"], "kinds": ["p0"]}},
    {"id": "me", "owner": True, "channel": "slack_dm", "target": "U-ME", "filters": {"kinds": ["alarm"]}}]}


def _ev(row, **kw):
    return Event(event_id=row["event_id"], domain=row["domain"], title=row["title"], first_seen=AT, last_updated=AT,
                 item_ids=[], keys=[], severity="P0", level=row["level"], summary=row["summary"],
                 entities=list(row.get("entities") or []), cves=list(row.get("cves") or []),
                 amount_usd_latest=row.get("amount_usd_latest"), **kw)


def _world():
    store, sent = MemoryStore(), []

    def sender(cfg, sub, msg, thread, cache):
        sent.append((sub.id, msg["view"]["event_id"], msg["key"]))
        return thread or "T1"
    senders = {c: sender for c in notify.CHANNELS}
    notify_station.run(MemoryStore(), TEAM, NOW, SITE, senders)          # first run of each subscription = baseline
    empty = MemoryStore()
    notify_station.run(empty, TEAM, NOW, SITE, senders)
    for k in (notify_station.STATUS_KEY, notify_station.BASELINED_KEY):
        store.put_source_state(k, empty.get_source_state(k))
    return store, sent, senders


def test_the_team_channel_gets_one_p0_per_event_and_the_alarm_dm_gets_none():
    store, sent, senders = _world()
    store.put_event(_ev(LIGHTER))
    notify_station.run(store, TEAM, NOW, SITE, senders)
    notify_station.run(store, TEAM, NOW, SITE, senders)                  # a second run sends nothing
    assert sent == [("team", LIGHTER["event_id"], "p0")]


def test_a_second_event_for_the_same_victim_is_blocked_named_on_ops_and_never_retried():
    store, sent, senders = _world()
    store.put_event(_ev(LIGHTER))
    notify_station.run(store, TEAM, NOW, SITE, senders)
    store.put_event(_ev({**LIGHTER, "event_id": "ev_0000000000000c09", "title": "Lighter halts withdrawals"}))
    st = notify_station.run(store, TEAM, NOW, SITE, senders)
    notify_station.run(store, TEAM, NOW, SITE, senders)
    assert sent == [("team", LIGHTER["event_id"], "p0")]
    assert [(b["event_id"], b["problems"][0]["error"]) for b in st["blocked"]] == [("ev_0000000000000c09", "duplicate_p0")]
    items = ops._notify({"notify": st})
    assert any(i["level"] == "warn" and "推送门禁拦下" in i["title"] and "duplicate_p0" in i["detail"] for i in items)


def test_alarms_go_to_owner_chats_that_list_alarm_and_never_to_a_p0_only_channel(monkeypatch):
    got = []
    monkeypatch.setattr(notify, "SENDERS", {c: (lambda cfg, s, m, t, c_: got.append(s.id) or "1") for c in notify.CHANNELS})
    alert.deliver(TEAM, ["[雷达告警] EventAnomaly：ALARM"], SITE)
    assert got == ["me"]


def test_a_first_report_that_gave_only_a_day_is_said_as_a_day_not_as_0800():
    """Live 2026-11-18: Puppet's KEV entry 「2026-11-17」 was announced as 首报 08:00 (00:00Z)."""
    v = notify.view({**LIGHTER, "first_seen": "2026-11-17T00:00:00Z"}, False, [])
    m = notify.plan(v, {}, SITE)[0]
    assert "🕐 首报 2026-11-17（来源只给日期）" in m["text"] and "08:00" not in m["text"]
    # Neo 2026-11-19: a day is not precise enough to push — the notice is held (G9), not dropped
    probs = notify.gate(m, v, SITE, [])
    assert [p["error"] for p in probs] == ["first_report_day_only"] and notify.held(probs)


@pytest.mark.parametrize("summary, title, want", [
    # live 2026-11-18 (the notice was too long up front): the subject and the CVE id repeat the headline
    ("Java4Shell（CVE-2026-114938）是Java Base64解码器的内存破坏漏洞，可能导致未认证远程代码执行，Oracle已发布修复。",
     "Java4Shell: Remote Code Execution in OpenJDK (CVE-2026-114938)",
     "Java Base64解码器的内存破坏漏洞，可能导致未认证远程代码执行。"),
    ("OpenJDK 的 Java4Shell(CVE-2026-114938)是可被未认证远程利用的代码执行漏洞,补丁已发布,需立即排查 Java 环境。",
     "Java4Shell: Remote Code Execution in OpenJDK (CVE-2026-114938)",
     "可被未认证远程利用的代码执行漏洞,需立即排查 Java 环境。"),
    ("OpenJDK Base64解码器曝Java4Shell未认证远程代码执行漏洞，已有修复，需尽快排查修补。",
     "Java4Shell: Remote Code Execution in OpenJDK (CVE-2026-114938)",
     "OpenJDK Base64解码器曝Java4Shell未认证远程代码执行漏洞，需尽快排查修补。"),
    # a fix clause in the middle of a clause is not a clause: kept
    ("攻击者在Oracle发布修复前已利用该漏洞。", "Java4Shell: Remote Code Execution in OpenJDK (CVE-2026-114938)",
     "攻击者在Oracle发布修复前已利用该漏洞。"),
    # a subject with information the headline lacks stays (a version range, a component)
    ("Apache Roller 4.0.0 至 6.1.4 的 XML-RPC 端点存在未认证反序列化远程代码执行漏洞。",
     "CVE-2026-129448 Apache Roller: Unauthenticated deserialization in the XML-RPC endpoint",
     "Apache Roller 4.0.0 至 6.1.4 的 XML-RPC 端点存在未认证反序列化远程代码执行漏洞。"),
    ("TYPO3 表单框架是信息泄露的源头。", "CVE-2026-125160 TYPO3 CMS - Information Disclosure in Form Framework",
     "TYPO3 表单框架是信息泄露的源头。"),
])
def test_the_summary_drops_what_the_headline_already_says(summary, title, want):
    assert notify.trim_summary(summary, title) == want


def test_a_vulnerability_p0_is_tagged_p0_vulnerability_and_says_exploitation_below():
    row = {**LIGHTER, "domain": "vuln", "title": "Java4Shell: Remote Code Execution in OpenJDK (CVE-2026-114938)",
           "cves": ["CVE-2026-114938"], "exploitation": "reported", "summary": "Java4Shell（CVE-2026-114938）是一个漏洞。"}
    _v, m = p0(row)
    assert m["text"].startswith("🚨 [P0 · 漏洞] Java4Shell")
    assert "🧩" not in m["text"] and "🔥" not in m["text"] and "✅" not in m["text"] and "⏫" not in m["text"]
    assert "📝 一个漏洞。" in m["text"]
