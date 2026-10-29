"""C3: what gets pushed, at most once per fact, threaded per event."""

from radar import notify

EV = {"event_id": "ev_1", "title": "PHP2Shell", "severity": "P0", "level_reason": "T1 confirmed"}
RESP = {"issues": [{"issue_id": "i1", "severity": "CRITICAL", "exploitable": "EXPLOITABLE", "pr_url": "https://x/pull/3"},
                   {"issue_id": "i2", "pr_url": "https://x/pull/3"}, {"issue_id": "i3", "pr_url": None}]}
IMP = {"status": "affected", "affected": 2, "checked": 5}


def test_plan_p0_affected_and_each_pr_once():
    ms = notify.plan(EV, RESP, IMP, {}, "https://site/")
    assert [m["key"] for m in ms] == ["p0", "affected:2", "pr:https://x/pull/3"]
    assert "https://site/#/events/ev_1" in ms[0]["text"] and ms[1]["text"].endswith("?section=env")


def test_plan_skips_sent_keys_and_a_new_fact_is_new():
    sent = {"keys": ["p0", "affected:2", "pr:https://x/pull/3"]}
    assert notify.plan(EV, RESP, IMP, sent, "s") == []
    assert [m["key"] for m in notify.plan(EV, RESP, {**IMP, "affected": 3}, sent, "s")] == ["affected:3"]
    assert notify.plan({**EV, "severity": "P1"}, None, {"status": "not_affected"}, {}, "s") == []


def test_record_keeps_the_first_thread():
    s = notify.record({}, "p0", "T1")
    s = notify.record(s, "affected:2", "T1")
    assert s == {"keys": ["p0", "affected:2"], "thread": "T1"}


def test_configured_requires_every_field_of_a_channel():
    assert notify.configured({"slack_bot_token": "x", "slack_channel_id": "C", "lark_app_id": "a"}) == ["slack"]
    assert notify.configured({}) == []
