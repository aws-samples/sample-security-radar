"""R0.2 — a CloudWatch alarm reaches the owner (SNS → AlertFn → the owner's subscriptions).

The stack's only alarm had no action: on 2026-11-12 the site's top event was wrong for eleven hours; had the cycle
itself died, the alarm would have turned red and told nobody."""
import ast
import json
import re
from pathlib import Path

import pytest

from radar import alert, notify

ROOT = Path(__file__).resolve().parents[1]
STACK = (ROOT / "infra" / "stack.py").read_text()
CFG = {"slack_bot_token": "xoxb-1", "subscriptions": [
    {"id": "ops", "owner": True, "channel": "slack_dm", "target": "U1"},
    {"id": "team", "channel": "slack_channel", "target": "C9"},
    {"id": "hook", "owner": True, "channel": "webhook", "target": "https://h.example/x", "secret": "s" * 32}]}


def sns(name="SecurityRadar-NoPublishedCycle", state="ALARM", reason="Threshold Crossed: no datapoints"):
    return {"Records": [{"Sns": {"Message": json.dumps({
        "AlarmName": name, "NewStateValue": state, "NewStateReason": reason,
        "AlarmDescription": "security-radar: no cycle published in 30 minutes", "StateChangeTime": "2026-11-12T03:58:00.000+0000"})}}]}


def test_an_alarm_goes_to_the_owners_chat_subscriptions_only():
    sent = []
    senders = {"slack_dm": lambda cfg, sub, m, thread, cache: sent.append((sub.id, m["text"])) or "ts",
               "slack_channel": lambda *a: sent.append(("team", "LEAK")) or "ts",
               "webhook": lambda *a: sent.append(("hook", "LEAK")) or "d"}
    out = alert.deliver(CFG, alert.messages(sns()), "https://radar.example", senders)
    assert [s for s, _ in sent] == ["ops"]                     # not the team channel, not a webhook (no event to sign)
    text = sent[0][1]
    assert "NoPublishedCycle" in text and "ALARM" in text and "no cycle published" in text
    assert "https://radar.example/#/ops" in text
    assert out == {"messages": 1, "sent": 1, "errors": []}


def test_a_recovery_is_told_too_and_a_long_reason_is_cut():
    (m,) = alert.messages(sns(state="OK", reason="x" * 5000))
    assert "OK" in m and len(m) < 1200


def test_delivery_that_reached_nobody_raises_so_the_invocation_is_retried_and_counted():
    def down(*a):
        raise ValueError("slack: channel_not_found")
    with pytest.raises(alert.AlertError) as e:
        alert.deliver(CFG, alert.messages(sns()), "", {"slack_dm": down})
    assert e.value.detail["error"] == "alert_not_delivered" and e.value.detail["attempted"] == 1


def test_no_owner_subscription_is_reported_not_raised():
    """A retry cannot create a subscription: say so once (the caller logs it as degraded)."""
    cfg = {"subscriptions": [{"id": "team", "channel": "slack_channel", "target": "C9"}], "slack_bot_token": "x"}
    assert alert.deliver(cfg, alert.messages(sns()), "", notify.SENDERS) == {
        "messages": 1, "sent": 0, "errors": [], "degraded": "no_owner_chat_subscription"}


def test_a_message_that_is_not_an_alarm_is_passed_on_as_text():
    assert alert.messages({"Records": [{"Sns": {"Message": "plain words", "Subject": "s"}}]}) == ["[雷达告警] s\nplain words"]


# --- the stack: every alarm has an action, and the dead-man switch counts published cycles ----------------------------

def _alarm_blocks():
    return re.findall(r"alarm\(\s*\"(\w+)\"", STACK)


def test_every_alarm_notifies_the_alert_topic():
    """One helper builds every alarm and attaches the topic; a bare cw.Alarm( elsewhere would be an alarm nobody hears."""
    tree = ast.parse(STACK)
    bare = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and ast.unparse(n.func) == "cw.Alarm"]
    assert len(bare) == 1, "cw.Alarm is called only inside the alarm() helper"
    assert "a.add_alarm_action(cw_actions.SnsAction(alerts))" in STACK and "a.add_ok_action(cw_actions.SnsAction(alerts))" in STACK
    assert set(_alarm_blocks()) >= {"NoPublishedCycle", "CycleFailed", "CycleTimedOut", "EventAnomaly", "AlertFnErrors"}


def test_the_dead_man_switch_counts_cycles_that_published_not_executions_that_succeeded():
    """A cycle skipped for overlap ends in a Succeed state (16 % of executions, measured 2026-11-12): counted as
    successes, they kept the old alarm green while nothing was published."""
    assert "metric_succeeded" not in STACK
    assert '$.type = "TaskStateExited"' in STACK and '$.details.name = "Publish"' in STACK


def test_the_alert_function_reads_the_notify_secret_and_nothing_else():
    assert "notify_cfg.grant_read(alert_fn)" in STACK
    assert "table.grant" not in re.search(r"alert_fn = .*?\n\n", STACK, re.DOTALL).group(0)
    assert "alerts.add_subscription(subs.LambdaSubscription(alert_fn))" in STACK


def test_cloudwatch_is_allowed_to_publish_to_the_topic_and_only_from_this_account():
    """Live 2026-11-12: the first test alarm ended in "Failed to execute action" — the topic had a resource policy
    (enforce_ssl) and no statement letting CloudWatch publish. Alarms that cannot notify are the bug R0.2 removes."""
    block = re.search(r"alerts\.add_to_resource_policy\(.*?\)\)\)\n", STACK, re.DOTALL).group(0)
    assert '"sns:Publish"' in block and 'ServicePrincipal("cloudwatch.amazonaws.com")' in block
    assert '"aws:SourceAccount": self.account' in block and "alarm:*" in block
