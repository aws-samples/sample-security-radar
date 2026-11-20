"""v1.4.0 — the 2026-11 security review's webhook recommendations, each from a case the reviewer tried:

R1 a target with a space / CR / LF / control character passed target_problem, then http.client raised InvalidURL at
   send time — not in SEND_ERRORS, so one self-service subscriber could crash every Notify run.
R4 the webhook path fails closed on a DNS error, and NAT64 (64:ff9b::/96) counts as internal.
"""
import http.client
import json
import socket

import pytest
from test_notify_station import CFG, NOW, _baseline, world  # noqa: F401  (fixture)

from radar import fetch, notify, notify_station, subscribe_api


@pytest.fixture
def public_dns(monkeypatch):
    monkeypatch.setattr(fetch.socket, "getaddrinfo", lambda h, *a, **k: [(2, 1, 6, "", ("93.184.215.14", 0))])


@pytest.mark.parametrize("target", ["https://hooks.example.com/a b", "https://hooks.example.com/a\r\nX-Evil: 1",
                                    "https://hooks.example.com/a\tb", "https://hooks.example.com/\x00", "https://hooks.example.com/\x7f",
                                    "https://hooks.example.com/a\x85b"])
def test_a_target_with_a_space_or_control_character_is_refused_at_registration_and_at_load(target, public_dns):
    assert subscribe_api.target_problem(target)["error"] == "target_control_char"
    conf = notify.parse_config({"subscriptions": [{"id": "s1", "channel": "webhook", "target": target, "secret": "s" * 40}]})
    assert conf.subscriptions == [] and conf.invalid[0]["error"] == "webhook_control_char"


def test_a_plain_target_still_passes(public_dns):
    assert subscribe_api.target_problem("https://hooks.example.com/radar?x=1&y=%20") is None


def test_http_client_errors_cost_one_delivery_not_the_run(world):  # noqa: F811
    store, sent, senders = world
    _baseline(store, senders)

    def invalid(cfg, sub, msg, thread, cache):
        raise http.client.InvalidURL("URL can't contain control characters")
    st = notify_station.run(store, CFG, NOW, "https://site", {**senders, "slack_channel": invalid})
    assert st["subscriptions"]["p0-only"]["status"] == "error" and st["status"] == "degraded"
    assert {s for s, *_ in sent} == {"web3-all"}


@pytest.mark.parametrize("addr", ["64:ff9b::a9fe:a9fe", "64:ff9b::a00:1"])
def test_nat64_is_internal_literal_and_resolved(addr, monkeypatch):
    assert fetch._internal_host(f"[{addr}]")
    monkeypatch.setattr(fetch.socket, "getaddrinfo", lambda h, *a, **k: [(10, 1, 6, "", (addr, 0, 0, 0))])
    assert fetch._internal_host("hooks.example.com")


def test_an_unresolvable_webhook_host_fails_closed_but_a_collector_redirect_check_does_not(monkeypatch):
    def nx(h, *a, **k):
        raise socket.gaierror(-2, "Name or service not known")
    monkeypatch.setattr(fetch.socket, "getaddrinfo", nx)
    assert fetch._internal_host("gone.example.com", unresolvable_is_internal=True)
    assert not fetch._internal_host("gone.example.com")          # the collector's open reports the real DNS error
    assert subscribe_api.target_problem("https://gone.example.com/h")["error"] == "target_not_public"
    sub = notify.Subscription(id="s1", channel="webhook", target="https://gone.example.com/h", owner=False, filters={}, secret="s" * 40)
    msg = {"key": "p0", "view": {"event_id": "ev_1"}, "text": "t"}
    monkeypatch.setattr(notify, "webhook_body", lambda s, m, v: json.dumps({}).encode())
    with pytest.raises(fetch.FetchError, match="webhook_internal"):
        notify.send_webhook({}, sub, msg, None, {})


# R2 — the operator's code-impact verdict and patch PRs never reach a self-service (owner false) subscription
def _world_with_pr(monkeypatch, owner):
    from test_notify_station import RESP

    from radar import publish
    resp = {k: {**v, "issues": [{"pr_url": "https://git.example/acme/pay/pull/7"}]} for k, v in RESP.items()}
    monkeypatch.setattr(publish, "_response", lambda e, s, now: resp.get(e.event_id))
    hook = {**CFG["subscriptions"][1], "owner": owner}
    return {**CFG, "rollout": "all", "subscriptions": [hook]}


@pytest.mark.parametrize("owner", [True, False])
def test_verdicts_and_prs_reach_the_owner_only(world, monkeypatch, owner):  # noqa: F811
    store, sent, senders = world
    cfg = _world_with_pr(monkeypatch, owner)
    _baseline(store, senders, cfg)
    notify_station.run(store, cfg, NOW, "https://site", senders)
    kinds = {k.split(":")[0] for _s, _e, k, _b in sent}
    bodies = [json.loads(b) for *_x, b in sent]
    if owner:
        assert {"affected", "pr"} <= kinds
        assert any((b["event"].get("impact") or {}).get("status") == "affected" for b in bodies)
    else:
        assert sent and not {"affected", "pr", "verdict"} & kinds
        assert all(b["event"]["impact"] is None and b["event"]["prs"] == [] and b["event"]["has_verdict"] is False
                   for b in bodies)
        assert "git.example" not in json.dumps(bodies)


@pytest.mark.parametrize("filters", [{"has_verdict": True}, {"kinds": ["p0", "pr"]}, {"kinds": ["verdict"]}])
def test_a_self_service_filter_on_operator_only_facts_is_refused(filters, public_dns):
    from test_subscribe_api import Box, call
    box = Box()
    st, err = call(box, "POST", body={"target": "https://hooks.example.com/x", "filters": filters})
    assert (st, err["error"]) == (400, "filter_operator_only") and box.saves == 0
