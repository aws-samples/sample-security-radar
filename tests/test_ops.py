"""D/M3 ops view: every rule fires on its fact and stays quiet otherwise; errors sort first."""
from __future__ import annotations

from radar import ops

QUIET = {"sources": [{"name": "CISA KEV", "status": "ok"}], "ledger": {"notify": {"slack": {"status": "ok"}}},
         "events": [{"event_id": "e", "tx": [{"chain": "ethereum", "verified": "confirmed"}]}], "digest": {"status": "ok"}}


def test_a_healthy_system_needs_nobody():
    assert ops.attention(QUIET) == []


def test_each_rule_fires_on_its_fact():
    f = {"sources": [{"name": "X", "status": "failing", "last_error": "HTTP 403", "last_error_at": "t"},
                     {"name": "Y", "status": "degraded", "last_error": "timeout"}],
         "ledger": {"over_budget": {"date": "2026-10-27", "continuum_usd": 1464.08, "cap": 500, "at": "t"},
                    "notify": {"slack": {"status": "not_configured"}, "lark": {"status": "error", "error": "401"}},
                    "gitlab_error": "AccessDenied", "cost_error": {"at": "t", "error": "throttled"}},
         "events": [{"event_id": "e1", "tx": [{"chain": "bsc", "check_error": "rpc_unreachable: Forbidden", "checked_at": "t"}]}],
         "digest": {"status": "failed", "day": "2026-10-29", "reason": "refused"}}
    got = ops.attention(f)
    codes = {i["code"] for i in got}
    assert codes == set(ops.RULES), set(ops.RULES) - codes                      # every rule is reachable
    assert [i["level"] for i in got] == sorted((i["level"] for i in got), key=ops.LEVELS.index)
    over = next(i for i in got if i["code"] == "over_budget")
    assert "1464.08" in over["detail"] and "500" in over["detail"]             # actual + limit (error 4 elements)
    assert next(i for i in got if i["code"] == "chain_rpc_error")["link"] == "/events/e1"


def test_an_unconfigured_channel_is_info_not_an_error():
    got = ops.attention({**QUIET, "ledger": {"notify": {"lark": {"status": "not_configured"}}}})
    assert [(i["code"], i["level"]) for i in got] == [("notify", "info")]
