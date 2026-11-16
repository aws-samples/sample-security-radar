"""D/M3 ops view: every rule fires on its fact and stays quiet otherwise; errors sort first."""
from __future__ import annotations

from radar import ops

QUIET = {"sources": [{"name": "CISA KEV", "status": "ok"}], "notify": {"status": "ok", "subscriptions": {"ops": {"status": "ok"}}},
         "events": [{"event_id": "e", "tx": [{"chain": "ethereum", "verified": "confirmed"}]}], "digest": {"status": "ok"}}


def test_a_healthy_system_needs_nobody():
    assert ops.attention(QUIET) == []


def test_each_rule_fires_on_its_fact():
    f = {"sources": [{"name": "X", "status": "failing", "last_error": "HTTP 403", "last_error_at": "t"},
                     {"name": "Y", "status": "degraded", "last_error": "timeout"}],
         "ledger": {"over_budget": {"date": "2026-10-27", "continuum_usd": 1464.08, "cap": 500, "at": "t"},
                    "gitlab_error": "AccessDenied", "cost_error": {"at": "t", "error": "throttled"}},
         "notify": {"status": "legacy_config", "at": "t",
                    "invalid": [{"error": "unknown_channel", "message": "m", "actual": "sms", "allowed": ["webhook"], "id": "x"}],
                    "subscriptions": {"lark": {"status": "error", "channel": "lark_chat", "error": {"error": "send_failed", "message": "401"}},
                                      "team": {"status": "gated_by_rollout"}}},
         "events": [{"event_id": "e1", "severity": "P0", "title": "Binance", "triage": None,
                     "tx": [{"chain": "bsc", "check_error": "rpc_unreachable: Forbidden", "checked_at": "t"}]},
                    {"event_id": "e2", "severity": "P2", "title": "Binance copy", "triage": None}],
         "dup_labels": {"e1|e2": {"label": "same", "at": "t"}},
         "splits": [{"older": "e1", "newer": "e2", "domain": "web3", "older_title": "Binance", "newer_title": "Binance copy"}],
         "enrich": {"at": "t", "epss_failed": 1, "epss_error": "http_error", "cve_meta_backlog": 3},
         "pending": {"ids": ["e1"], "at": "t"},
         "amount_outliers": [{"event_id": "e1", "title": "ZachXBT 欧盟实体", "values": [235e9]}],
         "amount_shared": [{"amount": 106e6, "events": [{"event_id": "e1", "title": "a"}, {"event_id": "e2", "title": "b"}]}],
         "raw_bad": [{"key": "raw/2026-11-10/x/krebs.jsonl", "lines": 2, "first_line": 1, "error": "JSONDecodeError: x", "at": "t"}],
         "row_sizes": [{"key": "SRC#__cve_meta__", "bytes": 281_000, "station": "publish", "at": "t"}],
         "spend": {"bedrock:global.anthropic.claude-haiku-5-5": 2_600, "bedrock:global.anthropic.claude-sonnet-5-5": 10},
         "slow_stations": [{"station": "publish", "worst_s": 256.0, "at": "t", "timeout_s": 300, "share": 0.85,
                            "median_s": 15.0}],
         "title_proposals": {"e1": {"verdict": "propose", "current": "Binance", "title": "Binance — DevOps laptop",
                                    "quote": "q", "source": "https://x", "at": "t"}},
         "late": [{"event_id": "e3", "title": "Linux TCP", "cve": "CVE-2026-98432", "cvss": 9.8, "assigner": "Linux",
                   "published": "2026-10-15T12:08:22Z", "first_seen": "2026-10-29T15:57:05Z",
                   "first_source": "The Hacker News", "lag_days": 14}],
         "digest": {"status": "failed", "day": "2026-10-29", "reason": "refused"},
         "stalled_sources": [{"source_id": "s", "name": "S", "kind": "overdue", "minutes": 90, "limit_min": 45}],
         "latency": {"n": 40, "p50": 12, "p90": 60, "tiers": {"T1": {"n": 10, "p50": 5, "p90": 9}}},
         "silent_stations": [{"station": "respond", "kind": "failing", "at": "t", "runs": 3}],
         "anomalies": [{"kind": "absorbed_other_domain", "level": "error", "event_id": "e1", "title": "Binance", "at": "t",
                        "actual": "web3 → vuln", "limit": "same domain", "message": "absorbed a web3 event"}],
         "mitigate": {"run_at": "t", "errors": [{"channel": "waf", "what": "web ACL x", "error": "AccessDenied"}],
                      "events": {"e1": {"plans": [{"state": "staged"}, {"state": "blocking"}]}},
                      "inspector": {"security-radar": {"scanned_on": "2026-10-29", "findings": [
                          {"severity": "critical", "purl": "pkg:npm/vitest@2.1.9", "fixed": "3.2.6"},
                          {"severity": "medium", "purl": "pkg:npm/x@1", "fixed": None}]}}}}
    got = ops.attention(f)
    codes = {i["code"] for i in got}
    assert codes == set(ops.RULES), set(ops.RULES) - codes                      # every rule is reachable
    assert [i["level"] for i in got] == sorted((i["level"] for i in got), key=ops.LEVELS.index)
    over = next(i for i in got if i["code"] == "over_budget")
    assert "1464.08" in over["detail"] and "500" in over["detail"]             # actual + limit (error 4 elements)
    assert next(i for i in got if i["code"] == "chain_rpc_error")["link"] == "/events/e1"
    mit = [i for i in got if i["code"] == "mitigate"]
    assert [i["level"] for i in mit] == ["warn", "warn", "info"] and mit[2]["title"].startswith("1 条")   # not checked ≠ waiting
    dep = next(i for i in mit if "Inspector" in i["title"])
    assert "1 个 critical" in dep["title"] and "vitest@2.1.9 → 3.2.6" in dep["detail"]


def test_an_unconfigured_channel_is_info_not_an_error():
    got = ops.attention({**QUIET, "notify": {"status": "not_configured", "subscriptions": {}}})
    assert [(i["code"], i["level"]) for i in got] == [("notify", "info")]


def test_push_problems_are_errors_and_a_gated_subscription_is_visible_not_ok():
    """legacy single-channel secret, an invalid subscription (code / actual / allowed) and a failed send are errors;
    a subscription the rollout gate held back is shown (info), never silently counted as ok."""
    got = ops._notify({"notify": {"status": "legacy_config", "invalid": [
        {"error": "unknown_channel", "message": "m", "actual": "sms", "allowed": ["webhook"], "id": "x"}],
        "subscriptions": {"team": {"status": "gated_by_rollout"}, "ops": {"status": "ok"}}}})
    assert [i["level"] for i in got] == ["error", "error", "info"]
    assert "'sms'" in got[1]["detail"] and "webhook" in got[1]["detail"] and "team" in got[2]["title"]
