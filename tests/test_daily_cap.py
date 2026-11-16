"""R5.6: Bedrock calls are counted per UTC day on an atomic counter; past the cap the call is not made."""
import pytest
from test_store_contract import table  # noqa: F401  (moto table fixture)

from radar import llm, ops
from radar.dynamo import DynamoStore
from radar.limits import Limits
from radar.store import MemoryStore


class Client:
    calls = 0

    def converse(self, **kw):
        Client.calls += 1
        return {"stopReason": "end_turn", "output": {"message": {"content": [{"text": "ok"}]}}, "usage": {}}


@pytest.fixture
def gated(monkeypatch):
    store = MemoryStore()
    monkeypatch.setattr(Limits, "BEDROCK_CALLS_PER_DAY_FAST", 2)
    monkeypatch.setattr(llm, "_client", Client())
    Client.calls = 0
    monkeypatch.setattr(llm, "gate", lambda model: store.add_count("2026-11-15", f"bedrock:{model}") <= llm.daily_cap(model))
    return store


def test_past_the_daily_cap_the_call_is_not_made_and_ops_says_so(gated):
    got = [llm.converse("p", llm.MODEL_FAST, 10).status for _ in range(4)]
    assert got == ["ok", "ok", "error", "error"] and Client.calls == 2
    assert llm.converse("p", llm.MODEL_BRIEF, 10).status == "ok"          # caps are per model
    [item] = ops.RULES["daily_cap_reached"]({"spend": gated.counts("2026-11-15")})
    assert "2 次" in item["detail"] and llm.MODEL_FAST in item["title"]


def test_the_dynamo_counter_is_atomic_per_day_and_kind(table):  # noqa: F811
    s = DynamoStore(table)
    assert [s.add_count("2026-11-15", "bedrock:x") for _ in range(3)] == [1, 2, 3]
    assert s.add_count("2026-11-16", "bedrock:x") == 1
    assert s.counts("2026-11-15") == {"bedrock:x": 3}


def test_the_lambda_handlers_install_the_gate(monkeypatch, table):  # noqa: F811
    import importlib
    monkeypatch.setenv("TABLE", "radar")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-northeast-1")
    import radar.handlers as h
    monkeypatch.setattr(llm, "gate", None)
    h = importlib.reload(h)
    assert llm.gate is h._bedrock_gate
    assert h._bedrock_gate(llm.MODEL_FAST) is True
    assert h._store.counts(h.timeutil.iso(h.timeutil.now())[:10]) == {f"bedrock:{llm.MODEL_FAST}": 1}


def test_raw_markers_and_spend_counters_expire_and_the_table_reads_ttl(table):  # noqa: F811
    """R5.3: markers Process no longer lists (it reads today + yesterday only) and day counters carry a TTL."""
    import re
    import time
    from pathlib import Path
    s = DynamoStore(table)
    s.mark_raw_processed("raw/2026-11-15/x.jsonl", "2026-11-15T00:00:00Z")
    s.add_count("2026-11-15", "bedrock:x")
    raw = int(table.get_item(Key={"pk": "RAW#raw/2026-11-15/x.jsonl", "sk": "DONE"})["Item"]["ttl"])
    spend = int(table.get_item(Key={"pk": "SPEND#2026-11-15", "sk": "bedrock:x"})["Item"]["ttl"])
    now = time.time()
    assert abs(raw - now - Limits.RAW_MARKER_TTL_DAYS * 86_400) < 60
    assert abs(spend - now - Limits.SPEND_TTL_DAYS * 86_400) < 60
    assert Limits.RAW_MARKER_TTL_DAYS > 2                              # Process lists two days: never expire those
    stack = (Path(__file__).resolve().parents[1] / "infra" / "stack.py").read_text()
    assert re.search(r'time_to_live_attribute="ttl"', stack)
