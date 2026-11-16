"""R5.3: every table write passes one size gate — above the warning line the row is noted and reaches #/ops, above the
hard line the write is refused with the row's key and size instead of DynamoDB's 400 that names neither."""
import pytest
from test_store_contract import table  # noqa: F401  (moto table fixture)

from radar import ops
from radar.dynamo import ROW_SIZES_KEY, DynamoStore, RowTooLarge
from radar.limits import Limits


@pytest.fixture
def small(monkeypatch):
    monkeypatch.setattr(Limits, "ROW_WARN_BYTES", 1_000)
    monkeypatch.setattr(Limits, "ROW_MAX_BYTES", 5_000)


def test_every_write_path_is_gated(table, small):  # noqa: F811
    s = DynamoStore(table)
    s.put_source_state("big_ledger", {"x": "a" * 2_000})
    s.put_response("ev_1", {"y": "b" * 2_000})
    assert set(s.near_limit) == {"SRC#big_ledger", "EVENT#ev_1/RESPONSE"}
    with pytest.raises(RowTooLarge) as e:
        s.put_source_state("huge_ledger", {"x": "a" * 6_000})
    assert e.value.detail["key"] == "SRC#huge_ledger" and e.value.detail["actual_bytes"] > 5_000
    assert e.value.detail["max_bytes"] == 5_000 and e.value.detail["error"] == "row_too_large"
    assert s.get_source_state("huge_ledger") == {}                     # refused before the call: nothing written


def test_a_noted_row_reaches_the_ledger_and_ops(table, small, monkeypatch):  # noqa: F811
    import radar.handlers as h
    s = DynamoStore(table)
    monkeypatch.setattr(h, "_store", s)
    s.put_source_state("big_ledger", {"x": "a" * 2_000})
    h._record_row_sizes("publish")
    led = s.get_source_state(ROW_SIZES_KEY)
    assert led["SRC#big_ledger"]["station"] == "publish" and led["SRC#big_ledger"]["bytes"] > 1_000
    assert s.near_limit == {}                                          # flushed once
    [item] = ops.RULES["row_near_limit"]({"row_sizes": [{"key": k, **v} for k, v in led.items()]})
    assert "SRC#big_ledger" in item["detail"] and item["level"] == "warn"


def test_every_timed_station_run_flushes_what_it_noted(table, small, monkeypatch):  # noqa: F811
    import radar.handlers as h
    s = DynamoStore(table)
    monkeypatch.setattr(h, "_store", s)

    @h._timed("process")
    def station(event, _ctx=None):
        s.put_source_state("grown", {"x": "a" * 2_000})
        return {}
    station({})
    assert s.get_source_state(ROW_SIZES_KEY)["SRC#grown"]["station"] == "process"
