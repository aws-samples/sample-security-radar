"""R4: per-day spend of the AWS services the radar drives, from Cost Explorer (shape captured live 2026-10-27)."""

from datetime import UTC, datetime

from radar import cost

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
CE = [  # get_cost_and_usage(GroupBy SERVICE, USAGE_TYPE) — numbers from the live account
    {"TimePeriod": {"Start": "2026-10-23", "End": "2026-10-24"}, "Groups": [
        {"Keys": ["AWS Continuum", "USE1-ContinuumInference"],
         "Metrics": {"UnblendedCost": {"Amount": "726.2917817"}, "UsageQuantity": {"Amount": "72.62917817"}}},
        {"Keys": ["AWS Security Agent", "APN1-repository-code-review"],
         "Metrics": {"UnblendedCost": {"Amount": "0"}, "UsageQuantity": {"Amount": "6.349166667"}}}]},
    {"TimePeriod": {"Start": "2026-10-25", "End": "2026-10-26"}, "Groups": [
        {"Keys": ["AWS Continuum", "USE1-ContinuumContext-Code"],
         "Metrics": {"UnblendedCost": {"Amount": "2.733"}, "UsageQuantity": {"Amount": "13665"}}}]},
    {"TimePeriod": {"Start": "2026-10-26", "End": "2026-10-27"}, "Groups": []},
]


def test_summarize_splits_services_and_counts_only_inference_units():
    s = cost.summarize(CE, NOW)
    d23, d25, d26 = s["days"]
    assert d23 == {"date": "2026-10-23", "continuum_usd": 726.29, "security_agent_usd": 0.0, "continuum_inference_units": 72.63}
    assert d25["continuum_usd"] == 2.73 and d25["continuum_inference_units"] == 0.0  # context rows are not inference
    assert d26["continuum_usd"] == 0.0 and s["total_usd"] == 729.02


def test_refresh_is_throttled_and_a_failure_backs_off_too():
    assert cost.due({}, NOW)
    assert not cost.due({"cost": {"fetched_at": "2026-10-27T09:00:00Z"}}, NOW)
    assert cost.due({"cost": {"fetched_at": "2026-10-27T05:00:00Z"}}, NOW)
    assert not cost.due({"cost": {"fetched_at": "2026-10-26T00:00:00Z"}, "cost_error": {"at": "2026-10-27T11:00:00Z"}}, NOW)
    assert cost.window(NOW) == ("2026-10-14", "2026-10-28")


def test_spend_cap_looks_at_the_last_two_billed_days():
    """R10: Cost Explorer lags ~24 h — a cap on 'today' alone would never fire on the day the money is spent."""
    led = {"cost": cost.summarize(CE, NOW)}                       # 10-23 $726.29 · 10-25 $2.73 · 10-26 $0
    assert cost.over_cap(led) is None                             # last two calendar days 10-25 / 10-26: under (10-23 is old)
    led["cost"]["days"].append({"date": "2026-10-27", "continuum_usd": 1464.08, "security_agent_usd": 0.0,
                                "continuum_inference_units": 146.41})
    hit = cost.over_cap(led)
    assert hit == {"date": "2026-10-27", "continuum_usd": 1464.08, "cap": 500}
    assert cost.over_cap({}) is None
