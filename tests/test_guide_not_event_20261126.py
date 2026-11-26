"""A how-to / guide opens no event (live 2026-11-25: Securelist's 「How to protect against preinstalled Android malware」
became a vulnerability P0 — one T1 article whose malware is in the wild)."""
from __future__ import annotations

import pytest

from radar import signals


@pytest.mark.parametrize("title", [
    "How to protect against preinstalled Android malware",
    "A practical guide to hardening Kubernetes clusters",
    "What is a supply-chain attack?",
    "10 tips to secure your crypto wallet",
    "如何防范预装恶意软件",
    "云主机安全加固指南",
])
def test_advice_is_a_guide(title):
    assert signals.is_guide(title)


@pytest.mark.parametrize("title", [
    "How attackers exploited CVE-2026-1 in Ivanti EPMM",
    "Preinstalled Android malware found on 40,000 TV boxes",
    "Guide Dogs charity hit by ransomware",
    "What happened at Bybit: $1.5B stolen",
    "CVE-2026-6460 PostgreSQL type confusion executes arbitrary code",
])
def test_a_report_is_not(title):
    assert not signals.is_guide(title)


def test_the_securelist_guide_opens_no_event_but_its_report_twin_does():
    from datetime import UTC, datetime

    from test_pipeline_replay import _raw

    from radar import pipeline
    from radar.registry import BY_ID
    fetched = datetime(2026, 11, 25, 9, 44, tzinfo=UTC)
    body = "Preinstalled malware on mobile devices is a major threat; it is actively exploited in the wild."
    guide = pipeline.normalize(_raw("securelist", "How to protect against preinstalled Android malware", body),
                               BY_ID["securelist"], fetched)
    report = pipeline.normalize(_raw("securelist", "Preinstalled Android malware found on 40,000 TV boxes", body),
                                BY_ID["securelist"], fetched)
    assert not guide.eventful and report.eventful
