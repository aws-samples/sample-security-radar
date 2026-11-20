"""The sample READMEs' "Security considerations" (security review condition) quote numbers that live in infra/stack.py.

A README number nobody re-reads drifts silently: if the access-log lifetime or the API throttle changes, these tests
turn red until the README says the same thing as the stack.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STACK = (ROOT / "infra" / "stack.py").read_text()


def _readme(name: str) -> Path:
    """sample/<name> here; in the published bundle that file IS the root README (build-sample lays sample/ over it)."""
    p = ROOT / "sample" / name
    return p if p.exists() else ROOT / name


def _int(pattern: str) -> int:
    m = re.search(pattern, STACK)
    assert m, pattern
    return int(m.group(1))


def test_english_notes_match_the_stack() -> None:
    t = _readme("README.md").read_text()
    sec = t.split("## Security considerations", 1)[1].split("\n## ", 1)[0]
    assert f"deleted after {_int(r'ACCESS_LOG_DAYS = (\d+)')} days" in sec
    assert f"({_int(r'throttling_rate_limit=(\d+)')} requests/s, burst {_int(r'throttling_burst_limit=(\d+)')})" in sec
    assert "RetentionDays.ONE_MONTH" in STACK.split('"ReadApiAccess"', 1)[1][:80] and "one month" in sec
    assert '"rollout": "owner_only"' in sec and "does **not** verify" in sec


def test_chinese_notes_match_the_stack() -> None:
    t = _readme("README_CN.md").read_text()
    sec = t.split("## 安全考虑", 1)[1].split("\n## ", 1)[0]
    assert f"{_int(r'ACCESS_LOG_DAYS = (\d+)')} 天后删除" in sec
    assert f"每秒 {_int(r'throttling_rate_limit=(\d+)')} 次、突发 {_int(r'throttling_burst_limit=(\d+)')}" in sec
    assert '"rollout": "owner_only"' in sec and "**不验证**" in sec
