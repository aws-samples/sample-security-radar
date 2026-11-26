"""Model outputs never ship in mock data or fixtures (security review 2026-11-26, suggestion 3: the build gate lived only
in scripts/build-sample.py, so the published sample had no check of its own). In the sample (no build script) the
files themselves must already be placeholders; in the main repository the same invariant is checked on what the
sample build turns them into."""
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL_DATA = ("tests/fixtures/events/", "ui/mock-data/data/", "ui/src/test/fixtures/")
MODEL_ID = re.compile(r"global\.anthropic|anthropic\.claude|claude-(?:sonnet|haiku|opus)")
BUILD = ROOT / "scripts" / "build-sample.py"


def _transform():
    if not BUILD.exists():                         # the published sample: files are what ships
        return lambda d: d
    spec = importlib.util.spec_from_file_location("build_sample", BUILD)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)                   # type: ignore[union-attr]
    return mod.placeholder_models


def _problems(node, where, out):
    if isinstance(node, list):
        for x in node:
            _problems(x, where, out)
        return
    if not isinstance(node, dict):
        if isinstance(node, str) and MODEL_ID.search(node):
            out.append(f"{where}: names a model")
        return
    if "event_id" in node and "title" in node:
        if isinstance(node.get("summary"), str) and node["summary"] and not node["summary"].startswith("示例"):
            out.append(f"{where}: summary is not a placeholder")
        if isinstance(node.get("team_send_reason"), str) and not node["team_send_reason"].startswith("示例仲裁理由"):
            out.append(f"{where}: team_send_reason is not a placeholder")
    for k, v in node.items():
        if isinstance(v, list) and v and all(isinstance(x, dict) and "text" in x and "cite" in x for x in v):
            bad = [x["text"] for x in v if isinstance(x.get("text"), str) and not x["text"].startswith("示例")]
            if bad:
                out.append(f"{where}: {k} has model text")
        else:
            _problems(v, where, out)


def test_mock_data_and_fixtures_carry_no_model_output():
    tf, out, seen = _transform(), [], 0
    for prefix in MODEL_DATA:
        for p in sorted((ROOT / prefix).rglob("*.json")):
            seen += 1
            _problems(tf(json.loads(p.read_text(encoding="utf-8"))), str(p.relative_to(ROOT)), out)
    assert seen > 0
    assert not out, out[:10]
