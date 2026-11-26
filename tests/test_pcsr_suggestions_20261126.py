"""Security review 2026-11-26, optional suggestions 1, 2, 4 — the sample's next version carries them."""
from __future__ import annotations

import json
import time

from radar import p0class, send_judge
from radar.limits import Limits
from radar.llm import LlmResult

EV = {"event_id": "ev_1", "title": "CVE-2026-1 MySQL Server RCE", "severity": "P0", "exploitation": "poc",
      "cves": ["CVE-2026-1"], "entities": []}
EVIDENCE = [{"item_id": "it_1", "source_id": "thehackernews", "title": "MySQL RCE", "text": "critical"}]


def _call(text):
    return lambda *a, **k: LlmResult(status="ok", text=text)


def test_the_reason_is_one_line_without_control_characters_and_at_most_60():
    long = "第一行\n\x07第二行" + "原因" * 80      # control characters inside the kept part, then over-long
    r = send_judge.judge(EV, EVIDENCE, "2026-11-26T00:00:00Z",
                         call=_call(json.dumps({"send": True, "reason": long, "cite": ["it_1"]})))
    assert r["send"] is True and len(r["reason"]) <= Limits.SEND_JUDGE_REASON_MAX == 60
    assert "\n" not in r["reason"] and "\x07" not in r["reason"]


def test_place_bounds_its_entities():
    ents = ["x " * 30_000 + "plugin"] * 50          # 60 KB entities: unbounded, the WordPress alternative took ~27 s
    t = time.monotonic()
    p0class.place("CVE-2026-2 something", ents)
    assert time.monotonic() - t < 1.0


def test_a_failing_arbitration_does_not_fail_the_analyze_run(monkeypatch):
    for k, v in {"AWS_DEFAULT_REGION": "ap-northeast-1", "AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "x"}.items():
        monkeypatch.setenv(k, v)
    from radar import handlers as h
    from radar.store import MemoryStore
    monkeypatch.setattr(h, "_store", MemoryStore())

    def broken(*_a, **_k):
        raise KeyError("store row")
    monkeypatch.setattr(h, "_send_judge", broken)
    for name, val in (("_daily_digest", None), ("_cluster_judge", []), ("_retitle_shadow", None), ("_ghsa_alias", [])):
        monkeypatch.setattr(h, name, lambda *_a, _v=val, **_k: _v)
    out = h.analyze_events({"changed": []})
    assert isinstance(out, dict)
