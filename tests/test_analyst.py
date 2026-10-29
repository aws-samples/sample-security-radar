"""Analyst station criteria. The LLM writes sentences; code decides whether each sentence may be shown as
grounded (M2-PLAN A2/A3). Fixture = real Sonnet 5.5 output for the PHP2Shell event (2026-10-23)."""

import json
from pathlib import Path

from radar import analyst
from radar.llm import LlmResult

FIX = Path(__file__).parent / "fixtures" / "analysis"
EVENT_DOC = json.loads((FIX / "php2shell_event.json").read_text())
REAL = json.loads((FIX / "php2shell_brief_sonnet55.json").read_text())


def _evidence():
    return [{"item_id": i["item_id"], "source": i["source_name"], "tier": i["tier"], "published_at": i["published_at"],
             "title": i["title"], "text": i["excerpt"]} for i in EVENT_DOC["items"]]


def test_real_brief_is_fully_grounded_after_date_normalisation():
    a = analyst.validate(REAL, _evidence())
    sentences = [s for k in analyst.SECTIONS for s in a[k]]
    assert len(sentences) == 24
    assert all(s["grounded"] for s in sentences), [s for s in sentences if not s["grounded"]]
    assert a["status"] == "ok"


def test_month_name_date_is_grounded_regression():
    """'10 月 17 日' cites text saying 'October 17' — the 2026-10-23 probe flagged this as ungrounded."""
    ev = [{"item_id": "it_a", "title": "", "text": "attempts dating back to October 17, 2026"}]
    a = analyst.validate({"what": [{"text": "可追溯至 2026 年 10 月 17 日", "cite": ["it_a"]}]}, ev)
    assert a["what"][0]["grounded"] is True


def test_fabricated_number_is_flagged_not_dropped():
    ev = [{"item_id": "it_a", "title": "PHP RCE", "text": "rated 9.2 on CVSS v4.0"}]
    a = analyst.validate({"what": [{"text": "CVSS 评分为 10.0", "cite": ["it_a"]}]}, ev)
    s = a["what"][0]
    assert s["grounded"] is False and s["issues"] == ["ungrounded_number"] and s["text"] == "CVSS 评分为 10.0"
    assert a["status"] == "partial"


def test_missing_and_unknown_citations():
    ev = [{"item_id": "it_a", "title": "x", "text": "y"}]
    a = analyst.validate({"impact": [{"text": "无引用的话", "cite": []}, {"text": "引用不存在", "cite": ["it_zzz"]}]}, ev)
    assert [s["issues"] for s in a["impact"]] == [["no_citation"], ["unknown_citation"]]


def test_missing_sections_become_empty_lists():
    a = analyst.validate({"what": []}, [])
    assert all(a[k] == [] for k in analyst.SECTIONS)


def _fake(result):
    return lambda prompt, model, max_tokens: result


def test_truncated_refused_and_bad_json_are_failed_with_reason():
    ev = _evidence()
    for res, reason in [(LlmResult("incomplete", "", {}, "m", 1.0), "incomplete"),
                        (LlmResult("refused", "", {}, "m", 1.0), "refused"),
                        (LlmResult("ok", "not json at all", {}, "m", 1.0), "bad_json")]:
        a = analyst.analyze(ev, "2026-10-23T07:00:00Z", call=_fake(res))
        assert a["status"] == "failed" and a["reason"] == reason
        assert all(a[k] == [] for k in analyst.SECTIONS)


def test_ok_call_returns_validated_analysis():
    res = LlmResult("ok", "```json\n" + json.dumps(REAL, ensure_ascii=False) + "\n```", {"inputTokens": 1}, "m", 1.0)
    a = analyst.analyze(_evidence(), "2026-10-23T07:00:00Z", call=_fake(res))
    assert a["status"] == "ok" and a["model"] == "m" and len(a["what"]) == 5


def test_input_hash_changes_with_evidence_and_prompt_version(monkeypatch):
    ev = _evidence()
    h1 = analyst.input_hash(ev)
    assert h1 == analyst.input_hash(json.loads(json.dumps(ev)))
    ev2 = [dict(ev[0], text=ev[0]["text"] + " update")] + ev[1:]
    assert analyst.input_hash(ev2) != h1
    monkeypatch.setattr(analyst, "PROMPT_VERSION", "brief-v999")
    assert analyst.input_hash(ev) != h1


def test_evidence_is_bounded():
    big = [{"item_id": f"it_{n}", "source": "s", "tier": "T2", "published_at": "2026-10-23T00:00:00Z",
            "title": "t", "text": "x" * 5000} for n in range(200)]
    assert len(analyst.render_prompt(analyst.trim_evidence(big)).encode()) <= analyst.PROMPT_MAX_BYTES
