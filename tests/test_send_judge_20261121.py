"""Send arbitration (Neo 2026-11-21): code prefilters (radar.cloudstack), the model answers send / not, code acts.
A failed or unsupported answer never sends."""
from __future__ import annotations

from radar import notify, send_judge
from radar.llm import LlmResult

EV = {"title": "CVE-2026-114952 Vulnerability in the MySQL Server", "severity": "P0", "exploitation": "poc",
      "cves": ["CVE-2026-114952"], "entities": ["Oracle", "MySQL"]}
EVIDENCE = [{"item_id": "it_rec", "source": "CVE List", "tier": "T1", "published_at": "2026-11-17T21:32:07Z",
             "title": "CVE-2026-114952 MySQL", "text": "unauthenticated attacker ... CVSS 3.1 Base Score 9.1"},
            {"item_id": "it_poc", "source": "Sploitus", "tier": "T2", "published_at": "2026-11-19T10:56:00Z",
             "title": "Exploit for CVE-2026-114952", "text": "public exploit"}]


def _call(text: str, status: str = "ok"):
    def call(prompt, model, max_tokens):
        assert "untrusted third-party text" in prompt and "EVIDENCE" in prompt
        return LlmResult(status=status, text=text, model=model)
    return call


def test_a_cited_yes_sends():
    row = send_judge.judge(EV, EVIDENCE, "2026-11-21T02:00:00Z",
                           call=_call('{"send": true, "reason": "MySQL 未认证可读写数据，且有公开 exploit", "cite": ["it_poc"]}'))
    assert row["send"] is True and row["status"] == "ok" and row["cite"] == ["it_poc"]


def test_a_no_does_not_send():
    row = send_judge.judge(EV, EVIDENCE, "t", call=_call('{"send": false, "reason": "小众应用", "cite": ["it_rec"]}'))
    assert row["send"] is False and row["status"] == "ok"


def test_a_yes_without_a_real_citation_does_not_send():
    row = send_judge.judge(EV, EVIDENCE, "t", call=_call('{"send": true, "reason": "x", "cite": ["it_invented"]}'))
    assert row["send"] is False and row["status"] == "uncited"


def test_a_failed_call_does_not_send():
    row = send_judge.judge(EV, EVIDENCE, "t", call=_call("", status="error"))
    assert row["send"] is False and row["status"] == "failed"


def test_an_unparsable_answer_does_not_send():
    row = send_judge.judge(EV, EVIDENCE, "t", call=_call("sure, send it"))
    assert row["send"] is False and row["status"] == "failed"


def test_the_decision_input_changes_only_with_what_matters():
    a = send_judge.input_hash(send_judge.decision_input(EV, EVIDENCE))
    same = send_judge.input_hash(send_judge.decision_input({**EV, "summary": "reworded"}, EVIDENCE))
    escalated = send_judge.input_hash(send_judge.decision_input({**EV, "exploitation": "confirmed"}, EVIDENCE))
    assert a == same and a != escalated


def test_the_team_filter_needs_a_yes():
    filters, bad = notify._filters({"team_send": True}, "team")
    assert bad is None
    row = {"event_id": "ev_1", "title": EV["title"], "severity": "P0", "domain": "vuln"}
    assert not notify.matches(filters, notify.view(row, False))                       # unasked: waits
    assert not notify.matches(filters, notify.view({**row, "team_send": False}, False))
    assert notify.matches(filters, notify.view({**row, "team_send": True}, False))
