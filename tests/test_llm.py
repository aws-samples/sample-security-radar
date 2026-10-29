"""LLM exit contract (measured 2026-10-23): reasoning block precedes text; max_tokens ⇒ incomplete; no temperature."""

from radar import llm


class _Client:
    def __init__(self, stop, blocks):
        self.stop, self.blocks, self.kw = stop, blocks, None
    def converse(self, **kw):
        self.kw = kw
        return {"stopReason": self.stop, "output": {"message": {"content": self.blocks}}, "usage": {"inputTokens": 3}}


def _run(monkeypatch, stop, blocks):
    c = _Client(stop, blocks)
    monkeypatch.setattr(llm, "_client", c)
    return llm.converse("hi", llm.MODEL_BRIEF, 8000), c


def test_text_block_after_reasoning_is_used(monkeypatch):
    r, c = _run(monkeypatch, "end_turn", [{"reasoningContent": {"x": 1}}, {"text": "{}"}])
    assert r.status == "ok" and r.text == "{}"
    assert "temperature" not in c.kw["inferenceConfig"]


def test_truncation_is_incomplete_not_ok(monkeypatch):
    r, _ = _run(monkeypatch, "max_tokens", [{"reasoningContent": {}}, {"text": '{"what": ['}])
    assert r.status == "incomplete"


def test_content_filter_is_refused(monkeypatch):
    r, _ = _run(monkeypatch, "content_filtered", [{"text": ""}])
    assert r.status == "refused"
