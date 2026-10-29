"""The ONLY exit for LLM calls in production (touchstone harness §2). Bedrock Converse, ap-northeast-1.

Contract facts measured 2026-10-23 (M2-PLAN §5): `temperature` is rejected by Claude 5.5 models; responses
carry a reasoningContent block before the text block; reasoning spends output budget, so a too-small
maxTokens truncates the JSON (stopReason=max_tokens) — that is `incomplete`, never a usable answer."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger()

MODEL_BRIEF = "global.anthropic.claude-sonnet-5-5"
MODEL_FAST = "global.anthropic.claude-haiku-5-5"
REGION = "ap-northeast-1"


@dataclass
class LlmResult:
    status: str                    # ok | incomplete | refused | error
    text: str
    usage: dict[str, Any] = field(default_factory=dict)
    model: str = ""
    latency_s: float = 0.0
    error: str | None = None


_client = None


def converse(prompt: str, model: str, max_tokens: int) -> LlmResult:
    global _client
    import boto3  # Lambda runtime provides boto3
    from botocore.exceptions import BotoCoreError, ClientError
    if _client is None:
        _client = boto3.client("bedrock-runtime", region_name=REGION)
    t = time.time()
    try:
        r = _client.converse(modelId=model, messages=[{"role": "user", "content": [{"text": prompt}]}],
                             inferenceConfig={"maxTokens": max_tokens})
    except (ClientError, BotoCoreError) as e:
        res = LlmResult("error", "", {}, model, time.time() - t, f"{type(e).__name__}: {str(e)[:200]}")
    else:
        stop = r.get("stopReason")
        text = next((b["text"] for b in r["output"]["message"]["content"] if "text" in b), "")
        status = {"end_turn": "ok", "max_tokens": "incomplete", "content_filtered": "refused",
                  "guardrail_intervened": "refused"}.get(stop, "error" if not text else "ok")
        res = LlmResult(status, text, r.get("usage", {}), model, time.time() - t, None if status == "ok" else f"stop={stop}")
    # ledger line: one per call (model, status, usage, latency) — replayable cost/latency accounting
    log.info(json.dumps({"ledger": "llm", "model": model, "status": res.status, "usage": res.usage,
                         "latency_s": round(res.latency_s, 2), "error": res.error}))
    return res
