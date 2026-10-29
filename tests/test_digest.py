"""C7 daily digest: code owns when / which / how many; the LLM only writes cited sentences, which code checks."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest

from radar import digest, llm
from radar.model import Event

SCHEMA = json.loads((Path(__file__).resolve().parents[1] / "schemas" / "site-data.schema.json").read_text())
NOW = datetime(2026, 10, 29, 1, 0, tzinfo=UTC)          # 09:00 HKT


def ev(eid, sev, level, updated="2026-10-29T00:30:00Z", timeline=(), domain="vuln", **kw):
    return Event(event_id=eid, domain=domain, title=f"title {eid}", first_seen="2026-10-28T03:00:00Z", last_updated=updated,
                 item_ids=[], keys=[], severity=sev, level=level, timeline=list(timeline), **kw)


def fake(text, status="ok"):
    calls = []

    def call(prompt, model, max_tokens):
        calls.append(prompt)
        return llm.LlmResult(status, text, {}, model, 0.1)
    call.calls = calls
    return call


@pytest.mark.parametrize("now, state, want", [
    (datetime(2026, 10, 28, 23, 59, tzinfo=UTC), {}, False),                         # 07:59 HKT — not yet
    (NOW, {"day": "2026-10-28", "status": "ok"}, True),                              # a new HKT day
    (NOW, {"day": "2026-10-29", "status": "ok"}, False),                             # done today
    (NOW, {"day": "2026-10-29", "status": "failed", "attempts": 1}, True),           # retry …
    (NOW, {"day": "2026-10-29", "status": "failed", "attempts": digest.MAX_ATTEMPTS}, False),   # … bounded
])
def test_runs_once_a_day_after_8_hkt_with_bounded_retries(now, state, want):
    assert digest.due(state, now) is want


def test_the_index_keeps_what_matters_and_the_header_is_counted_by_code():
    evs = [ev("a", "P0", "V3", timeline=[{"at": "2026-10-28T05:00:00Z", "kind": "created", "from": None, "to": "V3"}]),
           ev("b", "P1", "V1"),
           ev("c", "P2", "V1"),                                                        # P2, nothing changed ⇒ out
           ev("d", "P2", "V2", domain="web3", timeline=[{"at": "2026-10-28T09:00:00Z", "kind": "level_change", "from": "V1", "to": "V2"}]),
           ev("e", "P1", "V3", updated="2026-10-27T00:00:00Z")]                       # older than 24 h ⇒ out
    rows = digest.index(evs, NOW)
    assert [r["event_id"] for r in rows] == ["a", "b", "d"]                            # P0 first
    assert digest.header(rows) == {"events": 3, "p0": 1, "p1": 1, "new": 1, "escalated": 1, "web3": 1}


def test_a_quiet_day_is_a_result_and_costs_no_llm_call():
    call = fake("{}")
    d = digest.generate([ev("c", "P2", "V1")], NOW, call)
    assert d["status"] == "ok" and d["header"]["events"] == 0 and not call.calls and "no P0/P1" in d["reason"]


def test_sentences_are_checked_like_the_analysts_and_ungrounded_ones_are_kept_and_flagged():
    evs = [ev("a", "P0", "V3", cves=["CVE-2026-109618"])]
    text = json.dumps({"summary": [{"text": "a 被 KEV 收录（CVE-2026-109618）", "cite": ["a"]}],
                       "highlights": [{"text": "损失 999 万美元", "cite": ["a"]}],          # 999 is in no entry
                       "watch": [{"text": "不存在的事件", "cite": ["zzz"]}]})
    d = digest.generate(evs, NOW, fake(text))
    assert d["status"] == "partial"
    assert d["summary"][0]["grounded"] and d["highlights"][0]["issues"] == ["ungrounded_number"]
    assert d["watch"][0]["issues"] == ["unknown_citation"]


def test_a_failed_model_call_is_reported_not_hidden():
    d = digest.generate([ev("a", "P0", "V3")], NOW, fake("", status="refused"))
    assert d["status"] == "failed" and d["reason"] == "refused" and d["summary"] == []


def test_the_published_digest_fits_the_site_data_contract():
    from radar import publish
    d = digest.generate([ev("a", "P0", "V3")], NOW, fake(json.dumps({"summary": [{"text": "x", "cite": ["a"]}]})))
    view = {k: d[k] for k in publish.DIGEST_FIELDS}
    errs = list(jsonschema.Draft202012Validator({"$defs": SCHEMA["$defs"], "$ref": "#/$defs/Digest"}).iter_errors(view))
    assert not errs, errs[:2]
    assert digest.day_key(datetime(2026, 10, 28, 17, 0, tzinfo=UTC)) == "2026-10-29"   # 01:00 HKT is the next HKT day
