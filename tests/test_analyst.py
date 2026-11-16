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


def test_r1_8_a_number_is_grounded_only_as_a_whole_number():
    """Audit 02 Q6 #1: "26" was grounded by "2026" and "1.5" by "11.5" (single digits are not checked at all)."""
    by_id = {"a": "Released on 2026-11-15; the patch is 11.5 MB and fixes 12 bugs."}
    assert analyst._check({"text": "修复了 12 个缺陷", "cite": ["a"]}, by_id)["grounded"]
    assert not analyst._check({"text": "影响 26 个版本", "cite": ["a"]}, by_id)["grounded"]          # was matched inside 2026
    assert not analyst._check({"text": "补丁 1.5 MB", "cite": ["a"]}, by_id)["grounded"]


def test_r1_8_a_big_event_is_briefed_from_its_records_first_report_and_newest_per_tier():
    """Audit 02 Q6 #2: a 391-report event was briefed from its first 44 reports for ever (the cut was oldest-first and
    the hash taken after it never changed again)."""
    ev = [{"item_id": f"i{k:03}", "tier": "T1" if k % 10 == 0 else "T3", "published_at": f"2026-11-{1 + k // 20:02}",
           "title": f"report {k}", "text": "x" * 1_100} for k in range(200)]
    out = analyst.trim_evidence(ev, structured={"i057"})
    ids = [e["item_id"] for e in out]
    assert "i000" in ids and "i057" in ids                     # first report + a structured record
    assert "i199" in ids and "i190" in ids                     # newest T3 and newest T1
    assert ids == sorted(ids)                                  # time order kept
    small = ev[:5]
    assert analyst.trim_evidence(small) == [dict(e, text=e["text"][:analyst.ITEM_TEXT_MAX]) for e in small]   # fits ⇒ unchanged
    ev[-1] = {**ev[-1], "title": "new"}                        # a new latest report changes what the brief is fed
    assert analyst.input_hash(analyst.trim_evidence(ev, {"i057"})) != analyst.input_hash(out)


def test_r1_8_the_analyze_station_keeps_a_structured_record_in_a_big_events_brief(monkeypatch):
    for k, v in {"AWS_DEFAULT_REGION": "ap-northeast-1", "AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "x"}.items():
        monkeypatch.setenv(k, v)                      # importing handlers builds an S3 client (no region ⇒ a lookup)
    from radar import handlers as h
    from radar.model import Event, Item
    from radar.store import MemoryStore
    store = MemoryStore()

    def item(k, src, tier):
        at = f"2026-11-{1 + k // 20:02}T00:00:00Z"
        return Item(item_id=f"it_{k:04}", source_id=src, tier=tier, org=src, domain="web3", url=f"https://x/{k}",
                    canonical_url=f"https://x/{k}", title=f"r{k}", text="x" * 1_100, published_at=at, fetched_at=at,
                    content_hash=str(k), keys=[], links=[], entity=None, eventful=True, signals={}, extra={})
    items = [item(k, "defillama_hacks" if k == 57 else "odaily", "T3") for k in range(200)]
    for it in items:
        store.put_item(it)
    store.put_event(Event(event_id="ev_0000000000000001", domain="web3", title="x", first_seen=items[0].published_at,
                          last_updated="2026-11-15T00:00:00Z", item_ids=[i.item_id for i in items], keys=[], severity="P0"))
    seen = []
    monkeypatch.setattr(h, "_store", store)
    for f in ("_daily_digest", "_cluster_judge", "_retitle_shadow"):
        monkeypatch.setattr(h, f, lambda now: [])
    monkeypatch.setattr(analyst, "analyze", lambda ev_in, now: seen.append(ev_in) or {"status": "ok", "input_hash": "h"})
    monkeypatch.setattr(h.timeutil, "now", lambda: __import__("datetime").datetime(2026, 11, 15, tzinfo=__import__("datetime").UTC))
    h.analyze_events({})
    assert "it_0057" in [e["item_id"] for e in seen[0]]
