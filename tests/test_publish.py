"""Publish output must satisfy the UI contract (schemas/site-data.schema.json) for every document."""

import json
from pathlib import Path

import jsonschema
from test_pipeline_replay import FETCHED, snapshot_raws

from radar import pipeline, publish
from radar.store import MemoryStore

SCHEMA = json.loads((Path(__file__).parents[1] / "schemas" / "site-data.schema.json").read_text())


def test_every_published_document_validates_against_schema():
    store = MemoryStore()
    pipeline.ingest(snapshot_raws(), store, FETCHED)
    docs = publish.build(store, FETCHED)
    assert {"events.json", "sources.json"} <= docs.keys()
    assert sum(k.startswith("events/") for k in docs) == len(docs["events.json"]["events"]) > 100
    validator = jsonschema.Draft202012Validator(SCHEMA, format_checker=jsonschema.FormatChecker())
    for path, doc in docs.items():
        errors = sorted(validator.iter_errors(doc), key=str)
        assert not errors, f"{path}: {errors[0].message}"


def test_listing_puts_p0_first_then_newest():
    store = MemoryStore()
    pipeline.ingest(snapshot_raws(), store, FETCHED)
    evs = publish.build(store, FETCHED)["events.json"]["events"]
    sev = [e["severity"] for e in evs]
    assert sev == sorted(sev, key=lambda s: {"P0": 0, "P1": 1, "P2": 2}[s])
    p0 = [e["last_updated"] for e in evs if e["severity"] == "P0"]
    assert p0 == sorted(p0, reverse=True)


def test_never_run_sources_are_reported_as_such_not_ok():
    from radar.registry import BY_ID
    docs = publish.build(MemoryStore(), FETCHED)
    for s in docs["sources.json"]["sources"]:
        assert s["status"] == ("never_run" if BY_ID[s["source_id"]].enabled else "disabled")


def test_published_analysis_and_insights_validate_and_hide_internal_hash():
    from radar import analyst
    from radar.llm import LlmResult
    from radar.model import Event
    store = MemoryStore()
    pipeline.ingest(snapshot_raws(), store, FETCHED)
    php = next(Event.from_dict(e) for e in store.events.values() if "CVE-2026-109618" in e["cves"])
    real = (Path(__file__).parent / "fixtures" / "analysis" / "php2shell_brief_sonnet55.json").read_text()
    ev_in = [{"item_id": i.item_id, "source": i.source_id, "tier": i.tier, "published_at": i.published_at,
              "title": i.title, "text": i.text} for i in store.get_items(php.item_ids)]
    php.analysis = analyst.analyze(ev_in, "2026-10-23T04:00:00Z", call=lambda p, m, t: LlmResult("ok", real, {}, m, 1.0))
    store.put_event(php)
    docs = publish.build(store, FETCHED)
    validator = jsonschema.Draft202012Validator(SCHEMA, format_checker=jsonschema.FormatChecker())
    for path, doc in docs.items():
        errors = sorted(validator.iter_errors(doc), key=str)
        assert not errors, f"{path}: {errors[0].message}"
    d = docs[f"events/{php.event_id}.json"]
    assert d["analysis"]["status"] in ("ok", "partial") and "input_hash" not in d["analysis"]
    listing = docs["events.json"]
    assert listing["headline"] and 1 <= len(listing["now"]) <= 3 and listing["funnel"]["window_hours"] == 24


def test_published_response_impact_and_continuum_overview_validate():
    """A stored respond-station state renders into event.response, the listing impact chip, pipeline steps
    and continuum.json — all schema-valid, and the chip agrees with the response."""
    from radar import respond
    from radar.model import Event
    store = MemoryStore()
    pipeline.ingest(snapshot_raws(), store, FETCHED)
    php = next(Event.from_dict(e) for e in store.events.values() if "CVE-2026-109618" in e["cves"])
    root = Path(__file__).parents[1] / "integrations" / "continuum" / "targets" / "demo-shop"
    demo = respond.Target("demo-shop", "demo-shop", "d",
                          {f"demo-shop/{p.relative_to(root)}": p.read_text() for p in root.rglob("*") if p.is_file()})
    items = [{"title": i.title, "excerpt": i.text, "url": i.url, "source_name": i.source_id} for i in store.get_items(php.item_ids)]
    view = {"event_id": php.event_id, "domain": php.domain, "title": php.title, "severity": "P0", "level": php.level,
            "exploitation": php.exploitation, "cves": php.cves, "entities": php.entities,
            "independent_sources": php.independent_sources, "first_seen": php.first_seen}
    st, ops = respond.decide(view, items, None, None, [demo], respond.Budget(4, True, "2026-10-23"))
    for op in ops:
        st = respond.apply(st, op, {"finding_id": "cf-1", "status": "SUBMITTED", "title": "t", "scan_run_id": "s",
                                    "code_review_id": "cr", "job_id": "cj", "ok": True}, "2026-10-23T04:00:00Z")
    store.put_response(php.event_id, st)
    store.put_source_state("__continuum__", {"counters": {"requirements_synced": 1}, "reviews": ["2026-10-23T04:00:00Z"]})
    docs = publish.build(store, FETCHED)
    validator = jsonschema.Draft202012Validator(SCHEMA, format_checker=jsonschema.FormatChecker())
    for path in ("events.json", f"events/{php.event_id}.json", "continuum.json"):
        errors = sorted(validator.iter_errors(docs[path]), key=str)
        assert not errors, f"{path}: {errors[0].message}"
    d = docs[f"events/{php.event_id}.json"]
    row = next(e for e in docs["events.json"]["events"] if e["event_id"] == php.event_id)
    assert d["response"]["targets"][0]["verdict"] == "affected" and row["impact"]["status"] == "affected"
    steps = {s["step"]: s for s in d["pipeline_steps"]}
    assert steps["impact_match"]["status"] == "running" and "1 个受影响" in steps["impact_match"]["detail"]
    c = docs["continuum.json"]
    assert c["recent"][0]["event_id"] == php.event_id and c["ledger"]["code_reviews_24h"] == 1


def test_continuum_ledger_carries_cost_and_a_failed_read_stays_visible():
    """R4: spend reaches #/continuum; when the last Cost Explorer read failed the old numbers carry the error."""
    from test_cost import CE, NOW

    from radar import cost
    store = MemoryStore()
    store.put_source_state("__continuum__", {"cost": cost.summarize(CE, NOW),
                                             "cost_error": {"at": "2026-10-27T11:00:00Z", "error": "AccessDenied"}})
    c = publish.build(store, FETCHED)["continuum.json"]
    errors = sorted(jsonschema.Draft202012Validator(SCHEMA).iter_errors(c), key=str)
    assert not errors, errors[0].message
    assert c["ledger"]["cost"]["total_usd"] == 729.02 and c["ledger"]["cost"]["error"] == "AccessDenied"
    assert publish.build(MemoryStore(), FETCHED)["continuum.json"]["ledger"]["cost"] is None
