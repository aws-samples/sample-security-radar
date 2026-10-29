"""Store → site-data documents (schemas/site-data.schema.json). Pure: returns {relative_path: document};
the publish handler writes them to S3."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from radar import cluster_judge, coverage, insights, ops, respond, timeutil
from radar.limits import Limits
from radar.model import SEVERITY_ORDER, Event, Item
from radar.registry import BY_ID, SOURCES
from radar.store import Store
from radar.targets import NAMES as TARGET_NAMES


def _analysis_status(ev: Event) -> str:
    if ev.severity not in ("P0", "P1"):
        return "not_applicable" if not ev.analysis else ev.analysis["status"]
    return ev.analysis["status"] if ev.analysis else "pending"


def _public_analysis(ev: Event) -> dict[str, Any] | None:
    if not ev.analysis:
        return None
    a = {k: v for k, v in ev.analysis.items() if k != "input_hash"}  # cache key is internal
    return a


def _summary(ev: Event, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    return {**(extra or {}),
        "event_id": ev.event_id, "domain": ev.domain, "title": ev.title, "level": ev.level,
        "level_reason": ev.level_reason, "severity": ev.severity, "exploitation": ev.exploitation,
        "first_seen": ev.first_seen, "last_updated": ev.last_updated,
        "first_report_source": ev.first_report_source, "independent_sources": ev.independent_sources,
        "item_count": len(ev.item_ids), "cves": ev.cves, "entities": ev.entities, "chains": ev.chains,
        "amount_usd_latest": ev.amount_usd_latest, "amount_disputed": ev.amount_disputed,
        "summary": next((x["text"] for x in (ev.analysis or {}).get("bluf", []) if x.get("grounded")), ev.summary),
        "analysis_status": _analysis_status(ev),
    }


def _response(ev: Event, store: Store, now: datetime) -> dict[str, Any] | None:
    return respond.to_response(store.get_response(ev.event_id), TARGET_NAMES, timeutil.iso(now))


def _item_ref(it: Item, group: int) -> dict[str, Any]:
    src = BY_ID.get(it.source_id)
    name = src.name if src else it.source_id
    if it.source_id.startswith("x_") and it.extra.get("x_status"):
        name = f"X @{it.url.split('/')[3]}" if it.url.count("/") >= 4 else name
    return {
        "item_id": it.item_id, "source_id": it.source_id, "source_name": name, "tier": it.tier, "url": it.url,
        "title": it.title, "published_at": it.published_at, "excerpt": it.text[: Limits.EXCERPT_MAX_CHARS],
        "independent_group": group,
        "signals": {"exploited": it.signals["exploited"], "kev": it.signals["kev"], "poc": it.signals["poc"],
                    "amount_usd": it.signals["amount_usd"]},
    }


def _cve_details(cves: list[str], items: list[Item], epss: dict[str, dict[str, float]]) -> list[dict[str, Any]]:
    kev = {c: it for it in items if it.signals["kev"] for c in it.extra.get("cves") or []}
    return [{"cve": c, "kev": c in kev, "kev_date_added": kev[c].extra.get("kev_date_added") if c in kev else None,
             "ransomware": kev[c].extra.get("ransomware") if c in kev else None,
             "epss": epss.get(c, {}).get("epss"), "epss_percentile": epss.get(c, {}).get("percentile")}
            for c in cves]


def event_doc(ev: Event, store: Store, now: datetime, epss: dict[str, dict[str, float]] | None = None,
              titles: dict[str, str] | None = None) -> dict[str, Any]:
    from radar.pipeline import independent_groups  # local import: pipeline imports publish-free modules only
    items = sorted(store.get_items(ev.item_ids), key=lambda i: (i.published_at, i.source_id, i.item_id))
    groups = independent_groups(items)
    vel = insights.velocity(ev, items, now)
    resp = _response(ev, store, now)
    return {
        "kind": "event", "generated_at": timeutil.iso(now),
        "event": _summary(ev, {"velocity_6h": vel, "lifecycle": insights.lifecycle(ev, vel, now),
                               "impact": respond.impact(resp)}),
        "analysis": _public_analysis(ev),
        "response": resp,
        # C4: model-judged "same incident" pairs (advisory, never merged); titles only for events still published
        "possible_duplicates": cluster_judge.possible_duplicates(
            ev.event_id, store.get_source_state("__cluster_judge__").get("pairs") or {}, titles or {ev.event_id: ev.title}),
        "progress": insights.progress(ev, items, now),
        "pipeline_steps": insights.pipeline_steps(ev, items, resp),
        "items": [_item_ref(it, g) for it, g in zip(items, groups)],
        "timeline": ev.timeline, "amount_history": ev.amount_history,
        "cve_details": _cve_details(ev.cves, items, epss or {}),
        "tx": [{"chain": t["chain"], "hash": t["hash"], "explorer_url": t.get("explorer_url"),
                "verified": t.get("verified", "unchecked"),
                **({"block": t["block"]} if t.get("block") is not None else {}),
                **({"checked_at": t["checked_at"]} if t.get("checked_at") else {})} for t in ev.tx],
    }


def events_doc(store: Store, now: datetime) -> tuple[dict[str, Any], list[Event]]:
    since = timeutil.iso(now - timedelta(days=Limits.PUBLISH_WINDOW_DAYS))
    evs = store.events_updated_since(since)
    evs.sort(key=lambda e: e.last_updated, reverse=True)   # newest first …
    evs.sort(key=lambda e: -SEVERITY_ORDER[e.severity])     # … within severity (stable sort), P0 on top
    evs = evs[: Limits.PUBLISH_MAX_EVENTS]
    rows = []
    for e in evs:
        vel = insights.velocity(e, store.get_items(e.item_ids), now)
        rows.append(_summary(e, {"velocity_6h": vel, "lifecycle": insights.lifecycle(e, vel, now),
                                 "impact": respond.impact(_response(e, store, now))}))
    board = insights.now_board(evs, store, now)
    ok = sum(1 for s in SOURCES if s.enabled and store.get_source_state(s.source_id).get("consecutive_failures", 0) == 0
             and store.get_source_state(s.source_id).get("last_run"))
    total = sum(1 for s in SOURCES if s.enabled)
    day = timeutil.iso(now - timedelta(days=1))
    touched = [e for e in evs if e.last_updated >= day]
    fun = insights.funnel(store.get_source_state("__funnel__").get("runs", []), events_touched=len(touched),
                          corroborated=sum(1 for e in touched if e.level in ("V2", "V3", "V4")),
                          p0=sum(1 for e in evs if e.severity == "P0"), now=now)
    return {"kind": "events", "generated_at": timeutil.iso(now), "events": rows, "now": board,
            "headline": insights.headline(board, {e.event_id: e for e in evs}, ok, total, now), "funnel": fun,
            **_digest(store)}, evs


DIGEST_FIELDS = ("day", "generated_at", "model", "status", "reason", "header", "summary", "highlights", "watch", "event_ids")


def _digest(store: Store) -> dict[str, Any]:
    """C7: the latest daily digest as written by the analyze station (bookkeeping fields stay in the store)."""
    d = store.get_source_state("__digest__")
    return {"digest": {k: d.get(k) for k in DIGEST_FIELDS}} if d.get("day") else {}


def _status(st: dict[str, Any], enabled: bool) -> str:
    if not enabled:
        return "disabled"
    if not st.get("last_run"):
        return "never_run"
    fails = st.get("consecutive_failures", 0)
    if fails >= Limits.SOURCE_FAILING_AFTER:
        return "failing"
    return "degraded" if fails else "ok"


def sources_doc(store: Store, now: datetime) -> dict[str, Any]:
    day_ago = timeutil.iso(now - timedelta(days=1))
    rows = []
    for s in SOURCES:
        st = store.get_source_state(s.source_id)
        rows.append({
            "source_id": s.source_id, "name": s.name, "tier": s.tier, "domain": s.domain or "incident",
            "cadence_min": s.cadence_min, "enabled": s.enabled, "status": _status(st, s.enabled),
            "last_success": st.get("last_success"), "last_error": st.get("last_error"),
            "last_error_at": st.get("last_error_at"),
            "items_24h": sum(n for ts, n in st.get("runs", []) if ts >= day_ago),
        })
    return {"kind": "sources", "generated_at": timeutil.iso(now), "sources": rows}


def continuum_doc(store: Store, now: datetime, evs: list[Event]) -> dict[str, Any]:
    """Overview of the AWS Continuum / Security Agent integration, from the respond ledger + responses."""
    led = store.get_source_state("__continuum__")
    recent, patch_paths, issue_ids = [], set(), set()
    for e in evs:
        r = _response(e, store, now)
        if r and r["status"] != "not_eligible":
            patch_paths |= {p["path"] for p in r["patches"]}
            issue_ids |= {i["issue_id"] for i in r["issues"]}
            imp = respond.impact(r) or {"affected": 0, "checked": 0}
            recent.append({"event_id": e.event_id, "title": e.title, "severity": e.severity, "status": r["status"],
                           "affected": imp["affected"], "checked": imp["checked"], "updated_at": r["updated_at"]})
    c = led.get("counters") or {}
    day = timeutil.iso(now - timedelta(days=1))
    return {"kind": "continuum", "generated_at": timeutil.iso(now), "resources": led.get("resources") or [],
            "targets": led.get("targets") or [], "coverage": coverage.rows(led), "recent": recent[:50],
            "ledger": {"code_reviews_total": int(c.get("code_reviews_started", 0)),
                       "code_reviews_24h": sum(1 for t in led.get("reviews", []) if t >= day),
                       "scans_total": int(c.get("scans_requested", 0)),
                       "findings_submitted": int(c.get("findings_submitted", 0)),
                       # counted from the responses themselves (ledger counters only prove liveness and
                       # double-count when a finished review is re-read)
                       "issues": len(issue_ids), "patches": len(patch_paths),
                       # R4: per-day spend from Cost Explorer (null until the first read; error kept visible)
                       "cost": ({**led["cost"], "error": (led.get("cost_error") or {}).get("error")}
                                if led.get("cost") else None)}}


def ops_doc(store: Store, now: datetime, srcs: dict[str, Any], evs: list[Event]) -> dict[str, Any]:
    """D/M3: what needs a human, from state the stations already keep (radar.ops RULES)."""
    items = ops.attention({"sources": srcs["sources"], "ledger": store.get_source_state("__continuum__"),
                           "events": [{"event_id": e.event_id, "tx": e.tx} for e in evs],
                           "digest": store.get_source_state("__digest__")})
    return {"kind": "ops", "generated_at": timeutil.iso(now), "attention": items,
            "counts": {lv: sum(1 for i in items if i["level"] == lv) for lv in ops.LEVELS}}


def build(store: Store, now: datetime, changed: set[str] | None = None,
          epss: dict[str, dict[str, float]] | None = None) -> dict[str, dict[str, Any]]:
    """changed=None ⇒ every listed event gets a detail doc (first publish / full rebuild)."""
    listing, evs = events_doc(store, now)
    srcs = sources_doc(store, now)
    docs: dict[str, dict[str, Any]] = {"events.json": listing, "sources.json": srcs,
                                       "continuum.json": continuum_doc(store, now, evs), "ops.json": ops_doc(store, now, srcs, evs)}
    titles = {e.event_id: e.title for e in evs}
    for ev in evs:
        if changed is None or ev.event_id in changed:
            docs[f"events/{ev.event_id}.json"] = event_doc(ev, store, now, epss, titles)
    return docs
