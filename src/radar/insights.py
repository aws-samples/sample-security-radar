"""Insight layer: what deserves attention now, and why. All D-class (code) — the LLM never ranks, scores,
or writes the headline (research/09 §C②, M2-PLAN §3)."""

from __future__ import annotations

import math
from datetime import datetime, timedelta
from typing import Any

from radar import timeutil
from radar.model import Event, Item
from radar.store import Store

_SEV_W = {"P0": 100.0, "P1": 30.0}
_EXPL_W = {"confirmed": 2.0, "reported": 1.5, "poc": 1.2, "none": 1.0}
_EXPL_LABEL = {"confirmed": "在野利用·已确认", "reported": "在野利用·已报道", "poc": "PoC 已公开"}
NOW_MAX = 3
NOW_HALF_LIFE_H = 48.0       # freshness decay for ranking (P0 eligibility itself is Limits.P0_FRESH_HOURS)
NOW_MAX_AGE_H = 72.0


def _hours(a: str, now: datetime) -> float:
    t = timeutil.parse(a)
    return (now - t).total_seconds() / 3600 if t else math.inf


def velocity(ev: Event, items: list[Item], now: datetime, hours: int = 6) -> int:
    """Independent source groups whose FIRST report falls inside the window (echoes don't count)."""
    from radar.pipeline import independent_groups  # pipeline imports nothing from here
    items = sorted(items, key=lambda i: (i.published_at, i.source_id, i.item_id))
    since = timeutil.iso(now - timedelta(hours=hours))
    return sum(1 for t in _group_firsts(items, independent_groups(items)) if t >= since)


def lifecycle(ev: Event, velocity_6h: int, now: datetime) -> str:
    if ev.level == "V4":
        return "finalized"
    if velocity_6h > 0 or _hours(max(ev.first_seen, ev.escalated_at or ""), now) <= 24:
        return "escalating"
    quiet = _hours(ev.last_updated, now)
    if quiet <= 72:
        return "active"
    return "cooling" if quiet <= 14 * 24 else "dormant"


def _reasons(ev: Event, vel: int, now: datetime) -> list[str]:
    out = []
    if ev.exploitation in _EXPL_LABEL:
        out.append(_EXPL_LABEL[ev.exploitation])
    if ev.level in ("V3", "V4"):
        out.append("T1 已确认")
    out.append(f"{ev.independent_sources} 个独立来源")
    if vel:
        out.append(f"6h +{vel} 来源")
    if ev.amount_usd_latest:
        out.append(f"损失 ${ev.amount_usd_latest / 1e6:.1f}M" if ev.amount_usd_latest >= 1e6 else f"损失 ${ev.amount_usd_latest / 1e3:.0f}K")
    age = _hours(ev.first_seen, now)
    out.append(f"首见 {age:.0f}h 前" if age < 48 else f"首见 {age / 24:.0f}d 前")
    return out


def now_board(events: list[Event], store: Store, now: datetime) -> list[dict[str, Any]]:
    """Top ≤3 events to act on. score = severity × exploitation × freshness decay × (1 + source breadth + velocity).
    Every factor is shown back to the user as a reason tag; ties break on event_id for determinism."""
    scored = []
    for ev in events:
        if ev.severity not in _SEV_W:
            continue
        age = _hours(max(ev.first_seen, ev.escalated_at or ""), now)
        if age > NOW_MAX_AGE_H:
            continue
        vel = velocity(ev, store.get_items(ev.item_ids), now)
        score = _SEV_W[ev.severity] * _EXPL_W.get(ev.exploitation, 1.0) * math.exp(-age / NOW_HALF_LIFE_H) \
            * (1 + 0.15 * ev.independent_sources + 0.3 * vel)
        scored.append({"event_id": ev.event_id, "score": round(score, 3), "reasons": _reasons(ev, vel, now)})
    scored.sort(key=lambda b: (-b["score"], b["event_id"]))
    return scored[:NOW_MAX]


def headline(board: list[dict[str, Any]], by_id: dict[str, Event], sources_ok: int, sources_total: int,
             now: datetime) -> str:
    """One-line situation statement, templated (no LLM). Empty board says so explicitly, with check time and
    source health, so "nothing to do" never looks like "broken"."""
    hhmm = timeutil.iso(now)[11:16]
    if not board:
        return f"当前无必须处理事件 · 最近检查 {hhmm} UTC · 源 {sources_ok}/{sources_total} 正常"
    top = by_id[board[0]["event_id"]]
    title = top.title if len(top.title) <= 64 else top.title[:63] + "…"
    more = f" · 另有 {len(board) - 1} 件待处理" if len(board) > 1 else ""
    return f"{title} · {board[0]['reasons'][0]}{more}"


def funnel(runs: list[list[Any]], events_touched: int, corroborated: int, p0: int, now: datetime,
           window_hours: int = 24) -> dict[str, int]:
    """runs = [[iso, fetched, new_or_updated], …] appended by the process station each cycle."""
    since = timeutil.iso(now - timedelta(hours=window_hours))
    recent = [r for r in runs if r[0] >= since]
    return {"window_hours": window_hours, "fetched": sum(r[1] for r in recent),
            "new_or_updated_items": sum(r[2] for r in recent), "events_touched": events_touched,
            "corroborated": corroborated, "p0": p0}


# ---------------------------------------------------------------- event progress (L2 "进展流程")

STAGES = ("first_report", "second_source", "corroborated", "confirmed", "exploited", "analyzed", "finalized")


def progress(ev: Event, items: list[Item], now: datetime) -> list[dict[str, Any]]:
    """When each stage was reached, by EVIDENCE time: replay the event's items in publication order and
    record the publication time of the item that first made each stage true. Processing time is never used
    (a historical backfill would otherwise make every stage look like "today")."""
    from radar.limits import Limits
    from radar.model import EXPLOITATION_ORDER, LEVEL_ORDER
    from radar.pipeline import independent_groups, recompute
    items = sorted(items, key=lambda i: (i.published_at, i.source_id, i.item_id))
    at: dict[str, str | None] = dict.fromkeys(STAGES)
    if items:
        at["first_report"] = items[0].published_at
        firsts = _group_firsts(items, independent_groups(items))
        at["second_source"] = firsts[1] if len(firsts) > 1 else None
    for k in range(1, len(items) + 1):
        probe = Event(event_id=ev.event_id, domain=ev.domain, title="", first_seen=items[0].published_at,
                      last_updated=items[0].published_at, item_ids=[], keys=[])
        p = recompute(probe, items[:k], timeutil.parse(items[k - 1].published_at) or now)
        t = items[k - 1].published_at
        if at["corroborated"] is None and LEVEL_ORDER[p.level] >= 2:
            at["corroborated"] = t
        if at["confirmed"] is None and LEVEL_ORDER[p.level] >= 3:
            at["confirmed"] = t
        if at["exploited"] is None and EXPLOITATION_ORDER[p.exploitation] >= EXPLOITATION_ORDER["reported"]:
            at["exploited"] = t
    if ev.analysis and ev.analysis.get("status") in ("ok", "partial"):
        at["analyzed"] = ev.analysis.get("generated_at")
    if ev.level == "V4" and items:
        quiet = Limits.FINALIZE_QUIET_DAYS_WEB3 if ev.domain == "web3" else Limits.FINALIZE_QUIET_DAYS_VULN
        base = at["confirmed"] or at["corroborated"] or items[0].published_at
        at["finalized"] = timeutil.iso(timeutil.parse(base) + timedelta(days=quiet))  # rule-derived date
    return [{"stage": s, "at": at[s]} for s in STAGES]


def _group_firsts(items: list[Item], groups: list[int]) -> list[str]:
    first: dict[int, str] = {}
    for it, g in zip(items, groups):
        first.setdefault(g, it.published_at)
    return sorted(first.values())


def pipeline_steps(ev: Event, items: list[Item], resp: dict[str, Any] | None = None) -> list[dict[str, str]]:
    """What the system has done for this event — unbuilt steps say so explicitly (降级留痕)."""
    a = ev.analysis or {}
    if a.get("status") == "ok":
        ana = ("done", f"{a.get('model', '')} · 全部句子通过校验")
    elif a.get("status") == "partial":
        bad = sum(1 for k in ("bluf", "what", "impact", "exploitation", "actions", "unknowns")
                  for s in a.get(k, []) if not s.get("grounded"))
        ana = ("done", f"{bad} 句未通过校验（已灰显）")
    elif a.get("status") == "failed":
        ana = ("failed", f"生成失败：{a.get('reason')}")
    elif ev.severity in ("P0", "P1"):
        ana = ("pending", "排队中（每轮最多 6 个）")
    else:
        ana = ("skipped", "P2 不生成分析")
    return [
        {"step": "collected", "status": "done", "detail": f"{len(items)} 条证据"},
        {"step": "clustered", "status": "done", "detail": f"{ev.independent_sources} 个独立来源"},
        {"step": "verified", "status": "done", "detail": f"{ev.level} · {ev.level_reason}"},
        {"step": "analyzed", "status": ana[0], "detail": ana[1]},
        _impact_step(ev, resp),
        _remediated_step(resp),
        {"step": "notified", "status": "not_connected", "detail": "推送未接入"},
    ]


def _impact_step(ev: Event, resp: dict[str, Any] | None) -> dict[str, str]:
    """'Does it hit us' = AWS Security Agent + AWS Continuum over the registered targets (radar.respond)."""
    if resp is None:
        if ev.domain == "vuln" and ev.severity in ("P0", "P1"):
            return {"step": "impact_match", "status": "pending", "detail": "等待响应工位（AWS Security Agent / Continuum）"}
        return {"step": "impact_match", "status": "skipped", "detail": "P2 或非漏洞事件，不做代码侧检查"}
    if resp["status"] == "not_eligible":
        return {"step": "impact_match", "status": "skipped", "detail": resp["reason"]}
    ts = resp["targets"]
    aff = sum(1 for t in ts if t["verdict"] == "affected")
    pend = sum(1 for t in ts if t["verdict"] == "pending")
    status = "running" if pend or resp["status"] == "running" else ("failed" if resp["status"] == "failed" else "done")
    return {"step": "impact_match", "status": status,
            "detail": f"{len(ts)} 个目标检查，{aff} 个受影响" + (f"，{pend} 个评审中" if pend else "")}


def _remediated_step(resp: dict[str, Any] | None) -> dict[str, str]:
    if not resp or resp["status"] == "not_eligible":
        return {"step": "remediated", "status": "skipped", "detail": "无需修复"}
    if resp["patches"]:
        files = sorted({f for p in resp["patches"] for f in p["files_changed"]})
        return {"step": "remediated", "status": "done",
                "detail": f"{len(resp['patches'])} 份自动修复补丁（{len(files)} 个文件），待人工合并"}
    if any(t["verdict"] == "affected" for t in resp["targets"]):
        return {"step": "remediated", "status": "running", "detail": "受影响，等待 Security Agent / Continuum 生成补丁"}
    return {"step": "remediated", "status": "skipped", "detail": "未受影响，无需修复"}
