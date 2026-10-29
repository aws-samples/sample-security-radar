"""D (M3) · ops view: "what needs a human" — one list computed by code from state the stations already keep.

Every rule lives in RULES (one place; the page and its test read the same table). A rule turns facts into zero or more
attention items {code, level, title, detail, since, link}; levels: error (something is broken), warn (degraded or
needs a decision), info (expected, waiting on someone). Nothing here calls a network or an LLM.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

LEVELS = ("error", "warn", "info")
Facts = dict[str, Any]
Item = dict[str, Any]


def _sources(f: Facts) -> list[Item]:
    out = []
    for s in f.get("sources") or []:
        if s.get("status") in ("failing", "degraded"):
            out.append({"level": "error" if s["status"] == "failing" else "warn", "title": f"源 {s['name']} {s['status']}",
                        "detail": (s.get("last_error") or "")[:200], "since": s.get("last_error_at"), "link": "/sources"})
    return out


def _over_budget(f: Facts) -> list[Item]:
    o = (f.get("ledger") or {}).get("over_budget")
    return [{"level": "warn", "title": "Continuum 日花费超过预算线（只标记，不停扫）",
             "detail": f"{o.get('date')}: ${o.get('continuum_usd')} > ${o.get('cap')}", "since": o.get("at"), "link": "/continuum"}] if o else []


def _notify(f: Facts) -> list[Item]:
    out, st = [], (f.get("ledger") or {}).get("notify") or {}
    if st.get("error"):
        out.append({"level": "error", "title": "推送配置读取失败", "detail": st["error"][:200], "since": None, "link": None})
    for c in ("slack", "lark"):
        row = st.get(c) or {}
        if row.get("status") == "error":
            out.append({"level": "error", "title": f"{c} 推送失败", "detail": (row.get("error") or "")[:200], "since": row.get("at"), "link": None})
        elif row.get("status") == "not_configured":
            out.append({"level": "info", "title": f"{c} 推送未配置", "detail": "凭证写入 ~/.env 后运行 scripts/set-notify.sh",
                        "since": row.get("at"), "link": None})
    return out


def _repo_channels(f: Facts) -> list[Item]:
    led = f.get("ledger") or {}
    return [{"level": "error", "title": f"{ch} 仓库通道出错（每小时退避重试）", "detail": led[f"{ch}_error"][:200],
             "since": led.get("github_retry_at"), "link": "/continuum"} for ch in ("github", "gitlab") if led.get(f"{ch}_error")]


def _cost(f: Facts) -> list[Item]:
    e = (f.get("ledger") or {}).get("cost_error")
    return [{"level": "warn", "title": "AWS 花费读取失败（保留上次数字）", "detail": str(e.get("error"))[:200],
             "since": e.get("at"), "link": "/continuum"}] if e else []


def _chain(f: Facts) -> list[Item]:
    bad = [(e, t) for e in f.get("events") or [] for t in e.get("tx") or [] if t.get("check_error")]
    if not bad:
        return []
    chains = sorted({t.get("chain", "?") for _, t in bad})
    return [{"level": "warn", "title": f"链上核验 {len(bad)} 笔失败（6 h 后自动重试）", "detail": "链：" + "、".join(chains),
             "since": max((t.get("checked_at") or "") for _, t in bad) or None, "link": f"/events/{bad[0][0]['event_id']}"}]


def _digest(f: Facts) -> list[Item]:
    d = f.get("digest") or {}
    if d.get("status") == "failed":
        return [{"level": "error", "title": f"今日简报生成失败（{d.get('day')}）", "detail": str(d.get("reason")), "since": d.get("generated_at"), "link": "/"}]
    if d.get("status") == "partial":
        return [{"level": "warn", "title": f"今日简报有句子未通过校验（{d.get('day')}）", "detail": "未通过的句子已标出，不当作事实",
                 "since": d.get("generated_at"), "link": "/"}]
    return []


RULES: dict[str, Callable[[Facts], list[Item]]] = {
    "source_unhealthy": _sources, "over_budget": _over_budget, "notify": _notify, "repo_channel_error": _repo_channels,
    "cost_unavailable": _cost, "chain_rpc_error": _chain, "digest_not_ok": _digest,
}


def attention(f: Facts) -> list[Item]:
    """All rules, errors first; each item carries the rule code that produced it."""
    out = [{"code": code, **it} for code, rule in RULES.items() for it in rule(f)]
    return sorted(out, key=lambda it: (LEVELS.index(it["level"]), it["code"], it["title"]))
