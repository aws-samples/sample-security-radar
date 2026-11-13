"""Response decision table — the ONE place a trigger condition of an action is written down.

ACTIONS = every action the radar can take for an event (Security Agent requirement sync, Continuum context document,
CreateCodeFinding, CreateCodeScan, the paid code review, PR/MR delivery, WAF stage, notify) × its ordered gates.
A gate names a boolean fact, the outcome when that fact is False, a machine reason code, the page text, the pass
condition (for the generated docs) and the Limits attribute it reads. `decide` walks the gates in order: the first
failing gate decides; all pass ⇒ fire. The facts are computed in code next to the state they read (respond.decide,
handlers, publish) — the table owns order, codes, outcomes, texts and limits; the predicates stay code
(docs/research/action/02 §4.5: a DSL would be a second language).

Outcomes (four; the page shows each differently):
  fire            the call is issued; its execution result is folded onto the row (`result` ok | error, `error`,
                  `result_at`: mark_result) — a failed call never reads as a success
  not_fire        evaluated: a condition is not met, or the work is already done (idempotent)
  blocked         every condition met, a budget gate held it back (says which, and the limit)
  not_evaluated   nobody evaluated it this time (station off, out of window, per-cycle cap, channel not wired …) —
                  never rendered like not_fire: "not checked" ≠ "checked, nothing to do" (degradation-and-guards §1)

Generated from this table (never hand-written; tests compare): docs/design/CONTINUUM-INTEGRATION.md §2
(`python -m radar.decisions --explain`, `--check`, `--write`), radar.coverage detail texts (`describe`), the
schema enums of $defs/ResponseDecision (action / gate / outcome)."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from radar.limits import Limits

Outcome = Literal["fire", "not_fire", "blocked", "not_evaluated"]
OUTCOMES: tuple[str, ...] = ("fire", "not_fire", "blocked", "not_evaluated")


@dataclass(frozen=True)
class Gate:
    code: str               # stable machine reason code (schema enum is generated from these)
    fact: str               # boolean fact the caller supplies; the gate passes when it is True
    outcome: Outcome        # what failing this gate means
    text: str               # page reason when it fails (zh, may use {limit} and caller-supplied {…} fields)
    when: str               # pass condition, for the generated docs / coverage text
    limit: str | None = None  # Limits attribute this gate reads ({limit} defaults to its value)


@dataclass(frozen=True)
class Action:
    key: str
    label: str
    service: str            # security_agent | continuum | waf | radar
    scope: Literal["event", "target", "channel"]
    paid: bool
    decided_by: Literal["respond", "publish"]   # respond: persisted in the response state; publish: observed at publish
    op_kinds: tuple[str, ...]   # respond.Op kinds issued when it fires (closure test)
    pre: tuple[Gate, ...]       # shared gates evaluated before `gates`
    gates: tuple[Gate, ...]
    fire_text: str


# ------------------------------------------------------------------ the table

STATION_OFF = Gate("N_STATION_OFF", "station_configured", "not_evaluated", "响应站未配置（SA_AGENT_SPACE_ID），没有评估",
                   "响应站已配置（每轮在 __continuum__ 账本记 station.status）")
# Respond station preconditions (handlers.respond_events) + eligibility (respond.eligibility reads E_* in this order)
RESPOND_PRE: tuple[Gate, ...] = (
    STATION_OFF,
    Gate("N_OUT_OF_WINDOW", "in_window", "not_evaluated", "事件 {limit} 天内无更新且没有在跑的任务，响应站不再评估",
         "事件 {limit} 天内有更新，或仍有在跑的任务", "RESPOND_WINDOW_DAYS"),
    Gate("E_DOMAIN", "domain_ok", "not_fire", "{domain} 事件不涉及代码依赖，不做代码侧响应", "漏洞或 Web3 事件"),
    Gate("E_SEVERITY", "severity_ok", "not_fire", "{severity}/{exploitation}：只对 P0，或已利用/有 PoC 的 P1 做代码侧响应",
         "P0，或已利用 / 有 PoC 的 P1"),
    Gate("N_NOT_YET", "seen_by_station", "not_evaluated", "响应站还没有评估这个事件（下一轮）", "响应站已评估过"),
    Gate("E_NO_PRODUCT", "product_known", "not_fire", "产品不在登记表（网络设备/闭源产品不在代码里），无法定位代码",
         "漏洞类：产品命中登记表（radar.products）"),
    Gate("E_NO_WEB3_ANCHOR", "web3_anchor", "not_fire", "攻击手法不在登记表、证据中也没有地址类 IOC，无法在代码中定位",
         "Web3 类：攻击手法在登记表或证据里有地址 IOC（radar.patterns）"),
    Gate("N_CYCLE_CAP", "within_cycle_cap", "not_evaluated", "本轮名额已满（每轮最多 {limit} 个事件），排到下一轮评估",
         "本轮名额未满（每轮 ≤ {limit} 个事件，P0 优先）", "RESPOND_MAX_EVENTS"),
)
ELIGIBILITY_CODES = ("E_DOMAIN", "E_SEVERITY", "E_NO_PRODUCT", "E_NO_WEB3_ANCHOR")
CHANNEL_NOT_WIRED = Gate("N_CHANNEL_NOT_WIRED", "channel_wired", "not_evaluated",
                         "{channel} 渠道（集成 / 环境）未接通，没有评估", "该 Continuum 渠道（集成 + 环境）已接通")

ACTIONS: tuple[Action, ...] = (
    Action("sa_requirement", "Security Agent 规则同步", "security_agent", "event", False, "respond",
           ("sync_requirement",), RESPOND_PRE, (
               Gate("U_REQUIREMENT_CURRENT", "requirement_stale", "not_fire", "规则未变，今日已重申",
                    "规则内容变了，或今天还没重申（每日重申，防 CFN 栈更新冲掉规则）"),),
           "规则写入 Security Agent requirement pack"),
    Action("cn_context", "Continuum 知识文档", "continuum", "event", False, "respond", ("write_context",), RESPOND_PRE, (
        Gate("U_CONTEXT_SAME", "context_changed", "not_fire", "知识文档未变", "事件 + 已校验分析句组成的文档内容变了"),),
           "事件与分析卡写入 Continuum context/"),
    Action("cn_finding", "CreateCodeFinding", "continuum", "target", False, "respond",
           ("submit_finding", "submit_finding_gh", "submit_finding_gl"), RESPOND_PRE, (
               Gate("T_NO_CHANNEL", "routed", "not_fire", "目标不送 Continuum（targets.CHANNEL=none）",
                    "目标登记了 Continuum 渠道（targets.CHANNEL）"),
               CHANNEL_NOT_WIRED,
               Gate("T_NO_LOCATION", "has_location", "not_fire", "代码中没有可定位的受影响行",
                    "目标代码里有定位行（钉死的受影响版本 / 证据 IOC / 代码形态候选）"),
               Gate("U_FINDING_SUBMITTED", "has_new_location", "not_fire", "定位行都已提交过 finding（uid 幂等）",
                    "有还没在该渠道提交过的定位行"),),
           "OCSF 2002 finding 已提交（精确到文件行）"),
    Action("cn_scan", "CreateCodeScan 环境扫描（约 $450/次）", "continuum", "channel", True, "respond",
           ("request_scan", "request_scan_gh", "request_scan_gl"), RESPOND_PRE, (
               CHANNEL_NOT_WIRED,
               Gate("S_NOTHING_WAITING", "findings_waiting", "not_fire",
                    "没有待验证的新 finding（不为 P0 本身买扫描）", "有上次扫描请求之后提交、状态仍为 SUBMITTED 的雷达 finding"),
               Gate("S_IN_FLIGHT", "scan_idle", "not_fire", "环境扫描进行中，完成后再判断", "该环境没有在跑的扫描"),
               Gate("B_SCAN_INTERVAL", "scan_clock_open", "blocked", "每个环境 {limit} 小时最多一次扫描，时钟未到",
                    "该环境 {limit} 小时内没有成功发起过扫描", "CONTINUUM_SCAN_MIN_INTERVAL_H"),
               Gate("B_SCAN_THIS_CYCLE", "cycle_scan_free", "blocked", "本轮已为该环境发起扫描（一次覆盖所有事件）",
                    "本轮还没为该环境发起扫描"),),
           "环境扫描已发起"),
    Action("sa_review", "Security Agent 代码评审（付费）", "security_agent", "target", True, "respond",
           ("start_review",), RESPOND_PRE, (
               Gate("T_NOT_RELEVANT", "relevant", "not_fire", "目标未使用 {subject}，不评审",
                    "目标确实用到该产品（任一版本钉）/ 是合约代码"),
               Gate("R_SEVERITY", "review_severity", "not_fire", "P1 且未在野利用：只定位、不评审", "P0，或在野利用"),
               Gate("U_SAME_TRIGGER", "escalated", "not_fire", "上次评审之后事件没有升级（降级不重新评审）",
                    "上次评审之后事件升级了（severity / level / exploitation 任一升高）"),
               Gate("R_IN_FLIGHT", "review_idle", "not_fire", "评审进行中", "该目标没有在跑的评审"),
               Gate("B_REVIEWS_DAY", "review_budget", "blocked",
                    "今日 Security Agent 评审额度已用完（{limit}/天，滚动 24 小时），明天自动补做",
                    "滚动 24 小时内评审少于 {limit} 次（同一目标本轮已有评审则搭车、不扣额度）", "SA_REVIEWS_PER_DAY"),),
           "代码评审已发起（含雷达规则）"),
    Action("delivery", "补丁 PR / MR 交付", "continuum", "channel", False, "publish", (), (STATION_OFF,), (
        Gate("D_NO_PATCH", "has_patch", "not_fire", "尚无 Continuum 补丁", "Continuum issue 带 PATCH 工件"),
        Gate("D_NOT_NATIVE", "native_channel", "not_fire", "S3 渠道只产出 .patch 工件，不开 PR",
             "目标在仓库渠道（GitHub / GitLab）或由雷达代开 PR（deliver_prs）"),
        Gate("D_WAITING_LINK", "has_link", "not_fire", "补丁已生成，等待 PR / MR 链接", "拿到 PR / MR 链接"),),
           "补丁 PR / MR 已开出，待人审核合并"),
    Action("waf_stage", "WAF 规则挂载（Count 观察期）", "waf", "event", False, "publish", (), (
        Gate("M_STATION_OFF", "mitigate_ran", "not_evaluated", "缓解站还没有运行", "缓解站运行过"),
        Gate("M_OUT_OF_WINDOW", "in_mitigate_window", "not_evaluated", "事件 {limit} 天内无更新，缓解站不再评估",
             "事件 {limit} 天内有更新", "MITIGATE_WINDOW_DAYS"),), (
        Gate("W_NO_PLAN", "has_plan", "not_fire", "没有受影响目标对应的 WAF 托管规则组 / 规则族",
             "有受影响目标，且 CVE 在 AWS WAF 托管规则更新日志里（或 CWE 有通用规则族）"),
        Gate("W_NO_WEB_ACL", "on_web_acl", "not_fire", "受影响目标前没有登记雷达 web ACL —— 只给出规则，由你决定挂在哪里",
             "受影响目标前登记了雷达 web ACL"),
        Gate("W_ADVISORY", "appliable", "not_fire", "只有通用规则族建议，不自动挂载", "计划可自动挂载（托管规则组命中 CVE）"),
        Gate("W_UNCHECKED", "acl_checked", "not_evaluated", "web ACL 读取失败，本轮没查", "web ACL 本轮读到了"),
        Gate("W_NOT_IN_PLACE", "in_place", "not_fire", "规则不在 web ACL 上（缺失 / 版本过低 / 他人整组 Count）",
             "雷达规则在 web ACL 上（Count 观察期或人工 promote 后 Block）"),),
           "规则已挂上雷达 web ACL（整组 Count，人工 promote 后才拦截）"),
    # the Notify station (radar.notify_station, its own Lambda after Publish) runs whether or not the Security Agent
    # space exists — no STATION_OFF here; its facts come from what it recorded per event in __notify_status__
    Action("notify", "推送（订阅：Slack / Lark / Webhook）", "radar", "event", False, "publish", (), (), (
        Gate("N_NOTIFY_OFF", "notify_configured", "not_evaluated", "没有生效的订阅（未配置 / 配置无效 / 灰度只放行本人），没有评估",
             "至少一个订阅生效"),
        Gate("N_NOTIFY_WINDOW", "notify_in_window", "not_evaluated", "只推送 {limit} 天内有更新的 P0 / P1",
             "P0 / P1 且 {limit} 天内有更新", "RESPOND_WINDOW_DAYS"),
        Gate("N_NOTIFY_NOT_YET", "notify_seen", "not_evaluated", "推送站还没有处理这个事件（页面未写出或下一轮）",
             "推送站本轮处理过这个事件"),
        Gate("X_NO_SUBSCRIBER", "matched", "not_fire", "没有订阅的过滤条件匹配这个事件", "至少一个订阅匹配"),
        Gate("X_NOTHING_TO_SAY", "has_message", "not_fire", "非 P0、没有受影响目标、没有补丁 PR：不推送",
             "P0，或有受影响目标，或有补丁 PR"),
        # a send error is not a budget: it is a failed send (fire, result error), never this gate
        Gate("B_NOTIFY_PENDING", "cap_clear", "blocked", "还有消息未发出（每订阅每轮 ≤ {limit} 条，或时间不够），下一轮补发",
             "没有被每轮条数上限 / 时间压下的消息（出错订阅的未发消息记为发送失败）", "NOTIFY_MAX_PER_CYCLE"),),
           "消息已推送（每事件每订阅一个线程）"),
)
BY_KEY: dict[str, Action] = {a.key: a for a in ACTIONS}
OP_ACTION: dict[str, str] = {k: a.key for a in ACTIONS for k in a.op_kinds}   # respond.Op kind → the action it fires
# N_NOTIFY_WINDOW's severities. notify_station.views selects with notify_due — the station reads the table,
# the table never restates the station (a test monkeypatches these and watches the station follow)
NOTIFY_SEVERITIES: tuple[str, ...] = ("P0", "P1")
# __continuum__ ledger: handlers.respond_events records whether the station is configured, every cycle, configured or
# not — "the ledger exists" is not "the station runs" (a removed SA_AGENT_SPACE_ID left last cycle's rows looking live)
STATION_KEY, STATION_ON, STATION_OFF_STATUS = "station", "configured", "not_configured"
# informational line: never changes an outcome — written down so nobody re-adds a stop (R10, Neo 2026-10-28)
SPEND_LINE = ("CONTINUUM_DAILY_USD_CAP", "日花费 > ${limit}：只记账、告警，不拦扫描（R10）")


def gates(action: str) -> tuple[Gate, ...]:
    a = BY_KEY[action]
    return a.pre + a.gates


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def window_start(action: str, code: str, now: datetime) -> str:
    """ISO start of the window gate `code` of `action` (its Limits attribute, in days). The station applying that
    window calls this too, so the page's window and the station's cannot drift."""
    g = next(g for g in gates(action) if g.code == code)
    if not g.limit:
        raise KeyError(f"{action}.{code} reads no limit")
    return _iso(now - timedelta(days=getattr(Limits, g.limit)))


def notify_due(severity: str, last_updated: str, now: datetime) -> bool:
    """N_NOTIFY_WINDOW's fact: the events notify messages about (notify_station.views selects with this)."""
    return severity in NOTIFY_SEVERITIES and last_updated >= window_start("notify", "N_NOTIFY_WINDOW", now)


def station_on(led: dict[str, Any]) -> bool:
    """N_STATION_OFF's fact from the __continuum__ ledger. Strict: a ledger that does not say "configured" (written by
    an older station, or the station saying not_configured) is not evaluated — never last cycle's rows as current."""
    return (led.get(STATION_KEY) or {}).get("status") == STATION_ON


def mark_result(rows: dict[str, Any] | None, op_kind: str, scope: str | None, err: str | None, now: str) -> None:
    """Fold an executed op's result onto the fire row that issued it (respond.apply calls this for every op). Several
    ops of one row in a cycle (one submit per located line): one error makes the row an error. Rows are rebuilt by
    every decide, so a result never outlives its cycle."""
    action = OP_ACTION.get(op_kind)
    r = (rows or {}).get(key({"action": action, "scope": scope})) if action else None
    if r is None or r["outcome"] != "fire":
        return
    if err:
        r.update(result="error", error=str(err)[:200], result_at=now)
    elif r.get("result") != "error":
        r.update(result="ok", error=None, result_at=now)


def codes() -> list[str]:
    """Every gate code, table order, no duplicates (schema enum $defs/ResponseDecision.gate)."""
    return list(dict.fromkeys(g.code for a in ACTIONS for g in gates(a.key)))


def _limit(g: Gate, ctx: dict[str, Any]) -> Any:
    return ctx.get("limit", getattr(Limits, g.limit)) if g.limit else None


def reason(g: Gate, ctx: dict[str, Any] | None = None) -> str:
    """The page text of a failing gate. A template field the caller did not supply raises KeyError — a reason with a
    hole is a bug, not something to render."""
    c = dict(ctx or {})
    if g.limit:
        c["limit"] = _limit(g, c)
    return g.text.format_map(c)


def decide(action: str, facts: dict[str, bool], ctx: dict[str, Any] | None = None, *, scope: str | None = None,
           at: str | None = None) -> dict[str, Any]:
    """First failing gate decides; all pass ⇒ fire. Gates are read in order and only up to the first failure, so a
    caller need not compute facts behind it; a fact a reached gate needs and the caller did not give raises KeyError
    (never defaulted to True — a silent pass would buy a scan)."""
    a = BY_KEY[action]
    for g in gates(action):
        if not facts[g.fact]:
            return {"action": action, "scope": scope, "outcome": g.outcome, "gate": g.code, "reason": reason(g, ctx),
                    "at": at, **({"limit": _limit(g, ctx or {})} if g.limit else {})}
    return {"action": action, "scope": scope, "outcome": "fire", "gate": None, "reason": a.fire_text, "at": at}


def failing_at(action: str, code: str) -> dict[str, bool]:
    """Facts that make exactly gate `code` decide: every gate before it passes, it fails. Used where the caller knows
    which gate held the action (the eligibility code, the station's phase-2 review budget) — the outcome still comes
    from the table."""
    out: dict[str, bool] = {}
    for g in gates(action):
        if g.code == code:
            out[g.fact] = False
            return out
        out[g.fact] = True
    raise KeyError(f"{action}: no gate {code}")


def eligibility_gate(facts: dict[str, bool]) -> Gate | None:
    """The E_* gate (RESPOND_PRE order) an event fails, None = eligible — respond.eligibility's verdict."""
    return next((g for g in RESPOND_PRE if g.code in ELIGIBILITY_CODES and not facts[g.fact]), None)


def key(row: dict[str, Any]) -> str:
    return f"{row['action']}:{row['scope']}" if row.get("scope") else row["action"]


def record(rows: list[dict[str, Any]], prev: dict[str, Any] | None, now: str) -> dict[str, Any]:
    """rows → st['decisions'] (key → row). `at` = when this decision (outcome + gate) first held: kept from the previous
    cycle while unchanged, so a 5-minute cycle that decides the same thing does not rewrite the DynamoDB row and
    republish (docs/research/action/02 §7.3)."""
    out = {}
    for r in rows:
        k = key(r)
        p = (prev or {}).get(k) or {}
        same = p.get("outcome") == r["outcome"] and p.get("gate") == r["gate"]
        out[k] = {**r, "at": p.get("at") if same and p.get("at") else now}
    return out


# ------------------------------------------------------------------ publish-time evaluation (every action, every event)

def _facts_upto(action: str, known: dict[str, bool]) -> dict[str, bool]:
    return {g.fact: known.get(g.fact, True) for g in gates(action)}


def _respond_rows(ev: dict[str, Any], st: dict[str, Any] | None, led: dict[str, Any], now: datetime) -> list[dict[str, Any]]:
    from radar import respond  # lazy: respond imports this module
    nowi = _iso(now)
    st = respond.migrate_state(st) or {}
    window = window_start("sa_requirement", "N_OUT_OF_WINDOW", now)
    elig = st.get("eligibility") or {}
    station = {"station_configured": station_on(led),
               "in_window": ev.get("last_updated", "") >= window or respond.has_open_jobs(st),
               **respond.event_facts(ev),   # domain_ok / severity_ok: the same code respond.eligibility runs
               # the station saw it: it decided (rows), or recorded an eligibility verdict — an ineligible one, or an
               # eligible one the per-cycle cap then left out (handlers writes {eligibility, not_evaluated})
               "seen_by_station": bool(st.get("decisions")) or (bool(elig) and not elig.get("eligible"))
               or (bool(elig) and bool(st.get("not_evaluated"))),
               "product_known": True, "web3_anchor": True,
               "within_cycle_cap": not st.get("not_evaluated")}
    if elig and not elig.get("eligible") and elig.get("code") in ELIGIBILITY_CODES:
        station.update({k: v for k, v in failing_at("sa_requirement", elig["code"]).items() if not v})
    elif elig and not elig.get("eligible") and station["domain_ok"] and station["severity_ok"]:
        # a row written before eligibility carried its code: the only remaining reason is "cannot be located"
        station["product_known" if ev["domain"] == "vuln" else "web3_anchor"] = False
    ctx = {"domain": ev["domain"], "severity": ev["severity"], "exploitation": ev["exploitation"]}
    stored = st.get("decisions") or {}
    since = (st.get("not_evaluated") or {}).get("since")
    out = []
    for a in ACTIONS:
        if a.decided_by != "respond":
            continue
        pre = decide(a.key, _facts_upto(a.key, station), ctx)
        if pre["outcome"] != "fire" and pre["gate"] in {g.code for g in RESPOND_PRE}:
            # the station did not (re)decide this action now: say so, over whatever an older cycle decided
            held = [r for r in stored.values() if r["action"] == a.key]
            if pre["gate"] in ELIGIBILITY_CODES and held:
                out += held   # a cooled event: decide stored the eligibility outcome per scope
                continue
            out.append({**pre, "evaluated_by": "publish",
                        "at": since if pre["gate"] == "N_CYCLE_CAP" and since else nowi})
            continue
        out += [r for r in stored.values() if r["action"] == a.key]
    return out


def _delivery_rows(st: dict[str, Any] | None, led: dict[str, Any]) -> list[dict[str, Any]]:
    from radar import respond
    st = respond.migrate_state(st) or {}
    if not station_on(led):
        return [decide("delivery", {"station_configured": False})]
    rows = []
    prs = st.get("delivered_prs") or {}
    for ch, c in respond.CHANNELS.items():
        issues = (st.get(ch) or {}).get("issues") or []
        if not issues:
            continue
        patched = [i for i in issues if i.get("patch_path") or i.get("pr_url")]
        linked = [i for i in patched if i.get("pr_url") or prs.get(i.get("issue_id"))]
        acts = st.get("actions") or {}
        at = max((acts.get(f"pull_request:{i['issue_id']}", {}).get("updated_at") or "" for i in linked), default="") or None
        rows.append(_observed(decide("delivery", {"station_configured": True, "has_patch": bool(patched),
                                                  "native_channel": c.native_delivery or bool(linked), "has_link": bool(linked)},
                                     scope=ch, at=at)))
    return rows or [decide("delivery", {"station_configured": True, "has_patch": False})]


def _observed(row: dict[str, Any]) -> dict[str, Any]:
    """A publish-decided fire row is read from a ledger that records the done state (a PR link, a staged rule): its
    result is that state — ok."""
    return {**row, "result": "ok", "error": None, "result_at": row["at"]} if row["outcome"] == "fire" else row


def _waf_row(ev: dict[str, Any], mled: dict[str, Any], now: datetime) -> dict[str, Any]:
    window = window_start("waf_stage", "M_OUT_OF_WINDOW", now)
    plans = ((mled.get("events") or {}).get(ev["event_id"]) or {}).get("plans") or []
    on_acl = [p for p in plans if p.get("web_acl")]
    appliable = [p for p in on_acl if p.get("appliable")]
    facts = {"mitigate_ran": bool(mled.get("run_at")), "in_mitigate_window": ev.get("last_updated", "") >= window,
             "has_plan": bool(plans), "on_web_acl": bool(on_acl), "appliable": bool(appliable),
             "acl_checked": not any(p.get("state") == "unchecked" for p in appliable),
             "in_place": any(p.get("state") in ("staged", "blocking") for p in appliable)}
    return _observed(decide("waf_stage", facts, at=mled.get("run_at")))


def _notify_row(ev: dict[str, Any], status: dict[str, Any], now: datetime) -> dict[str, Any]:
    """From the Notify station's own record (__notify_status__.events, written every run for each event it considered):
    the subscriptions' filters live in the secret, so only the station can say which subscription matched."""
    subs = (status.get("subscriptions") or {}).values()
    live = status.get("status") in ("ok", "degraded") and any(
        r.get("status") in ("ok", "baseline", "error") for r in subs)
    e = (status.get("events") or {}).get(ev["event_id"])
    facts = {"notify_configured": live,
             "notify_in_window": notify_due(ev["severity"], ev.get("last_updated", ""), now),
             "notify_seen": e is not None and not e.get("held"),
             "matched": bool(e and e.get("matched")),
             "has_message": bool(e and e.get("has_message")),
             "cap_clear": not (e and e.get("pending"))}
    at = status.get("at")
    out = decide("notify", facts, at=at)
    if out["outcome"] != "fire":
        return out
    if e and e.get("failed"):
        return {**out, "result": "error", "error": "; ".join(e.get("errors") or ["send_failed"])[:200], "result_at": at}
    return {**out, "result": "ok", "error": None, "result_at": at}


def evaluate(ev: dict[str, Any], st: dict[str, Any] | None, ledgers: dict[str, Any], now: datetime,
             resp: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Every action of the table for one event, as the event page shows it (Response.decisions).
    ev: event_id / domain / severity / exploitation / last_updated (/ title, level_reason); st: the stored response state;
    ledgers: {"respond": __continuum__, "mitigate": __mitigate__, "notify": __notify_status__}; resp: respond.to_response(st).
    Respond-decided rows come from the state (respond.decide wrote them); the station preconditions it did not see
    (station off, out of window, per-cycle cap, never evaluated) are evaluated here and win."""
    led = ledgers.get("respond") or {}
    out = _respond_rows(ev, st, led, now) + _delivery_rows(st, led) + [_waf_row(ev, ledgers.get("mitigate") or {}, now),
                                                                         _notify_row(ev, ledgers.get("notify") or {}, now)]
    for r in out:
        a = BY_KEY[r["action"]]
        r.update(label=a.label, service=a.service, paid=a.paid, evaluated_by=r.get("evaluated_by") or a.decided_by)
    return [{k: r.get(k) for k in DECISION_FIELDS if k in r or k in REQUIRED_FIELDS} for r in out]


# evaluate's ledgers → their store keys. Restated (handlers.CONTINUUM_KEY / NOTIFY_KEY, mitigate_station.MITIGATE_KEY
# are the authority) because importing the station modules into publish would load boto3 adapters; a test pins equality.
LEDGERS = {"respond": "__continuum__", "mitigate": "__mitigate__", "notify": "__notify_status__"}
REQUIRED_FIELDS = ("action", "label", "service", "scope", "outcome", "gate", "reason", "at", "paid", "evaluated_by")
DECISION_FIELDS = (*REQUIRED_FIELDS, "limit", "result", "error", "result_at")


# ------------------------------------------------------------------ generated text (docs, coverage, schema)

def describe(action: str) -> str:
    """One line for radar.coverage: what fires, and every condition in order (respond preconditions summarised)."""
    a = BY_KEY[action]
    head = "资格通过后，" if a.pre is RESPOND_PRE else ""   # the eligibility row states the E_* gates once
    return f"{head}当且仅当：" + "；".join(_when(g) for g in a.gates) + f" ⇒ {a.fire_text}"


def describe_eligibility() -> str:
    """The E_* gates' pass conditions, table order (radar.coverage eligibility row)."""
    return "；".join(_when(g) for g in RESPOND_PRE if g.code in ELIGIBILITY_CODES)


def _when(g: Gate) -> str:
    return g.when.format(limit=getattr(Limits, g.limit)) if g.limit else g.when


def explain() -> str:
    """Markdown for docs/design/CONTINUUM-INTEGRATION.md §2 (between the decisions markers)."""
    shared = " / ".join(f"`{a.key}`" for a in ACTIONS if a.pre is RESPOND_PRE)
    lines = ["每个动作的 gate 按顺序判断，**第一个不通过的 gate 决定结果**；全部通过 ⇒ `fire`。",
             ("结果四态：`fire` 已发出 · `not_fire` 已评估、条件不满足或已是最新 · `blocked` 条件满足、被预算闸挡住 · "
              "`not_evaluated` 这一轮没人评估（站未配置 / 超窗口 / 超每轮名额 / 渠道未接通）。"),
             "", f"响应站前置（{shared} 共用）：", "",
             "| # | 原因码 | 不通过 ⇒ | 通过条件 |", "|---|---|---|---|"]
    lines += [_row(i, g) for i, g in enumerate(RESPOND_PRE, 1)]
    for a in ACTIONS:
        lines += ["", f"**`{a.key}` — {a.label}**（{a.service}{' · 付费' if a.paid else ''}"
                      + (f" · op {', '.join(f'`{k}`' for k in a.op_kinds)}" if a.op_kinds else "")
                      + f" · {'respond 站判定并落库' if a.decided_by == 'respond' else 'publish 时从账本观察'}）"
                      + (" · 先过响应站前置" if a.pre is RESPOND_PRE else ""), "",
                  "| # | 原因码 | 不通过 ⇒ | 通过条件 |", "|---|---|---|---|"]
        own = a.gates if a.pre is RESPOND_PRE else a.pre + a.gates
        lines += [_row(i, g) for i, g in enumerate(own, 1)]
        lines.append(f"| ✓ | — | `fire` | {a.fire_text} |")
    lim, text = SPEND_LINE
    lines += ["", f"另：{text.format(limit=getattr(Limits, lim))}（`Limits.{lim}`）。"]
    return "\n".join(lines) + "\n"


def _row(i: int, g: Gate) -> str:
    when = _when(g)
    lim = f"（`Limits.{g.limit}`）" if g.limit else ""
    return f"| {i} | `{g.code}` | `{g.outcome}` | {when}{lim} |"


ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "design" / "CONTINUUM-INTEGRATION.md"
SCHEMA = ROOT / "schemas" / "site-data.schema.json"
BEGIN, END = "<!-- decisions:begin (generated: uv run python -m radar.decisions --write) -->", "<!-- decisions:end -->"


def doc_section(text: str) -> str:
    """The generated block of the design doc (KeyError-like ValueError if the markers are gone)."""
    if BEGIN not in text or END not in text:
        raise ValueError(f"{DOC.name}: decision markers missing")
    return text.split(BEGIN, 1)[1].split(END, 1)[0].strip("\n") + "\n"


def schema_enums() -> dict[str, list[str]]:
    return {"action": [a.key for a in ACTIONS], "gate": codes(), "outcome": list(OUTCOMES),
            "service": list(dict.fromkeys(a.service for a in ACTIONS))}


def _write() -> None:
    text = DOC.read_text()
    head, rest = text.split(BEGIN, 1)
    DOC.write_text(head + BEGIN + "\n" + explain() + END + rest.split(END, 1)[1])
    schema = json.loads(SCHEMA.read_text())
    props = schema["$defs"]["ResponseDecision"]["properties"]
    for k, v in schema_enums().items():
        if k == "gate":
            props[k]["enum"] = [*v, None]
        else:
            props[k]["enum"] = v
    SCHEMA.write_text(json.dumps(schema, ensure_ascii=False, indent=2) + "\n")


def check() -> list[str]:
    """Drift between the table and what restates it; empty = in sync."""
    bad = []
    if doc_section(DOC.read_text()) != explain():
        bad.append(f"{DOC.name} §2 differs from the table (run: uv run python -m radar.decisions --write)")
    props = json.loads(SCHEMA.read_text())["$defs"]["ResponseDecision"]["properties"]
    for k, v in schema_enums().items():
        want = [*v, None] if k == "gate" else v
        if props[k]["enum"] != want:
            bad.append(f"schema ResponseDecision.{k} enum differs from the table")
    return bad


def main(argv: list[str]) -> int:
    if "--write" in argv:
        _write()
        return 0
    if "--check" in argv:
        bad = check()
        for b in bad:
            print(b, file=sys.stderr)
        return 1 if bad else 0
    print(explain(), end="")
    return 0


if __name__ == "__main__":   # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
