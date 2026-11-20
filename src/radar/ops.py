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
                        "detail": (s.get("degraded") or s.get("last_error") or "")[:200], "since": s.get("last_error_at"), "link": "/sources"})
    return out


def _over_budget(f: Facts) -> list[Item]:
    o = (f.get("ledger") or {}).get("over_budget")
    return [{"level": "warn", "title": "Continuum 日花费超过预算线（只标记，不停扫）",
             "detail": f"{o.get('date')}: ${o.get('continuum_usd')} > ${o.get('cap')}", "since": o.get("at"), "link": "/continuum"}] if o else []


def _notify(f: Facts) -> list[Item]:
    """The notify station's status row (radar.notify_station.STATUS_KEY). A subscription held back by the rollout gate
    is shown as such — never as ok."""
    st = f.get("notify") or {}
    out, top, at = [], st.get("status"), st.get("at")
    if top == "error":
        out.append({"level": "error", "title": "推送配置读取失败", "detail": ((st.get("error") or {}).get("message") or "")[:200],
                    "since": at, "link": None})
    elif top == "legacy_config":
        out.append({"level": "error", "title": "推送配置仍是旧的单频道格式，未推送",
                    "detail": "运行 scripts/set-notify.sh 写入订阅表（subscriptions）", "since": at, "link": None})
    elif top == "not_configured":
        out.append({"level": "info", "title": "推送未配置（没有订阅）", "detail": "运行 scripts/set-notify.sh 写入订阅表",
                    "since": at, "link": None})
    for bad in st.get("invalid") or []:   # error rule 5: code, message, actual, allowed
        out.append({"level": "error", "title": f"订阅配置无效：{bad.get('id') or '（无 id）'}",
                    "detail": f"{bad.get('error')}: {bad.get('message')}（实际 {bad.get('actual')!r}，允许 {bad.get('allowed')!r}）"[:300],
                    "since": at, "link": None})
    for b in st.get("blocked") or []:    # the send gate (notify.gate): a notice refused is said, never silent
        p = (b.get("problems") or [{}])[0]
        out.append({"level": "warn", "title": f"推送门禁拦下一条 {b.get('key')}（订阅 {b.get('subscription')}）",
                    "detail": f"{p.get('error')}: {p.get('message')}（实际 {p.get('actual')!r}，要求 {p.get('limit')!r}）"[:300],
                    "since": at, "link": f"#/events/{b.get('event_id')}" if b.get("event_id") else None})
    for sid, row in sorted((st.get("subscriptions") or {}).items()):
        if row.get("status") == "error":
            err = row.get("error") or {}
            out.append({"level": "error", "title": f"订阅 {sid} 推送失败（{row.get('channel')}）",
                        "detail": f"{err.get('error')}: {err.get('message')}"[:200], "since": row.get("at"), "link": None})
        elif row.get("status") == "gated_by_rollout":
            out.append({"level": "info", "title": f"订阅 {sid} 被灰度挡住（rollout=owner_only），本轮未推送",
                        "detail": "开放给所有订阅：secret 里 rollout 设为 all", "since": row.get("at"), "link": None})
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


def _mitigate(f: Facts) -> list[Item]:
    led = f.get("mitigate") or {}
    out = [{"level": "warn", "title": f"缓解站没查成：{e.get('what')}（下一轮重试）", "detail": str(e.get("error"))[:200],
            "since": led.get("run_at"), "link": "/mitigate"} for e in led.get("errors") or []]
    for tid, row in sorted((led.get("inspector") or {}).items()):
        sev = [f["severity"] for f in row.get("findings") or []]
        if "critical" in sev or "high" in sev:
            out.append({"level": "warn", "title": f"{tid} 的依赖有 {sev.count('critical')} 个 critical / {sev.count('high')} 个 high 漏洞（Inspector）",
                        "detail": "；".join(sorted({f"{f['purl']} → {f['fixed']}" for f in row["findings"]
                                                    if f["severity"] in ("critical", "high") and f.get("fixed")}))[:200],
                        "since": row.get("scanned_on"), "link": "/mitigate"})
    if (wait := (led.get("dns") or {}).get("waiting")):
        out.append({"level": "warn", "title": f"{len(wait)} 个新出现的域名没有进入已确认拦截的 DNS 名单",
                    "detail": "、".join(wait[:8])[:200] + " —— 核对后再确认一次：scripts/promote.py dns radar-ioc-domains --by <name>",
                    "since": led.get("run_at"), "link": "/mitigate"})
    for g in led.get("waf_grown") or []:
        out.append({"level": "warn", "title": f"已确认的 WAF 规则 {g['group']} 的计划扩大了：{g['beyond']} 仍只计数",
                    "detail": f"{g.get('by')} 于 {g.get('at')} 确认的是 {', '.join(g.get('approved') or []) or '整组'}；"
                              f"新增部分要拦截需再确认一次：scripts/promote.py waf {g['web_acl']} {g['group']} --by <name>",
                    "since": led.get("run_at"), "link": "/mitigate"})
    staged = [(eid, p) for eid, m in (led.get("events") or {}).items() for p in m.get("plans") or [] if p.get("state") == "staged"]
    if staged:
        out.append({"level": "info", "title": f"{len(staged)} 条 WAF 规则在 Count 观察期，等人确认后切 Block",
                    "detail": "确认没有误拦后运行 scripts/promote.py waf <web ACL> <rule>", "since": led.get("run_at"),
                    "link": f"/events/{staged[0][0]}"})
    return out


def _untriaged(f: Facts) -> list[Item]:
    """P0 events no operator has dispositioned yet (scripts/triage.py) — info: it is a queue, not a fault."""
    return [{"level": "info", "title": f"P0 未处置：{e.get('title', '')[:60]}", "detail": "scripts/triage.py <事件> triage|tracking|closed|false_positive",
             "since": None, "link": f"/events/{e['event_id']}"}
            for e in f.get("events") or [] if e.get("severity") == "P0" and not e.get("triage")]


def _dup_confirmed(f: Facts) -> list[Item]:
    """Item 6: pairs an operator labelled 'same' (scripts/dup_label.py) while both events are still published — info:
    a repair queue (scripts/recluster_web3.py --event A --event B), not a fault."""
    titles = {e["event_id"]: e.get("title", "") for e in f.get("events") or []}
    out = []
    for k, lab in sorted((f.get("dup_labels") or {}).items()):
        a, b = k.split("|")
        if lab.get("label") == "same" and a in titles and b in titles:
            out.append({"level": "info", "title": f"人工确认重复，待合并：{titles[a][:40]}",
                        "detail": f"scripts/recluster_web3.py --domain <域> --since <日期> --event {a} --event {b}",
                        "since": lab.get("at"), "link": f"/events/{a}"})
    return out


def _judge_merges(f: Facts, titles: dict[str, str]) -> list[Item]:
    """C4 v2 shadow: pairs the cluster judge would merge (grounded 'same' + ≥ 2 code evidences, radar.cluster_judge)
    while both events are still published and no operator has labelled the pair — info: nothing merged (unless
    Limits.CLUSTER_AUTO_MERGE); the operator confirms with scripts/dup_label.py, which queues the repair above.
    Filed under duplicate_confirmed's rule (same queue, one rule table entry) — facts["cluster_judge"] is the ledger
    publish loads (cluster_judge.load(store, "__cluster_judge__"))."""
    labels = f.get("dup_labels") or {}
    out = []
    for row in sorted((f.get("cluster_judge") or {}).values(), key=lambda r: (r.get("a", ""), r.get("b", ""))):
        a, b = row.get("a"), row.get("b")
        if not row.get("would_merge") or row.get("merged") or a not in titles or b not in titles \
                or "|".join(sorted((a, b))) in labels:
            continue
        ev = "；".join(e.get("detail", "") for e in row.get("evidence") or [])
        out.append({"level": "info", "title": f"聚类裁判建议合并：{titles[a][:40]} ↔ {titles[b][:40]}",
                    "detail": f"受害方「{row.get('victim', '')}」 · {ev} · {row.get('why', '')[:120]} — "
                              f"scripts/dup_label.py {a} {b} same --note \"聚类裁判 v2\"（不同则 different；影子模式，未合并）",
                    "since": row.get("at"), "link": f"/events/{a}"})
    return out


AUTO_MERGE_MIN_SAME = 30          # the bar Neo set 11-17 for auto-merge: ≥ 30 judged-same pairs a fact decided, 0 wrong
HUMAN_LOOK_AFTER_DAYS = 14         # a 'same' no fact decided in this long is shown for a person to look at once


def _judge_quality(f: Facts) -> list[Item]:
    """The shadow judge measured without labelling (Neo 11-19): the daily delayed-truth report (handlers._judge_truth)
    as one line — warn when a suggested merge was wrong or `same` precision is under 98 % — plus the few `same`
    verdicts no fact decided after HUMAN_LOOK_AFTER_DAYS and no one labelled (≤ 5), for a person to look at once."""
    rep = f.get("judge_truth") or {}
    out: list[Item] = []
    if rep:
        prec, said, wrong = rep.get("same_precision"), rep.get("same_said", 0), rep.get("would_merge_wrong", 0)
        bar = said >= AUTO_MERGE_MIN_SAME and wrong == 0 and (prec or 0) >= 0.98
        bad = wrong > 0 or (said >= 5 and prec is not None and prec < 0.98)
        out.append({"level": "warn" if bad else "info",
                    "title": f"聚类裁判准确率（延迟真值）：判同 {said} 对，准确率 {prec if prec is not None else '—'}",
                    "detail": f"事实判定 {rep.get('decided', 0)} 对 · 建议合并中错 {wrong} 对 · 漏判同 {rep.get('missed_same', 0)} 对 · "
                              f"自动合并门槛（判同 ≥ {AUTO_MERGE_MIN_SAME} 对、0 错、≥ 98 %）{'已达到' if bar else '未达到'}",
                    "since": rep.get("at"), "link": None})
    from radar import timeutil
    decided = {(r["a"], r["b"]) for r in rep.get("rows") or []}
    labels = f.get("dup_labels") or {}
    titles = {e["event_id"]: e.get("title", "") for e in f.get("events") or []}
    now = timeutil.parse(rep.get("at") or "")
    look = []
    for row in (f.get("cluster_judge") or {}).values():
        a, b, at = row.get("a"), row.get("b"), timeutil.parse(row.get("at") or "")
        if row.get("verdict") != "same" or row.get("by") != "model" or (a, b) in decided or a not in titles \
                or b not in titles or "|".join(sorted((a, b))) in labels or not at or not now \
                or (now - at).days < HUMAN_LOOK_AFTER_DAYS:
            continue
        look.append({"level": "info", "title": f"裁判判同、{HUMAN_LOOK_AFTER_DAYS} 天无事实可证，请看一眼：{titles[a][:36]} ↔ {titles[b][:36]}",
                     "detail": f"scripts/dup_label.py {a} {b} same|different", "since": row.get("at"), "link": f"/events/{a}"})
    return out + sorted(look, key=lambda i: i["since"] or "")[:5]


TOKEN_WARN_DAYS = 14               # the GHSA lookup's GitHub token: warn this long before it expires


def _ghsa_alias(f: Facts) -> list[Item]:
    """R12's GHSA → CVE lookup: not configured / failing while GHSA-only events wait is a warn; the GitHub token's own
    expiry (read from GitHub's answer header) is a warn TOKEN_WARN_DAYS before."""
    st = f.get("ghsa_alias") or {}
    out: list[Item] = []
    if st.get("status") in ("not_configured", "error") and st.get("pending"):
        out.append({"level": "warn", "title": f"GHSA → CVE 查询未工作（{st['status']}），{st['pending']} 个 GHSA 待查",
                    "detail": "scripts/set-ghsa-token.sh（读 ~/.env 的 GITHUB_ADVISORY_TOKEN）" if st["status"] == "not_configured"
                              else str(st.get("error", ""))[:160], "since": st.get("at"), "link": None})
    from radar import timeutil
    exp, now = timeutil.parse(str(st.get("token_expires") or "")[:19].replace(" ", "T") + "Z"), timeutil.parse(st.get("at") or "")
    if exp and now and (exp - now).days < TOKEN_WARN_DAYS:
        out.append({"level": "warn", "title": f"GHSA 查询用的 GitHub token 将于 {str(st['token_expires'])[:10]} 到期",
                    "detail": "在 GitHub 重新生成（Public repositories 只读、无权限），写入 ~/.env 后运行 scripts/set-ghsa-token.sh",
                    "since": st.get("at"), "link": None})
    return out


def _splits(f: Facts) -> list[Item]:
    """One story shown as two events (pipeline.split_candidates) — warn: the page under-counts the older event and the
    newer one duplicates it on the wall until the repair runs."""
    return [{"level": "warn", "title": f"同一事件被拆成两个：{s['newer_title'][:40]}",
             "detail": f"并入 {s['older_title'][:40]} — scripts/recluster_web3.py --domain {s['domain']} --since <日期> "
                       f"--event {s['older']} --event {s['newer']}（先 dry run）",
             "since": None, "link": f"/events/{s['newer']}"} for s in f.get("splits") or []]


def _late(f: Facts) -> list[Item]:
    """A critical CVE the radar first saw days after its CVE record was published (publish._late_detections) — info:
    a source-coverage gap to review (which feed would have carried it, e.g. the CNA's own list), not a fault.
    Live 2026-11-02: CVE-2026-98432 (Linux CNA, 9.8) published 10-15, first seen 10-29 via The Hacker News."""
    return [{"level": "info", "title": f"首篇报道晚于 CVE 公开 {d['lag_days']} 天：{d['title'][:40]}",
             "detail": f"{d['cve']} · CVSS {d['cvss']} · CNA {d['assigner'] or '?'} 于 {d['published'][:10]} 公开 · "
                       f"首报 {d['first_seen'][:10]}（{d['first_source']}）— 核对哪个数据源本可更早带来它",
             "since": d["first_seen"], "link": f"/events/{d['event_id']}"} for d in f.get("late") or []]


def _title_proposals(f: Facts) -> list[Item]:
    """Shadow-mode root-cause titles that passed every code gate (radar.retitle_judge) — info: nothing changed on the
    page; an operator adopts one with scripts/retitle.py (or ignores it)."""
    titles = {e["event_id"]: e.get("title", "") for e in f.get("events") or []}
    out = []
    from radar.retitle_judge import STATS, adoption_line
    props = f.get("title_proposals") or {}
    rate = adoption_line(props.get(STATS))
    for eid, r in sorted(props.items()):
        if eid != STATS and r.get("verdict") == "propose" and eid in titles and titles[eid] == r.get("current"):
            out.append({"level": "info", "title": f"标题建议（影子，未生效）：{r['title'][:70]}",
                        "detail": f"原：{titles[eid][:60]} · 依据「{r.get('quote', '')[:120]}」 — "
                                  f"scripts/retitle.py {eid} \"{r['title']}\" --source {r.get('source') or '<url>'}"
                                  f" · {rate}",
                        "since": r.get("at"), "link": f"/events/{eid}"})
    return out


def _slow(f: Facts) -> list[Item]:
    """A station whose slowest recent run used ≥ 60 % of its Lambda timeout (radar.stationtime) — warn: there is still
    headroom, which is the point (live 2026-11-02: publish crept 89 s → 256 s for two days, then failed at 300 s)."""
    return [{"level": "warn", "title": f"{s['station']} 站点接近超时：最慢 {s['worst_s']:.0f} s / 上限 {s['timeout_s']} s",
             "detail": f"最近 {s['share']:.0%} 的超时额度 · 中位 {s['median_s']:.0f} s — 先查它慢在哪一步（复杂度随数据增长？）",
             "since": s["at"], "link": "/ops"} for s in f.get("slow_stations") or []]


def _enrich(f: Facts) -> list[Item]:
    """EPSS / CVE-record lookups that failed in the last publish run — warn: pages show '—' where a number belongs
    (live 2026-11-02 the EPSS column went blank on every page and was found by eye). A lookup backlog is info."""
    e = f.get("enrich") or {}
    out = []
    if e.get("epss_failed"):
        out.append({"level": "warn", "title": f"EPSS 查询失败 {e['epss_failed']} 批（FIRST API）",
                    "detail": f"{e.get('epss_error', '')} — 事件页 EPSS 显示 —；下轮自动重试", "since": e.get("at"), "link": "/ops"})
    if e.get("cve_meta_failed"):
        out.append({"level": "warn", "title": f"CVE 记录查询失败 {e['cve_meta_failed']} 个（cveawg.mitre.org）",
                    "detail": f"{e.get('cve_meta_error', '')} — 公开时间 / CVSS 暂缺；下轮自动重试", "since": e.get("at"), "link": "/ops"})
    if e.get("cve_meta_backlog"):
        out.append({"level": "info", "title": f"CVE 记录待补 {e['cve_meta_backlog']} 个",
                    "detail": "每轮发布按剩余时间补齐（Limits.CVE_META_*）", "since": e.get("at"), "link": "/ops"})
    return out


def _deferred(f: Facts) -> list[Item]:
    """Event pages the publish station had no time for (they go out next run, first) — warn: if it persists, a page
    is too slow for the station (see station_slow)."""
    p = f.get("pending") or {}
    n = len(p.get("ids") or [])
    return [{"level": "warn", "title": f"{n} 个事件页因发布超时预算顺延到下一轮",
             "detail": "下轮优先发布；持续出现说明某页过慢（看 station_slow）", "since": p.get("at"), "link": "/ops"}] if n else []


def _amount_outliers(f: Facts) -> list[Item]:
    """A loss figure set aside as implausible (pipeline._mark_outliers) — warn: the headline is right without it, but
    someone should see what a source claimed (live 2026-11-04: $235B — the bank's balance sheet)."""
    return [{"level": "warn", "title": f"离群金额未计入损失：{o['title'][:50]}",
             "detail": "离群值 " + " · ".join(f"${v:,.0f}" for v in o["values"]) + " —— 核对原文：资产规模 / 价格 / 买入额被当成了损失？",
             "since": None, "link": f"/events/{o['event_id']}"} for o in f.get("amount_outliers") or []]


def _amount_shared(f: Facts) -> list[Item]:
    """Several published web3 events with the same specific loss figure — warn: one theft counted several times."""
    out = []
    for g in f.get("amount_shared") or []:
        ids = " ".join(f"--event {e['event_id']}" for e in g["events"])
        out.append({"level": "warn", "title": f"{len(g['events'])} 个事件同报损失 ${g['amount']:,.0f}：{g['events'][0]['title'][:40]}",
                    "detail": f"疑为同一起事件被拆开 —— scripts/recluster_web3.py --since <日期> {ids}（先 dry run）",
                    "since": None, "link": f"/events/{g['events'][0]['event_id']}"})
    return out


def _latency(f: Facts) -> list[Item]:
    """Published → held over the last 24 hours (radar.latency). Always stated (info); warn when the median is past
    LATENCY_WARN_P50_MIN on enough samples — the radar is behind its sources."""
    from radar.limits import Limits
    push = f.get("push_latency")
    pushed = [{"level": "info", "title": f"时效：成为 P0 到推送，中位 {push['p50']} 分钟，90 分位 {push['p90']} 分钟（近 7 天 {push['n']} 次推送）",
               "detail": "从事件升为现在这一级（首报或升级所依据的最新报道的发布时间）到第一次推给一个订阅；超过 48 小时的不计", "since": None,
               "link": "/ops"}] if push else []
    s = f.get("latency")
    if not s:
        return pushed
    slow = s["p50"] > Limits.LATENCY_WARN_P50_MIN and s["n"] >= Limits.LATENCY_MIN_SAMPLES
    tiers = " · ".join(f"{t} {v['p50']}/{v['p90']}（{v['n']} 条）" for t, v in (s.get("tiers") or {}).items())
    return [{"level": "warn" if slow else "info",
             "title": f"时效：报道发布到雷达持有，中位 {s['p50']} 分钟，90 分位 {s['p90']} 分钟（近 24 小时 {s['n']} 条）",
             "detail": f"各级 中位/90 分位：{tiers}" + (f" —— 中位超过界限 {Limits.LATENCY_WARN_P50_MIN} 分钟" if slow else ""),
             "since": None, "link": "/sources"}, *pushed]


def _stalled(f: Facts) -> list[Item]:
    """Sources not being collected (overdue — error) or gone quiet (silent — warn), from publish.stalled_sources. One
    item per kind: when the cycle itself is down every source is overdue at once."""
    out = []
    rows = f.get("stalled_sources") or []
    late = sorted((r for r in rows if r["kind"] == "overdue"), key=lambda r: -r["minutes"])
    if late:
        out.append({"level": "error", "title": f"{len(late)} 个信源超过 3 个节奏没有被采集",
                    "detail": "；".join(f"{r['name']} {r['minutes']} 分钟（界限 {r['limit_min']}）" for r in late[:8])[:300],
                    "since": None, "link": "/sources"})
    quiet = [r for r in rows if r["kind"] == "silent"]
    if quiet:
        out.append({"level": "warn", "title": f"{len(quiet)} 个一向有产出的信源连续 {quiet[0]['days']} 天没有新内容",
                    "detail": "；".join(f"{r['name']}（平时每天 {r['usual_per_day']} 条）" for r in quiet[:8])[:300] + " —— 源站改版、换地址，或被拦",
                    "since": None, "link": "/sources"})
    return out


def _silent(f: Facts) -> list[Item]:
    """A station that raised on every recent run, or has not run at all (radar.stationtime.silent) — error: the cycle
    catches Analyze / Respond / Mitigate / Notify failures and still succeeds, so nothing else reports it."""
    out = []
    for s in f.get("silent_stations") or []:
        if s["kind"] == "failing":
            out.append({"level": "error", "title": f"{s['station']} 站点连续 {s['runs']} 轮失败（周期仍算成功）",
                        "detail": "看该函数的 CloudWatch 日志里的异常；本站的产出停在上一次成功时", "since": s["at"], "link": "/ops"})
        else:
            out.append({"level": "error", "title": f"{s['station']} 站点 {s['minutes']} 分钟没有运行记录（界限 {s['limit_min']} 分钟）",
                        "detail": "被超时杀掉、没被调用，或周期整体停了 —— 看状态机最近的执行", "since": s["at"], "link": "/ops"})
    return out


_ANOMALY = {"absorbed_other_domain": "事件吸收了另一类事件", "absorbed_large_event": "事件吸收了一个已成形的事件",
            "items_jump": "事件的报道数一轮内激增", "cves_jump": "事件的 CVE 数一轮内激增",
            "loss_changed": "事件的头条损失一轮内变了一个数量级"}


def _anomalies(f: Facts) -> list[Item]:
    """An event that changed shape within one cycle (radar.anomaly) — error when it absorbed another story or its loss
    moved ×10: the page may be showing two stories as one (live 2026-11-12, eleven hours unnoticed)."""
    return [{"level": a["level"], "title": f"{_ANOMALY.get(a['kind'], a['kind'])}：{a['title'][:50]}",
             "detail": f"{a['actual']}（界限 {a['limit']}）· {a['message']} —— 先看事件页的时间线，再 "
                       f"scripts/recluster_web3.py --domain <域> --since <日期> --event {a['event_id']}（dry run）",
             "since": a["at"], "link": f"/events/{a['event_id']}"} for a in f.get("anomalies") or []]


def _raw_bad(f: Facts) -> list[Item]:
    """Raw lines Process could not read in the last day: skipped, the rest of their batch processed (handlers.process)."""
    rows = f.get("raw_bad") or []
    if not rows:
        return []
    lines = sum(r["lines"] for r in rows)
    return [{"level": "warn", "title": f"{lines} 条原始记录读不了，已跳过（{len(rows)} 个批次）",
             "detail": "其余记录照常处理。首个：" + rows[0]["key"] + f" 第 {rows[0]['first_line']} 行 —— {rows[0]['error']}",
             "since": rows[0]["at"], "link": "/ops"}]


def _daily_caps(f: Facts) -> list[Item]:
    """A paid call kind past its daily cap today (radar.llm.daily_cap): the calls after it were not made."""
    from radar import llm
    out = []
    for kind, n in sorted((f.get("spend") or {}).items()):
        if kind.startswith("bedrock:") and n > (cap := llm.daily_cap(kind.split(":", 1)[1])):
            out.append({"level": "warn", "title": f"今天 Bedrock {kind.split(':', 1)[1]} 已到日上限 {cap} 次",
                        "detail": f"之后的 {n - cap} 次没有调用（分析卡 / 判定照常降级为 failed，明天恢复）。"
                                  "上限在 Limits.BEDROCK_CALLS_PER_DAY_*。",
                        "since": None, "link": "/ops"})
    return out


def _row_sizes(f: Facts) -> list[Item]:
    """Table rows written in the last day above Limits.ROW_WARN_BYTES (radar.dynamo: above ROW_MAX_BYTES the write fails)."""
    from radar.limits import Limits
    rows = f.get("row_sizes") or []
    if not rows:
        return []
    top = "；".join(f"{r['key']} {r['bytes'] // 1000} KB（{r['station']}）" for r in rows[:3])
    return [{"level": "warn", "title": f"{len(rows)} 行接近 DynamoDB 400 KB 上限",
             "detail": f"最大的：{top}。超过 {Limits.ROW_MAX_BYTES // 1000} KB 写入会被拒绝，该工位那一轮失败。",
             "since": min(r["at"] for r in rows), "link": "/ops"}]


RULES: dict[str, Callable[[Facts], list[Item]]] = {
    "event_anomaly": _anomalies, "station_silent": _silent, "source_stalled": _stalled, "collect_latency": _latency,
    "source_unhealthy": _sources, "over_budget": _over_budget, "notify": _notify, "repo_channel_error": _repo_channels,
    "cost_unavailable": _cost, "chain_rpc_error": _chain, "digest_not_ok": _digest, "mitigate": _mitigate,
    "p0_untriaged": _untriaged, "duplicate_confirmed": _dup_confirmed, "event_split": _splits,
    # cluster judge v2 (shadow): a grounded "same" with enough code evidence — its own code, not duplicate_confirmed's
    "cluster_merge_suggested": lambda f: _judge_merges(f, {e["event_id"]: e.get("title", "") for e in f.get("events") or []}),
    "late_detection": _late, "title_proposal": _title_proposals, "judge_quality": _judge_quality, "ghsa_alias": _ghsa_alias,
    "station_slow": _slow, "enrich_degraded": _enrich, "publish_deferred": _deferred,
    "amount_outlier": _amount_outliers, "amount_shared": _amount_shared, "raw_lines_skipped": _raw_bad,
    "row_near_limit": _row_sizes, "daily_cap_reached": _daily_caps,
}


def attention(f: Facts) -> list[Item]:
    """All rules, errors first; each item carries the rule code that produced it."""
    out = [{"code": code, **it} for code, rule in RULES.items() for it in rule(f)]
    return sorted(out, key=lambda it: (LEVELS.index(it["level"]), it["code"], it["title"]))
