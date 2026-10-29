"""Integration coverage registry: every AWS Continuum / AWS Security Agent capability on the radar's trigger
chain, and how its status is *computed* from the respond ledger (live = observed working in production,
wired = code path exists but no live evidence yet). "100 %" means every applicable capability is live;
not_applicable / needs_user rows say why, and do not count in the denominator.

Registry, not prose (context-budget §2): the UI page and docs read this, nobody hand-maintains a table."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Capability:
    key: str
    capability: str
    service: str            # security_agent | continuum | radar
    detail: str
    counter: str | None     # ledger counter that proves it live (>0); None ⇒ fixed status below
    fixed: str | None = None  # not_applicable | needs_user


CAPABILITIES: tuple[Capability, ...] = (
    Capability("eligibility", "事件 → 代码侧响应资格（产品登记表）", "radar", "只对 P0 或已利用/有 PoC 的 P1，且产品可在代码中定位", "events_considered"),
    Capability("inventory", "目标代码清单（确定性定位受影响版本）", "radar", "Dockerfile / CI 镜像 / composer / Lambda runtime 等逐行定位", "inventory_scans"),
    Capability("requirement", "雷达规则 → Security Agent requirement pack", "security_agent", "BatchCreate/UpdateSecurityRequirements，按名称幂等", "requirements_synced"),
    Capability("code_review", "代码评审（含雷达规则）", "security_agent", "CreateCodeReview + StartCodeReviewJob，P0 且目标用到该产品才发起", "code_reviews_started"),
    Capability("review_results", "评审结果回流（命中雷达规则的 finding）", "security_agent", "BatchGetFindings，按 [Requirement: radar-…] 判定命中", "code_reviews_completed"),
    Capability("remediation", "自动修复 diff 当场落盘", "security_agent", "codeRemediationStrategy=AUTOMATIC；预签名链接 180 秒内抓取", "sa_patches"),
    Capability("environment", "Continuum S3 集成 + 环境（每个仓库一个 zip）", "continuum", "us-east-1（东京无端点）；按名称对账，幂等；每环境 1 个 S3 源、≤10 个仓库", "environment_ensured"),
    Capability("context", "威胁情报 → Continuum 知识文档", "continuum", "事件与已校验的分析卡写入 context/", "contexts_written"),
    Capability("code_finding", "雷达 finding → Continuum 验证", "continuum", "CreateCodeFinding：OCSF 2002 + osint 证据，精确到文件行", "findings_submitted"),
    Capability("code_scan", "雷达触发环境扫描", "continuum", "CreateCodeScan，6 小时去抖", "scans_requested"),
    Capability("finding_verdict", "Continuum 验证结论回流", "continuum", "GetCodeFinding.validation.verdict / discardReason", "finding_verdicts"),
    Capability("issues", "Issue / 可利用性证据 / 补丁回流", "continuum", "GetCodeIssue + VALIDATION_EVIDENCE + PATCH artifacts", "issues_seen"),
    Capability("github", "补丁以 GitHub PR 交付", "continuum",
               "GitHub 源环境（App 授权一次）：雷达 finding 提交进去，Continuum 验证后原生开 PR，"
               "事件页回链；人只做合并",
               "github_prs", "needs_user"),
    Capability("gitlab", "补丁以 GitLab MR 交付", "continuum",
               "GitLab 源环境（项目 access token 建一次 integration，token 只进 Continuum）：同一条链，补丁以 MR 交付",
               "gitlab_mrs", "needs_user"),
    Capability("collector", "基础设施上下文 Collector", "continuum", "雷达运行在 ap-northeast-1，Collector 必须与环境同在 us-east-1，采不到雷达的资源", None, "not_applicable"),
    Capability("pentest", "渗透测试验证可利用性", "security_agent", "目标是代码仓库而非对外站点；雷达 UI 本身在 Basic Auth 之后", None, "not_applicable"),
)


def rows(ledger: dict[str, Any]) -> list[dict[str, Any]]:
    counters = ledger.get("counters") or {}
    out = []
    for c in CAPABILITIES:
        if c.fixed and c.counter:
            # needs a human step first: needs_user until the integration exists, then measured like any other
            n = int(counters.get(c.counter, 0))
            ready = bool((ledger.get("env") or {}).get(f"{c.key}_environment_id"))
            status, evidence = ("live", f"{c.counter}={n}") if n > 0 else (("wired", None) if ready else (c.fixed, None))
            if status == c.fixed and ledger.get(f"{c.key}_error"):  # human step done, blocked downstream — say so
                evidence = f"blocked: {ledger[f'{c.key}_error'][:120]}"
        elif c.fixed:
            status, evidence = c.fixed, None
        else:
            n = int(counters.get(c.counter or "", 0))
            status, evidence = ("live", f"{c.counter}={n}") if n > 0 else ("wired", None)
        out.append({"capability": c.capability, "service": c.service, "status": status, "detail": c.detail, "evidence": evidence})
    return out


def percent(rs: list[dict[str, Any]]) -> float:
    applicable = [r for r in rs if r["status"] in ("live", "wired")]
    return round(100.0 * sum(r["status"] == "live" for r in applicable) / len(applicable), 1) if applicable else 0.0
