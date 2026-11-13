"""Attack stages — the one stage enum (04-reconstruction W1). Cloud kill chain + on-chain + response, in attack order;
each stage carries its Chinese label, the rule that detects it in a report title, and the AWS controls that would have
blocked / detected / limited it (data, not prose). Everything else is generated from STAGES:

  schemas/site-data.schema.json  $defs.AttackStage (canonical ids + the legacy aliases still accepted)
  ui/src/generated/stages.ts     the UI's stage table (labels, order, segment, expected, controls)

  uv run python scripts/gen_stages.py           # rewrite both
  uv run python scripts/gen_stages.py --check   # exit 1 if either is stale (also tests/test_stages.py)

Before this module the M4 phase enum had four hand copies (signals.PHASES, the schema enum, attackFlow.ts PHASE_ORDER +
PHASE_LABEL, and its CORE subset) with no test pinning them together (04-reconstruction B7); the cloud kill chain did
not exist, so 「Hackers used leaked AWS access keys to drain hot wallet」 read as the drain (§0.3).

Classification stays one stage per report, decided on its title, by PRIORITY (not attack order): an exchange's own
statement is a statement even if it says "hack"; a report naming *how* the attacker got in (leaked keys, a compromised
laptop) is evidence of that stage rather than of the theft, which the other reports and the chain rows already carry.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from radar.signals import _A, _CLAUSE, _Z

Segment = Literal["cloud", "chain", "response", "context"]
Effect = Literal["block", "detect", "limit", "investigate"]

EFFECT_ZH: dict[str, str] = {"block": "阻断", "detect": "检测", "limit": "限制爆炸半径", "investigate": "调查"}


class Cue(Protocol):
    def search(self, text: str) -> Any: ...


@dataclass(frozen=True)
class Control:
    """An AWS control that would have stopped (block), seen (detect) or bounded (limit) the stage; `how` says what of it."""
    service: str
    effect: Effect
    how: str


@dataclass(frozen=True)
class Stage:
    id: str
    order: int
    zh: str
    en: str
    segment: Segment
    mitre: str | None          # ATT&CK tactic for orientation; None for on-chain / response stages it has no tactic for
    cue: Cue | None            # title rule; None = never decided from a title (only from chain rows, or never)
    controls: tuple[Control, ...] = ()
    # domains whose attack flow lists this stage under 「尚无证据的阶段」 when nothing evidences it (the old UI CORE list):
    # a cloud stage is not expected of a flash-loan exploit, so it is never listed as missing
    expected: tuple[str, ...] = ()
    in_flow: bool = True       # drawn as a step of the attack flow ("other" is not)


# ---- title cues (moved from signals.phase; M4 D4 + P0 fixes B2 / B3) ---------------------------------------------------
_ATTR = re.compile(_A + r"(?:North Korea\w*|DPRK|Lazarus|TraderTraitor|attribut\w*|same (?:attacker|hacker|group))" + _Z
                   + r"|朝鲜|同一攻击者|同一批|同一黑客|幕后", re.IGNORECASE)
_RECOVER = re.compile(_A + r"(?:returned|bounty|recovered|refund\w*)" + _Z + r"|追回|返还|归还|赏金", re.IGNORECASE)
# the freeze stage has its own cues: the amount regex signals._FROZEN also holds recovery words (a recovered amount is
# not a loss), so reusing it judged 「Exchange recovered $10M of stolen assets」 a freeze (04-reconstruction B2)
_FREEZE = re.compile(_A + r"(?:froze|frozen|freez\w*|blacklist\w*|seiz(?:ed|ure))" + _Z + r"|冻结|没收", re.IGNORECASE)
_DISCLOSURE = re.compile(r"^(?:币安|Binance|何一|CZ|Tether|Circle|官方)\s*[：:]"
                         + "|" + _A + r"(?:statement|investigat\w*|confirm(?:s|ed)?|SAFU|cover all|post-?mortem"
                         + r"|withdrawals? (?:are |were )?(?:paused|suspended|resumed|halted))" + _Z
                         + r"|公告|声明|回应|暂停(?:充提|提币|充值)|恢复(?:充提|提币)|全额赔付|初步调查", re.IGNORECASE)
# Attack preparation. A rehearsal or funding is the attacker's by itself ("Exploit contract funded by Tornado Cash"); the
# generic words (prepares / 提前 / 准备 …) only when an attacker comes first in the same clause — the attacker is the one
# preparing — and the clause is not about the victim making good. 「Protocol prepares compensation plan for users」,
# 「投资者转向加密衍生品提前布局」 and 「遭黑客攻击后，交易所准备重新开放充值」 were the attack chain's first step
# (04-reconstruction B3; the last from review of p0/signals).
_PREP_ALONE = re.compile(_A + r"(?:rehears\w*|funded (?:by|via|through))" + _Z + r"|演练|彩排|资助", re.IGNORECASE)
_PREP_WORD = re.compile(_A + r"(?:in advance|prepar\w*)" + _Z + r"|提前|预先|准备", re.IGNORECASE)
_PREP_ATTACKER = re.compile(_A + r"(?:attackers?|hackers?|exploiters?|threat actors?)" + _Z + r"|攻击者|黑客", re.IGNORECASE)
_PREP_VICTIM = re.compile(_A + r"(?:compensat\w*|reimburs\w*)" + _Z + r"|赔付|补偿", re.IGNORECASE)


def _attacker_prepares(clause: str) -> bool:
    who = _PREP_ATTACKER.search(clause)
    return bool(who and _PREP_WORD.search(clause, who.end()) and not _PREP_VICTIM.search(clause))


class _Prep:
    """The prep rule; has .search like the regex cues."""

    @staticmethod
    def search(t: str) -> bool:
        return bool(_PREP_ALONE.search(t) or any(_attacker_prepares(c) for c in _CLAUSE.split(t)))


# Cloud kill chain cues (new). Narrow on purpose: an advisory saying "RCE" or "scanning" is not an incident's stage, so
# each cue names the attacker's act in an incident ("leaked AWS access keys", "laptop compromised", "moved laterally").
_Q = r"(?:(?:aws|api|access|cloud|iam|secret)[- ])+"          # qualifiers that make a "key" a cloud credential
_CREDENTIAL = re.compile(_A + r"(?:(?:leaked|stolen|exposed|phished|compromised|hardcoded) " + _Q + r"(?:credentials?|keys?|tokens?)"
                         + r"|" + _Q + r"(?:credentials?|keys?|tokens?) (?:were |was )?(?:leaked|stolen|exposed|compromised)"
                         + r"|(?:stolen|leaked) (?:credentials?|session (?:cookies?|tokens?))"
                         + r"|credential (?:theft|harvest\w*|stuffing|leak\w*)|AKIA[0-9A-Z]{16})" + _Z
                         + r"|凭证(?:泄露|被盗|遭窃)|(?:访问|API|云)密钥(?:泄露|被盗)|AK/?SK", re.IGNORECASE)
_KEY = re.compile(_A + r"(?:private[- ]keys?|seed phrases?|mnemonics?|keys? (?:were |was )?compromis\w*"
                  + r"|compromis\w* (?:signing |signer |private |multi-?sig )?keys?|signing (?:service|infrastructure|server|keys?)"
                  + r"|multi-?sig (?:signers?|owners?) compromis\w*|EIP-?7702)" + _Z
                  + r"|私钥|助记词|签名(?:服务|密钥|机|服务器)|多签(?:被|遭)", re.IGNORECASE)
# Privilege escalation and lateral movement are vulnerability classes too: an advisory title says "local privilege
# escalation" / "提权漏洞", and "pivots to" is also a business word. Only the completed act counts — "escalated", "gained
# admin access", "moved laterally". The bare noun read the CISA CSAF advisory「Canimaan Software ClamXAV local privilege
# escalation」(tests/fixtures/snapshots/2026-11-06) as an incident stage, and with any "exploited" report beside it a
# plain CVE event drew a 权限提升 → 资产转出 flow (review of p1/stages).
_PRIVESC = re.compile(_A + r"(?:escalated (?:its |their |his |her )?(?:own )?privileges?"
                      + r"|(?:gained|obtained) (?:admin\w*|root|elevated) (?:access|rights|privileges?))" + _Z
                      + r"|(?:成功|已)提权|提权后|提升了(?:\S{0,4})?权限|获取了管理员权限", re.IGNORECASE)
_LATERAL = re.compile(_A + r"(?:lateral movement|moved laterally|laterally moved)" + _Z + r"|横向(?:移动|渗透)(?!漏洞)",
                      re.IGNORECASE)
_PERSIST = re.compile(_A + r"(?:backdoor\w*|web ?shells?|persistence|rogue (?:admin|account|iam user)s?)" + _Z
                      + r"|后门|持久化", re.IGNORECASE)
_EXEC = re.compile(_A + r"(?:(?:executed|ran) (?:a )?malicious (?:scripts?|payloads?|code|binar(?:y|ies))"
                   + r"|malicious (?:scripts?|payloads?|code) (?:was |were )?(?:executed|run))" + _Z
                   + r"|执行(?:了)?恶意(?:代码|脚本|命令)", re.IGNORECASE)
# a phished *employee* / spear-phishing is how the attacker got in; a retail wallet user "lost $50K to phishing" is the
# theft itself and stays the transfer (red team of P1b: bare phish\w* here moved those reports out of the drain and listed
# 资产转出 as having no evidence)
_INITIAL = re.compile(_A + r"(?:spear[- ]?phish\w*|phish\w* (?:emails? |campaigns? )?(?:targeting |against )?(?:[a-z]+ )?(?:employees?|staff|engineers?|developers?|devops)"
                      + r"|phished (?:employees?|staff|engineers?|developers?)|social[- ]engineer\w*|fake (?:job|interview|recruiter)s?"
                      + r"|(?:laptop|workstation|device|computer|endpoint)s? (?:was |were |had been )?(?:compromised|hacked|infected|breached)"
                      + r"|supply[- ]chain (?:attack|compromise)|malicious (?:npm |pypi )?(?:package|dependency|update)s?|initial access)" + _Z
                      + r"|钓鱼邮件|社工|社会工程|(?:电脑|设备|终端|笔记本)(?:被|遭)(?:入侵|攻破|感染)|供应链(?:攻击|投毒)|恶意(?:包|依赖|更新)",
                      re.IGNORECASE)
_RECON = re.compile(_A + r"(?:reconnaissance|port[- ]scan\w*|mass[- ]scann\w*|scanning for|probing for)" + _Z
                    + r"|侦察|踩点|大规模扫描", re.IGNORECASE)
_LAUNDER = re.compile(_A + r"(?:sold|sell\w*|dump\w*|swap\w*|bridge\w*|launder\w*|borrow\w*|moved (?:through|to|into)"
                      + r"|peel chain|consolidat\w*|mixer|Tornado Cash deposits?)" + _Z
                      + r"|抛售|售出|卖出|买入|兑换|换成|跨链|混币|洗钱|借出|转入|转移至|归集", re.IGNORECASE)
_TRANSFER = re.compile(_A + r"(?:drain\w*|stolen|steal\w*|hack(?:ed)?|outflows?|swept|sweep\w*|exploit\w*|compromis\w*"
                       + r"|hot wallets?|lost|poison\w*|phish\w*|drainer)" + _Z
                       + r"|转出|转走|被盗|盗走|流出|清扫|遭攻击|攻击|热钱包|遭窃|失窃|钓鱼", re.IGNORECASE)
_IMPACT = re.compile(_A + r"(?:price|liquidat\w*|short(?:ed|s)?|exposure|unaffected|not affected|market)" + _Z
                     + r"|未受|影响|下跌|上涨|跌幅|涨幅|价格|爆仓|做空|敞口|市场", re.IGNORECASE)

_W3 = ("web3",)

STAGES: tuple[Stage, ...] = (
    Stage("recon", 10, "侦察", "Reconnaissance", "cloud", "TA0043", _RECON, (
        Control("AWS WAF Bot Control", "block", "托管规则组拦截扫描器 / 爬虫流量"),
        Control("AWS Shield Advanced", "limit", "探测与放大流量的 L3/L4/L7 防护"),
        Control("Amazon GuardDuty", "detect", "Recon:EC2/PortProbeUnprotectedPort 等侦察类发现"))),
    Stage("prep", 15, "资源准备", "Resource development", "chain", "TA0042", _Prep()),
    Stage("initial_access", 20, "初始入口", "Initial access", "cloud", "TA0001", _INITIAL, (
        Control("AWS WAF", "block", "公网入口只经 ALB / CloudFront + WAF，源站不直接暴露"),
        Control("AWS IAM Identity Center", "block", "员工登录走 SSO + MFA，钓到的密码登不进控制台"),
        Control("Amazon Inspector", "detect", "网络可达性与 EC2 / ECR / Lambda 漏洞"))),
    Stage("execution", 30, "执行", "Execution", "cloud", "TA0002", _EXEC, (
        Control("Amazon GuardDuty", "detect", "Runtime Monitoring（EKS / ECS / EC2）发现可疑进程"),
        Control("Amazon Inspector", "detect", "被执行的漏洞组件在扫描结果里"))),
    Stage("persistence", 40, "持久化", "Persistence", "cloud", "TA0003", _PERSIST, (
        Control("AWS Organizations SCP", "block", "拒绝在生产账户新建 IAM 用户 / 长期访问密钥"),
        Control("Amazon GuardDuty", "detect", "Persistence:IAMUser/AnomalousBehavior"),
        Control("AWS Config", "detect", "新 IAM 用户 / 访问密钥的配置规则"))),
    Stage("credential_access", 50, "凭证获取", "Credential access", "cloud", "TA0006", _CREDENTIAL, (
        Control("IAM Roles for Service Accounts (IRSA) / EKS Pod Identity", "block", "工作负载用短期凭证，没有可泄露的长期 AK/SK"),
        Control("AWS Secrets Manager", "limit", "密钥集中存放并轮换，泄露后可立即作废"),
        Control("Amazon GuardDuty", "detect", "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"))),
    Stage("privilege_escalation", 60, "权限提升", "Privilege escalation", "cloud", "TA0004", _PRIVESC, (
        Control("IAM permissions boundary / SCP", "block", "角色权限设上限，拿到的身份提不了权"),
        Control("IAM Access Analyzer", "detect", "未使用权限与对外访问"),
        Control("AWS Security Hub", "detect", "CSPM 中的 IAM 控件"))),
    Stage("lateral_movement", 70, "横向移动", "Lateral movement", "cloud", "TA0008", _LATERAL, (
        Control("Amazon VPC 安全组 / 分段", "limit", "按安全组引用放行，服务间不默认互通"),
        Control("Amazon VPC Lattice", "block", "服务间调用需 IAM 鉴权策略"),
        Control("Amazon GuardDuty", "detect", "EKS / S3 Protection 发现异常访问"))),
    Stage("key_access", 80, "密钥接触", "Signing-key access", "chain", None, _KEY, (
        Control("AWS KMS / AWS CloudHSM", "block", "签名私钥不出 HSM，主机上没有明文私钥可偷"),
        Control("AWS Nitro Enclaves", "limit", "签名服务在隔离环境内按交易策略签名"))),
    Stage("asset_transfer", 90, "资产转出", "Asset transfer", "chain", "TA0040", _TRANSFER, (
        Control("AWS Nitro Enclaves", "limit", "签名策略中的限额 / 延时 / 白名单地址"),
        Control("AWS CloudTrail + Amazon EventBridge", "detect", "kms:Sign 调用异常告警"),
    ), _W3),
    Stage("laundering", 100, "洗钱", "Laundering", "chain", None, _LAUNDER, expected=_W3),
    Stage("freeze", 110, "冻结", "Freeze", "response", None, _FREEZE, expected=_W3),
    Stage("disclosure", 120, "官方披露", "Disclosure", "response", None, _DISCLOSURE, (
        Control("AWS Security Incident Response", "investigate", "事件响应协同与取证"),), _W3),
    Stage("attribution", 130, "归因", "Attribution", "response", None, _ATTR, (
        Control("Amazon Detective", "investigate", "按身份 / 资源关联 CloudTrail 与 VPC Flow Logs 还原行为"),), _W3),
    Stage("recovery", 140, "追回", "Recovery", "response", None, _RECOVER, expected=_W3),
    Stage("impact", 150, "外溢影响", "Impact", "context", None, _IMPACT),
    Stage("other", 999, "其他", "Other", "context", None, None, in_flow=False),
)
BY_ID: dict[str, Stage] = {s.id: s for s in STAGES}
IDS: tuple[str, ...] = tuple(s.id for s in STAGES)

# Title classification order (first match wins). Response stages first (a statement saying "hack" is a statement), then
# preparation, then the cloud / key stages that name how the attacker got in, then laundering before the transfer
# (a report about swapping stolen tokens is laundering, not the theft itself), impact last.
PRIORITY: tuple[str, ...] = ("attribution", "recovery", "freeze", "disclosure", "prep", "credential_access", "key_access",
                             "privilege_escalation", "lateral_movement", "persistence", "execution", "initial_access",
                             "recon", "laundering", "asset_transfer", "impact")

# Legacy M4 phase values → stage (renamed 2026-11-11). Event documents published before then still carry the old values
# and are read by the UI, so the schema keeps accepting them and the UI maps them on read (generated from this map).
# Collapse: drop the aliases once no published document older than the rename is served (PUBLISH_WINDOW_DAYS after the
# first deploy of this module) — the date is data, not a comment, so the schema description states it.
ALIASES: dict[str, str] = {"drain": "asset_transfer", "statement": "disclosure"}
ALIASES_COLLAPSE_AFTER = "2027-01-15"


def canonical(value: str | None) -> str:
    """The stage of a stored / published value: aliases mapped, unknown → 'other'."""
    v = ALIASES.get(value or "", value or "other")
    return v if v in BY_ID else "other"


def before_transfer(stage: str) -> bool:
    """A stage of how the attacker got in (prep, the cloud kill chain, key access) — ordered before the transfer."""
    return BY_ID[stage].order < BY_ID["asset_transfer"].order


def of_title(title: str | None) -> str:
    """The stage of one report, decided on its title (one stage per report, by PRIORITY)."""
    t = title or ""
    return next((s for s in PRIORITY if BY_ID[s].cue.search(t)), "other")  # type: ignore[union-attr]


# ---- on-chain rows as stage evidence (04-reconstruction §5, B8) --------------------------------------------------------
# Every row here is confirmed by the chain itself (a log, a receipt, eth_getCode), so it evidences its stage as much as a
# report does — before this the flow listed 「尚无报道的阶段：冻结」 next to a table of issuer freezes.

# Which clock a kind's time is. "chain": the row's own block time — when it happened. "checked": when the radar looked —
# an EIP-7702 delegation is read with eth_getCode at check time and its history is not queried (onchain.NOT_QUERIED), so
# that time is *after* the incident and says nothing about when the key was used. Shown as the on-chain time, it put
# 「密钥接触 链上 10-30 00:00 · 1 笔」 hours after the 20:24 theft (review of p1/stages).
CLOCK: dict[str, str] = {"outflow": "chain", "freeze": "chain", "attack_tx": "chain", "delegation": "checked"}


def chain_evidence(onchain_doc: dict[str, Any] | None, victims: set[str],
                   attack_txs_doc: dict[str, Any] | None) -> list[dict[str, Any]]:
    """[{stage, kind, clock, count, first_at, first_tx}] in stage order: what the published on-chain sections confirm.

    outflow from a victim wallet → asset_transfer; any other outflow (a receiver moving it on, into an exchange) →
    laundering; an issuer freeze → freeze; a decoded successful attack tx → asset_transfer; a victim wallet still
    delegated by EIP-7702 → key_access. `clock` (CLOCK) says whether first_at is when it happened or when it was checked.
    """
    found: dict[tuple[str, str], list[tuple[str, str | None]]] = {}

    def add(stage: str, kind: str, at: str, ref: str | None) -> None:
        found.setdefault((stage, kind), []).append((at, ref))

    for r in (onchain_doc or {}).get("rows") or []:
        if r["kind"] == "freeze":
            add("freeze", "freeze", r["t"], r["tx"])
        elif r["kind"] == "outflow":
            add("asset_transfer" if r.get("from") in victims else "laundering", "outflow", r["t"], r["tx"])
    for d in (onchain_doc or {}).get("delegation") or []:
        if d.get("delegate"):
            add("key_access", "delegation", d["checked_at"], None)
    for tx in (attack_txs_doc or {}).get("txs") or []:
        if tx.get("status") == "success":
            add("asset_transfer", "attack_tx", tx["t"], tx["tx"])
    out = []
    for (stage, kind), hits in found.items():
        at, ref = min(hits, key=lambda h: h[0])
        out.append({"stage": stage, "kind": kind, "clock": CLOCK[kind], "count": len(hits), "first_at": at, "first_tx": ref})
    return sorted(out, key=lambda e: (BY_ID[e["stage"]].order, e["kind"]))


# ---- generated artefacts ---------------------------------------------------------------------------------------------

def schema_def() -> dict[str, Any]:
    """$defs.AttackStage of schemas/site-data.schema.json."""
    return {"description": f"Attack stage (radar.stages — generated by scripts/gen_stages.py, do not edit). Canonical ids in "
                           f"attack order; {', '.join(f'{k}→{v}' for k, v in ALIASES.items())} are legacy M4 values still "
                           f"accepted in documents published before the rename, until {ALIASES_COLLAPSE_AFTER}.",
            "enum": [*IDS, *ALIASES]}


def ui_module() -> str:
    """ui/src/generated/stages.ts."""
    import json
    rows = [{"id": s.id, "order": s.order, "zh": s.zh, "en": s.en, "segment": s.segment, "mitre": s.mitre,
             "expected": list(s.expected), "inFlow": s.in_flow,
             "controls": [{"service": c.service, "effect": c.effect, "how": c.how} for c in s.controls]} for s in STAGES]

    def lit(v: Any) -> str:
        return json.dumps(v, ensure_ascii=False)
    ids = " | ".join(lit(i) for i in IDS)
    body = ",\n".join("  " + lit(r) for r in rows)
    return ("// GENERATED by scripts/gen_stages.py from src/radar/stages.py — do not edit.\n"
            "// `uv run python scripts/gen_stages.py` rewrites it; tests/test_stages.py fails when it is stale.\n\n"
            f"export type StageId = {ids};\n"
            "export type StageSegment = 'cloud' | 'chain' | 'response' | 'context';\n"
            "export type ControlEffect = 'block' | 'detect' | 'limit' | 'investigate';\n"
            "export interface StageControl { service: string; effect: ControlEffect; how: string }\n"
            "export interface StageDef {\n  id: StageId; order: number; zh: string; en: string; segment: StageSegment;"
            " mitre: string | null;\n  expected: readonly string[]; inFlow: boolean; controls: readonly StageControl[];\n}\n\n"
            "/** Every stage in attack order (radar.stages.STAGES). */\n"
            f"export const STAGES: readonly StageDef[] = [\n{body},\n];\n\n"
            "/** Legacy M4 phase values in documents published before the rename → stage (radar.stages.ALIASES). */\n"
            f"export const STAGE_ALIASES: Readonly<Record<string, StageId>> = {lit(ALIASES)};\n\n"
            f"export const EFFECT_ZH: Readonly<Record<ControlEffect, string>> = {lit(EFFECT_ZH)};\n")
