"""Five renderings of ONE rule pack (radar.rulepack row) — wafv2 JSON, CloudFormation, Terraform, AWS CLI steps, a human
page. Every rendering wraps the same `statement` objects; tests read the JSON and the CloudFormation back and compare
the statement trees, and round-trip the Terraform block tree (01-waf §4.5: one source, five views).

Secrets never enter a pack: the origin-lockdown rule carries {{ORIGIN_SECRET}} and each rendering resolves it at the
reader's side (CloudFormation: Secrets Manager dynamic reference; Terraform: a data source; CLI: an environment
variable read by jq, never an argv word). The radar renders text; it never calls a write API for a reader."""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from typing import Any

from radar import mitigate
from radar.limits import Limits
from radar.rulepack import IPSET_ARN_PLACEHOLDER, ORIGIN_SECRET_PLACEHOLDER, quote_href

RULE_GROUP_ARN_PLACEHOLDER = "{{RULE_GROUP_ARN}}"
CAPACITY_HEADROOM = 1.2          # a RuleGroup's capacity is fixed at creation: room for one more small rule
REFERENCE_PRIORITY = mitigate.PASTE_PRIORITY_BASE - 1   # the reference rule's placeholder priority in the reader's web ACL

# id → (download filename, media type, label) — the UI lists these; nothing else names them
RENDERINGS: tuple[tuple[str, str, str, str], ...] = (
    ("wafv2_json", "rule-group.json", "application/json", "AWS WAF API JSON"),
    ("cloudformation", "rule-pack.cfn.json", "application/json", "CloudFormation"),
    ("terraform", "rule-pack.tf", "text/plain", "Terraform"),
    ("cli", "rule-pack.sh", "text/x-shellscript", "AWS CLI 步骤"),
    ("markdown", "rule-pack.md", "text/markdown", "说明（人读）"),
)


def metric(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", name)[:128] or "radarrule"


def _vis(name: str) -> dict[str, Any]:
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": metric(name)}


def rules(pack: dict[str, Any]) -> list[dict[str, Any]]:
    """The RuleGroup's Rules[] — every rule Count, priority = its order in the pack."""
    return [{"Name": r["rule_id"], "Priority": i, "Statement": r["statement"], "Action": {"Count": {}},
             "VisibilityConfig": _vis(r["rule_id"])} for i, r in enumerate((pack.get("custom") or []) + (pack.get("templates") or []))]


def capacity(pack: dict[str, Any]) -> int | None:
    wcu = (pack.get("capacity") or {}).get("wcu")
    return math.ceil(wcu * CAPACITY_HEADROOM) if isinstance(wcu, int) and wcu > 0 else None


def _ip_sets(pack: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"Name": f"{pack['name']}-ips", "IPAddressVersion": r["ip_set"]["version"], "Addresses": r["ip_set"]["addresses"]}
            for r in pack.get("templates") or [] if r.get("ip_set")][:1]


def _has_origin(pack: dict[str, Any]) -> bool:
    return any(r["kind"] == "origin_lockdown" for r in pack.get("templates") or [])


def reference(pack: dict[str, Any], arn: Any = RULE_GROUP_ARN_PLACEHOLDER) -> dict[str, Any]:
    """The one rule a reader adds to THEIR web ACL — OverrideAction Count: nothing in the group blocks."""
    return {"Name": pack["name"], "Priority": REFERENCE_PRIORITY, "Statement": {"RuleGroupReferenceStatement": {"ARN": arn}},
            "OverrideAction": {"Count": {}}, "VisibilityConfig": _vis(pack["name"])}


# ---------------------------------------------------------------- 1. wafv2 JSON
def wafv2_json(pack: dict[str, Any]) -> dict[str, Any]:
    managed = pack.get("managed") or []
    return {"Note": mitigate.MITIGATION_NOTE,
            "RuleGroup": {"Name": pack["name"], "Scope": "CLOUDFRONT", "Capacity": capacity(pack), "Rules": rules(pack),
                          "VisibilityConfig": _vis(pack["name"])},
            "IPSets": [{**s, "Scope": "CLOUDFRONT"} for s in _ip_sets(pack)],
            "WebACLReference": reference(pack),
            "ManagedRules": [m["rule"] for m in managed if m.get("appliable")],
            "AdvisoryManagedRules": [m["rule"] for m in managed if not m.get("appliable")],
            "Placeholders": {RULE_GROUP_ARN_PLACEHOLDER: "create-rule-group 返回的 ARN",
                             **({IPSET_ARN_PLACEHOLDER: "create-ip-set 返回的 ARN"} if _ip_sets(pack) else {}),
                             **({ORIGIN_SECRET_PLACEHOLDER: "CloudFront 注入的源站密钥（Secrets Manager，绝不写进文件）"}
                                if _has_origin(pack) else {})}}


# ---------------------------------------------------------------- 2. CloudFormation (JSON)
def _cfn_value(v: Any) -> Any:
    """API JSON → CFN: ARN keys are `Arn` in CFN; placeholders become intrinsic functions."""
    if isinstance(v, dict):
        out = {}
        for k, x in v.items():
            if k == "ARN" and x == IPSET_ARN_PLACEHOLDER:
                out["Arn"] = {"Fn::GetAtt": ["RadarIpSet", "Arn"]}
            elif k == "ARN":
                out["Arn"] = x
            elif k == "SearchString" and x == ORIGIN_SECRET_PLACEHOLDER:
                out[k] = {"Fn::Sub": "{{resolve:secretsmanager:${OriginSecretName}:SecretString}}"}
            else:
                out[k] = _cfn_value(x)
        return out
    if isinstance(v, list):
        return [_cfn_value(x) for x in v]
    return v


def cloudformation(pack: dict[str, Any]) -> dict[str, Any]:
    cap = capacity(pack)
    params: dict[str, Any] = {
        "Scope": {"Type": "String", "Default": "CLOUDFRONT", "AllowedValues": ["CLOUDFRONT", "REGIONAL"],
                  "Description": "CLOUDFRONT 只能在 us-east-1 部署"},
        "RuleGroupCapacity": {"Type": "Number", "MinValue": 1,
                              "Description": "建后不可改；= CheckCapacity × 1.2" + ("" if cap else "（雷达未取得 CheckCapacity：先运行 CLI 第 1 步）"),
                              **({"Default": cap} if cap else {})}}
    res: dict[str, Any] = {}
    for s in _ip_sets(pack):
        res["RadarIpSet"] = {"Type": "AWS::WAFv2::IPSet", "Properties": {**s, "Scope": {"Ref": "Scope"}}}
    if _has_origin(pack):
        params["OriginSecretName"] = {"Type": "String", "Description": "Secrets Manager 里源站密钥 header 值的 secret 名"}
    res["RadarRuleGroup"] = {"Type": "AWS::WAFv2::RuleGroup", "Properties": {
        "Name": pack["name"], "Scope": {"Ref": "Scope"}, "Capacity": {"Ref": "RuleGroupCapacity"},
        "Rules": _cfn_value(rules(pack)), "VisibilityConfig": _vis(pack["name"])}}
    return {"AWSTemplateFormatVersion": "2010-09-09",
            "Description": f"{pack['name']} — security-radar rule pack (Count only). {mitigate.MITIGATION_NOTE}",
            "Parameters": params, "Resources": res,
            "Outputs": {"RuleGroupArn": {"Value": {"Fn::GetAtt": ["RadarRuleGroup", "Arn"]},
                                         "Description": "在 web ACL 里加一条 RuleGroupReferenceStatement 引用它，OverrideAction Count"}}}


# ---------------------------------------------------------------- 3. Terraform (block tree → HCL)
class Expr(str):
    """An HCL expression (rendered bare), not a string literal."""


@dataclass
class Block:
    name: str
    attrs: list[tuple[str, Any]] = field(default_factory=list)
    children: list[Block] = field(default_factory=list)


_SNAKE = {"CloudWatchMetricsEnabled": "cloudwatch_metrics_enabled", "IPSetReferenceStatement": "ip_set_reference_statement",
          "ARN": "arn", "SqliMatchStatement": "sqli_match_statement", "XssMatchStatement": "xss_match_statement"}
_PASCAL = {v: k for k, v in _SNAKE.items()}
_LIST_CHILD = {"Statements": "statement", "TextTransformations": "text_transformation"}
_ONE_CHILD = {"Statement": "statement", "ScopeDownStatement": "scope_down_statement"}


def _snake(k: str) -> str:
    return _SNAKE.get(k) or re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", k).lower()


def _pascal(k: str) -> str:
    return _PASCAL.get(k) or "".join(p[:1].upper() + p[1:] for p in k.split("_"))


def to_blocks(name: str, d: dict[str, Any], tf_value: Any = None) -> Block:
    """A WAF API object → a Terraform block (nested objects are blocks; lists of objects repeat the child block)."""
    b = Block(name)
    for k, v in d.items():
        if k in _LIST_CHILD:
            b.children += [to_blocks(_LIST_CHILD[k], x, tf_value) for x in v]
        elif k in _ONE_CHILD:
            b.children.append(to_blocks(_ONE_CHILD[k], v, tf_value))
        elif isinstance(v, dict):
            b.children.append(to_blocks(_snake(k), v, tf_value))
        else:
            b.attrs.append((_snake(k), tf_value(v) if tf_value else v))
    return b


def from_blocks(b: Block) -> dict[str, Any]:
    """Inverse of to_blocks (tests: the Terraform tree reads back to the same statement)."""
    out: dict[str, Any] = {_pascal(k): v for k, v in b.attrs}
    for c in b.children:
        if c.name == "statement" and b.name in ("and_statement", "or_statement"):
            out.setdefault("Statements", []).append(from_blocks(c))
        elif c.name == "text_transformation":
            out.setdefault("TextTransformations", []).append(from_blocks(c))
        elif c.name == "statement":
            out["Statement"] = from_blocks(c)
        elif c.name == "scope_down_statement":
            out["ScopeDownStatement"] = from_blocks(c)
        else:
            out[_pascal(c.name)] = from_blocks(c)
    return out


def _hcl_value(v: Any) -> str:
    if isinstance(v, Expr):
        return str(v)
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        return "[" + ", ".join(_hcl_value(x) for x in v) + "]"
    # HCL string literal: JSON escaping + escape template sequences so "${" / "%{" in a value stay literal
    return json.dumps(str(v), ensure_ascii=False).replace("${", "$${").replace("%{", "%%{")


def hcl(b: Block, indent: int = 0, label: str = "") -> str:
    pad = "  " * indent
    head = f"{pad}{b.name}{label} {{"
    if not b.attrs and not b.children:
        return head + "}"
    lines = [head] + [f"{pad}  {k} = {_hcl_value(v)}" for k, v in b.attrs] + [hcl(c, indent + 1) for c in b.children] + [f"{pad}}}"]
    return "\n".join(lines)


def _tf_placeholder(v: Any) -> Any:
    if v == IPSET_ARN_PLACEHOLDER:
        return Expr("aws_wafv2_ip_set.radar.arn")
    if v == ORIGIN_SECRET_PLACEHOLDER:
        return Expr("data.aws_secretsmanager_secret_version.origin.secret_string")
    return v


def terraform_rule_blocks(pack: dict[str, Any]) -> list[Block]:
    out = []
    for r in rules(pack):
        b = Block("rule", [("name", r["Name"]), ("priority", r["Priority"])])
        b.children.append(Block("action", [], [Block("count")]))
        b.children.append(to_blocks("statement", r["Statement"], _tf_placeholder))
        b.children.append(to_blocks("visibility_config", r["VisibilityConfig"]))
        out.append(b)
    return out


def terraform(pack: dict[str, Any]) -> str:
    cap = capacity(pack)
    parts = [f"# {mitigate.MITIGATION_NOTE}", f"# {pack['name']} — security-radar rule pack. Every rule is Count.",
             'variable "scope" {\n  type    = string\n  default = "CLOUDFRONT" # CLOUDFRONT: provider region us-east-1\n}',
             'variable "capacity" {\n  type    = number\n' + (f"  default = {cap}\n" if cap else
                                                              "  # no default: run `aws wafv2 check-capacity` first (CLI step 1) × 1.2\n") + "}"]
    for s in _ip_sets(pack):
        parts.append(hcl(Block("resource", [("name", s["Name"]), ("scope", Expr("var.scope")),
                                            ("ip_address_version", s["IPAddressVersion"]), ("addresses", s["Addresses"])]),
                         label=' "aws_wafv2_ip_set" "radar"'))
    if _has_origin(pack):
        parts.append('variable "origin_secret_arn" {\n  type = string # Secrets Manager secret: the origin header value\n}\n'
                     'data "aws_secretsmanager_secret_version" "origin" {\n  secret_id = var.origin_secret_arn\n}')
    rg = Block("resource", [("name", pack["name"]), ("scope", Expr("var.scope")), ("capacity", Expr("var.capacity"))],
               terraform_rule_blocks(pack) + [to_blocks("visibility_config", _vis(pack["name"]))])
    parts.append(hcl(rg, label=' "aws_wafv2_rule_group" "radar"'))
    parts.append('output "rule_group_arn" {\n  value = aws_wafv2_rule_group.radar.arn\n}')
    return "\n\n".join(parts) + "\n"


# ---------------------------------------------------------------- 4. AWS CLI steps
# UpdateWebACL resets every field it is not given ⇒ the update input is GetWebACL's object with all of them carried over
# (mitigate.ACL_CARRY_FIELDS — the list the station's own put_rules uses).
_CARRY = ", ".join(json.dumps(k) for k in mitigate.ACL_CARRY_FIELDS)
_UPDATE = ("{Name: .WebACL.Name, Scope: env.SCOPE, Id: .WebACL.Id, LockToken: .LockToken, DefaultAction: .WebACL.DefaultAction, "
           f"VisibilityConfig: .WebACL.VisibilityConfig}} + (.WebACL | with_entries(select(.key | IN({_CARRY}))))")


def cli(pack: dict[str, Any]) -> str:
    name, cap = pack["name"], capacity(pack)
    ref = json.dumps(reference(pack, "$arn"), ensure_ascii=False).replace('"$arn"', "$arn")
    ips = _ip_sets(pack)
    out = [f"# {mitigate.MITIGATION_NOTE}",
           f"# {name}: 客户自持的 RuleGroup，所有规则 Count；web ACL 里只加一条引用（回滚 = 删这一条）。",
           "# 需要 AWS CLI v2 与 jq。CLOUDFRONT 作用域必须用 us-east-1。先 get 再 update：所有字段原样带回。",
           "set -euo pipefail",
           'export SCOPE="${SCOPE:-CLOUDFRONT}" REGION="${REGION:-us-east-1}"',
           ': "${ACL_NAME:?你的 web ACL 名}"; : "${ACL_ID:?你的 web ACL Id}"',
           "cat > rules.json <<'JSON'", json.dumps(rules(pack), ensure_ascii=False, indent=2), "JSON"]
    if ips:
        s = ips[0]
        out += ["", "# 0a. IP 集合（攻击源 IP，取自证据里的去武装写法）",
                (f'IPSET_ARN=$(aws wafv2 create-ip-set --name {s["Name"]} --scope "$SCOPE" --region "$REGION" '
                 f'--ip-address-version {s["IPAddressVersion"]} --addresses {" ".join(s["Addresses"])} --query Summary.ARN --output text)'),
                "jq --arg a \"$IPSET_ARN\" 'walk(if . == \"" + IPSET_ARN_PLACEHOLDER + "\" then $a else . end)' rules.json > r.tmp && mv r.tmp rules.json"]
    if _has_origin(pack):
        out += ["", "# 0b. 源站密钥：从 Secrets Manager 读进环境变量，由 jq 从 env 取 —— 不出现在任何命令行参数里",
                ': "${ORIGIN_SECRET_ID:?Secrets Manager secret id}"',
                'export ORIGIN_SECRET="$(aws secretsmanager get-secret-value --secret-id "$ORIGIN_SECRET_ID" --query SecretString --output text)"',
                "jq 'walk(if . == \"" + ORIGIN_SECRET_PLACEHOLDER + "\" then env.ORIGIN_SECRET else . end)' rules.json > r.tmp && mv r.tmp rules.json",
                "# rules.json 现在含密钥：用完即删（见最后一步）"]
    out += ["", "# 1. 只读：算 WCU（也是语法校验 —— 不合法的规则在这里报错）",
            'aws wafv2 check-capacity --scope "$SCOPE" --region "$REGION" --rules file://rules.json --cli-binary-format raw-in-base64-out',
            "", f"# 2. 建规则组（capacity 建后不可改：取第 1 步结果 × {CAPACITY_HEADROOM}）",
            f'CAPACITY="${{CAPACITY:-{cap if cap else "请填第1步结果×1.2"}}}"',
            (f'arn=$(aws wafv2 create-rule-group --name {name} --scope "$SCOPE" --region "$REGION" --capacity "$CAPACITY" '
             '--rules file://rules.json --cli-binary-format raw-in-base64-out '
             f'--visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName={metric(name)} '
             '--query Summary.ARN --output text)'),
            "", "# 3. 读你的 web ACL，在 Rules 末尾追加一条引用（OverrideAction Count）；其余字段原样带回（漏带的字段会被重置）",
            "#    不加 raw-in-base64-out：get-web-acl 输出里已有规则的 SearchString 是 base64，原样回传才不会被二次编码",
            'aws wafv2 get-web-acl --name "$ACL_NAME" --id "$ACL_ID" --scope "$SCOPE" --region "$REGION" > acl.json',
            f"jq --arg arn \"$arn\" '{_UPDATE} + {{Rules: (.WebACL.Rules + [{ref}])}}' acl.json > update.json",
            f"# 若你的 ACL 已用 Priority {REFERENCE_PRIORITY}，先把 update.json 里这条改成未用的值",
            'aws wafv2 update-web-acl --cli-input-json file://update.json --region "$REGION"',
            "rm -f rules.json update.json   # 不留含密钥 / 规则副本的文件",
            "", "# 回滚（一条引用即可摘下，立即生效）：",
            '#   aws wafv2 get-web-acl --name "$ACL_NAME" --id "$ACL_ID" --scope "$SCOPE" --region "$REGION" > acl.json',
            f"#   jq '{_UPDATE} + {{Rules: [.WebACL.Rules[] | select(.Name != \"{name}\")]}}' acl.json > rollback.json",
            '#   aws wafv2 update-web-acl --cli-input-json file://rollback.json --region "$REGION"',
            f'#   aws wafv2 delete-rule-group --name {name} --scope "$SCOPE" --region "$REGION" --id <规则组 Id> --lock-token <get-rule-group 的 LockToken>']
    if ips:
        out.append(f'#   aws wafv2 delete-ip-set --name {ips[0]["Name"]} --scope "$SCOPE" --region "$REGION" --id <Id> --lock-token <LockToken>')
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- 5. human page
_FIELD = {"UriPath": "URI 路径", "QueryString": "查询串", "Method": "请求方法"}
_OP = {"EQ": "=", "NE": "≠", "LE": "≤", "LT": "<", "GE": "≥", "GT": ">"}
_POS = {"EXACTLY": "等于", "STARTS_WITH": "以…开头", "ENDS_WITH": "以…结尾", "CONTAINS": "包含", "CONTAINS_WORD": "包含单词"}


def _field(ftm: dict[str, Any]) -> str:
    k, v = next(iter(ftm.items()))
    if k == "SingleHeader":
        return f"header `{v['Name']}`"
    if k == "SingleQueryArgument":
        return f"查询参数 `{v['Name']}`"
    if k == "Body":
        return f"请求体（前 {Limits.WAF_BODY_INSPECT_BYTES // 1024} KB）"
    return _FIELD.get(k, k)


def _tt(s: dict[str, Any]) -> str:
    ts = [t["Type"] for t in sorted(s.get("TextTransformations") or [], key=lambda t: t["Priority"]) if t["Type"] != "NONE"]
    return f"（先 {' → '.join(ts)}）" if ts else ""


def describe(stmt: dict[str, Any]) -> str:
    """One sentence of what a statement counts — generated, so the page never restates a rule by hand."""
    k, s = next(iter(stmt.items()))
    if k == "AndStatement":
        return " 且 ".join(describe(x) for x in s["Statements"])
    if k == "OrStatement":
        return " 或 ".join(describe(x) for x in s["Statements"])
    if k == "NotStatement":
        return f"不满足「{describe(s['Statement'])}」"
    if k == "ByteMatchStatement":
        return f"{_field(s['FieldToMatch'])}{_tt(s)} {_POS[s['PositionalConstraint']]} `{s['SearchString']}`"
    if k == "RegexMatchStatement":
        return f"{_field(s['FieldToMatch'])}{_tt(s)} 匹配正则 `{s['RegexString']}`"
    if k == "SizeConstraintStatement":
        return f"{_field(s['FieldToMatch'])} 长度 {_OP[s['ComparisonOperator']]} {s['Size']}" + ("（即：带了这个 header）" if
                                                                                            s["ComparisonOperator"] == "GT" and s["Size"] == 0 else "")
    if k == "SqliMatchStatement":
        return f"{_field(s['FieldToMatch'])}{_tt(s)} 被 AWS SqliMatch 判为 SQL 注入（敏感度 {s.get('SensitivityLevel', 'LOW')}）"
    if k == "RateBasedStatement":
        return f"同一 IP 在 {s.get('EvaluationWindowSec', 300) // 60} 分钟内超过 {s['Limit']} 次请求"
    if k == "IPSetReferenceStatement":
        return "源 IP 在规则包的 IP 集合内"
    return k


def _quote_md(q: dict[str, Any]) -> str:
    if q.get("repo"):
        href = quote_href(q)
        where = f"[{q['path']}:{q['line']}]({href})" if href else f"`{q['path']}:{q['line']}`（路径未通过校验，不给链接）"
        return (f"`{q['repo']}@{q['sha'][:10]}` {where}"
                f" 逐字 `{q['token']}`")
    href = quote_href(q)
    return (f"[{q['url']}]({href})" if href else f"`{q['url']}`") + f"：「{q['sentence']}」"


def markdown(pack: dict[str, Any]) -> str:
    out = [mitigate.MITIGATION_NOTE, "", f"# WAF 规则包 · {pack['event_id']}", "",
           (f"客户自持的规则组 `{pack['name']}`：所有规则 **Count**（只计数不拦截），web ACL 里只加一条引用 "
            "（`RuleGroupReferenceStatement`，`OverrideAction: Count`）。雷达不写你的任何资源，下面是可复制的文本。"), ""]
    cap = pack.get("capacity") or {}
    out.append(f"**WCU**：{cap.get('wcu') if cap.get('wcu') is not None else '未检查'}（{cap.get('detail') or cap.get('state')}）")
    managed = pack.get("managed") or []
    if managed:
        out += ["", "## AWS 托管规则组", ""]
        out += [f"- {m['group_label']}（`{m['group']}`，{m['tier']} 层{'' if m['appliable'] else '，仅建议'}）："
                f"{m['reason']}" + (f"；需 ≥ {m['min_version']}（确认你的默认版本不低于它）" if m.get("min_version") else "")
                for m in managed]
    for title, rows in (("自定义规则", pack.get("custom") or []), ("模板（启发式，非证据规则）", pack.get("templates") or [])):
        if not rows:
            continue
        out += ["", f"## {title}（{len(rows)} 条）"]
        for r in rows:
            off = (r.get("verified") or {}).get("offline") or {}
            out += ["", f"### `{r['rule_id']}` · {r['confidence']} · 离线验证 {off.get('state', 'unchecked')}", "",
                    f"- **计数什么**：{describe(r['statement'])}", "- **为什么**：" + "；".join(_quote_md(q) for q in r["source_quotes"]),
                    f"- **可能误伤**：{r['false_positive_note']}", f"- **离线验证**：{off.get('detail', '')}"]
    rej = pack.get("rejected") or []
    if rej:
        out += ["", f"## 未生成的规则（{len(rej)}）", ""]
        out += [f"- {x.get('cve') or x['source']} · `{x['extractor']}` · **{x['reason']}**：{x['detail']}" for x in rej]
    out += ["", "## 从 Count 切到 Block", "",
            ("1. 挂上后看 CloudWatch 指标（每条规则的 MetricName = 规则名去掉非字母数字）`CountedRequests`，并用 "
             "`aws wafv2 get-sampled-requests` 看被计数的样本，至少覆盖一个完整业务周期（建议 24–72 小时）。"),
            ("2. 样本里没有正常流量 ⇒ 用 `update-rule-group` 把那一条的 `Action` 改为 `Block`；"
             "整组拦截则把 web ACL 引用的 `OverrideAction` 改为 `None`。逐条切，不要整组一次切。"),
            "3. heuristic 规则（模板、SqliMatch）误报风险更高：观察期加倍。",
            "", "## 回滚", "",
            f"- 从 web ACL 删掉名为 `{pack['name']}` 的那一条引用（一条，立即生效），再 `delete-rule-group`。",
            "- 回滚不影响 web ACL 里的其他规则。", "",
            "## 修复", "", "这只是打补丁之前的缓解：升级到修复版本才是唯一完整的修复。"]
    if pack.get("license"):
        out += ["", "## 许可", "", f"自定义规则的特征派生自 nuclei-templates：{pack['license']}。规则属检测模板派生，Count 观察后由你决定 Block。"]
    return "\n".join(out) + "\n"


def render_all(pack: dict[str, Any]) -> list[dict[str, str]]:
    texts = {"wafv2_json": json.dumps(wafv2_json(pack), ensure_ascii=False, indent=2) + "\n",
             "cloudformation": json.dumps(cloudformation(pack), ensure_ascii=False, indent=2) + "\n",
             "terraform": terraform(pack), "cli": cli(pack), "markdown": markdown(pack)}
    return [{"id": i, "filename": f, "media_type": m, "label": lb, "text": texts[i]} for i, f, m, lb in RENDERINGS]

