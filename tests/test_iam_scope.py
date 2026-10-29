"""R1: the respond Lambda's IAM actions are exactly the Security Agent / Continuum operations the code calls.

A call added without its action fails live as AccessDenied (caught as a failed action, easy to miss); an action
left behind after its call is removed is privilege nobody uses. Both directions are checked statically: infra/stack.py
is read with ast (importing it would need aws-cdk-lib in the test environment)."""

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _constants() -> dict[str, list[str]]:
    tree = ast.parse((ROOT / "infra" / "stack.py").read_text())
    return {n.targets[0].id: ast.literal_eval(n.value) for n in tree.body
            if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
            and n.targets[0].id in ("SA_REVIEW_ACTIONS", "SA_PACK_ACTIONS", "CN_ACTIONS")}


def _calls() -> dict[str, set[str]]:
    """snake_case operations reached through a Security Agent / Continuum client in continuum_aws.py."""
    tree = ast.parse((ROOT / "src" / "radar" / "continuum_aws.py").read_text())
    names = {"sa": "sa", "cn": "cn"}  # local variable → service (assigned from _sa() / _cn())
    out: dict[str, set[str]] = {"sa": set(), "cn": set()}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        v = node.value
        svc = (names.get(v.id) if isinstance(v, ast.Name) else
               {"_sa": "sa", "_cn": "cn"}.get(v.func.id) if isinstance(v, ast.Call) and isinstance(v.func, ast.Name) else None)
        if svc and not node.attr.startswith("meta") and not node.attr.startswith("exceptions"):
            out[svc].add(node.attr)
    return out


def _camel(snake: str) -> str:
    return "".join(p.capitalize() for p in snake.split("_"))


def test_iam_actions_equal_the_calls_in_code():
    c, calls = _constants(), _calls()
    assert {_camel(x) for x in calls["sa"]} == set(c["SA_REVIEW_ACTIONS"]) | set(c["SA_PACK_ACTIONS"])
    assert {_camel(x) for x in calls["cn"]} == set(c["CN_ACTIONS"])


def test_no_wildcard_service_actions_left():
    src = (ROOT / "infra" / "stack.py").read_text()
    assert not re.search(r'"(securityagent|continuum):\*"', src)


def _waf_calls() -> set[str]:
    tree = ast.parse((ROOT / "src" / "radar" / "mitigate_aws.py").read_text())
    return {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Call)
            and isinstance(n.value.func, ast.Name) and n.value.func.id == "_waf"}


def test_mitigate_waf_actions_equal_the_calls_and_writes_are_prefix_scoped():
    tree = ast.parse((ROOT / "infra" / "stack.py").read_text())
    c = {n.targets[0].id: ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
         and isinstance(n.targets[0], ast.Name) and n.targets[0].id in ("WAF_READ_ACTIONS", "WAF_WRITE_ACTIONS")}
    # case-insensitive: boto3 snake_case loses the acronym (update_web_acl ↔ UpdateWebACL)
    assert {_camel(x).lower() for x in _waf_calls()} == {a.lower() for a in c["WAF_READ_ACTIONS"] + c["WAF_WRITE_ACTIONS"]}
    src = (ROOT / "infra" / "stack.py").read_text()
    # B3: the write is scoped to radar-prefixed web ACLs, never "*"
    assert 'global/webacl/security-radar-*/*' in src and not re.search(r'"wafv2:\*"', src)
    from radar import mitigate
    assert mitigate.RADAR_ACL_PREFIX == "security-radar-"
