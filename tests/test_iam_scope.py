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


def test_publish_writes_only_site_data_and_its_code_writes_nowhere_else():
    """R5.4 (audit 05 4.2): Publish could overwrite index.html and the JS bundle — the page every reader runs. Its grant
    is data/* and every site write in the publish path names a data/ key, so the narrowing cannot break a write."""
    import re
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    stack = (root / "infra" / "stack.py").read_text()
    assert re.search(r'site\.grant_put\(publish_fn, "data/\*"\)', stack)
    assert not re.search(r"site\.grant_put\(publish_fn\)", stack)
    handlers = (root / "src" / "radar" / "handlers.py").read_text()
    site_keys = re.findall(r'_s3\.put_object\(Bucket=bucket, Key=(f?"[^"]*")', handlers)
    assert site_keys and all(k.lstrip("f").startswith('"data/') for k in site_keys), site_keys


def test_the_functions_get_exactly_the_table_actions_the_store_uses_and_no_scan():
    """R5.4: grant_read_write_data gave every function Scan (whole-table reads). The grant now lists the operations
    radar.dynamo calls; a new call shape needs the list to change, and nothing in src scans."""
    import ast
    import re
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    stack = (root / "infra" / "stack.py").read_text()
    actions = next(ast.literal_eval(n.value) for n in ast.walk(ast.parse(stack))
                   if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "TABLE_ACTIONS")
    assert "Scan" not in actions and "table.grant_read_write_data(" not in stack.split("def fn(", 1)[1].split("return f", 1)[0]
    used = set()
    for f in (root / "src" / "radar").rglob("*.py"):
        # calls on a table or DynamoDB client object (patterns.scan / anomaly.scan are not table scans)
        for m in re.findall(r"(?:self\.t|table|client|tbl|_table)\.(get_item|put_item|update_item|delete_item|query|scan"
                            r"|batch_get_item|batch_writer)\(", f.read_text()):
            used.add(m)
    camel = {"get_item": "GetItem", "put_item": "PutItem", "update_item": "UpdateItem", "delete_item": "DeleteItem",
             "query": "Query", "batch_get_item": "BatchGetItem", "batch_writer": "BatchWriteItem", "scan": "Scan"}
    assert {camel[u] for u in used} <= set(actions), used


def test_r5_4_collect_writes_only_rows_under_its_leading_keys():
    """The station that parses untrusted feed content gets writes only on COLLECT_WRITE_KEYS (dynamodb:LeadingKeys);
    tests/test_collect_batching.py runs it and checks every key it writes falls under them."""
    src = (ROOT / "infra" / "stack.py").read_text()
    assert re.search(r'collect_fn = fn\("CollectFn", "collect_batch", \d+, write_keys=COLLECT_WRITE_KEYS\)', src)
    assert '"ForAllValues:StringLike": {"dynamodb:LeadingKeys": write_keys}' in src
    reads = ast.literal_eval(re.search(r"^TABLE_READ_ACTIONS = (\[.*\])", src, re.MULTILINE).group(1))
    assert set(reads) == {"GetItem", "BatchGetItem", "Query"}           # a write action here would escape the condition
