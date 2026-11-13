"""radar.packrender: five renderings of one pack — same statements everywhere, no secret anywhere, Count only."""

import json
import re
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from radar import mitigate, packrender, rulepack

FIX = Path(__file__).parent / "fixtures" / "nuclei"
SHA = "0123456789abcdef0123456789abcdef01234567"
CVES = ("CVE-2026-87902", "CVE-2026-9586", "CVE-2026-104935", "CVE-2026-42018", "CVE-2026-96655", "CVE-2026-109619")
ITEMS = [SimpleNamespace(item_id="it_1", url="https://e.x/a", title="Credential stuffing wave",
                         text="The origin server was exposed to the internet. C2 at 8.8.8[.]8 seen.")]


@pytest.fixture(scope="module")
def pack() -> dict:
    poc = {c: {"state": "found", "path": f"http/cves/2026/{c}.yaml", "sha": SHA, "text": (FIX / f"{c}.yaml").read_text()} for c in CVES}
    cat = {"CVE-2026-87902": [mitigate.CveRules("AWSManagedRulesWordPressRuleSet", (), "Version_1.2", "2026-09-25")]}
    d = rulepack.build({"event_id": "ev_40bbda4fb2090dde", "cves": list(CVES)}, ITEMS, poc, cat, {}).to_dict()
    d["capacity"] = {"state": "pass", "wcu": 41, "detail": "CheckCapacity 41 WCU"}
    return d


def cfn_rules_as_api(rules_cfn: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """CFN Rules → API shape (Arn → ARN, intrinsic placeholders back) — tests compare it with rules(pack)."""
    def back(v: Any) -> Any:
        if isinstance(v, dict):
            if v == {"Fn::GetAtt": ["RadarIpSet", "Arn"]}:
                return rulepack.IPSET_ARN_PLACEHOLDER
            if v == {"Fn::Sub": "{{resolve:secretsmanager:${OriginSecretName}:SecretString}}"}:
                return rulepack.ORIGIN_SECRET_PLACEHOLDER
            return {("ARN" if k == "Arn" else k): back(x) for k, x in v.items()}
        if isinstance(v, list):
            return [back(x) for x in v]
        return v
    return back(rules_cfn)


def _texts(pack: dict) -> dict[str, str]:
    return {r["id"]: r["text"] for r in packrender.render_all(pack)}


def test_json_and_cloudformation_carry_the_same_statement_tree(pack):
    api = json.loads(_texts(pack)["wafv2_json"])["RuleGroup"]["Rules"]
    cfn = json.loads(_texts(pack)["cloudformation"])["Resources"]["RadarRuleGroup"]["Properties"]["Rules"]
    assert api == packrender.rules(pack)
    assert cfn_rules_as_api(cfn) == api
    # CFN names the ARN key `Arn` — the API's `ARN` would fail to deploy
    assert '"ARN"' not in json.dumps(cfn) and '"Arn"' in json.dumps(cfn)
    assert {r["Name"] for r in api} == {r["rule_id"] for r in pack["custom"] + pack["templates"]}


def test_terraform_block_tree_reads_back_to_the_statement(pack):
    for r in packrender.rules(pack):
        assert packrender.from_blocks(packrender.to_blocks("statement", r["Statement"])) == r["Statement"]
    tf = _texts(pack)["terraform"]
    assert tf.count("\n  rule {") == len(pack["custom"]) + len(pack["templates"])
    assert "aws_wafv2_ip_set.radar.arn" in tf and "data.aws_secretsmanager_secret_version.origin.secret_string" in tf
    if shutil.which("terraform"):    # syntax only (no provider download): `terraform fmt -` parses HCL
        assert subprocess.run(["terraform", "fmt", "-"], input=tf, text=True, capture_output=True, check=False).returncode == 0


def test_every_rule_counts_and_the_reference_overrides_to_count(pack):
    j = json.loads(_texts(pack)["wafv2_json"])
    assert all(r["Action"] == {"Count": {}} for r in j["RuleGroup"]["Rules"])
    assert j["WebACLReference"]["OverrideAction"] == {"Count": {}}
    assert all(m["OverrideAction"] == {"Count": {}} for m in j["ManagedRules"])
    assert j["RuleGroup"]["Capacity"] == 50                      # ceil(41 × 1.2)


def test_no_secret_value_in_any_rendering(pack):
    """W8: the pack carries placeholders only. The origin secret is resolved at the reader's side in each rendering."""
    t = _texts(pack)
    whole = json.dumps(pack) + "".join(t.values())
    assert rulepack.ORIGIN_SECRET_PLACEHOLDER in json.dumps(pack)
    assert "{{resolve:secretsmanager:${OriginSecretName}:SecretString}}" in t["cloudformation"]
    assert "env.ORIGIN_SECRET" in t["cli"] and not re.search(r"--\S+\s+\"?\$ORIGIN_SECRET\b", t["cli"])   # never an argv word
    assert not re.search(r"AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20}|sk-[A-Za-z0-9]{20}", whole)


def test_cli_checks_capacity_first_and_gives_the_rollback(pack):
    cli = _texts(pack)["cli"]
    assert cli.index("check-capacity") < cli.index("create-rule-group") < cli.index("update-web-acl")
    assert "回滚" in cli and f'select(.Name != \\"{pack["name"]}\\")'.replace("\\", "") in cli.replace("\\", "")
    assert "--cli-input-json file://update.json" in cli
    if shutil.which("bash"):
        assert subprocess.run(["bash", "-n"], input=cli, text=True, capture_output=True, check=False).returncode == 0


def test_cli_update_carries_every_field_the_station_carries(pack):
    """Without jq (CI): the update program names every field mitigate_aws.put_rules carries over — one list, two users."""
    cli = _texts(pack)["cli"]
    assert mitigate.ACL_CARRY_FIELDS and all(f'"{k}"' in cli for k in mitigate.ACL_CARRY_FIELDS)


@pytest.mark.skipif(not shutil.which("jq"), reason="jq not installed")
def test_cli_update_keeps_every_field_of_the_web_acl(pack, tmp_path):
    line = next(x for x in _texts(pack)["cli"].splitlines() if x.startswith("jq --arg arn"))
    (tmp_path / "acl.json").write_text(json.dumps({"LockToken": "L", "WebACL": {
        "Name": "a", "Id": "i", "DefaultAction": {"Allow": {}}, "VisibilityConfig": {"MetricName": "m"}, "Description": "d",
        "TokenDomains": ["x.example"], "AssociationConfig": {"RequestBody": {}}, "Rules": [{"Name": "theirs", "Priority": 0}]}}))
    subprocess.run(["bash", "-c", line], cwd=tmp_path, check=True, env={"PATH": "/usr/bin:/bin:/opt/homebrew/bin:/opt/anaconda3/bin",
                                                                          "SCOPE": "CLOUDFRONT", "arn": "arn:x"})
    u = json.loads((tmp_path / "update.json").read_text())
    assert (u["Description"], u["TokenDomains"], u["LockToken"], u["Scope"]) == ("d", ["x.example"], "L", "CLOUDFRONT")
    assert [r["Name"] for r in u["Rules"]] == ["theirs", pack["name"]]
    assert u["Rules"][1]["Statement"] == {"RuleGroupReferenceStatement": {"ARN": "arn:x"}}


def test_human_page_opens_with_the_mitigation_note_and_explains_each_rule(pack):
    md = _texts(pack)["markdown"]
    assert md.splitlines()[0] == mitigate.MITIGATION_NOTE and "缓解 ≠ 修复" in md
    for r in pack["custom"] + pack["templates"]:
        assert f"`{r['rule_id']}`" in md
    assert "Count 切到 Block" in md and "## 回滚" in md
    assert "fingerprint_only" in md                               # rejected candidates are listed, with the reason
    assert f"blob/{SHA}/http/cves/2026/CVE-2026-87902.yaml#L" in md


def test_renderings_registry_is_the_one_list_the_page_offers(pack):
    rs = packrender.render_all(pack)
    assert [r["id"] for r in rs] == [x[0] for x in packrender.RENDERINGS]
    assert len({r["filename"] for r in rs}) == len(rs) and all(r["text"].endswith("\n") for r in rs)
