"""R5.4: cdk-nag exemptions are per resource (infra/nag_findings.json), each with a stated reason — no whole-stack
exemption that would also silence the next resource."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NAG = (ROOT / "infra" / "nag.py").read_text()
FINDINGS = json.loads((ROOT / "infra" / "nag_findings.json").read_text())


def test_every_exempted_rule_has_a_reason_and_every_reason_is_used():
    reasons = set(re.findall(r'"(AwsSolutions-[A-Z0-9]+)":', NAG))
    assert set(FINDINGS) == reasons


def test_exemptions_are_per_resource_never_per_stack():
    assert "NagSuppressions.add_stack_suppressions(" not in NAG and "add_resource_suppressions_by_path" in NAG
    assert all(p.startswith("/SecurityRadar") for paths in FINDINGS.values() for p in paths)


def test_the_findings_parser_reads_both_finding_shapes():
    import importlib.util
    spec = importlib.util.spec_from_file_location("nf", ROOT / "scripts" / "nag_findings.py")
    nf = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(nf)
    log = ("ERROR AwsSolutions-S1: The S3 Bucket has server access logs disabled.\n   SecurityRadar/RawBucket/Resource\n"
           "   Rule Annotation::error-annotation\n"
           "ERROR AwsSolutions-IAM5[Resource::<X.Arn>/code/*]: wildcard\n   SecurityRadarContinuum/Role/DefaultPolicy/Resource\n")
    assert nf.parse(log) == {"AwsSolutions-IAM5": ["/SecurityRadarContinuum/Role/DefaultPolicy/Resource"],
                             "AwsSolutions-S1": ["/SecurityRadar/RawBucket/Resource"]}


def test_an_exemption_names_a_resource_of_its_own_stack():
    """The path filter in nag.apply: an exemption listed for one stack must not be applied to another."""
    src = NAG.split("def apply(", 1)[1]
    assert 'if path.startswith(f"/{s.stack_name}/"):' in src
