"""cdk-nag (AwsSolutions) for every stack: `cdk synth -c nag=on` — CI runs it, so a new resource with an unexplained
finding fails the build. Each suppression says WHY it does not apply to this sample (and what production should do);
a rule fixed in the stacks is not listed here (VPC7 flow logs, SF1/SF2 Step Functions logging + X-Ray: fixed)."""

from aws_cdk import Aspects, Stack
from cdk_nag import AwsSolutionsChecks, NagPackSuppression, NagSuppressions

REASONS: dict[str, str] = {
    "AwsSolutions-IAM4": "AWSLambdaBasicExecutionRole (CloudWatch Logs only) on the CDK-created Lambda roles; every "
                         "service permission is an explicit inline statement.",
    "AwsSolutions-IAM5": "Wildcards are (a) CDK grant_* object/index scopes on the stack's own buckets and table "
                         "(bucket/*, table/index/*), (b) read-only APIs without resource-level permissions "
                         "(wafv2 List/Get/Describe/CheckCapacity, inspector-scan:ScanSbom, ce:GetCostAndUsage, route53resolver List*), "
                         "(c) Continuum / Security Agent resources created at runtime, scoped to this account. Writes to "
                         "WAF / DNS Firewall are scoped to the radar's own resources (verified with simulate-principal-policy).",
    "AwsSolutions-L1": "Python 3.12 is pinned to match CI and the test environment; upgrade together with them.",
    "AwsSolutions-S1": "Sample: no S3 server access logging (cost, extra bucket). Enable it for production.",
    "AwsSolutions-SMG4": "Secrets hold third-party API keys and a generated demo credential; they cannot be rotated "
                         "by a Lambda rotation function. Rotate with the issuer.",
    "AwsSolutions-CFR1": "Demo distributions: no geo restriction (audience not region-bound).",
    "AwsSolutions-CFR2": "The UI is behind a Basic Auth gate for the demo; the WAF demo distribution has AWS WAF. "
                         "For production put the UI behind Amazon Cognito / IAM Identity Center and AWS WAF.",
    "AwsSolutions-CFR3": "Sample: no CloudFront standard logs (cost, extra bucket). Enable for production.",
    "AwsSolutions-APIG2": "Routes: GET /api/{proxy+} (path validated by the Lambda against the published layout, "
                          "radar.api._PATH; no body) and /api/subscriptions GET / POST / DELETE {id} — the POST body is "
                          "validated in the Lambda (radar.subscribe_api: size, fields, https target that resolves public).",
    "AwsSolutions-APIG3": "Sample: no AWS WAF on the API (cost). It is throttled (20 rps); every request needs a Cognito "
                          "token — the read scope for /api/data, the subscribe scope for /api/subscriptions (own rows "
                          "only). Add AWS WAF for production.",
    "AwsSolutions-COG2": "The user pool has no users and self sign-up is off: it only issues client-credentials tokens "
                         "to app clients, where MFA does not apply.",
    "AwsSolutions-COG8": "The Plus tier adds threat protection for user sign-in; this pool has no users (machine clients "
                         "only), so there is no sign-in to protect.",
    "AwsSolutions-CFR4": "Default *.cloudfront.net certificate (no custom domain in a sample), which fixes the minimum "
                         "TLS policy; use a custom domain with TLSv1.2_2021 for production.",
}


def apply(stacks: list[Stack]) -> None:
    """Exempt exactly the (rule, resource) pairs in nag_findings.json (scripts/nag_findings.py writes it), each with
    its rule's reason (R5.4). It was add_stack_suppressions: every rule exempted for the whole stack, so a NEW resource
    with an unexplained finding passed silently."""
    import json
    import os
    from pathlib import Path
    findings: dict[str, list[str]] = json.loads((Path(__file__).with_name("nag_findings.json")).read_text())
    for s in stacks:
        Aspects.of(s).add(AwsSolutionsChecks(verbose=True))
        if os.environ.get("NAG_RAW") == "1":     # scripts/nag_findings.py: list every finding unexempted
            continue
        for rule, paths in findings.items():
            for path in paths:
                if path.startswith(f"/{s.stack_name}/"):
                    NagSuppressions.add_resource_suppressions_by_path(
                        s, path, [NagPackSuppression(id=rule, reason=REASONS[rule])], apply_to_children=True)
