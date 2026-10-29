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
                         "(wafv2 List/Get/Describe, inspector-scan:ScanSbom, ce:GetCostAndUsage, route53resolver List*), "
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
    "AwsSolutions-CFR4": "Default *.cloudfront.net certificate (no custom domain in a sample), which fixes the minimum "
                         "TLS policy; use a custom domain with TLSv1.2_2021 for production.",
    "AwsSolutions-DDB3": "Point-in-time recovery: the table holds re-derivable radar state (sources are re-fetched).",
}


def apply(stacks: list[Stack]) -> None:
    for s in stacks:
        Aspects.of(s).add(AwsSolutionsChecks(verbose=True))
        NagSuppressions.add_stack_suppressions(s, [NagPackSuppression(id=k, reason=v) for k, v in REASONS.items()],
                                               apply_to_nested_stacks=True)
