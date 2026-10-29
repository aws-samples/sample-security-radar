"""M3 WAF demo (us-east-1 — CLOUDFRONT-scope web ACLs live there): a radar-owned web ACL in front of a CloudFront
distribution that refuses every request (infra/deny_all.js), so the end-to-end check (scripts/waf-e2e.py) can show a
virtual patch counting, then blocking, a PHP2Shell-shaped request — with no application behind it to expose.

The web ACL is created EMPTY and its rules are runtime state owned by the mitigate station (radar.mitigate_station):
this definition must not carry rules, or a stack update would wipe what the station staged / a human promoted.
(If it ever does, the station re-stages its rules next cycle; promotions are kept in DynamoDB and re-applied.)"""

from pathlib import Path

from aws_cdk import CfnOutput, RemovalPolicy, Stack, Tags
from aws_cdk import aws_cloudfront as cf
from aws_cdk import aws_cloudfront_origins as origins
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_wafv2 as wafv2
from constructs import Construct

ROOT = Path(__file__).resolve().parents[1]


def demo_acl_name(stage: str = "") -> str:
    """Deterministic, and under the prefix the radar's UpdateWebACL permission is scoped to (radar.mitigate)."""
    return f"security-radar-{stage}-waf-demo" if stage else "security-radar-waf-demo"


class MitigateDemoStack(Stack):
    def __init__(self, scope: Construct, cid: str, *, stage: str = "", **kw) -> None:
        super().__init__(scope, cid, **kw)
        name = demo_acl_name(stage)
        acl = wafv2.CfnWebACL(self, "DemoWebAcl", name=name, scope="CLOUDFRONT",
                              default_action=wafv2.CfnWebACL.DefaultActionProperty(allow={}),
                              description="Security Radar WAF demo: rules are staged by the mitigate station",
                              visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                                  sampled_requests_enabled=True, cloud_watch_metrics_enabled=True, metric_name="RadarWafDemo"),
                              rules=[])
        Tags.of(acl).add("security-radar:owner", "mitigate")
        origin = s3.Bucket(self, "EmptyOrigin", block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                           encryption=s3.BucketEncryption.S3_MANAGED, enforce_ssl=True,
                           removal_policy=RemovalPolicy.DESTROY, auto_delete_objects=True)
        gate = cf.Function(self, "DenyAll", runtime=cf.FunctionRuntime.JS_2_0,
                           code=cf.FunctionCode.from_file(file_path=str(ROOT / "infra" / "deny_all.js")))
        dist = cf.Distribution(
            self, "DemoDistribution", comment="Security Radar WAF demo (refuses every request)", web_acl_id=acl.attr_arn,
            default_behavior=cf.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(origin),
                viewer_protocol_policy=cf.ViewerProtocolPolicy.HTTPS_ONLY,
                allowed_methods=cf.AllowedMethods.ALLOW_ALL, cache_policy=cf.CachePolicy.CACHING_DISABLED,
                function_associations=[cf.FunctionAssociation(function=gate, event_type=cf.FunctionEventType.VIEWER_REQUEST)]))
        CfnOutput(self, "DemoUrl", value=f"https://{dist.distribution_domain_name}")
        CfnOutput(self, "DemoWebAclName", value=name)
        CfnOutput(self, "DemoWebAclArn", value=acl.attr_arn)
