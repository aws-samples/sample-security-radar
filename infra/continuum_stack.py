"""AWS Continuum side of the respond station (us-east-1 — Continuum has no endpoint in ap-northeast-1).

Only what CloudFormation can own: the code/context/patch bucket and the integration role. The Continuum
integration + environment have no CFN type and are reconciled by the respond Lambda (radar.continuum_aws).
Names are deterministic so the Tokyo stack can reference them without cross-region exports."""

from pathlib import Path

from aws_cdk import CfnOutput, Duration, RemovalPolicy, Stack
from aws_cdk import aws_iam as iam
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_s3_deployment as s3deploy
from constructs import Construct

TARGETS_DIR = Path(__file__).resolve().parents[1] / "build" / "targets"  # scripts/build-targets.sh (every target, SA bucket)
CN_TARGETS_DIR = Path(__file__).resolve().parents[1] / "build" / "targets-cn"  # only the S3-channel zips

def prefix(stage: str) -> str:
    """Every deterministic name derives from the stage, so `-c stage=repro` deploys a full second copy."""
    return f"security-radar-{stage}" if stage else "security-radar"


def integration_role(stage: str) -> str:
    return f"{prefix(stage)}-continuum-integration"


def external_id(stage: str) -> str:
    return f"{prefix(stage)}-continuum"  # not a secret: the trust is also pinned to aws:SourceAccount


def bucket_name(account: str, stage: str = "") -> str:
    return f"{prefix(stage)}-continuum-{account}-us-east-1"


class ContinuumStack(Stack):
    def __init__(self, scope: Construct, cid: str, *, stage: str = "", **kw) -> None:
        super().__init__(scope, cid, **kw)
        b = s3.Bucket(self, "CodeBucket", bucket_name=bucket_name(self.account, stage),
                      block_public_access=s3.BlockPublicAccess.BLOCK_ALL, encryption=s3.BucketEncryption.S3_MANAGED,
                      enforce_ssl=True, versioned=True, removal_policy=RemovalPolicy.DESTROY if stage else RemovalPolicy.RETAIN,
                      auto_delete_objects=bool(stage),
                      lifecycle_rules=[s3.LifecycleRule(noncurrent_version_expiration=Duration.days(30))])
        role = iam.Role(self, "IntegrationRole", role_name=integration_role(stage), path="/continuum/integrations/",
                        assumed_by=iam.ServicePrincipal("continuum.amazonaws.com", conditions={
                            "StringEquals": {"sts:ExternalId": external_id(stage), "aws:SourceAccount": self.account}}))
        role.add_to_policy(iam.PolicyStatement(actions=["s3:ListBucket"], resources=[b.bucket_arn]))
        role.add_to_policy(iam.PolicyStatement(actions=["s3:GetObject", "s3:GetObjectVersion"],
                                               resources=[b.arn_for_objects("code/*"), b.arn_for_objects("context/*")]))
        role.add_to_policy(iam.PolicyStatement(actions=["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion"],
                                               resources=[b.arn_for_objects("continuum-patches/*")]))
        # only the S3-channel targets (radar.targets.CHANNEL) ship here: every zip under code/ is scanned and paid for.
        # prune within code/ only ⇒ zips of targets that moved channel are removed; context/ and patches untouched
        s3deploy.BucketDeployment(self, "Targets", sources=[s3deploy.Source.asset(str(CN_TARGETS_DIR))],
                                  destination_bucket=b, destination_key_prefix="code/", prune=True, memory_limit=512)
        CfnOutput(self, "ContinuumBucketName", value=b.bucket_name)
        CfnOutput(self, "IntegrationRoleArn", value=role.role_arn)
