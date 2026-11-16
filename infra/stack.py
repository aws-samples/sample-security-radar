"""Security Radar M1 stack (DESIGN §4). Private by default: both buckets block public access, the site is
reachable only through CloudFront (OAC) behind a fail-closed Basic-auth function."""

import json
from pathlib import Path

import continuum_stack
import mitigate_stack
from aws_cdk import CfnOutput, CfnResource, Duration, Fn, RemovalPolicy, SecretValue, Stack
from aws_cdk import aws_apigateway as apigw
from aws_cdk import aws_cloudfront as cf
from aws_cdk import aws_cloudfront_origins as origins
from aws_cdk import aws_cloudwatch as cw
from aws_cdk import aws_cloudwatch_actions as cw_actions
from aws_cdk import aws_cognito as cognito
from aws_cdk import aws_dynamodb as ddb
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as targets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_route53resolver as r53r
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_s3_deployment as s3deploy
from aws_cdk import aws_secretsmanager as sm
from aws_cdk import aws_securityhub as securityhub
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sns_subscriptions as subs
from aws_cdk import aws_stepfunctions as sfn
from aws_cdk import aws_stepfunctions_tasks as tasks
from constructs import Construct

ROOT = Path(__file__).resolve().parents[1]
# R5.5 recovery windows: how long an overwritten / deleted object stays restorable (scripts/restore.py)
ACCESS_LOG_DAYS = 30        # CloudFront standard logs (they carry reader IPs) are deleted after this
RAW_NONCURRENT_DAYS = 30    # raw batches are append-only: a noncurrent version exists only after a delete
SITE_NONCURRENT_DAYS = 7    # site data is rewritten every cycle: 7 days of history, not months
CYCLE_MINUTES = 5   # = radar.limits.Limits.CYCLE_MINUTES (tests/test_collect_batching.py); research/17
# Site CSP (tests/test_site_headers.py): third-party URLs reach the page (feed links, exchange notices) and one missed
# safeHref was stored XSS (research/action/05 #2). Fitted to the built UI: one external module script, no eval;
# style 'unsafe-inline' because React style props / the radar's injected <style> are inline; data: images = the
# select arrow's SVG background; data: fonts = the small Inter subsets vite inlines into the CSS (a headless run of
# 12 routes with font-src 'self' alone blocked them on the first page); everything fetched is ./data/* on this origin.
SITE_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
            "frame-ancestors 'self'")
# IAM actions of the respond Lambda (R1). Kept equal to the calls in src/radar/continuum_aws.py by
# tests/test_iam_scope.py; resource types per action from the Service Authorization Reference.
TABLE_ACTIONS = ["GetItem", "BatchGetItem", "Query", "PutItem", "UpdateItem", "DeleteItem", "BatchWriteItem"]
TABLE_READ_ACTIONS = ["GetItem", "BatchGetItem", "Query"]
COLLECT_WRITE_KEYS = ["SRC#*"]   # source state, SEEN, crash records, the row-size / station-time ledgers — nothing else
SA_REVIEW_ACTIONS = ["CreateCodeReview", "StartCodeReviewJob", "BatchGetCodeReviewJobs", "ListFindings", "BatchGetFindings",
                     "ListCodeReviews", "ListCodeReviewJobsForCodeReview"]   # reuse an unstarted review (audit 04 6.6)
SA_PACK_ACTIONS = ["ListSecurityRequirements", "BatchCreateSecurityRequirements", "BatchUpdateSecurityRequirements",
                   "BatchDeleteSecurityRequirements"]
# mitigate station (M3): reads anywhere, writes only radar-prefixed web ACLs (B3; tests/test_iam_scope.py)
# CheckCapacity (P2 rule pack): read-only WCU + syntax check of a reader's pack; no resource type ⇒ "*"
WAF_READ_ACTIONS = ["CheckCapacity", "DescribeManagedRuleGroup", "GetWebACL", "ListAvailableManagedRuleGroupVersions", "ListWebACLs"]
WAF_WRITE_ACTIONS = ["UpdateWebACL"]
DNS_READ_ACTIONS = ["ListFirewallDomainLists", "ListFirewallDomains", "ListFirewallRules"]
CN_ACTIONS = ["CreateCodeFinding", "CreateCodeScan", "CreateEnvironment", "CreateIntegration", "GetCodeFinding",
              "GetCodeIssue", "GetCodeIssueArtifact", "GetCodeScan", "GetEnvironment", "ListCodeFindings",
              "ListCodeIssueArtifacts", "ListCodeScans", "ListEnvironments", "ListIntegrations", "UpdateEnvironment"]


class RadarStack(Stack):
    def __init__(self, scope: Construct, cid: str, *, stage: str = "", **kw) -> None:
        super().__init__(scope, cid, **kw)
        ephemeral = bool(stage)  # a non-default stage is a throwaway copy: everything is destroyed with the stack
        keep = RemovalPolicy.DESTROY if ephemeral else RemovalPolicy.RETAIN
        name = continuum_stack.prefix(stage)

        def bucket(name: str, noncurrent_days: int, lifecycle_rules: list[s3.LifecycleRule] = ()) -> s3.Bucket:
            """Versioned (R5.5): an overwrite or a delete — a bad Publish, a wrong prune — is recoverable for
            `noncurrent_days` (scripts/restore.py); older versions expire so the bucket does not grow without bound."""
            return s3.Bucket(self, name, block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                             encryption=s3.BucketEncryption.S3_MANAGED, enforce_ssl=True, versioned=True,
                             removal_policy=keep, auto_delete_objects=ephemeral,
                             lifecycle_rules=[*lifecycle_rules, s3.LifecycleRule(
                                 id="noncurrent", noncurrent_version_expiration=Duration.days(noncurrent_days),
                                 abort_incomplete_multipart_upload_after=Duration.days(1))])

        # raw batches are the evidence and the replay source (recluster): kept, never expired — 30 days in
        # Standard, then Intelligent-Tiering (research/19 B8: the 90-day expiry contradicted "keep everything"; after
        # incremental collection raw/ grows ~25 MB/day ≈ 9 GB/year)
        raw = bucket("RawBucket", RAW_NONCURRENT_DAYS, lifecycle_rules=[s3.LifecycleRule(transitions=[s3.Transition(
            storage_class=s3.StorageClass.INTELLIGENT_TIERING, transition_after=Duration.days(30))])])
        site = bucket("SiteBucket", SITE_NONCURRENT_DAYS)   # ~20 documents rewritten every cycle ⇒ short window

        table = ddb.Table(self, "Table", partition_key=ddb.Attribute(name="pk", type=ddb.AttributeType.STRING),
                          sort_key=ddb.Attribute(name="sk", type=ddb.AttributeType.STRING),
                          billing_mode=ddb.BillingMode.PAY_PER_REQUEST, removal_policy=keep,
                          deletion_protection=not ephemeral,
                          time_to_live_attribute="ttl",         # R5.3: RAW markers + SPEND counters (radar.dynamo._expires)    # R5.5: a stack delete or a console slip cannot drop it
                          point_in_time_recovery_specification=ddb.PointInTimeRecoverySpecification(
                              point_in_time_recovery_enabled=True))
        table.add_global_secondary_index(index_name="gsi1",
                                         partition_key=ddb.Attribute(name="gsi1pk", type=ddb.AttributeType.STRING),
                                         sort_key=ddb.Attribute(name="gsi1sk", type=ddb.AttributeType.STRING))

        # value is set out-of-band (scripts/sync-collector-keys.sh) — never in code or CloudFormation
        secret = sm.Secret(self, "CollectorSecret", description="security-radar collector credentials "
                           "(X_API_KEY, FIRECRAWL_API_KEYS)")

        code = lambda_.Code.from_asset(str(ROOT / "build" / "lambda"))
        # which commit is live: `aws lambda get-function-configuration` answers it (scripts/verify.sh checks it is HEAD)
        env = {"TABLE": table.table_name, "RAW_BUCKET": raw.bucket_name, "SITE_BUCKET": site.bucket_name,
               "RADAR_COMMIT": self.node.try_get_context("commit") or "unknown"}

        def fn(name: str, handler: str, timeout_s: int, memory: int = 512, write_keys: list[str] | None = None,
               **extra) -> lambda_.Function:
            f = lambda_.Function(self, name, runtime=lambda_.Runtime.PYTHON_3_12, architecture=lambda_.Architecture.ARM_64,
                                 handler=f"radar.handlers.{handler}", code=code, timeout=Duration.seconds(timeout_s),
                                 memory_size=memory, environment=env,
                                 log_group=logs.LogGroup(self, f"{name}Logs", retention=logs.RetentionDays.ONE_MONTH,
                                                         removal_policy=RemovalPolicy.DESTROY), **extra)
            # R5.4: the actions radar.dynamo uses, nothing more — grant_read_write_data also gave Scan (whole-table
            # reads) and ConditionCheckItem; no Lambda scans (tests/test_iam_scope.py)
            res = [table.table_arn, f"{table.table_arn}/index/*"]
            if write_keys is None:
                f.add_to_role_policy(iam.PolicyStatement(actions=[f"dynamodb:{a}" for a in TABLE_ACTIONS], resources=res))
            else:
                # R5.4 LeadingKeys: writes only to rows whose partition key matches (tests/test_iam_scope.py runs the
                # station and checks every key it writes); reads stay table-wide
                f.add_to_role_policy(iam.PolicyStatement(
                    actions=[f"dynamodb:{a}" for a in TABLE_ACTIONS if a in TABLE_READ_ACTIONS], resources=res))
                f.add_to_role_policy(iam.PolicyStatement(
                    actions=[f"dynamodb:{a}" for a in TABLE_ACTIONS if a not in TABLE_READ_ACTIONS], resources=res,
                    conditions={"ForAllValues:StringLike": {"dynamodb:LeadingKeys": write_keys}}))
            return f

        plan_fn = fn("PlanFn", "plan", 30)
        # overlap guard: Plan lists this state machine's running executions (name pattern, no reference ⇒ no cycle)
        plan_fn.add_to_role_policy(iam.PolicyStatement(actions=["states:ListExecutions"], resources=[
            f"arn:aws:states:{self.region}:{self.account}:stateMachine:Cycle*"]))
        # … and what a running one is doing (collect-only cycles, roadmap R2.2)
        plan_fn.add_to_role_policy(iam.PolicyStatement(actions=["states:GetExecutionHistory"], resources=[
            f"arn:aws:states:{self.region}:{self.account}:execution:Cycle*:*"]))
        # the station that reads untrusted feed content can write only source-state rows (R5.4)
        collect_fn = fn("CollectFn", "collect_batch", 180, write_keys=COLLECT_WRITE_KEYS)
        collect_fn.add_environment("SECRET_ARN", secret.secret_arn)
        secret.grant_read(collect_fn)
        raw.grant_put(collect_fn)
        # single writer for events: no concurrent cluster/merge races (DESIGN §5)
        process_fn = fn("ProcessFn", "process", 600, memory=1024, reserved_concurrent_executions=1)
        raw.grant_read(process_fn)
        # analyst station: Bedrock Claude via global cross-region inference profiles (research/05 ②)
        analyze_fn = fn("AnalyzeFn", "analyze_events", 600, memory=512, reserved_concurrent_executions=1)
        analyze_fn.add_to_role_policy(iam.PolicyStatement(
            actions=["bedrock:InvokeModel", "bedrock:Converse"],
            resources=[f"arn:aws:bedrock:{self.region}:{self.account}:inference-profile/global.anthropic.claude-*",
                       "arn:aws:bedrock:*::foundation-model/anthropic.claude-*"]))
        publish_fn = fn("PublishFn", "publish_site", 300, memory=1769)   # 1769 MB = one full vCPU: page building is CPU-bound (2026-11-11)
        site.grant_put(publish_fn, "data/*")             # site data only: index.html and the JS bundle are deploy-time (R5.4)
        site.grant_read(publish_fn, "data/search/*")     # search shards are merged, not rebuilt (radar.search)
        site.grant_delete(publish_fn, "data/events/*")   # removed events' stale detail pages (radar.removals)

        # respond station: AWS Security Agent here (Tokyo) + AWS Continuum in us-east-1 (CONTINUUM-INTEGRATION.md)
        sa_code = bucket("SecurityAgentCodeBucket", RAW_NONCURRENT_DAYS)   # code bundles: replaced per deploy
        sa_role = iam.Role(self, "SecurityAgentServiceRole", assumed_by=iam.ServicePrincipal(
            "securityagent.amazonaws.com", conditions={"StringEquals": {"aws:SourceAccount": self.account}}))
        sa_code.grant_read(sa_role)
        sa_role.add_to_policy(iam.PolicyStatement(
            actions=["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            resources=[f"arn:aws:logs:{self.region}:{self.account}:log-group:/aws/securityagent/*"]))
        space = CfnResource(self, "AgentSpace", type="AWS::SecurityAgent::AgentSpace", properties={
            "Name": name, "Description": "Security Radar respond station: radar-triggered code reviews",
            "AwsResources": {"S3Buckets": [sa_code.bucket_arn], "IamRoles": [sa_role.role_arn]},
            "CodeReviewSettings": {"ControlsScanning": True, "GeneralPurposeScanning": True},
            "Tags": [{"Key": "project", "Value": "security-radar"}]})
        pack = CfnResource(self, "RequirementPack", type="AWS::SecurityAgent::SecurityRequirementPack", properties={
            "Name": name, "Status": "ENABLED",
            "Description": "Requirements generated by Security Radar from P0/P1 events (managed by the respond Lambda)",
            "Tags": [{"Key": "project", "Value": "security-radar"}]})
        cn_bucket = continuum_stack.bucket_name(self.account, stage)
        cn_role = f"arn:aws:iam::{self.account}:role/continuum/integrations/{continuum_stack.integration_role(stage)}"
        respond_fn = fn("RespondFn", "respond_events", 600, memory=1024, reserved_concurrent_executions=1)
        for k, v in {"SA_AGENT_SPACE_ID": space.get_att("AgentSpaceId").to_string(),
                     "SA_PACK_ID": pack.get_att("PackId").to_string(), "SA_SERVICE_ROLE_ARN": sa_role.role_arn,
                     "SA_CODE_BUCKET": sa_code.bucket_name, "CN_REGION": "us-east-1", "CN_BUCKET": cn_bucket,
                     "CN_INTEGRATION_ROLE_ARN": cn_role, "CN_EXTERNAL_ID": continuum_stack.external_id(stage),
                     "CN_ENV_NAME": name}.items():
            respond_fn.add_environment(k, v)
        if self.node.try_get_context("github_repo"):  # Continuum GitHub integration target (PR delivery), cdk.json
            respond_fn.add_environment("CN_GITHUB_REPO", self.node.try_get_context("github_repo"))
        for ctx, var in (("sa_gitlab_integration_id", "SA_GITLAB_INTEGRATION_ID"), ("sa_gitlab_repo_id", "SA_GITLAB_REPO_ID")):
            if self.node.try_get_context(ctx):   # C2d: Security Agent reviews the gitlab target on the integrated repo
                respond_fn.add_environment(var, self.node.try_get_context(ctx))
        if self.node.try_get_context("gitlab_project"):  # Continuum GitLab integration target (MR delivery), cdk.json
            respond_fn.add_environment("CN_GITLAB_PROJECT", self.node.try_get_context("gitlab_project"))
        if self.node.try_get_context("gitlab_url"):      # self-managed GitLab; absent ⇒ gitlab.com (radar.respond)
            respond_fn.add_environment("CN_GITLAB_URL", self.node.try_get_context("gitlab_url"))
        if self.node.try_get_context("review_budget") is not None:  # default lives in radar.limits, not here
            respond_fn.add_environment("SA_REVIEWS_PER_DAY", str(self.node.try_get_context("review_budget")))
        # R1 least privilege: exactly the operations radar/continuum_aws.py calls, on the resource types the Service
        # Authorization Reference lists for them (list_securityagent.html / list_continuum.html, read 2026-10-27).
        # tests/test_iam_scope.py keeps this list equal to the calls in the code.
        sa_space_arn = f"arn:aws:securityagent:{self.region}:{self.account}:agent-space/{space.get_att('AgentSpaceId').to_string()}"
        sa_pack_arn = (f"arn:aws:securityagent:{self.region}:{self.account}:security-requirement-pack/"
                       f"{pack.get_att('PackId').to_string()}")
        respond_fn.add_to_role_policy(iam.PolicyStatement(actions=[f"securityagent:{a}" for a in SA_REVIEW_ACTIONS],
                                                          resources=[sa_space_arn]))
        respond_fn.add_to_role_policy(iam.PolicyStatement(actions=[f"securityagent:{a}" for a in SA_PACK_ACTIONS],
                                                          resources=[sa_pack_arn]))
        # environments are created at runtime by the respond Lambda ⇒ ids unknown at synth: scope to this account's
        # Continuum resources in us-east-1 (environments, their findings/scans/issues, integrations)
        cn_arn = f"arn:aws:continuum:us-east-1:{self.account}"
        respond_fn.add_to_role_policy(iam.PolicyStatement(
            actions=[f"continuum:{a}" for a in CN_ACTIONS],
            resources=[f"{cn_arn}:environments/*", f"{cn_arn}:integrations/*"]))
        # C2c PR links: read-only, single-repo GitHub token for the demo fleet. CDK creates a placeholder; the real value
        # is put out of band (scripts/set-fleet-token.sh) so it never appears in the template or in git.
        fleet_ro = sm.Secret(self, "DemoFleetGithubRO", description="security-radar: read-only GitHub token (demo-fleet PRs)",
                             secret_string_value=SecretValue.unsafe_plain_text("placeholder"))
        fleet_ro.grant_read(respond_fn)
        # P3 notify station: its own Lambda after Publish (a message never links to a page not written yet), single
        # writer of the push state (reserved concurrency 1), independent of the Security Agent space. NotifyConfig =
        # bot credentials + the subscription table (radar.notify) as one JSON; placeholder until scripts/set-notify.sh
        # writes it — the station reports not_configured until then. Only this function can read it.
        notify_fn = fn("NotifyFn", "notify_events", 300, memory=512, reserved_concurrent_executions=1)
        notify_cfg = sm.Secret(self, "NotifyConfig", description="security-radar: push credentials + subscriptions (JSON)",
                               secret_string_value=SecretValue.unsafe_plain_text("placeholder"))
        notify_cfg.grant_read(notify_fn)
        notify_fn.add_environment("NOTIFY_SECRET_ARN", notify_cfg.secret_arn)
        respond_fn.add_environment("DEMO_FLEET_RO_SECRET_ARN", fleet_ro.secret_arn)
        # R4 spend tile: Cost Explorer has no resource-level permissions (the reference lists none for this action)
        respond_fn.add_to_role_policy(iam.PolicyStatement(actions=["ce:GetCostAndUsage"], resources=["*"]))
        respond_fn.add_to_role_policy(iam.PolicyStatement(actions=["iam:PassRole"], resources=[sa_role.role_arn, cn_role]))
        respond_fn.add_to_role_policy(iam.PolicyStatement(
            actions=["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
            resources=[f"arn:aws:s3:::{cn_bucket}", f"arn:aws:s3:::{cn_bucket}/*"]))
        sa_code.grant_read(respond_fn)
        s3deploy.BucketDeployment(self, "Targets", sources=[s3deploy.Source.asset(str(continuum_stack.TARGETS_DIR))],
                                  destination_bucket=sa_code, prune=False, memory_limit=512)
        site.grant_put(respond_fn, "data/continuum/*")

        # mitigate station (M3): WAF virtual patches on radar-owned web ACLs (infra/mitigate_stack.py), staged in Count;
        # a human promotes to Block (scripts/promote.py). Own role: the respond role never gets WAF write.
        mitigate_fn = fn("MitigateFn", "mitigate_events", 300, memory=512, reserved_concurrent_executions=1)
        demo_acl = mitigate_stack.demo_acl_name(stage)
        mitigate_fn.add_environment("MITIGATE_WEB_ACLS", json.dumps(
            {t: {"name": demo_acl, "scope": "CLOUDFRONT"} for t in ("demo-shop", "wp-storefront")}))
        mitigate_fn.add_to_role_policy(iam.PolicyStatement(actions=[f"wafv2:{a}" for a in WAF_READ_ACTIONS], resources=["*"]))
        mitigate_fn.add_to_role_policy(iam.PolicyStatement(
            actions=[f"wafv2:{a}" for a in WAF_WRITE_ACTIONS],
            resources=[f"arn:aws:wafv2:us-east-1:{self.account}:global/webacl/security-radar-*/*",
                       f"arn:aws:wafv2:us-east-1:{self.account}:global/managedruleset/*/*"]))
        # DNS Firewall (M3.4): an empty demo VPC (no NAT, no internet path) whose DNS goes through a radar-owned rule group.
        # Domain list contents and rules are runtime state of the mitigate station (CFN never sets them ⇒ never wipes them).
        dns_vpc = ec2.Vpc(self, "DnsDemoVpc", max_azs=1, nat_gateways=0, restrict_default_security_group=True,
                          flow_logs={"all": ec2.FlowLogOptions(destination=ec2.FlowLogDestination.to_cloud_watch_logs(
                              logs.LogGroup(self, "DnsDemoVpcFlowLogs", retention=logs.RetentionDays.ONE_WEEK,
                                            removal_policy=RemovalPolicy.DESTROY)))},   # cdk-nag VPC7
                          subnet_configuration=[ec2.SubnetConfiguration(name="isolated", cidr_mask=24,
                                                                        subnet_type=ec2.SubnetType.PRIVATE_ISOLATED)])
        ioc_list = r53r.CfnFirewallDomainList(self, "IocDomains", name=f"{name}-ioc-domains")
        dns_rg = r53r.CfnFirewallRuleGroup(self, "DnsRuleGroup", name=f"{name}-dns")
        r53r.CfnFirewallRuleGroupAssociation(self, "DnsRuleGroupVpc", firewall_rule_group_id=dns_rg.attr_id,
                                             vpc_id=dns_vpc.vpc_id, priority=1000, name=f"{name}-dns-demo-vpc")
        dns_logs = logs.LogGroup(self, "DnsQueryLogs", retention=logs.RetentionDays.ONE_WEEK, removal_policy=RemovalPolicy.DESTROY)
        qlc = r53r.CfnResolverQueryLoggingConfig(self, "DnsQueryLogging", destination_arn=dns_logs.log_group_arn,
                                                 name=f"{name}-dns-demo")
        r53r.CfnResolverQueryLoggingConfigAssociation(self, "DnsQueryLoggingVpc", resolver_query_log_config_id=qlc.attr_id,
                                                      resource_id=dns_vpc.vpc_id)
        mitigate_fn.add_environment("DNS_RULE_GROUP_ID", dns_rg.attr_id)
        mitigate_fn.add_environment("DNS_DOMAIN_LIST_ID", ioc_list.attr_id)
        mitigate_fn.add_to_role_policy(iam.PolicyStatement(actions=[f"route53resolver:{a}" for a in DNS_READ_ACTIONS],
                                                           resources=["*"]))
        mitigate_fn.add_to_role_policy(iam.PolicyStatement(
            actions=["route53resolver:CreateFirewallRule", "route53resolver:UpdateFirewallRule"],
            resources=[dns_rg.attr_arn, f"arn:aws:route53resolver:{self.region}:*:firewall-domain-list/*"]))
        mitigate_fn.add_to_role_policy(iam.PolicyStatement(actions=["route53resolver:UpdateFirewallDomains"],
                                                           resources=[ioc_list.attr_arn]))
        probe = lambda_.Function(self, "DnsProbeFn", runtime=lambda_.Runtime.PYTHON_3_12, architecture=lambda_.Architecture.ARM_64,
                                 handler="radar.handlers.dns_probe", code=code, timeout=Duration.seconds(15), memory_size=128,
                                 vpc=dns_vpc, vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_ISOLATED),
                                 log_group=logs.LogGroup(self, "DnsProbeFnLogs", retention=logs.RetentionDays.ONE_WEEK,
                                                         removal_policy=RemovalPolicy.DESTROY))
        CfnOutput(self, "DnsProbeFunction", value=probe.function_name)
        CfnOutput(self, "DnsQueryLogGroup", value=dns_logs.log_group_name)
        CfnOutput(self, "DnsRuleGroupId", value=dns_rg.attr_id)

        # Security Hub CSPM (M3.5): the radar's findings next to GuardDuty / Inspector. One hub per account and Region ⇒
        # only the default stage owns it; NO default standards (Neo 2026-10-29: receive radar findings only, no checks).
        # Opt-in (`-c security_hub=on`, set in cdk.json here): enabling an account-wide service is the deployer's call.
        if not stage and self.node.try_get_context("security_hub") == "on":
            securityhub.CfnHub(self, "SecurityHub", enable_default_standards=False, auto_enable_controls=False)
            mitigate_fn.add_environment("SECURITY_HUB", "on")
            mitigate_fn.add_to_role_policy(iam.PolicyStatement(
                actions=["securityhub:BatchImportFindings"],
                resources=[f"arn:aws:securityhub:{self.region}:{self.account}:product/{self.account}/default"]))

        # Inspector as the dependency judge (radar.inspector): stateless ScanSbom over the target zips respond reads
        mitigate_fn.add_to_role_policy(iam.PolicyStatement(actions=["inspector-scan:ScanSbom"], resources=["*"]))
        mitigate_fn.add_environment("SA_CODE_BUCKET", sa_code.bucket_name)
        sa_code.grant_read(mitigate_fn)

        def invoke(name: str, f: lambda_.Function, **extra) -> tasks.LambdaInvoke:
            t = tasks.LambdaInvoke(self, name, lambda_function=f, payload_response_only=True, **extra)
            t.add_retry(errors=["Lambda.ServiceException", "Lambda.SdkClientException"],
                        max_attempts=3, backoff_rate=2, interval=Duration.seconds(5))
            # the single-writer stations run with reserved concurrency 1: an overlapping cycle (5-min rate, or a manual
            # full publish) is throttled — it waits for the other run (~15 s) instead of failing (live 2026-11-10 00:50)
            t.add_retry(errors=["Lambda.TooManyRequestsException"], max_attempts=6, backoff_rate=2,
                        interval=Duration.seconds(15))
            return t

        collect_task = invoke("Collect", collect_fn)
        # a batch that crashed as a whole: its sources keep their state and are due again next cycle
        collect_failed = sfn.Pass(self, "CollectFailed", parameters={"results": [], "failed_batch.$": "$.source_ids"})
        collect_task.add_catch(collect_failed, errors=["States.ALL"], result_path=sfn.JsonPath.DISCARD)
        # one iteration per batch of sources (collect.batches): ~15 invocations for 167 sources, not 167
        fan_out = sfn.Map(self, "CollectAll", items_path="$.sources", max_concurrency=10, result_path="$.results",
                          item_selector={"source_ids.$": "$$.Map.Item.Value.source_ids", "slot.$": "$.slot"})
        fan_out.item_processor(collect_task)
        # analysis failure must not block publishing: catch ⇒ publish with the process output unchanged
        publish_task = invoke("Publish", publish_fn)
        analyze_step = invoke("Analyze", analyze_fn)
        respond_step = invoke("Respond", respond_fn)
        mitigate_step = invoke("Mitigate", mitigate_fn)
        notify_step = invoke("Notify", notify_fn)
        # push never fails the cycle: a failed Notify is caught and the cycle still succeeds (state is per send, so the
        # next run picks up exactly what this one did not send)
        notify_step.add_catch(sfn.Pass(self, "NotifyFailed"), errors=["States.ALL"], result_path="$.notify_error")
        # neither station may block publishing: a failure is caught and publishing proceeds with prior state
        analyze_step.add_catch(sfn.Pass(self, "AnalyzeFailed").next(respond_step), errors=["States.ALL"],
                               result_path="$.analyze_error")
        respond_step.add_catch(sfn.Pass(self, "RespondFailed").next(mitigate_step), errors=["States.ALL"],
                               result_path="$.respond_error")
        mitigate_step.add_catch(sfn.Pass(self, "MitigateFailed").next(publish_task), errors=["States.ALL"],
                                result_path="$.mitigate_error")
        plan_task = invoke("Plan", plan_fn, payload=sfn.TaskInput.from_object(
            {"input.$": "$", "execution.$": "$$.Execution.Id", "started.$": "$$.Execution.StartTime"}))
        # an earlier cycle still running ⇒ this one ends here (handlers.plan): no two cycles collect and process at once
        overlap = sfn.Choice(self, "Overlap").when(sfn.Condition.boolean_equals("$.skip", True),
                                                   sfn.Succeed(self, "SkippedOverlap"))
        # an earlier cycle past collection ⇒ this one collected and ends here: Process stays one writer (handlers.plan)
        collected_only = sfn.Choice(self, "CollectOnly").when(sfn.Condition.boolean_equals("$.collect_only", True),
                                                              sfn.Succeed(self, "CollectedOnly"))
        rest = (invoke("Process", process_fn, payload=sfn.TaskInput.from_object(
                    {"results.$": "$.results", "full.$": "$.full", "slot.$": "$.slot"}))
                .next(analyze_step)
                .next(respond_step)
                .next(mitigate_step)
                .next(publish_task)
                .next(notify_step))
        cycle = fan_out.next(collected_only.otherwise(rest))
        definition = plan_task.next(overlap.otherwise(cycle))
        # every state transition logged (no execution data: payloads carry event ids only, still kept out) + X-Ray (cdk-nag SF1/SF2)
        cycle_logs = logs.LogGroup(self, "CycleLogs", retention=logs.RetentionDays.ONE_MONTH, removal_policy=RemovalPolicy.DESTROY)
        machine = sfn.StateMachine(self, "Cycle", definition_body=sfn.DefinitionBody.from_chainable(definition),
                                   timeout=Duration.minutes(25), tracing_enabled=True,
                                   logs=sfn.LogOptions(destination=cycle_logs, level=sfn.LogLevel.ALL,
                                                       include_execution_data=False))
        # off until the auth gate is verified (deploy order: empty origin → gate → anonymous 401 → content)
        events.Rule(self, "Every10Min", schedule=events.Schedule.rate(Duration.minutes(CYCLE_MINUTES)),
                    targets=[targets.SfnStateMachine(machine)],
                    enabled=self.node.try_get_context("schedule") == "on")

        # ---- alarms (roadmap R0.2): every alarm notifies; the owner hears it through the chat that already works ----
        # SNS → AlertFn → the owner's chat subscriptions (radar.alert). No table, no buckets: it reads one secret.
        alerts = sns.Topic(self, "Alerts", display_name="security-radar alarms", enforce_ssl=True)
        # enforce_ssl gives the topic a resource policy, and with one present nothing is allowed implicitly: without this
        # statement every alarm action failed ("Failed to execute action", live 2026-11-12, found by firing a test alarm)
        alerts.add_to_resource_policy(iam.PolicyStatement(
            actions=["sns:Publish"], resources=[alerts.topic_arn],
            principals=[iam.ServicePrincipal("cloudwatch.amazonaws.com")],
            conditions={"StringEquals": {"aws:SourceAccount": self.account},
                        "ArnLike": {"aws:SourceArn": f"arn:aws:cloudwatch:{self.region}:{self.account}:alarm:*"}}))
        alert_fn = lambda_.Function(
            self, "AlertFn", runtime=lambda_.Runtime.PYTHON_3_12, architecture=lambda_.Architecture.ARM_64,
            handler="radar.handlers.alert", code=code, timeout=Duration.seconds(30), memory_size=256,
            environment={"NOTIFY_SECRET_ARN": notify_cfg.secret_arn},
            log_group=logs.LogGroup(self, "AlertFnLogs", retention=logs.RetentionDays.ONE_MONTH,
                                    removal_policy=RemovalPolicy.DESTROY))

        notify_cfg.grant_read(alert_fn)
        alerts.add_subscription(subs.LambdaSubscription(alert_fn))

        def alarm(name: str, description: str, metric: cw.IMetric, threshold: float, below: bool = False,
                  missing: cw.TreatMissingData = cw.TreatMissingData.NOT_BREACHING) -> cw.Alarm:
            a = cw.Alarm(self, name, alarm_description=f"security-radar: {description}", metric=metric,
                         threshold=threshold, evaluation_periods=1, treat_missing_data=missing,
                         comparison_operator=(cw.ComparisonOperator.LESS_THAN_THRESHOLD if below
                                              else cw.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD))
            a.add_alarm_action(cw_actions.SnsAction(alerts))
            a.add_ok_action(cw_actions.SnsAction(alerts))
            return a

        def log_metric(name: str, group: logs.ILogGroup, pattern: logs.IFilterPattern, minutes: int) -> cw.Metric:
            logs.MetricFilter(self, f"{name}Filter", log_group=group, filter_pattern=pattern,
                              metric_namespace="SecurityRadar", metric_name=name, metric_value="1")
            return cw.Metric(namespace="SecurityRadar", metric_name=name, statistic="Sum", period=Duration.minutes(minutes))

        # dead-man switch on cycles that PUBLISHED: an execution skipped for overlap ends in a Succeed state too (16 % of
        # executions, measured 2026-11-12), so "executions succeeded" stayed green while nothing reached the site
        published = log_metric("CyclePublished", cycle_logs, logs.FilterPattern.literal(
            '{ $.type = "TaskStateExited" && $.details.name = "Publish" }'), 30)
        alarm("NoPublishedCycle", "no cycle published the site in 30 minutes", published, 1, below=True,
              missing=cw.TreatMissingData.BREACHING)
        alarm("CycleFailed", "2 or more cycles failed in 30 minutes",
              machine.metric_failed(period=Duration.minutes(30), statistic="Sum"), 2)
        alarm("CycleTimedOut", "a cycle hit the state machine timeout",
              machine.metric_timed_out(period=Duration.minutes(30), statistic="Sum"), 1)
        # an event changed shape within one cycle (radar.anomaly; the process station logs `degraded: event_anomaly`)
        alarm("EventAnomaly", "an event changed shape within one cycle — see #/ops",
              log_metric("EventAnomaly", process_fn.log_group, logs.FilterPattern.literal('"event_anomaly"'), 5), 1)
        # the last hop itself: an alert that could not be delivered
        alarm("AlertFnErrors", "an alarm could not be delivered to the owner",
              alert_fn.metric_errors(period=Duration.minutes(30), statistic="Sum"), 1)

        # UI credential: generated by Secrets Manager; only its hash reaches CloudFront (scripts/set-ui-auth.sh)
        ui_secret = sm.Secret(self, "UiBasicAuth", description="security-radar UI basic auth (username/password)",
                              generate_secret_string=sm.SecretStringGenerator(
                                  secret_string_template='{"username": "demo"}', generate_string_key="password",  # noqa: S106 # nosec B106 (a username; the password is generated)
                                  exclude_punctuation=True, password_length=24))
        auth_store = cf.KeyValueStore(self, "AuthStore", comment="security-radar basic auth hash")
        auth_fn = cf.Function(self, "BasicAuth", runtime=cf.FunctionRuntime.JS_2_0, key_value_store=auth_store,
                              code=cf.FunctionCode.from_file(file_path=str(ROOT / "infra" / "basic_auth.js")))
        # = the managed SECURITY_HEADERS policy's five headers, values unchanged, plus the CSP
        site_headers = cf.ResponseHeadersPolicy(
            self, "SiteHeaders", comment="security-radar site: managed security headers + CSP",
            security_headers_behavior=cf.ResponseSecurityHeadersBehavior(
                content_security_policy=cf.ResponseHeadersContentSecurityPolicy(content_security_policy=SITE_CSP, override=True),
                content_type_options=cf.ResponseHeadersContentTypeOptions(override=True),
                frame_options=cf.ResponseHeadersFrameOptions(frame_option=cf.HeadersFrameOption.SAMEORIGIN, override=True),
                referrer_policy=cf.ResponseHeadersReferrerPolicy(
                    referrer_policy=cf.HeadersReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN, override=True),
                strict_transport_security=cf.ResponseHeadersStrictTransportSecurity(
                    access_control_max_age=Duration.seconds(31536000), override=True),
                xss_protection=cf.ResponseHeadersXSSProtection(protection=True, mode_block=True, override=True)))
        # ---- token access for agents and scripts (roadmap R7.1) ----
        # Amazon Cognito issues the tokens (client-credentials grant, one app client per consumer, created by
        # scripts/radar-token.py); API Gateway's Cognito authorizer verifies signature, expiry and the scope. The radar
        # mints and checks no token of its own. Read-only: one GET route, one Lambda that reads data/* of the site bucket.
        api_users = cognito.UserPool(
            self, "ApiUsers", user_pool_name=f"{name}-api", self_sign_up_enabled=False,   # no users: machine clients only
            password_policy=cognito.PasswordPolicy(min_length=16, require_digits=True, require_lowercase=True,
                                                   require_uppercase=True, require_symbols=True),
            removal_policy=RemovalPolicy.DESTROY)
        api_users.add_resource_server("ApiResource", identifier="radar", scopes=[
            cognito.ResourceServerScope(scope_name="read", scope_description="read the radar's published documents"),
            cognito.ResourceServerScope(scope_name="subscribe", scope_description="register the caller's own webhook subscriptions")])
        api_domain = api_users.add_domain("ApiDomain", cognito_domain=cognito.CognitoDomainOptions(
            domain_prefix=Fn.join("-", [name, Fn.select(0, Fn.split("-", Fn.select(2, Fn.split("/", self.stack_id))))])))
        api_fn = lambda_.Function(
            self, "ApiFn", runtime=lambda_.Runtime.PYTHON_3_12, architecture=lambda_.Architecture.ARM_64,
            handler="radar.api.handler", code=code, timeout=Duration.seconds(10), memory_size=512,
            environment={"SITE_BUCKET": site.bucket_name},
            log_group=logs.LogGroup(self, "ApiFnLogs", retention=logs.RetentionDays.ONE_MONTH,
                                    removal_policy=RemovalPolicy.DESTROY))
        site.grant_read(api_fn, "data/*")
        read_api = apigw.RestApi(
            self, "ReadApi", rest_api_name=f"{name}-read", endpoint_types=[apigw.EndpointType.REGIONAL],
            cloud_watch_role=True,   # access logs need the account-level API Gateway logging role (none was set)
            deploy_options=apigw.StageOptions(
                stage_name="v1", throttling_rate_limit=20, throttling_burst_limit=40,
                logging_level=apigw.MethodLoggingLevel.ERROR,
                access_log_destination=apigw.LogGroupLogDestination(logs.LogGroup(
                    self, "ReadApiAccess", retention=logs.RetentionDays.ONE_MONTH, removal_policy=RemovalPolicy.DESTROY)),
                access_log_format=apigw.AccessLogFormat.json_with_standard_fields(
                    caller=False, http_method=True, ip=True, protocol=True, request_time=True, resource_path=True,
                    response_length=True, status=True, user=False)))
        api_auth = apigw.CognitoUserPoolsAuthorizer(self, "ReadAuth", cognito_user_pools=[api_users])
        api_root = read_api.root.add_resource("api")
        # self-service webhook subscriptions (R7.3): the API's only writes, under their own scope. The store is one
        # secret (it holds the signing keys); this Lambda reads and writes that secret and nothing else, one at a time.
        self_subs = sm.Secret(self, "SelfSubscriptions", description="security-radar: self-service webhook subscriptions (JSON)",
                              removal_policy=RemovalPolicy.DESTROY)
        subscribe_fn = lambda_.Function(
            self, "SubscribeFn", runtime=lambda_.Runtime.PYTHON_3_12, architecture=lambda_.Architecture.ARM_64,
            handler="radar.subscribe_api.handler", code=code, timeout=Duration.seconds(10), memory_size=512,
            reserved_concurrent_executions=1, environment={"SELF_SUBSCRIPTIONS_ARN": self_subs.secret_arn,
                                                           "TABLE": table.table_name},
            log_group=logs.LogGroup(self, "SubscribeFnLogs", retention=logs.RetentionDays.ONE_MONTH,
                                    removal_policy=RemovalPolicy.DESTROY))
        self_subs.grant_read(subscribe_fn)
        self_subs.grant_write(subscribe_fn)
        # … and one item of the table: the notify station's status row, so a subscriber sees whether its webhook is
        # being delivered (roadmap R8.7). LeadingKeys pins the read to that partition key.
        subscribe_fn.add_to_role_policy(iam.PolicyStatement(
            actions=["dynamodb:GetItem"], resources=[table.table_arn],
            conditions={"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": ["SRC#__notify_status__"]}}))
        self_subs.grant_read(notify_fn)
        notify_fn.add_environment("SELF_SUBSCRIPTIONS_ARN", self_subs.secret_arn)
        subs_res = api_root.add_resource("subscriptions")
        write = {"authorizer": api_auth, "authorization_type": apigw.AuthorizationType.COGNITO,
                 "authorization_scopes": ["radar/subscribe"]}
        for verb in ("GET", "POST"):
            subs_res.add_method(verb, apigw.LambdaIntegration(subscribe_fn), **write)
        subs_res.add_resource("{id}").add_method("DELETE", apigw.LambdaIntegration(subscribe_fn), **write)
        api_root.add_proxy(any_method=False).add_method(
            "GET", apigw.LambdaIntegration(api_fn), authorizer=api_auth,
            authorization_type=apigw.AuthorizationType.COGNITO, authorization_scopes=["radar/read"])

        # ROADMAP R3.6 veto: the phone layout waits for a week of access data. Standard logs (time, path, user agent,
        # IP per request — no cookies, no headers) for ACCESS_LOG_DAYS, then deleted. Not versioned: nothing to restore.
        access_logs = s3.Bucket(self, "AccessLogBucket", block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                encryption=s3.BucketEncryption.S3_MANAGED, enforce_ssl=True,
                                object_ownership=s3.ObjectOwnership.OBJECT_WRITER,   # CloudFront writes logs with an ACL
                                removal_policy=keep, auto_delete_objects=ephemeral,
                                lifecycle_rules=[s3.LifecycleRule(id="expire", expiration=Duration.days(ACCESS_LOG_DAYS))])
        dist = cf.Distribution(
            self, "Site", default_root_object="index.html", price_class=cf.PriceClass.PRICE_CLASS_200,
            enable_logging=True, log_bucket=access_logs, log_file_prefix="site/", log_includes_cookies=False,
            # /api/* → the token-gated API (no Basic Auth function here: API Gateway is the gate; nothing is cached)
            additional_behaviors={"api/*": cf.BehaviorOptions(
                origin=origins.RestApiOrigin(read_api), viewer_protocol_policy=cf.ViewerProtocolPolicy.HTTPS_ONLY,
                # POST / DELETE exist only on /api/subscriptions; every other method on every path is API Gateway's 403
                allowed_methods=cf.AllowedMethods.ALLOW_ALL, cache_policy=cf.CachePolicy.CACHING_DISABLED,
                origin_request_policy=cf.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
                response_headers_policy=site_headers)},
            default_behavior=cf.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(site),
                viewer_protocol_policy=cf.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                cache_policy=cf.CachePolicy.CACHING_OPTIMIZED,
                response_headers_policy=site_headers,
                function_associations=[cf.FunctionAssociation(function=auth_fn,
                                                              event_type=cf.FunctionEventType.VIEWER_REQUEST)]))

        # the address readers are sent to: a public entrance in front of the distribution when there is one (context
        # public_url, infra/cdk.json), else the distribution itself
        site_url = self.node.try_get_context("public_url") or f"https://{dist.distribution_domain_name}"
        notify_fn.add_environment("SITE_URL", site_url)    # links in P3 messages
        alert_fn.add_environment("SITE_URL", site_url)     # the #/ops link in an alert
        publish_fn.add_environment("SITE_URL", site_url)   # links in data/feeds/*
        mitigate_fn.add_environment("SITE_URL", site_url)  # Security Hub remediation links
        for k, v in {"SiteUrl": f"https://{dist.distribution_domain_name}", "DistributionId": dist.distribution_id,
                     "SiteBucketName": site.bucket_name, "AccessLogBucketName": access_logs.bucket_name, "RawBucketName": raw.bucket_name, "TableName": table.table_name,
                     "SecretArn": secret.secret_arn, "UiSecretArn": ui_secret.secret_arn, "DemoFleetRoSecretArn": fleet_ro.secret_arn, "NotifySecretArn": notify_cfg.secret_arn, "AuthStoreArn": auth_store.key_value_store_arn,
                     "StateMachineArn": machine.state_machine_arn, "SaCodeBucketName": sa_code.bucket_name,
                     "AgentSpaceId": space.get_att("AgentSpaceId").to_string(),
                     "RequirementPackId": pack.get_att("PackId").to_string(), "ContinuumBucketName": cn_bucket,
                     "ApiUserPoolId": api_users.user_pool_id,
                     "ApiTokenUrl": f"https://{api_domain.domain_name}.auth.{self.region}.amazoncognito.com/oauth2/token"}.items():
            CfnOutput(self, k, value=v)
