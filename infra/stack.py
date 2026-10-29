"""Security Radar M1 stack (DESIGN §4). Private by default: both buckets block public access, the site is
reachable only through CloudFront (OAC) behind a fail-closed Basic-auth function."""

import json
from pathlib import Path

import continuum_stack
import mitigate_stack
from aws_cdk import CfnOutput, CfnResource, Duration, RemovalPolicy, SecretValue, Stack
from aws_cdk import aws_cloudfront as cf
from aws_cdk import aws_cloudfront_origins as origins
from aws_cdk import aws_cloudwatch as cw
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
from aws_cdk import aws_stepfunctions as sfn
from aws_cdk import aws_stepfunctions_tasks as tasks
from constructs import Construct

ROOT = Path(__file__).resolve().parents[1]
CYCLE_MINUTES = 10
# IAM actions of the respond Lambda (R1). Kept equal to the calls in src/radar/continuum_aws.py by
# tests/test_iam_scope.py; resource types per action from the Service Authorization Reference.
SA_REVIEW_ACTIONS = ["CreateCodeReview", "StartCodeReviewJob", "BatchGetCodeReviewJobs", "ListFindings", "BatchGetFindings"]
SA_PACK_ACTIONS = ["ListSecurityRequirements", "BatchCreateSecurityRequirements", "BatchUpdateSecurityRequirements",
                   "BatchDeleteSecurityRequirements"]
# mitigate station (M3): reads anywhere, writes only radar-prefixed web ACLs (B3; tests/test_iam_scope.py)
WAF_READ_ACTIONS = ["DescribeManagedRuleGroup", "GetWebACL", "ListAvailableManagedRuleGroupVersions", "ListWebACLs"]
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

        def bucket(name: str, **extra) -> s3.Bucket:
            return s3.Bucket(self, name, block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                             encryption=s3.BucketEncryption.S3_MANAGED, enforce_ssl=True,
                             removal_policy=keep, auto_delete_objects=ephemeral, **extra)

        raw = bucket("RawBucket", lifecycle_rules=[s3.LifecycleRule(expiration=Duration.days(90))])
        site = bucket("SiteBucket")

        table = ddb.Table(self, "Table", partition_key=ddb.Attribute(name="pk", type=ddb.AttributeType.STRING),
                          sort_key=ddb.Attribute(name="sk", type=ddb.AttributeType.STRING),
                          billing_mode=ddb.BillingMode.PAY_PER_REQUEST, removal_policy=keep,
                          point_in_time_recovery_specification=ddb.PointInTimeRecoverySpecification(
                              point_in_time_recovery_enabled=True))
        table.add_global_secondary_index(index_name="gsi1",
                                         partition_key=ddb.Attribute(name="gsi1pk", type=ddb.AttributeType.STRING),
                                         sort_key=ddb.Attribute(name="gsi1sk", type=ddb.AttributeType.STRING))

        # value is set out-of-band (scripts/sync-collector-keys.sh) — never in code or CloudFormation
        secret = sm.Secret(self, "CollectorSecret", description="security-radar collector credentials "
                           "(X_API_KEY, FIRECRAWL_API_KEYS)")

        code = lambda_.Code.from_asset(str(ROOT / "build" / "lambda"))
        env = {"TABLE": table.table_name, "RAW_BUCKET": raw.bucket_name, "SITE_BUCKET": site.bucket_name}

        def fn(name: str, handler: str, timeout_s: int, memory: int = 512, **extra) -> lambda_.Function:
            f = lambda_.Function(self, name, runtime=lambda_.Runtime.PYTHON_3_12, architecture=lambda_.Architecture.ARM_64,
                                 handler=f"radar.handlers.{handler}", code=code, timeout=Duration.seconds(timeout_s),
                                 memory_size=memory, environment=env,
                                 log_group=logs.LogGroup(self, f"{name}Logs", retention=logs.RetentionDays.ONE_MONTH,
                                                         removal_policy=RemovalPolicy.DESTROY), **extra)
            table.grant_read_write_data(f)
            return f

        plan_fn = fn("PlanFn", "plan", 30)
        collect_fn = fn("CollectFn", "collect_one", 180)
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
        publish_fn = fn("PublishFn", "publish_site", 300, memory=1024)
        site.grant_put(publish_fn)

        # respond station: AWS Security Agent here (Tokyo) + AWS Continuum in us-east-1 (CONTINUUM-INTEGRATION.md)
        sa_code = bucket("SecurityAgentCodeBucket")
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
        # C3 push credentials (Slack bot token + channel, Lark app + chat) as one JSON; placeholder until
        # scripts/set-notify.sh copies them from ~/.env — the station reports not_configured per channel until then
        notify_cfg = sm.Secret(self, "NotifyConfig", description="security-radar: Slack / Lark push credentials (JSON)",
                               secret_string_value=SecretValue.unsafe_plain_text("placeholder"))
        notify_cfg.grant_read(respond_fn)
        respond_fn.add_environment("NOTIFY_SECRET_ARN", notify_cfg.secret_arn)
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
            t.add_retry(errors=["Lambda.ServiceException", "Lambda.TooManyRequestsException", "Lambda.SdkClientException"],
                        max_attempts=3, backoff_rate=2, interval=Duration.seconds(5))
            return t

        collect_task = invoke("Collect", collect_fn)
        collect_failed = sfn.Pass(self, "CollectFailed", parameters={
            "source_id.$": "$.source_id", "key": None, "count": 0, "ok": False})
        collect_task.add_catch(collect_failed, errors=["States.ALL"], result_path=sfn.JsonPath.DISCARD)
        fan_out = sfn.Map(self, "CollectAll", items_path="$.sources", max_concurrency=6, result_path="$.results",
                          item_selector={"source_id.$": "$$.Map.Item.Value.source_id", "slot.$": "$.slot"})
        fan_out.item_processor(collect_task)
        # analysis failure must not block publishing: catch ⇒ publish with the process output unchanged
        publish_task = invoke("Publish", publish_fn)
        analyze_step = invoke("Analyze", analyze_fn)
        respond_step = invoke("Respond", respond_fn)
        mitigate_step = invoke("Mitigate", mitigate_fn)
        # neither station may block publishing: a failure is caught and publishing proceeds with prior state
        analyze_step.add_catch(sfn.Pass(self, "AnalyzeFailed").next(respond_step), errors=["States.ALL"],
                               result_path="$.analyze_error")
        respond_step.add_catch(sfn.Pass(self, "RespondFailed").next(mitigate_step), errors=["States.ALL"],
                               result_path="$.respond_error")
        mitigate_step.add_catch(sfn.Pass(self, "MitigateFailed").next(publish_task), errors=["States.ALL"],
                                result_path="$.mitigate_error")
        definition = (invoke("Plan", plan_fn)
                      .next(fan_out)
                      .next(invoke("Process", process_fn, payload=sfn.TaskInput.from_object(
                          {"results.$": "$.results", "full.$": "$.full"})))
                      .next(analyze_step)
                      .next(respond_step)
                      .next(mitigate_step)
                      .next(publish_task))
        # every state transition logged (no execution data: payloads carry event ids only, still kept out) + X-Ray (cdk-nag SF1/SF2)
        machine = sfn.StateMachine(self, "Cycle", definition_body=sfn.DefinitionBody.from_chainable(definition),
                                   timeout=Duration.minutes(25), tracing_enabled=True,
                                   logs=sfn.LogOptions(destination=logs.LogGroup(self, "CycleLogs", retention=logs.RetentionDays.ONE_MONTH,
                                                                                 removal_policy=RemovalPolicy.DESTROY),
                                                       level=sfn.LogLevel.ALL, include_execution_data=False))
        # off until the auth gate is verified (deploy order: empty origin → gate → anonymous 401 → content)
        events.Rule(self, "Every10Min", schedule=events.Schedule.rate(Duration.minutes(CYCLE_MINUTES)),
                    targets=[targets.SfnStateMachine(machine)],
                    enabled=self.node.try_get_context("schedule") == "on")

        # dead-man switch: no successful cycle in 30 min ⇒ ALARM (notification wiring deferred: push is M2)
        cw.Alarm(self, "NoSuccessfulCycle", alarm_description="security-radar: no successful cycle in 30 minutes",
                 metric=machine.metric_succeeded(period=Duration.minutes(30), statistic="Sum"),
                 threshold=1, evaluation_periods=1, comparison_operator=cw.ComparisonOperator.LESS_THAN_THRESHOLD,
                 treat_missing_data=cw.TreatMissingData.BREACHING)

        # UI credential: generated by Secrets Manager; only its hash reaches CloudFront (scripts/set-ui-auth.sh)
        ui_secret = sm.Secret(self, "UiBasicAuth", description="security-radar UI basic auth (username/password)",
                              generate_secret_string=sm.SecretStringGenerator(
                                  secret_string_template='{"username": "demo"}', generate_string_key="password",  # nosec B106 (a username; the password is generated)
                                  exclude_punctuation=True, password_length=24))
        auth_store = cf.KeyValueStore(self, "AuthStore", comment="security-radar basic auth hash")
        auth_fn = cf.Function(self, "BasicAuth", runtime=cf.FunctionRuntime.JS_2_0, key_value_store=auth_store,
                              code=cf.FunctionCode.from_file(file_path=str(ROOT / "infra" / "basic_auth.js")))
        dist = cf.Distribution(
            self, "Site", default_root_object="index.html", price_class=cf.PriceClass.PRICE_CLASS_200,
            default_behavior=cf.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(site),
                viewer_protocol_policy=cf.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                cache_policy=cf.CachePolicy.CACHING_OPTIMIZED,
                response_headers_policy=cf.ResponseHeadersPolicy.SECURITY_HEADERS,
                function_associations=[cf.FunctionAssociation(function=auth_fn,
                                                              event_type=cf.FunctionEventType.VIEWER_REQUEST)]))

        respond_fn.add_environment("SITE_URL", f"https://{dist.distribution_domain_name}")  # links in C3 messages
        mitigate_fn.add_environment("SITE_URL", f"https://{dist.distribution_domain_name}")  # Security Hub remediation links
        for k, v in {"SiteUrl": f"https://{dist.distribution_domain_name}", "DistributionId": dist.distribution_id,
                     "SiteBucketName": site.bucket_name, "RawBucketName": raw.bucket_name, "TableName": table.table_name,
                     "SecretArn": secret.secret_arn, "UiSecretArn": ui_secret.secret_arn, "DemoFleetRoSecretArn": fleet_ro.secret_arn, "NotifySecretArn": notify_cfg.secret_arn, "AuthStoreArn": auth_store.key_value_store_arn,
                     "StateMachineArn": machine.state_machine_arn, "SaCodeBucketName": sa_code.bucket_name,
                     "AgentSpaceId": space.get_att("AgentSpaceId").to_string(),
                     "RequirementPackId": pack.get_att("PackId").to_string(), "ContinuumBucketName": cn_bucket}.items():
            CfnOutput(self, k, value=v)
