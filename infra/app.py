"""CDK app: `cd infra && npx cdk deploy` (any non-production AWS profile, region ap-northeast-1)."""

import aws_cdk as cdk
from continuum_stack import ContinuumStack
from mitigate_stack import MitigateDemoStack
from stack import RadarStack

app = cdk.App()
# `-c stage=<name>` deploys an independent full copy (reproducibility check); default = the live deployment
stage = app.node.try_get_context("stage") or ""
suffix = stage.capitalize()
stacks = [ContinuumStack(app, f"SecurityRadarContinuum{suffix}", stage=stage, env=cdk.Environment(region="us-east-1")),
          MitigateDemoStack(app, f"SecurityRadarMitigateDemo{suffix}", stage=stage, env=cdk.Environment(region="us-east-1")),
          RadarStack(app, f"SecurityRadar{suffix}", stage=stage, env=cdk.Environment(region="ap-northeast-1"))]
if app.node.try_get_context("nag") == "on":   # CI: an unexplained cdk-nag finding fails synth (infra/nag.py)
    import nag
    nag.apply(stacks)
app.synth()
