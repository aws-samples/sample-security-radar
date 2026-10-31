"""C2d · a gitlab-channel target is reviewed on the integrated gitlab.com repository (Security Agent's automatic fix then
opens a merge request there); every other target keeps the S3 code bundle; without the integration configured the
gitlab target falls back to S3 too (never a review against nothing)."""
from radar import continuum_aws, targets

ENV = {"SA_CODE_BUCKET": "bucket", "SA_GITLAB_INTEGRATION_ID": "i-0000test", "SA_GITLAB_REPO_ID": "12345678"}


def gitlab_target() -> str:
    return next(t for t, ch in targets.CHANNEL.items() if ch == "gitlab")


def test_the_gitlab_target_is_reviewed_on_the_integrated_repository():
    assert continuum_aws.review_assets(gitlab_target(), ENV) == {
        "integratedRepositories": [{"integrationId": "i-0000test", "providerResourceId": "12345678"}]}


def test_other_targets_and_an_unconfigured_integration_use_the_s3_bundle():
    other = next(t for t, ch in targets.CHANNEL.items() if ch != "gitlab")
    assert continuum_aws.review_assets(other, ENV) == {"sourceCode": [{"s3Location": f"s3://bucket/code/{other}.zip"}]}
    t = gitlab_target()
    assert continuum_aws.review_assets(t, {"SA_CODE_BUCKET": "bucket"}) == {"sourceCode": [{"s3Location": f"s3://bucket/code/{t}.zip"}]}
