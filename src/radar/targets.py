"""Code bases the respond station checks ("your environment"). Each is uploaded as a zip to
s3://<continuum bucket>/code/<target_id>.zip (and the Security Agent bucket) by
scripts/sync-continuum-targets.sh. Adding a target = one row here + one line in that script.
Continuum quota: ≤10 repositories per environment."""

from __future__ import annotations

# Demo targets live in integrations/continuum/targets/<id>/ — small, realistic, DELIBERATELY vulnerable code bases,
# each mirroring a real incident the radar tracked on 2026-10-23. security-radar = this repo (git archive HEAD).
TARGETS: tuple[tuple[str, str, str], ...] = (
    ("demo-shop", "demo-shop", "PHP 商城：运行时钉在 PHP 8.3.30（PHP2Shell 受影响版本）"),
    ("node-gateway", "node-gateway", "Node.js 遥测网关：Node 24.22.0 + 对公网请求体做 Brotli 解压（Node2Shell）"),
    ("wp-storefront", "wp-storefront", "WordPress 店铺：自研插件按 URL 参数选模板（已修复的白名单写法）"),
    ("alps-vault", "alps-vault", "BNB Chain 质押金库：白名单含 Hardhat 默认账户、现货储备定价、先转账后记账"),
    ("security-radar", "security-radar", "本雷达自身仓库（Python 3.12 Lambda + Node 24 构建的 React UI）"),
)
NAMES = {t[0]: t[1] for t in TARGETS}

# Which Continuum environment validates each target — exactly one (cost, 2026-10-28: the same code in two environments
# was validated and scanned twice; the radar's own 404 KB repo was 99 % of what every S3-environment scan read).
#   s3      the S3 environment (code/<id>.zip in the Continuum bucket) — patches as artifacts
#   github  the GitHub environment on the demo-fleet repo — patches as native pull requests
#   gitlab  the GitLab environment on gitlab.com — patches as native merge requests
#   none    not sent to Continuum (Security Agent still reviews it)
CHANNEL: dict[str, str] = {"demo-shop": "github", "node-gateway": "github", "wp-storefront": "s3",
                           "alps-vault": "gitlab", "security-radar": "none"}
CHANNELS = ("s3", "github", "gitlab", "none")
assert set(CHANNEL) == set(NAMES) and set(CHANNEL.values()) <= set(CHANNELS), "every target needs exactly one channel"


def on(channel: str) -> tuple[str, ...]:
    return tuple(t for t in NAMES if CHANNEL[t] == channel)
