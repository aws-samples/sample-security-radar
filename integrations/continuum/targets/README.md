# Demo targets — deliberately vulnerable, never deployed

Each directory here is a small application with **one known class of vulnerability on purpose**. Continuum and
Security Agent are pointed at them (packaged from tracked files to S3 / a repository channel) and scored on whether they
find, prove and patch exactly that bug. Fixing a target would destroy the measurement.

| target | the deliberate defect (docs/design/CONTINUUM-INTEGRATION.md) |
|---|---|
| `wp-storefront` | `shop-pages` plugin: `include $_GET['tpl'] . '.php'` (file inclusion); runtime written only as `php8.3` |
| `node-gateway` | Node runtime pinned at 24.22.0 in 3 places (fix version from the advisory); unauthenticated `/ingest` |
| `demo-shop` | PHP runtime pinned at 8.3.30 in 3 places (PHP2Shell-shaped; fix 8.3.36) |
| `alps-vault` | key-allowlist vault whose allowlist holds the public Hardhat account; a bsc config with a public key |

Nothing here runs: no stack deploys these as services (the only CloudFront in the demo stack refuses every request,
`infra/deny_all.js`). checkov skips this directory (`.checkov.yaml`). semgrep does NOT: a repository `.semgrepignore` made Probe's semgrep job
report zero findings of any kind (scans 1c05a7d8 / 55d55fb, 2026-11-11), and a scanner that silently stops is worse
than a known finding — so the wp-storefront file inclusion stays visible in Probe as the one expected critical.
Incidental dependency advisories inside a target (e.g. `qs` under node-gateway's express) are left as they are for the
same reason: changing a target changes the baseline every recorded scan is compared with.
