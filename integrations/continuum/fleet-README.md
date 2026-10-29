# security-radar-demo-fleet

> ⚠️ **Deliberately vulnerable code. Do not deploy.** Every flaw here is intentional and documented.

Small repositories, each mirroring a real incident that Security Radar tracked on 2026-10-23. Each demo target lives
in exactly one Continuum channel (one environment per repo keeps every scan paid once): this GitHub repo holds
`demo-shop/` and `node-gateway/`; `wp-storefront/` is validated through the S3 channel and `alps-vault/` through the
GitLab channel (gitlab.com). Earlier PRs for the moved directories stay here as history. Security Radar
detects the incident, locates the affected lines in this repository, and hands the work to **AWS Security Agent** and
**AWS Continuum**, which validate exploitability and open pull requests with patches here.

| Directory | Incident (radar) | What is wrong on purpose |
|---|---|---|
| `demo-shop/` | PHP2Shell — PHP core RCE (CVE-2026-109618 / 109619 / 115560), fixed in 8.3.36 | PHP pinned to 8.3.30 in `Dockerfile`, `composer.json`, `.gitlab-ci.yml`; container runs as root |
| `node-gateway/` | Node2Shell — crafted Brotli data → code execution on Node.js 24.22.0 | Node pinned to 24.22.0; public endpoint decompresses untrusted request bodies with the bundled Brotli decoder |

Source of truth: `integrations/continuum/targets/` in the Security Radar repository (`scripts/sync-fleet.py --channel <github|gitlab>`; each mirror holds only its channel's targets).
Merging a Continuum PR here is the one human step in the loop.
