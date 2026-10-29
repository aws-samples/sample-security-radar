<p align="center">
  <img src="docs/brand/logo.svg" width="112" height="112" alt="Security Radar logo"/>
</p>

<h1 align="center">Security Radar</h1>

<p align="center">
  <b>The trigger for AWS Security Agent and AWS Continuum: a security headline from the outside world →<br/>
  the exact line in your code → a validated patch delivered as a pull / merge request.</b>
</p>

<p align="center">
  <img alt="License: MIT-0" src="https://img.shields.io/badge/license-MIT--0-blue">
  <img alt="AWS CDK" src="https://img.shields.io/badge/AWS%20CDK-Python-FF9900">
  <img alt="Preview" src="https://img.shields.io/badge/AWS%20Continuum%20code%20scanning-preview-8C4FFF">
</p>

[中文说明](README_CN.md)

> **Preview notice.** This sample calls AWS Continuum code scanning, which is in **public preview**. APIs and behaviour
> may change. Use a non-production AWS account.

## What it is

Attacks on exchanges and DeFi protocols move fast: hot-wallet key leaks and contract exploits are often used within
minutes of disclosure. AWS Security Agent and AWS Continuum can review code, prove exploitability and write patches —
but they do not know **what just happened outside, which line of your code it touches, or when a paid scan is worth it**.

Security Radar is the **source** of that chain. It tracks the outside security world (CISA KEV, vendor advisories,
security media, Web3 incident databases; an X source is available but off by default), decides in code what is real and
what is urgent, and when an event matches your code it **pulls the trigger**:

1. **AWS Security Agent** — the radar writes the event as a security requirement and starts a code review; Security Agent
   returns findings and a fix diff.
2. **AWS Continuum** — the radar submits a finding pinned to the file and line and asks for validation; once Continuum
   proves the issue exploitable it produces a patch and opens a **native pull request (GitHub) or merge request (GitLab)**.
3. **A human** reviews and merges.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/respond-loop-dark.svg">
  <img src="docs/diagrams/respond-loop.svg" alt="Respond loop: radar → AWS Security Agent + AWS Continuum">
</picture>

## Key mechanisms

| Mechanism | What it means |
|---|---|
| **Decisions in code, not in an LLM** | De-duplication, independent-source counting, verification level V0–V4, severity P0–P2, version comparison and IOC matching are deterministic code. An LLM (Amazon Bedrock) only writes sentences, each with citations that code checks (citation exists, every number appears in the cited text). |
| **Located to the line** | A pinned vulnerable version or an IOC (address, key) found in your repository becomes a finding with file and line, e.g. `Dockerfile:1`, `composer.json:8`, `.gitlab-ci.yml:2`. When the version cannot be compared, the radar says so and leaves it to Security Agent. |
| **On-chain evidence** | For Web3 incidents the attack transaction is checked on a public RPC node (`eth_getTransactionReceipt`); a successful transaction raises the event to *corroborated*. |
| **Three code hosts, one chain** | Each target lives in exactly one Continuum environment: S3 (patch artifacts), GitHub (native PRs) or GitLab (native MRs). Adding a host is one row in `respond.REPO_CHANNELS`, one adapter in `scripts/sync-fleet.py` and one integration. |
| **Cost guardrails** | A scan is requested only to validate radar findings that were submitted successfully, at most once per environment per 24 h, with scheduled scans off. A daily budget line is flagged on the ops page, never silently enforced. |
| **Operator view** | Daily 08:00 HKT digest (code picks and counts, the LLM writes cited sentences), advisory "possible duplicate" hints, and an ops page listing what needs a human. |

## Architecture

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/architecture-dark.svg">
  <img src="docs/diagrams/architecture.svg" alt="Security Radar architecture">
</picture>

Serverless on AWS: EventBridge (every 10 min) → Step Functions (plan → collect → process → analyze → respond → publish) →
Lambda + DynamoDB + S3 → CloudFront. AWS Security Agent runs in the radar's Region; AWS Continuum runs in `us-east-1`.

| Path | Content |
|---|---|
| `src/radar/` | Parsers, pipeline (normalize → cluster → verify → score), analyst, respond station, on-chain checks, digest, ops rules |
| `infra/` | AWS CDK (Python): two stacks (radar + Security Agent in `ap-northeast-1`, Continuum side in `us-east-1`) |
| `integrations/continuum/targets/` | **Deliberately vulnerable** demo repositories used as scan targets (see below) |
| `ui/` | React 18 + Vite + TypeScript; `ui/mock-data/` for local development only |
| `tests/`, `mutations.txt` | pytest (fixtures recorded once, no network) and a mutation registry proving each guard's test fails when the guard is removed |

## Deploy

**Prerequisites:** a **non-production** AWS account; AWS Continuum code scanning (preview) available in the account;
AWS Security Agent in `ap-northeast-1`; Amazon Bedrock access to Anthropic Claude Sonnet / Haiku; CDK bootstrapped in
`ap-northeast-1` and `us-east-1`; `uv`, Node.js ≥ 22, AWS CLI v2.

```bash
export AWS_PROFILE=<non-production-profile>
./scripts/deploy-all.sh                          # build → both CDK stacks → arm the UI gate → upload UI → one cycle → verify
STAGE=demo ./scripts/deploy-all.sh               # an isolated copy (every name carries the stage)
STAGE=demo ./scripts/verify.sh                   # PASS/FAIL acceptance + integration coverage
STAGE=demo ./scripts/destroy-stage.sh            # remove that copy
```

Optional channels: GitHub PRs (`uv run python scripts/sync-fleet.py --channel github --apply`, then authorize the
AWS Continuum GitHub App once and set `github_repo` in `infra/cdk.json`) and GitLab MRs (`--channel gitlab`, with a
personal access token in `~/.env`; set `gitlab_project`, and `gitlab_url` for a self-managed instance reachable by
Continuum).

**Costs.** AWS Continuum code scanning bills per inference unit — see the AWS Continuum pricing page; scans are the
dominant cost, which is why the radar scans only to validate its own findings. Bedrock, Lambda, DynamoDB, S3 and
CloudFront costs are small for one deployment. Destroy demo stages when you are done.

## ⚠️ Deliberately vulnerable demo code

`integrations/continuum/targets/` contains small repositories that are **vulnerable on purpose** (an unpatched PHP
runtime, a remote file inclusion, a smart contract that trusts a well-known public test key, a Node.js runtime with a
known decompression flaw). They exist only as scan targets for the demo. **Do not deploy them, and do not reuse any key
or address from them.**

## Notes on data sources and access

- Feeds are fetched from their public endpoints and respect each publisher's terms. The X source is **off by default**:
  set `X_SEARCH_URL` and `X_API_KEY` to a data source you are licensed to use, then enable it in `src/radar/registry.py`.
- Test fixtures were recorded once; third-party news text is reduced to title, link, date and one sentence (see `NOTICE`).
- The UI is gated with HTTP Basic Auth at CloudFront (credential generated into AWS Secrets Manager). This is a demo gate,
  not an identity system — for anything beyond a demo, put the site behind Amazon Cognito or AWS IAM Identity Center.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file. Third-party test fixtures are listed in
[NOTICE](NOTICE).

## Disclaimer

This is sample code for demonstration and education. It is not intended for production use as is. You are responsible
for testing, securing and optimizing it for your own requirements and for complying with the terms of every data source
you connect.
