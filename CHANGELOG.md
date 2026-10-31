# Changelog

## [Unreleased]

Incident follow-up: the radar follows a web3 incident the way an on-chain analyst does.
- Amount measures: every amount is a loss, a freeze or context; the headline uses losses only; frozen amount separate.
- Attack phases per report, a named attribution (stated by T1/T2 sources), an attack flow on the event page.
- On-chain station (`radar/onchain.py`): minute-level reconstruction of young web3 incidents from public JSON-RPC —
  ERC-20 outflows, issuer freezes, current EIP-7702 delegation; the sender of a verified attack transaction is followed
  too; per-chain fallback nodes inside one wall-clock RPC budget per run.
- Attack-transaction breakdown (`radar/attacktx.py`): each verified attack tx's ERC-20 transfers, per token the largest
  net gainer / loser, plus the native coin the transaction sends.
- Event page: two tabs (incident / your environment); dispositions set from `scripts/triage.py` with IAM credentials
  (no web write surface), shown read-only; the ops page lists P0 events nobody has dispositioned.
- AWS Security Agent ⇄ GitLab: a gitlab-channel target can be reviewed on the integrated repository
  (`scripts/sa-gitlab-integration.py`), so Security Agent's automatic fix opens a merge request.
- Sources: crypto media, forensic research blogs and an exchange's announcement API.

## [1.0.0] - 2026-10-29

First public release as an AWS sample.

- Radar: 13 public sources (X source available, off by default), clustering with independent-source counting,
  verification levels V0–V4, severity P0–P2 with a 72 h freshness rule, on-chain verification of attack transactions.
- Respond station: AWS Security Agent requirements + code reviews; AWS Continuum findings, scans, issues and patches;
  three code hosts (S3 / GitHub / GitLab) with native PR / MR delivery; cost guardrails in code.
- Operator view: Amazon Bedrock analysis cards and a daily digest, every sentence cited and checked by code;
  possible-duplicate hints; an ops page of what needs a human.
- Infrastructure: three AWS CDK stacks, one-command deploy / verify / destroy, isolated stages.
- Fast path: a mitigate station after the respond step — AWS WAF virtual patches (Count until a human promotes them),
  Route 53 Resolver DNS Firewall (defanged domain indicators + AWS-managed threat lists, ALERT until promoted),
  Amazon Inspector ScanSbom as the dependency judge, optional AWS Security Hub export.
- UI: mitigation section on the event page and a `#/mitigate` page.
