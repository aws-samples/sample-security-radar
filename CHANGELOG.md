# Changelog

## [1.0.0] - 2026-10-29

First public release as an AWS sample.

- Radar: 13 public sources (X source available, off by default), clustering with independent-source counting,
  verification levels V0–V4, severity P0–P2 with a 72 h freshness rule, on-chain verification of attack transactions.
- Respond station: AWS Security Agent requirements + code reviews; AWS Continuum findings, scans, issues and patches;
  three code hosts (S3 / GitHub / GitLab) with native PR / MR delivery; cost guardrails in code.
- Operator view: Amazon Bedrock analysis cards and a daily digest, every sentence cited and checked by code;
  possible-duplicate hints; an ops page of what needs a human.
- Infrastructure: two AWS CDK stacks, one-command deploy / verify / destroy, isolated stages.
