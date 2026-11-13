# Changelog

## [1.2.0] - 2026-11-13

The radar reports its own mistakes, clustering is measured, and collection is wider and faster.

- **Self-monitoring**: an event that changes shape within one cycle (domain flips, absorbs several events, headline
  loss collapses) is reported; a station that fails every run or stopped running, and a source that is not collected
  or went quiet, appear on the ops page. Five Amazon CloudWatch alarms (no published cycle, cycle failed / timed out,
  event anomaly, alert delivery) notify the owner through an Amazon SNS topic.
- **Deploy guard**: `scripts/deploy-all.sh` starts with a preflight (clean deployed paths, full test suite) and ends by
  comparing what the site showed before and after the deployment.
- **Clustering rules, each from a live case**: only a report of an event may merge two events (never a newsletter,
  never a theft with a flaw, never disjoint CVEs); a name is evidence for the event it names, not for every event
  whose coverage mentions it. `scripts/move_item.py` moves one report to another event and keeps it there.
- **Timeliness measured and shown**: published → held and first report → P0 push (median / p90) on the ops page;
  deferred work is retried, CVE records that failed to load are retried, short lists are read every 5–10 minutes.
- **Mitigation stays what was approved**: a promoted AWS WAF rule blocks the rules approved at promotion; what later
  events add keeps counting and is reported. An approved DNS Firewall rule keeps its approved domains.
- **WAF rule pack per event**: rules built from verbatim features of a pinned nuclei template or an evidence
  sentence, checked by an offline AWS WAF matcher, rendered as wafv2 JSON / CloudFormation / Terraform / AWS CLI.
- **Response decisions**: one decision table decides every response action; each event page shows the outcome,
  reason code and time of every action, and "not evaluated" looks unlike "not fired".
- **Notifications**: subscriptions (Slack, Lark, webhook) with their own station after Publish; Atom / JSON feeds.
- **Sources**: the CVE List itself (cvelistV5 delta), CISA CSAF advisories, AWS security bulletins, vendor PSIRTs and
  CERTs, exchange announcement boards, public Telegram channel previews and WeChat official-account feeds — every
  one admitted by an onboarding harness (`scripts/source-onboard.py`). Incremental, batched collection on a
  5-minute cycle.
- **Pages**: search over every event ever published, an exchange announcement board.
- Fixes: a missed secret read no longer marks pending notifications as sent; a webhook address never reaches the ops
  page; RPC errors do not count as verification attempts; a pull request from a fork is not treated as the radar's patch.

## [1.1.1] - 2026-11-11

- `scripts/destroy-stage.sh`: a comment on the heredoc line swallowed the cleanup; cleanup and `cdk destroy` run again.

## [1.1.0] - 2026-11-09

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
