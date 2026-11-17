# Changelog

## [1.3.0] - 2026-11-17

Agents and subscribers can read the radar without the UI, collection covers more vendors within a fixed budget, and a
bad write can be undone.

- **Token access for agents**: an Amazon Cognito user pool issues client-credentials tokens (scope `radar/read`,
  one hour); an Amazon API Gateway REST API behind the same CloudFront distribution serves `GET /api/data/*` read-only
  from the site bucket. `scripts/radar-token.py create|list|revoke|usage` issues one app client per consumer and writes
  its credentials to a 0600 file (the secret is never printed).
- **Agent kit** (`src/radar/agentkit/`, standard library only): a CLI (`python -m radar.agentkit.cli`), a stdio MCP
  server (`python -m radar.agentkit.mcp`, no port opened) with read-only tools (`recent_events`, `get_event`,
  `search_events`, `cve_status`, `rule_pack`, `health`, `feeds`), the `security-radar` skill
  (`integrations/skill/security-radar/`) and `llms.txt`. Credentials come from the environment, never follow a
  redirect; errors carry code, message, actual value and limit.
- **Self-registered webhooks**: a client issued with `--subscribe` gets scope `radar/subscribe` and may list, add and
  remove its own https webhook subscriptions (`/api/subscriptions`; another client's are "not found") — the only write
  the API offers. `python -m radar.agentkit.subscriptions` wraps it. The `#/subscribe` page lists feeds, webhooks and
  agent access.
- **Subscription filters and message kinds**: filter by CVE, exploitation, minimum level and minimum loss; message
  kinds `p0` / `update` / `waf` / `verdict` / `pr` / `digest`. A P0 thread gets one correction when its event is
  merged away or withdrawn; the daily digest goes only to subscriptions that list `digest`. New channel `lark_dm`
  (a person by open_id or e-mail).
- **Sources**: Microsoft Security Update Guide (JSON API; Microsoft's own exploited statement is used directly), VMware
  advisories through Broadcom's list API (the first source read by POST), SonicWall PSIRT, Ivanti security
  advisories, Google Cloud security bulletins. Chrome Releases moved to the feed the blog redirects to.
- **Collection within a budget**: every request one source makes in a run shares a 60 s budget; a host that fails 3
  times in a row is skipped for the rest of the run; failing sources back off and `Retry-After` is honoured; while a
  P0 is moving, T1 sources run at half their cadence; a cycle that finds an earlier one still processing only collects.
- **Recovery**: site, raw and code buckets are versioned (old versions kept 7 / 30 / 30 days); the table has deletion
  protection and a TTL for short-lived rows; `scripts/restore.py` restores a bucket prefix as of a time or the table
  into a new table by point-in-time recovery (dry run by default, never deletes a version).
- **Least privilege**: each Lambda gets exactly the table actions the code uses (no `Scan`); the Collect station,
  which reads untrusted feed content, may write only source-state rows (`dynamodb:LeadingKeys`); Publish may write only
  `data/*` of the site bucket. Every table write passes one row-size gate; Amazon Bedrock calls have a daily cap per
  model; cdk-nag exemptions are recorded per resource (`infra/nag_findings.json`).
- **CloudFront standard logs**: kept 30 days in their own bucket, without cookies.
- **Clustering rules**: a digest (newsletter, daily round-up, bulletin) is a report of no single event; a report naming
  CVEs years apart merges nothing; "exploited" counts only when it is said about that event; an attacker's own loss is
  not the victim's.
- **P0 send gate**: every P0 notice is checked right before it is sent — it is P0, has a headline without links,
  links to its own event page, carries no repository findings, no broken characters, says when the event was first
  reported (UTC+8) and fits one block; a second P0 for the same CVE or victim within 72 h is held. A notice that fails
  is not sent, not retried, and listed on the ops page with its code. Each subscription keeps a bounded ledger of the
  P0s it announced. Corrections have kinds (`withdrawn`, `merged`), so a channel can hear a withdrawal and not a merge;
  CloudWatch alarms go only to owner chats that list `alarm` (or set no kinds).
- **Duplicate-event suggestions (shadow)**: candidate pairs are chosen in code from report evidence (shared names,
  close losses, strong keys); a model answers same / different / unsure and must quote the shared victim and one
  headline per side, which code verifies. Grounded suggestions appear on the ops page; nothing merges automatically
  (`Limits.CLUSTER_AUTO_MERGE` is off until labelled precision is measured).
- **Web3 losses**: an earnings result, a position, a valuation, a market move, a liquidation or a leveraged long /
  short is not a theft; a headline figure may be refined by a close body figure; `scripts/recluster_web3.py
  --reclassify` replays one event under these rules (writes need `--event`).
- **UI**: an entry-chunk size gate (≤ 120 KB gzip, every lazy page its own chunk), fonts off the render-blocking path;
  a first-seen order and "new since your last visit" on the home page; an action pack per code target on the event
  page; a freshness line and a reload offer after a deployment; search hits without an event page link to their source.
- Fixes: an event removed again after an earlier prune loses its page again; severity always wins over recency in the listing; a raw line that does not parse is skipped and counted
  instead of failing its batch; redirects to http or internal addresses are refused; Firecrawl answers are
  size-capped; analyst briefs of large events are written from structured records plus the first and newest reports.

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
- **Timeliness measured and shown**: published → held and became P0 → push (median / p90) on the ops page;
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
