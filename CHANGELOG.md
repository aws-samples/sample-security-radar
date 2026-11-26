# Changelog

## [1.6.20] - 2026-11-26

A code-execution flaw in a mainstream cloud component with a public exploit is P0, authenticated or not (one independent reporter plus the exploit).

## [1.6.19] - 2026-11-26

A how-to / guide article without a CVE opens no event (it was a vulnerability P0 once).

## [1.6.18] - 2026-11-26

Review follow-ups: the arbitration reason is one line of at most 60 characters; P0-wall placement bounds its input; a failing arbitration does not fail the Analyze run; a test keeps model output out of mock data and fixtures.

## [1.6.17] - 2026-11-25

Theft notices: the loss line opens with 💸 (the headline has 💰).

## [1.6.16] - 2026-11-25

P0 notices: a Web3 theft opens with 💰, a vulnerability with 🚨.

## [1.6.15] - 2026-11-25

Subscriptions can exclude P0-wall products (`not_p0_products`), e.g. a channel that takes every P0 except WordPress plugins.

## [1.6.14] - 2026-11-24

Every event on the P0 wall gets a current detail page, including those outside the listing cap (a demoted P0).

## [1.6.13] - 2026-11-24

The attack path no longer places a WAF block when the rule pack is empty; it says why AWS WAF cannot stop the attack (a non-HTTP protocol such as MySQL on 3306 — with the network-access step that does work —, an OS component, or the pack's own reason).

## [1.6.12] - 2026-11-24

Documentation: CONTRIBUTING says the diagrams are committed and arcflow (the maintainer's diagram tool) is not a dependency.

## [1.6.11] - 2026-11-23

The loss headline follows the reports: the latest hack-database update wins, and ≥ 3 independent reports of a larger loss (one T1 / T2, naming the incident) raise the figure.

## [1.6.10] - 2026-11-22

The GitHub advisory lookup accepts ASCII repository names only (`re.ASCII`).

## [1.6.9] - 2026-11-22

A P0 wall (`#/p0`, `p0.json`): every vulnerability P0 of the window on its product tile (95 products in 14 groups, `radar.p0class`); the cloud-component flag a subscription filters on is that taxonomy's group flag.

## [1.6.8] - 2026-11-21

A send arbitration (one fast-model call per P0 cloud-stack vulnerability) decides whether a team channel gets the notice (`team_send`); a failed or uncited answer never sends.

## [1.6.7] - 2026-11-21

A subscription can receive only vulnerabilities in mainstream cloud components (`cloud_stack`).

## [1.6.6] - 2026-11-21

A critical flaw with a public exploit for a newly filed CVE is P0 without a second reporter; a CVE story from a crypto
outlet or a web3 security account is a vulnerability unless it is a crypto theft.

## [1.6.5] - 2026-11-20

Review follow-ups: the GitHub advisory lookup can no longer stop the Analyze step (ASCII owner / repository names, network
and parse errors are a failed lookup, the call is guarded); the published lookup state carries an error code only; the X
source allows the operator's own `X_SEARCH_URL` host; secret temp files are deleted; comments name requirements, not
people; the attack-path prompt marks the evidence as untrusted data; the deck describes one patch per flaw.

## [1.6.4] - 2026-11-20

One patch per flaw: the radar locates the line, Continuum validates and patches it. Security Agent keeps the rules (the
requirement pack); the radar no longer starts a review per event (`SA_EVENT_REVIEWS=1` turns it back on), and a review
never fixes on its own.

## [1.6.3] - 2026-11-20

A vendor advisory listing several CVEs of one product keys all of them (up to 12); a long report about one of the many
CVEs it names keys that one; 「9.8-rated」 reads as critical.

## [1.6.2] - 2026-11-20

A CVE a report names only to set it apart ("distinct from CVE-…") is no longer the event's; the CVE publication date
is the one the event's title names.

## [1.6.1] - 2026-11-19

GitHub advisory ids are linked to their CVEs.

- **GHSA → CVE**: for vulnerability events that name a GitHub advisory and no CVE, the analyze station asks GitHub's
  REST API with a read-only token (Secrets Manager; `scripts/set-ghsa-token.sh`): the global advisory, else the
  repository advisory, and the unreviewed advisories whose references name the GHSA. A link merges the two events of one
  flaw; #/ops warns when the lookup is not configured and before the token expires.

## [1.6.0] - 2026-11-19

Fewer rewrites, checked summaries, a measured duplicate judge, and GitHub advisory ids as identifiers.

- **Briefs**: a brief is rewritten only when a fact the code decided changed — severity or exploitation (at once), the
  CVE set or the loss amount (at most once per 6 h), a cited report that left the event, or a failed brief. Another
  report repeating the story no longer rewrites it (7-day replay: ~203 rewrites a day → ~10). The analyze station builds
  attack paths first and starts no model call with less than 120 s left.
- **Summaries**: the first grounded BLUF sentence becomes the summary only if it does not contradict the code's CVEs,
  exploitation or amount; otherwise the code's own summary is used and the reason is published (`summary_rejected`).
- **Duplicate judge (shadow)**: candidates must share a distinctive word (51,404 → 599 pairs on a 60-day replay), web3
  pairs first, error verdicts retried, a larger token budget. Its quality is measured without labelling: on the
  labelled corpus (`scripts/judge_eval.py`) and daily against delayed truth (shared attack tx / attacker / CVE, two
  records of one hack database), shown on #/ops with the auto-merge bar.
- **GitHub advisory ids**: GHSA ids are identifiers and strong keys; a vulnerability P0 needs a CVE or a GHSA; a notice
  names its identifier when its headline does not, so a CVE assigned later edits the sent notice.
- **Sources**: VulnCheck, ProjectDiscovery, CERT/CC Vulnerability Notes, ZDI published advisories, GreyNoise, Tenable
  Research Advisories (225 in all).
- **Deploys**: the preflight runs the per-commit CI checks (lint, types, UI tests / build, axe) where the maintainer
  pipeline exists, and the deployment synthesizes with cdk-nag; a failed verify check prints why.

## [1.5.0] - 2026-11-19

The site reads on a phone and an iPad, the wall says what it shows, and an event page explains how the attack works.

- **Navigation**: the sidebar collapses to an icon rail (remembered); the wall opens with it collapsed and needs no back
  button. Under 800 px the sidebar is a top bar with a full-screen menu.
- **Phone and iPad**: the wall re-flows by the width of the main area (stage on its own row under 1280 px, one column
  under 760 px); wide tables scroll in their box; grids and the event breadcrumb never push a page wider than the screen.
- **Wall**: the 2D scope and the 3D scene follow the light / dark theme (in the light theme the 3D effects become ink);
  a key 「怎么读这张图」 names every glyph; the centre sphere is captioned with the state of your code; the rings name
  their channel and state. P0 halos and crosshairs scale about themselves (they drew far from their dots).
- **Attack path** (`radar.attack_path`): for P0 / P1 vulnerabilities, entry → condition → trigger → impact in grounded,
  cited sentences, and each defence placed at the step it stops — immediate block, temporary mitigation, long-term fix;
  the radar's own WAF rule pack and AWS's fixed builds are placed by code.
- **Judgement and notices**: a catalog announcement naming no CVE (「CISA Adds Four Known Exploited Vulnerabilities to
  Catalog」) is never P0 / P1; a P0 notice is held, not sent, when its first report gives only a day or a vulnerability
  names no CVE (it is sent once that resolves); a notice deleted by hand gets no later correction.

## [1.4.0] - 2026-11-19

Critical vulnerabilities reach P0 on discovery, sent notices stay current, AWS's own fix status is shown, and the
security review's hardening recommendations are in.

- **P0 on discovery**: a vulnerability whose reports say it is critical (unauthenticated / pre-auth RCE, or CVSS
  9.0–10.0) is P0 once two independent reporting sources say so; catalog listings (CVE records, KEV, CSAF, exploit and
  distro catalogs) are not reports. A 30-day backtest: +15 P0s with reporting sources only, +118 had catalogs counted.
- **Notices stay current**: within 7 days of the send, a Slack P0 notice whose content changed (the AWS line appeared, a
  title or summary was corrected) is edited in place after the same send gate; a vulnerability that turns out exploited
  gets one thread reply. The notice head is shorter: no repeated CVE id or subject, no "a fix was released" clause.
- **AWS fix status** (`radar.awsfix`): for the CVEs of P0 / P1 vulnerability events, the Amazon Linux Security Center's
  per-CVE page — fixed / pending / no fix / not affected per platform, the ALAS advisories — on the event page, and one
  line in the P0 notice. Pages are re-read every 2 h for 3 days after the first read.
- **WAF rule pack**: a new extractor turns an endpoint the vendor's advisory names as vulnerable (or to remove / block)
  into a Count rule on the URI path (URL-decoded, normalized, lower-cased), quoted verbatim and gated offline.
- **Re-normalize from raw** (`scripts/renormalize.py`): re-reads stored reports from their raw batches under today's
  rules and reports what would change (dry run); `--apply-signals` writes judgement fields only.
- **Security hardening** (review recommendations):
  - Webhook targets with a space, CR / LF or a control character are refused at registration and at load;
    `http.client` errors cost one delivery, never the Notify run; the webhook path fails closed on DNS errors;
    NAT64 `64:ff9b::/96` is internal.
  - Self-service subscriptions never receive the operator's code-impact verdict or patch PR links.
  - Every credentialed call follows no redirect off its host (a structural test checks each one).
  - cdk-nag IAM4 / SMG4 / CFR3 reasons say exactly what they exempt; the retained API Gateway CloudWatch role is
    explicit and documented.
  - The agent kit's token cache opens with `O_NOFOLLOW` in a 0700 directory; MCP tool descriptions say results are
    untrusted third-party text.
- **Fixes**: more negations of exploitation ("no exploitation … reported", "not listed in KEV", "none … under active
  attack", FAQ questions); a report listing more than three CVEs merges no events; a source that gives only a day is
  shown as a day, not a made-up time.

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
