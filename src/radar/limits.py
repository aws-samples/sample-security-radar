"""All thresholds in one place (degradation-and-guards §5). Changing a number here changes behaviour
everywhere; tests import these instead of repeating literals."""

from __future__ import annotations


class Limits:
    TIMEOUT_WATCHDOG_S = 15         # a station logs phases + stack this long before its Lambda deadline
    # R5.6 Bedrock calls per UTC day, per model tier — ~3× measured (2026-11-14: Haiku 715, Sonnet 203 ≈ $6/day). The
    # per-cycle caps bound one run; these bound a day of runs (the 5-minute cycle doubled them). Past the cap a call
    # is not made: llm.converse returns status error / daily_cap and #/ops daily_cap_reached says so.
    BEDROCK_CALLS_PER_DAY_FAST = 2_500
    BEDROCK_CALLS_PER_DAY_BRIEF = 800
    RAW_MARKER_TTL_DAYS = 14        # RAW#…/DONE markers expire (R5.3): Process lists only today's and yesterday's batches
    SPEND_TTL_DAYS = 90             # SPEND#<day> counters expire (R5.3)
    ROW_WARN_BYTES = 250_000        # any table row above this is noted ⇒ #/ops row_near_limit (DynamoDB max 400 KB)
    ROW_MAX_BYTES = 395_000         # … above this the write is refused with the key and the size (R5.3), not a 400 from
                                    # DynamoDB that names neither
    EVENT_ROW_COMPACT_BYTES = 300_000  # an event row above this is compacted before the write (DynamoDB max 400 KB)
    EVENT_STREAM_KEEP = 300         # … and if still too big: the newest report-added / amount-changed entries kept
    # --- cycle & collection (research/17) ---
    CYCLE_MINUTES = 5               # EventBridge rate; infra/stack.py reads this constant
    REFRESH_EVERY_MINUTES = 55      # time-driven refresh (P0→P1 freshness, V4): ≥ this since the last one (ledger), ~hourly
    COLLECT_BATCH = 12              # light sources per Collect invocation (heavy ones run alone)
    COLLECT_THREADS = 8             # host groups fetched concurrently inside one invocation
    COLLECT_DEADLINE_S = 150        # of the 180 s Collect timeout: sources not started by then wait one cycle, logged
    CVE_PENDING_RETRIES = 5         # runs a CVE waits for its unreadable record before it is given up (logged)
    CVE_PENDING_MAX = 200           # CVEs waiting in the source state (~450 B each ⇒ ≤ 90 KB of the 400 KB row)
    MAX_CVE_RECORDS = 60            # CVE records fetched per run (cvelistV5 delta; ~130 new CVEs a day)
    CVE_LIST_EVENT_CVSS = 9.0       # a CVE List entry opens an event only when critical (else it is context)
    # --- incremental collection (collect.incremental) ---
    SEEN_CAP = 3000                 # older entries remembered per source beyond its current response (≈ 45 B each)
    FIRST_RUN_DAYS = 3              # a newly added feed hands over only its last 3 days, not its archive
    POC_RETRIES = 3                 # runs a DeFiHackLabs entry waits for its unreadable .sol before going without it
    # --- clustering ---
    ENTITY_WINDOW_DAYS = 3          # same normalized entity within ±N days ⇒ same web3/incident event
    ENTITY_SPAN_DAYS = 21           # … rolling from the latest evidence, at most this long after the first report
    AMOUNT_OUTLIER_RATIO = 100         # a lone prose loss this many times the event's other figures is an outlier …
    MAX_PLAUSIBLE_LOSS_USD = 20_000_000_000   # … and so is any lone prose loss above this (largest theft on record ≈ $6.3B)
    LATE_LOSS_TOLERANCE = 0.2          # a later report of the victim with a loss within ±20 % of the event's …
    LATE_LOSS_DAYS = 30                # … up to this long after the latest evidence is the same theft
    LATE_LOSS_EXACT_TOLERANCE = 0.02   # a loss within ±2 % (the same figure restated) …
    LATE_LOSS_EXACT_DAYS = 180         # … stays evidence this long (a recovery / post-mortem months later)
    AMOUNT_KEY_WEIGHT = 5              # a shared specific loss figure scores like 5 shared names
    AMOUNT_KEY_MIN_USD = 10_000_000    # amt:<value> clustering key: only a figure this large …
    AMOUNT_KEY_ROUND_USD = 10_000_000  # … and not a multiple of this (「1亿」「$50M」 are common)
    ECHO_TITLE_SIMILARITY = 0.85    # titles this similar from different sources ⇒ echo (same origin)
    MIN_ENTITY_TOKEN_LEN = 3

    # --- verification ---
    FINALIZE_QUIET_DAYS_WEB3 = 7    # web3 V3/V2 → V4 after this many days with stable amount
    FINALIZE_QUIET_DAYS_VULN = 14
    AMOUNT_STABLE_RATIO = 0.10      # |latest - value 7d ago| / latest below this ⇒ stable
    AMOUNT_DISPUTE_RATIO = 3.0      # max/min across sources above this ⇒ amount_disputed
    AMOUNT_DISPUTE_FLOOR = 0.01     # a source's figure below this share of the largest one is a sub-amount or a price, not a rival loss estimate

    # --- severity ---
    P0_FRESH_HOURS = 72             # P0 = "act now": first seen or escalated within this window, else P1
    WEB3_P0_USD = 1_000_000
    WEB3_P1_USD = 100_000
    CVSS_CRITICAL = 9.0

    # --- publish ---
    PUBLISH_WINDOW_DAYS = 60
    PUBLISH_MAX_EVENTS = 500
    EXCERPT_MAX_CHARS = 600

    # --- collection ---
    HTTP_TIMEOUT_S = 25
    SEARCH_URL_READS_PER_RUN = 400   # R3.5: items read per publish for search rows' source URLs (new rows only, once each)
    SOURCE_BUDGET_S = 60             # R2.5: wall time of every request one source makes in a run (direct + fallback +
                                     # follow-ups); live max 86 s (ex_bit2me 11-13) of the 150 s batch deadline
    SOURCE_BUDGET_MIN_CALL_S = 3     # less left than this ⇒ the next call is refused, not started with a uselessly short timeout
    CHAIN_RPC_TIMEOUT_S = 6          # C6: one eth_getTransactionReceipt; worst case 8 × 6 s = 48 s of a 600 s process station
    CHAIN_CHECKS_PER_CYCLE = 8       # C6: RPC calls per 10-min cycle (process station stays well inside its timeout)
    RPC_WALL_S_PER_CYCLE = 120       # all public-RPC calls of one process run (verify + on-chain + attack-tx, fallbacks included); 5-min cycles since 2026-11-10 (typical use ≈ 20 s)
    CHAIN_RECHECK_H = 6              # C6: not_found / RPC error ⇒ re-check after this long …
    CHAIN_MAX_ATTEMPTS = 3           # … at most this many times (then the verdict stays not_found)
    # M4 D6 on-chain reconstruction (radar.onchain): P0 web3 incidents only
    ONCHAIN_ACTIVE_DAYS = 3          # reconstruct while the event is this young (laundering moves for days; issuers freeze for hours)
    ONCHAIN_WINDOW_BEFORE_H = 3      # window starts before first_seen (the drain precedes the first report: Binance 20:24 vs 20:51)
    ONCHAIN_WINDOW_AFTER_H = 24      # … and ends after it
    ONCHAIN_MIN_USD = 1_000_000      # floor of the row / receiver threshold (onchain.min_usd) …
    ONCHAIN_MAX_MIN_USD = 10_000_000 # … its ceiling: routine CEX withdrawals run to a few $M (Binance 18:21–19:55: $1–3M)
    ONCHAIN_LOSS_SHARE = 0.005       # … and its scale: 0.5 % of the incident's loss
    ONCHAIN_CODE_RECHECK_MIN = 60    # eth_getCode of a victim wallet at most this often
    ONCHAIN_MAX_ROWS = 300           # rows kept per case (one ledger entry each, ≤ 400 KB)
    ONCHAIN_MAX_DOWNSTREAM = 8       # receivers followed (≤ 2 hops) — the case must not explode into a chain-wide crawl
    ONCHAIN_CALLS_PER_CYCLE = 40     # all events together; typical 0.5 s/call ⇒ 20 s; worst case 40 × 6 s = 240 s of the 600 s process station
    ATTACKTX_CALLS_PER_CYCLE = 20   # attack-tx breakdown: receipts + block time + token symbol/decimals (receipts never change)
    ATTACKTX_PRICE_CALLS_PER_CYCLE = 5   # ★2 one DefiLlama request per tx (all its tokens + native); prices at a past block never change
    PRICE_MIN_CONFIDENCE = 0.9       # DefiLlama's own confidence; below it (thin pools, a just-exploited token) no dollar figure
    ATTACKTX_MAX_TOKENS = 12        # tokens shown per attack tx (most transfers first); tokens_total states the rest
    ATTACKTX_TOKEN_LEDGER_MAX = 3000  # shared token symbol/decimals ledger, newest kept (~100 B each; one DynamoDB item ≤ 400 KB)
    HTTP_MAX_BYTES = 20_000_000
    PUBLISH_RESERVE_S = 45           # publish stops building event pages with this much left (S3 writes of ~370 docs ≈ 15 s)
    CVE_META_CALLS_PER_RUN = 60      # CVE Services record lookups per publish (112 CVEs live 2026-11-02 ⇒ backfill in 2 runs)
    CVE_META_BUDGET_S = 60           # … and wall time for them, of the publish station's 300 s
    LATE_DETECTION_HOURS = 72        # #/ops late_detection: first seen this long after the CVE record was published …
    LATE_DETECTION_MIN_CVSS = 9.0    # … for a critical CVE …
    LATE_DETECTION_RECENT_DAYS = 14  # … among events first seen this recently (a review queue, not an archive)
    RESURFACED_DAYS = 30             # CVE published this long before the radar's first report ⇒ resurfaced, not missed
    CVE_META_RESCORE_HOURS = 24
    EPSS_MISSING_RECHECK_HOURS = 6   # a CVE FIRST does not score yet (published today) is asked again this often      # an unscored record is re-read this often (CVE-2026-98432: published 10-15, scored 10-24)
    SOURCE_FAILING_AFTER = 3        # consecutive failures ⇒ status "failing"
    # radar.latency — published → held, measured every cycle
    LATENCY_MAX_HOURS = 48          # older when first seen ⇒ a backfill, not a latency sample
    LATENCY_SAMPLES_MAX = 3000      # 24 h of samples (~35 B each; 650 a day measured 2026-11-12)
    LATENCY_WARN_P50_MIN = 60       # #/ops warns above this median (measured 48 on 2026-11-12; R2 targets ≤ 20)
    LATENCY_MIN_SAMPLES = 20        # fewer in 24 h ⇒ stated, not judged
    # #/ops source_stalled (publish.stalled_sources): not collected / gone quiet
    SOURCE_OVERDUE_CADENCES = 3     # no run for this many cadences …
    SOURCE_OVERDUE_MIN_MINUTES = 30 # … and at least this long (cycles are skipped under load: gaps reach 17.5 min)
    SOURCE_SILENT_DAYS = 3          # nothing handed over for this many days …
    SOURCE_SILENT_BASELINE_DAYS = 14  # … by a source whose median over the days before was ≥ 1 a day
    SOURCE_DAYS_KEPT = 30           # per-day counts kept in the source state (~15 B a day)
    TWITTERAPI_MIN_INTERVAL_S = 5.5  # never-topped-up key: 1 request / 5 s
    TWITTERAPI_RETRIES = 2
    X_WINDOW_MAX_H = 24              # R2.4: an X search reaches back to the last success, at most this far
    # X fallback through firecrawl profile snapshots (docs/research/13): 30 credits per handle, from a one-off key pool
    # shared with the blocked-site sources — a cap per day so a long twitterapi outage cannot drain it (≈ 5 full runs)
    X_FIRECRAWL_MAX_HANDLES = 20
    X_FIRECRAWL_CONCURRENCY = 4      # 20 profiles × 5–15 s serially would outlive the 180 s collect Lambda
    X_FIRECRAWL_TIMEOUT_S = 45
    FIRECRAWL_CREDITS_X_PROFILE = 30
    X_FIRECRAWL_CREDITS_PER_DAY = 3_000
    OWN_NAME_BONUS = 4              # once per event: the report names the event's own victim (pipeline._names_event)
    REMOVED_EVENTS_MAX = 2000       # radar.removals ledgers (~80 B a row): what publish must still prune from the site
    # radar.anomaly — an event that changes shape in one cycle (live 2026-11-12: 2 → 703 reports, web3 into vuln)
    ANOMALY_ABSORBED_ITEMS = 20     # absorbing an event this established is reported
    ANOMALY_ITEMS_ADDED = 50        # reports gained in one cycle …
    ANOMALY_GROWTH_MIN_ITEMS = 20   # … or doubling, for an event at least this big
    ANOMALY_CVES_ADDED = 5
    ANOMALY_LOSS_RATIO = 10         # headline loss ×10 either way
    ANOMALY_SHOW_HOURS = 48         # how long a row stays on #/ops
    ANOMALY_MAX = 200               # ledger rows (~300 B each)
    GENERIC_NAME_EVENTS = 3         # a name key held by this many events names none of them (pipeline.find_events)
    MERGE_MAX_CVE_YEARS = 2         # two events whose CVEs are this many years apart are never proved one by a report naming both
    MERGE_MAX_LINKS = 8             # an item citing more pages than this is a newsletter: it attaches, merges nothing
    MERGE_MAX_EVENTS_PER_ITEM = 3   # an item proving more events "the same story" is a digest (it links to all of them)
    SURGE_HOURS = 6                  # R2.3: a P0 updated within this many hours puts the radar in surge …
    SOURCE_IDLE_DAYS = 7             # … a source that handed over nothing for this many days (with ≥ 14 days of
    SOURCE_IDLE_MAX_MIN = 120        #     history) runs at twice its cadence, never slower than this
    HOST_BREAKER_AFTER = 3           # R2.5: this many failures in a row on one host ⇒ its other sources wait for the next cycle
    SOURCE_BACKOFF_AFTER = 3         # R2.5: from the 3rd failure in a row the cadence doubles per failure …
    SOURCE_BACKOFF_MAX_MIN = 360     # … up to 6 h; a success resets it (consecutive_failures = 0)
    RETRY_AFTER_MAX_S = 6 * 3600     # a server's Retry-After is honoured up to 6 h (a longer one is not taken as given)
    FEED_FIRECRAWL_FALLBACKS_PER_DAY = 24   # per source: a direct feed fetch that failed is retried through firecrawl

    # --- respond (AWS Security Agent + AWS Continuum) ---
    RESPOND_WINDOW_DAYS = 7          # only events updated within this window are (re)considered
    RESPOND_MAX_EVENTS = 8           # per cycle; bounds station time (each op is one or two API calls)
    RESPOND_OPEN_JOBS_BOOTSTRAP_DAYS = 30  # one-off look-back for events with open jobs, before the ledger listed them
    SA_REVIEWS_PER_DAY = 6           # paid Security Agent code reviews (≈27 min, $10/CIU) per rolling 24 h
    CONTINUUM_DAILY_USD_CAP = 500    # R10 budget line: a billed day above is flagged (ledger + log), never blocks a scan
    CONTINUUM_SCHEDULED_SCAN = "PT0H"   # no scheduled scans (API allows only PT0H / P1D / P2D / P7D): the radar triggers the scans it needs
    COST_REFRESH_H = 6               # Cost Explorer read for the ledger ($0.01/request; CE data lags ~24 h anyway)
    NOTIFY_MAX_PER_CYCLE = 10        # messages per subscription per cycle; the rest go next cycle (C3 / P3)
    AMOUNT_REFINE_RATIO = 0.05      # a body figure within 5% of the headline's loss refines it (signals.loss_amount)
    NOTIFY_HEADLINE_MIN_CHARS = 4   # a P0 notice's cleaned headline (notify.gate G4)
    NOTIFY_P0_MAX_CHARS = 900       # … and the whole plain-text notice
    NOTIFY_P0_DEDUP_HOURS = 72      # the same CVE / victim again within this window is not a new P0 (gate G3)
    NOTIFY_P0_LEDGER_MAX = 200      # sent P0s remembered per subscription for G3 (a row, bounded)
    SELF_SUBSCRIPTIONS_PER_CLIENT = 3   # self-service webhooks one token client may hold (radar.subscribe_api)
    SELF_SUBSCRIPTIONS_MAX = 20         # … and in all; with the operator's own they stay under NOTIFY_SUBSCRIPTIONS_MAX
    NOTIFY_SUBSCRIPTIONS_MAX = 50    # subscriptions read from the NotifyConfig secret; more are reported, not used
    NOTIFY_STATE_ROW_MAX_BYTES = 200_000   # one push-state row (DynamoDB item limit 400 KB): refused above, never truncated
    NOTIFY_FOLLOW_HOURS = 72         # a removed event's subscribers are corrected within this long after the removal
    NOTIFY_RESERVE_S = 30            # the notify station stops sending with this many seconds left (one send ≤ 2 × HTTP timeout)
    WEBHOOK_SECRET_MIN_CHARS = 32    # per-subscription HMAC key length (≈ 192 bits as base64)
    FEED_MAX_ITEMS = 50              # newest events per data/feeds/<name> document
    PR_SYNC_H = 1                    # demo-fleet PR list → event pages (C2c); the PR schedule is hourly too
    COST_WINDOW_DAYS = 14            # days of per-service spend shown on #/continuum
    REQUIREMENT_TTL_DAYS = 14        # R6: a radar-* rule not re-asserted for this long leaves the Security Agent pack
    INSPECTOR_SCANS_PER_DAY = 5      # M3: ScanSbom calls per day ($0.03 each, first 25 free); one per target with lockfiles
    MITIGATE_WINDOW_DAYS = 30        # M3: a mitigation stays planned/checked while the event is this fresh (patch windows run long)
    REVIEW_LIST_MAX_PAGES = 20             # ListCodeReviews pages read for an unstarted review to reuse (audit 04 6.6)
    CONTINUUM_SCAN_MIN_INTERVAL_H = 24     # ≤ 1 paid environment scan per day per environment (≈ $450 each, measured 10-26)

    # --- P2 WAF rule pack (radar.pocs / radar.wafmatch / radar.rulepack; docs/research/action/01-waf.md, 08-poc-sources.md) ---
    POC_LOOKUPS_PER_HOUR = 30        # GitHub commits-API calls (unauthenticated limit 60/h per IP; the Lambda's IP may be shared)
    POC_LOOKUPS_PER_RUN = 10         # … and per run, so one cycle cannot spend the hour
    POC_BUDGET_S = 30                # wall time for template lookups, of the mitigate station's timeout
    POC_RECHECK_DAYS = 7             # a pinned template's newest commit is re-read this often (templates change: 7–59 commits each)
    POC_INDEX_SHARDS = 32            # cves.json index {cve: path}: 4,585 rows ≈ 10 KB a shard; 40k rows still < POC_ROW_MAX_BYTES
    POC_TEMPLATE_MAX_BYTES = 100_000 # a template larger than this is not stored (state too_large) — real ones are 1–10 KB
    POC_ROW_MAX_BYTES = 200_000      # no ledger row the radar writes for PoCs exceeds this (DynamoDB item limit 400 KB)
    WAF_CHANGELOG_REFRESH_H = 3      # R4.5: AWS managed-rule changelog re-read this often (was once a day)
    WAF_BODY_INSPECT_BYTES = 8_192   # AWS WAF body inspection limit (ALB / AppSync; CloudFront default 16 KB) — the matcher uses the smaller
    WAF_SEARCH_STRING_MAX = 200      # ByteMatchStatement.SearchString max length (API reference)
    RULEPACK_MIN_TOKEN = 3           # a verbatim match string shorter than this is never a rule ("/", "a", "..")
    RULEPACK_MAX_RULES = 20          # custom + template rules per pack (the rest listed as rejected, reason given)
    RULEPACK_MAX_WCU = 500           # a pack above this would take a third of a default web ACL's 1,500 WCU ⇒ capacity over_budget
    RULEPACK_CAPACITY_CHECKS_PER_RUN = 20   # CheckCapacity calls per run (free, read-only); a pack is re-checked only when it changes
    RULEPACK_RATE_LIMIT = 300        # rate template default: requests per IP per 5-minute window (a template value, not evidence)

    # --- C4 v2 cluster judge (radar.cluster_judge; Neo 2026-11-17: evidence candidates, grounded verdicts, shadow merge) ---
    CLUSTER_WINDOW_H = 48            # web3 pairs first seen this close are candidates (Lighter 11-16: the two halves were hours apart)
    CLUSTER_LOSS_TOLERANCE = 0.15    # two headline loss figures within ±15 % of the larger one count as "the same loss"
    CLUSTER_HEADLINES = 5            # report headlines per side in the prompt (and the grounding check's corpus)
    CLUSTER_ITEMS_READ = 20          # reports read per candidate event to pick them (first 10 + last 10: bounded store reads)
    CLUSTER_MERGE_TIME_H = 24        # code evidence "first seen close together" (tighter than the candidate window)
    CLUSTER_MIN_EVIDENCE = 2         # code evidences a grounded 'same' needs before it would merge
    CLUSTER_AUTO_MERGE = False       # SHADOW: would_merge is computed and shown on #/ops; nothing merges until this is True
    CLUSTER_MERGES_PER_CYCLE = 2     # with auto-merge on: pairs merged per analyze run (each one is undoable, see merge())
