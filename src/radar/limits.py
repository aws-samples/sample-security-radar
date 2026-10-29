"""All thresholds in one place (degradation-and-guards §5). Changing a number here changes behaviour
everywhere; tests import these instead of repeating literals."""

from __future__ import annotations


class Limits:
    # --- clustering ---
    ENTITY_WINDOW_DAYS = 3          # same normalized entity within ±N days ⇒ same web3/incident event
    ECHO_TITLE_SIMILARITY = 0.85    # titles this similar from different sources ⇒ echo (same origin)
    MIN_ENTITY_TOKEN_LEN = 3

    # --- verification ---
    FINALIZE_QUIET_DAYS_WEB3 = 7    # web3 V3/V2 → V4 after this many days with stable amount
    FINALIZE_QUIET_DAYS_VULN = 14
    AMOUNT_STABLE_RATIO = 0.10      # |latest - value 7d ago| / latest below this ⇒ stable
    AMOUNT_DISPUTE_RATIO = 3.0      # max/min across sources above this ⇒ amount_disputed

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
    CHAIN_RPC_TIMEOUT_S = 6          # C6: one eth_getTransactionReceipt; worst case 8 × 6 s = 48 s of a 600 s process station
    CHAIN_CHECKS_PER_CYCLE = 8       # C6: RPC calls per 10-min cycle (process station stays well inside its timeout)
    CHAIN_RECHECK_H = 6              # C6: not_found / RPC error ⇒ re-check after this long …
    CHAIN_MAX_ATTEMPTS = 3           # … at most this many times (then the verdict stays not_found)
    HTTP_MAX_BYTES = 20_000_000
    SOURCE_FAILING_AFTER = 3        # consecutive failures ⇒ status "failing"
    TWITTERAPI_MIN_INTERVAL_S = 5.5  # never-topped-up key: 1 request / 5 s
    TWITTERAPI_RETRIES = 2

    # --- respond (AWS Security Agent + AWS Continuum) ---
    RESPOND_WINDOW_DAYS = 7          # only events updated within this window are (re)considered
    RESPOND_MAX_EVENTS = 8           # per cycle; bounds station time (each op is one or two API calls)
    SA_REVIEWS_PER_DAY = 6           # paid Security Agent code reviews (≈27 min, $10/CIU) per rolling 24 h
    CONTINUUM_DAILY_USD_CAP = 500    # R10 budget line: a billed day above is flagged (ledger + log), never blocks a scan
    CONTINUUM_SCHEDULED_SCAN = "PT0H"   # no scheduled scans (API allows only PT0H / P1D / P2D / P7D): the radar triggers the scans it needs
    COST_REFRESH_H = 6               # Cost Explorer read for the ledger ($0.01/request; CE data lags ~24 h anyway)
    NOTIFY_MAX_PER_CYCLE = 10        # Slack/Lark messages per channel per cycle; the rest go next cycle (C3)
    PR_SYNC_H = 1                    # demo-fleet PR list → event pages (C2c); the PR schedule is hourly too
    COST_WINDOW_DAYS = 14            # days of per-service spend shown on #/continuum
    REQUIREMENT_TTL_DAYS = 14        # R6: a radar-* rule not re-asserted for this long leaves the Security Agent pack
    INSPECTOR_SCANS_PER_DAY = 5      # M3: ScanSbom calls per day ($0.03 each, first 25 free); one per target with lockfiles
    MITIGATE_WINDOW_DAYS = 30        # M3: a mitigation stays planned/checked while the event is this fresh (patch windows run long)
    CONTINUUM_SCAN_MIN_INTERVAL_H = 24     # ≤ 1 paid environment scan per day per environment (≈ $450 each, measured 10-26)
