"""Source registry — the single source of truth for what we collect (code, not docs).

`python -m radar.registry --explain` prints the table. Tier semantics:
  T1 authoritative (government, vendor PSIRT, security firm with on-chain evidence, reproducible PoC)
  T2 established media / research / aggregators
  T3 community, quick-news re-posters, unknown accounts — never confirms anything on its own
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field

from radar.model import Domain, Tier
from radar.registry_feeds import EXCHANGES, FEEDS, SOCIAL


@dataclass(frozen=True)
class Source:
    source_id: str
    name: str
    tier: Tier
    org: str
    domain: Domain | None          # None ⇒ classify per item (media, mixed X lists)
    parser: str                    # key into radar.parsers.PARSERS
    url: str
    cadence_min: int
    via: str = "direct"            # "direct" | "firecrawl" (sites that block AWS egress, see research/05)
    enabled: bool = True
    always_eventful: bool = False  # structured incident/vuln databases: every entry is an event
    handles: tuple[str, ...] = field(default_factory=tuple)  # X sources only
    url_is_identity: bool = True   # False ⇒ item URLs are synthetic/shared (no per-entry page): no url: key
    board: str | None = None       # "exchange" ⇒ also listed on the announcement board (#/announcements)
    notes: str = ""
    post_json: str | None = None   # an API answered only to POST (Broadcom's advisory list): the JSON body to send


# Admitted feeds whose AWS egress later stopped working: fetched through firecrawl instead (collect: via="firecrawl").
# Each row says when and what was measured — the generated table (registry_feeds) stays as onboarding produced it.
FEED_EGRESS_OVERRIDES: dict[str, tuple[str, int, str]] = {
    # (via, cadence_min, evidence)
    "ubuntu_usn": ("firecrawl", 60, ("2026-11-11 14:30Z: every IPv4 connect from the radar's Lambda egress times out "
                                     "(probe Lambda, Errno 110); firecrawl returns the full RSS")),
}


def _feed(row: tuple) -> Source:
    o = FEED_EGRESS_OVERRIDES.get(row[0])
    if not o:
        return Source(*row)
    sid, name, tier, org, domain, parser, url, _cadence = row
    return Source(sid, name, tier, org, domain, parser, url, o[1], via=o[0], notes=o[2])


@dataclass(frozen=True)
class Handle:
    org: str
    tier: Tier
    domain: Domain | None


# X accounts. Same org as a non-X source ⇒ the two are NOT independent (SlowMist tweet + SlowMist Hacked
# entry count once). Unknown accounts default to T3 (see handle_info).
HANDLES: dict[str, Handle] = {
    "slowmist_team": Handle("slowmist", "T1", "web3"),
    "misttrack_io": Handle("slowmist", "T1", "web3"),
    "peckshieldalert": Handle("peckshield", "T1", "web3"),
    "certikalert": Handle("certik", "T1", "web3"),
    "cyvers_": Handle("cyvers", "T1", "web3"),
    "blocksecteam": Handle("blocksec", "T1", "web3"),
    "phalcon_xyz": Handle("blocksec", "T1", "web3"),
    "zachxbt": Handle("zachxbt", "T1", "web3"),
    "realscamsniffer": Handle("scamsniffer", "T1", "web3"),
    "hypernativelabs": Handle("hypernative", "T1", "web3"),
    "lookonchain": Handle("lookonchain", "T2", "web3"),
    "spotonchain": Handle("spotonchain", "T2", "web3"),
    # M4 D5: Chinese on-chain analysts who tracked the Binance laundering minute by minute; Arkham labels wallets
    "embercn": Handle("embercn", "T2", "web3"),
    "ai_9684xtpa": Handle("ai_9684xtpa", "T2", "web3"),
    "arkham": Handle("arkham", "T2", "web3"),
    "cisacyber": Handle("cisa", "T1", None),
    "watchtowrcyber": Handle("watchtowr", "T2", "vuln"),
    "horizon3attack": Handle("horizon3", "T2", "vuln"),
    "thehackersnews": Handle("thehackernews", "T2", None),
    "bleepincomputer": Handle("bleepingcomputer", "T2", None),
}


def handle_info(handle: str) -> Handle:
    return HANDLES.get(handle.lower(), Handle(f"x:{handle.lower()}", "T3", None))


SOURCES: tuple[Source, ...] = (
    # --- vulnerabilities / exploitation (T1) ---
    Source("cisa_kev", "CISA KEV", "T1", "cisa", "vuln", "kev",
           "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", 5,
           always_eventful=True),
    Source("cisa_advisories", "CISA Advisories", "T1", "cisa", None, "feed",
           "https://www.cisa.gov/cybersecurity-advisories/all.xml", 30),
    Source("chrome_releases", "Chrome Releases", "T1", "google", "vuln", "feed",
           "https://feeds.feedburner.com/GoogleChromeReleases", 10),   # the blog 302s to http:// feedburner (R2.8 refuses the downgrade)
    Source("fortinet_psirt", "Fortinet PSIRT", "T1", "fortinet", "vuln", "feed",
           "https://filestore.fortinet.com/fortiguard/rss/ir.xml", 10),
    # R2.7 coverage (admitted 2026-11-15 by scripts/source-onboard.py from the radar's Lambda: ok, newest within days)
    Source("sonicwall_psirt", "SonicWall PSIRT", "T1", "sonicwall", "vuln", "feed",
           "https://psirtapi.global.sonicwall.com/api/v1/feed/rss.xml", 30),
    Source("ivanti_advisories", "Ivanti Security Advisories", "T1", "ivanti", "vuln", "feed",
           "https://www.ivanti.com/blog/topics/security-advisory/rss", 30),
    # Microsoft's own CVEs (not Azure Linux copies of upstream ones), newest revision first — reached directly from the
    # radar's Lambda (scripts/probe-from-lambda.py 2026-11-15: 200, 457 KB, 1.1 s)
    Source("msrc", "Microsoft Security Update Guide", "T1", "microsoft", "vuln", "msrc",
           "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability?$filter=isMariner%20eq%20false%20and%20"
           "issuingCna%20eq%20%27Microsoft%27&$orderBy=latestRevisionDate%20desc&$top=100", 60),
    # VMware (Broadcom) advisories: no feed since the move to Broadcom; the support portal's list API answers a POST
    # (scripts/probe-from-lambda.py --data 2026-11-15: 200 with the radar's headers, 403 without a User-Agent)
    Source("broadcom_vmsa", "VMware Security Advisories (Broadcom)", "T1", "broadcom", "vuln", "broadcom",
           "https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/getSecurityAdvisoryList", 60,
           post_json='{"pageNumber":0,"pageSize":20,"searchVal":"","segment":"VC","sortInfo":{"column":"","order":""}}'),
    Source("gcp_bulletins", "Google Cloud Security Bulletins", "T1", "google_cloud", "vuln", "feed",
           "https://docs.cloud.google.com/feeds/google-cloud-security-bulletins.xml", 60),
    # CISA advisories through CISA's CSAF provider (GitHub ROLIE feeds): CISA's CDN 403s the radar's AWS egress on the
    # RSS since 2026-11-04 (cisa_advisories below stays for whatever it still delivers). OT = ICS advisories, IT = VA-*.
    Source("cisa_csaf_ot", "CISA ICS Advisories (CSAF)", "T1", "cisa", "vuln", "rolie",
           "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/cisa-csaf-ot-feed-tlp-white.json", 30),
    Source("cisa_csaf_it", "CISA Vulnerability Advisories (CSAF)", "T1", "cisa", "vuln", "rolie",
           "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/IT/white/cisa-csaf-it-feed-tlp-white.json", 30),
    # AWS's own advisories: "is the cloud I run on affected / patched" (2026-11-02: CVE-2026-98432 bulletin 2026-160)
    # the CVE Program's own record feed (cvelistV5 delta.json, ~7-min windows): every new CVE, critical ones as events
    Source("cve_list", "CVE List (cvelistV5 delta)", "T1", "cve", "vuln", "cvelist_delta",
           "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json", 5),
    Source("aws_bulletins", "AWS Security Bulletins", "T1", "aws", "vuln", "feed",
           "https://aws.amazon.com/security/security-bulletins/rss/feed/", 30),
    # --- media (T2) ---
    Source("bleepingcomputer", "BleepingComputer", "T2", "bleepingcomputer", None, "feed",
           "https://www.bleepingcomputer.com/feed/", 15),
    Source("thehackernews", "The Hacker News", "T2", "thehackernews", None, "feed",
           "https://feeds.feedburner.com/TheHackersNews", 15),
    Source("securityweek", "SecurityWeek", "T2", "securityweek", None, "feed",
           "https://www.securityweek.com/feed/", 15),
    Source("anquanke", "安全客", "T2", "anquanke", None, "feed", "https://api.anquanke.com/data/v1/rss", 30),
    Source("freebuf", "FreeBuf", "T2", "freebuf", None, "feed", "https://www.freebuf.com/feed", 30,
           via="firecrawl", enabled=False,
           notes="405 WAF page from AWS egress AND from firecrawl (2026-10-23) — unreachable, kept for visibility"),
    # --- crypto media (T2) — M4 D5: the English first reports and rolling updates of CEX / DeFi incidents
    #     (2026-10-29 Binance: CoinDesk 7, The Defiant 6, The Block 2, Decrypt 2 items in one feed snapshot) ---
    Source("theblock", "The Block", "T2", "theblock", None, "feed", "https://www.theblock.co/rss.xml", 15),
    Source("coindesk", "CoinDesk", "T2", "coindesk", None, "feed", "https://www.coindesk.com/arc/outboundfeeds/rss/", 15),
    Source("decrypt", "Decrypt", "T2", "decrypt", None, "feed", "https://decrypt.co/feed", 15),
    Source("cointelegraph", "Cointelegraph", "T2", "cointelegraph", None, "feed", "https://cointelegraph.com/rss", 15),
    Source("thedefiant", "The Defiant", "T2", "thedefiant", None, "feed", "https://thedefiant.io/api/feed", 15),
    Source("rekt", "rekt.news", "T2", "rekt", "web3", "feed", "https://rekt.news/rss/feed.xml", 60),
    # --- forensic research (T1): full reconstructions and attribution (TRM / Chainalysis named North Korea for Binance);
    #     Elliptic's feed was 404 on 2026-10-30 — not registered ---
    Source("trm_blog", "TRM Labs", "T1", "trm", None, "feed", "https://www.trmlabs.com/resources/blog/rss.xml", 60),
    Source("chainalysis_blog", "Chainalysis", "T1", "chainalysis", None, "feed", "https://www.chainalysis.com/feed/", 60),
    Source("slowmist_medium", "SlowMist Medium", "T1", "slowmist", "web3", "feed", "https://slowmist.medium.com/feed", 60),
    # --- the victim's own channel (T1): official loss / freeze / withdrawal statements, first-hand ---
    Source("binance_announcements", "Binance 公告", "T1", "binance", "web3", "binance_cms",
           # every catalog (listing, delisting, wallet maintenance, 「Security Incident | Recovery Update」…), 10 each —
           # catalog 49 alone missed the recovery updates of Binance's own incident (2026-11-10)
           "https://www.binance.com/bapi/composite/v1/public/cms/article/list/query?type=1&pageNo=1&pageSize=10", 5,
           board="exchange"),
    # --- web3 structured (always eventful) ---
    Source("defillama_hacks", "DeFiLlama Hacks", "T2", "defillama", "web3", "defillama",
           "https://api.llama.fi/hacks", 10, always_eventful=True,
           url_is_identity=False),
    Source("slowmist_hacked", "SlowMist Hacked", "T1", "slowmist", "web3", "slowmist",
           "https://hacked.slowmist.io/", 10, always_eventful=True,
           url_is_identity=False),
    Source("defihacklabs", "DeFiHackLabs", "T1", "defihacklabs", "web3", "defihacklabs",
           "https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/main/README.md", 30,
           always_eventful=True, notes="PoC .sol headers carry Attack Tx; reproducible ⇒ T1"),
    # --- web3 quick news (T3: speed, not evidence) ---
    Source("odaily", "Odaily 快讯", "T3", "odaily", None, "feed", "https://rss.odaily.news/rss/newsflash", 10),
    Source("panews", "PANews", "T3", "panews", None, "feed",
           "https://www.panewslab.com/rss.xml?lang=zh&type=NEWS", 10),
    # --- X (OFF by default in this sample): connect an X data source you are licensed to use. One OR-query covers
    # every handle; the parser expects an advanced-search page ({"tweets": [...]}). Set X_SEARCH_URL + X_API_KEY.
    Source("x_security", "X · security accounts", "T1", "x", None, "twitterapi",
           "", 60, handles=tuple(HANDLES), enabled=False,
           notes="off by default: bring your own licensed X data source (X_SEARCH_URL, X_API_KEY)"),
    # admitted by scripts/source-onboard.py — the tables live in registry_feeds (generated, one row per feed)
    *(_feed(row) for row in FEEDS),
    *(Source(*row, board="exchange") for row in EXCHANGES),
    *(Source(*row) for row in SOCIAL),
)

if len({s.source_id for s in SOURCES}) != len(SOURCES):   # an import-time invariant; `assert` vanishes under python -O
    raise ValueError("duplicate source_id in SOURCES")
BY_ID: dict[str, Source] = {s.source_id: s for s in SOURCES}


def _reporter_tokens() -> frozenset[str]:
    """Words that name a *reporter*, derived from the registry: every non-exchange source's org, name words and domain
    stem. Live 2026-11-10 (dry run of the 141 onboarded feeds): ChainCatcher's own name in every body glued 16 unrelated
    reports — Binance, Keplr, Drift, ACryptoS — into one event through tok:chaincatcher. The hand list in
    keys.MATCH_STOP could not keep up with 167 sources. An exchange's own board is not a reporter: an exchange is
    often the victim (Binance)."""
    out: set[str] = set()
    for s in SOURCES:
        if s.board == "exchange" or s.parser == "twitterapi":
            continue
        host = s.url.split("/")[2] if "://" in s.url else ""
        stem = host.split(".")[-2] if host.count(".") >= 1 else ""
        # identity only — org, domain stem, a one-word brand name. NOT the words of a multi-word name: 「Google News ·
        # crypto hacks」 made tok:hack a reporter and split 9 Binance reports off the Binance event (domain replay)
        brand = [w for w in re.findall(r"[a-z0-9]+", s.name.lower()) if len(w) >= 4]
        out |= {w for w in (stem, s.org.replace("_", ""), *(brand if len(brand) == 1 else ())) if len(w) >= 4}
    victims = {w for s in SOURCES if s.board == "exchange" for w in re.findall(r"[a-z0-9]{3,}", s.org.replace("_", " ").lower())}
    return frozenset(out - victims)


REPORTER_TOKENS = _reporter_tokens()
# Exchange names — victims, from the announcement boards' orgs. A Title Case English headline keeps only name-shaped
# words (keys.headline_names), so 「Binance Confirms 7,499 BTC SAFU Transfer After Hack」 carried no binance key at all
# and had joined the Binance event only through tok:defiant (the reporter's name; domain replay 2026-11-10). Words that
# are also plain English are left out.
_NOT_A_NAME = frozenset({"crypto", "bullish", "gate", "bitbase", "x"})
EXCHANGE_NAMES = frozenset(s.org.split("_")[0] for s in SOURCES
                           if s.board == "exchange" and len(s.org.split("_")[0]) >= 3) - _NOT_A_NAME


def explain() -> str:
    rows = ["| id | name | tier | domain | parser | cadence | via | enabled |", "|---|---|---|---|---|---|---|---|"]
    rows += [f"| {s.source_id} | {s.name} | {s.tier} | {s.domain or 'per-item'} | {s.parser} | {s.cadence_min}m"
             f" | {s.via} | {s.enabled} |" for s in SOURCES]
    return "\n".join(rows)


if __name__ == "__main__":
    if "--explain" in sys.argv:
        print(explain())
