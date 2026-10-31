"""Source registry — the single source of truth for what we collect (code, not docs).

`python -m radar.registry --explain` prints the table. Tier semantics:
  T1 authoritative (government, vendor PSIRT, security firm with on-chain evidence, reproducible PoC)
  T2 established media / research / aggregators
  T3 community, quick-news re-posters, unknown accounts — never confirms anything on its own
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field

from radar.model import Domain, Tier


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
    notes: str = ""


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
           "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", 30,
           always_eventful=True),
    Source("cisa_advisories", "CISA Advisories", "T1", "cisa", None, "feed",
           "https://www.cisa.gov/cybersecurity-advisories/all.xml", 30),
    Source("chrome_releases", "Chrome Releases", "T1", "google", "vuln", "feed",
           "https://chromereleases.googleblog.com/feeds/posts/default", 30),
    Source("fortinet_psirt", "Fortinet PSIRT", "T1", "fortinet", "vuln", "feed",
           "https://filestore.fortinet.com/fortiguard/rss/ir.xml", 30),
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
           "https://www.binance.com/bapi/composite/v1/public/cms/article/list/query?type=1&catalogId=49&pageNo=1&pageSize=20", 10),
    # --- web3 structured (always eventful) ---
    Source("defillama_hacks", "DeFiLlama Hacks", "T2", "defillama", "web3", "defillama",
           "https://api.llama.fi/hacks", 30, always_eventful=True,
           url_is_identity=False),
    Source("slowmist_hacked", "SlowMist Hacked", "T1", "slowmist", "web3", "slowmist",
           "https://hacked.slowmist.io/", 30, always_eventful=True,
           url_is_identity=False),
    Source("defihacklabs", "DeFiHackLabs", "T1", "defihacklabs", "web3", "defihacklabs",
           "https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/main/README.md", 60,
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
)

BY_ID: dict[str, Source] = {s.source_id: s for s in SOURCES}


def explain() -> str:
    rows = ["| id | name | tier | domain | parser | cadence | via | enabled |", "|---|---|---|---|---|---|---|---|"]
    rows += [f"| {s.source_id} | {s.name} | {s.tier} | {s.domain or 'per-item'} | {s.parser} | {s.cadence_min}m"
             f" | {s.via} | {s.enabled} |" for s in SOURCES]
    return "\n".join(rows)


if __name__ == "__main__":
    if "--explain" in sys.argv:
        print(explain())
