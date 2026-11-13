"""Deterministic extraction: ids, canonical URLs, blocking keys. No LLM here — every function has one
correct answer and a unit test."""

from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# ASCII lookarounds, not \b: a CJK neighbour is a word character, so 「微软修复CVE-2026-12345漏洞」 had no cve: key
CVE_RE = re.compile(r"(?<![A-Za-z0-9])CVE-(\d{4})-(\d{4,7})(?![A-Za-z0-9])", re.IGNORECASE)
TX_URL_RE = re.compile(r"https?://(?:www\.)?([a-z0-9.-]+)/tx/(0x[0-9a-fA-F]{64})")
# BlockSec Phalcon names the chain in the path, not the host: …/phalcon/explorer/tx/<chain>/<hash> (docs/research/16:
# the only tx form live posts used that TX_URL_RE missed — X100 "Attack TX", the Binance sweeper call)
PHALCON_TX_RE = re.compile(r"https?://(?:app|phalcon)\.blocksec\.com/(?:phalcon/)?explorer/tx/([a-z0-9-]+)/(0x[0-9a-fA-F]{64})")
PHALCON_CHAIN = {"eth": "ethereum", "bsc": "bsc", "arbitrum": "arbitrum", "base": "base", "polygon": "polygon",
                 "avax": "avalanche", "optimism": "optimism", "linea": "linea", "blast": "blast", "scroll": "scroll",
                 "sonic": "sonic", "gnosis": "gnosis", "fantom": "fantom", "cronos": "cronos"}
X_STATUS_RE = re.compile(r"https?://(?:www\.|mobile\.)?(?:x|twitter)\.com/([A-Za-z0-9_]{1,15})/status(?:es)?/(\d{6,25})")

# explorer host → chain name (only hosts we have seen in sources; unknown hosts keep the host as chain)
EXPLORERS: dict[str, str] = {
    "etherscan.io": "ethereum", "bscscan.com": "bsc", "arbiscan.io": "arbitrum",
    "basescan.org": "base", "polygonscan.com": "polygon", "optimistic.etherscan.io": "optimism",
    "snowtrace.io": "avalanche", "snowscan.xyz": "avalanche", "ftmscan.com": "fantom", "explorer.cronos.org": "cronos",
    "cronoscan.com": "cronos", "lineascan.build": "linea", "blastscan.io": "blast",
    "scrollscan.com": "scroll", "sonicscan.org": "sonic", "gnosisscan.io": "gnosis",
    "app.blocksec.com": "evm", "phalcon.blocksec.com": "evm",
}

_TRACKING_PARAMS = re.compile(r"^(utm_|fbclid$|gclid$|ref$|ref_src$|s$|t$|src$)", re.IGNORECASE)

# words that are never an entity on their own (first-token entity keys would merge unrelated events)
_ENTITY_STOP = frozenset(
    ["the", "a", "an", "of", "and", "for", "on", "in", "by", "to", "with", "from", "new", "defi", "protocol", "finance", "financial", "bridge", "token", "network", "exchange", "wallet", "ai", "dao", "swap", "labs", "chain", "multi", "crypto", "smart", "contract", "hack", "hacked", "exploit", "exploited", "attack", "attacker", "stolen", "drained", "loss", "security", "alert", "update", "breaking", "unknown", "user", "users", "victim"]
)


def short_hash(*parts: str, n: int = 16) -> str:
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:n]


def item_id(source_id: str, identity: str) -> str:
    return "it_" + short_hash(source_id, identity)


def event_id(seed: str) -> str:
    return "ev_" + short_hash(seed)


def canonical_url(url: str) -> str:
    """Lowercase scheme/host, drop fragment, tracking params, trailing slash; twitter.com → x.com."""
    if not url:
        return ""
    p = urlsplit(url.strip())
    host = (p.hostname or "").lower().removeprefix("www.").removeprefix("mobile.")
    if host == "twitter.com":
        host = "x.com"
    q = urlencode([(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if not _TRACKING_PARAMS.match(k)])
    path = p.path.rstrip("/") or "/"
    return urlunsplit(((p.scheme or "https").lower(), host, path, q, ""))


def cves(text: str) -> list[str]:
    return sorted({f"CVE-{y}-{n}" for y, n in CVE_RE.findall(text or "")})


def tx_refs(text: str) -> list[dict[str, str]]:
    """Transaction hashes that appear as explorer URLs (bare 0x64 strings are too ambiguous: they are
    also block hashes, storage slots, signatures)."""
    out: dict[str, dict[str, str]] = {}
    for host, h in TX_URL_RE.findall(text or ""):
        host = host.lower()
        out[h.lower()] = {"chain": EXPLORERS.get(host, host), "hash": h.lower(),
                          "explorer_url": f"https://{host}/tx/{h}"}
    for m in PHALCON_TX_RE.finditer(text or ""):
        ch = PHALCON_CHAIN.get(m.group(1))
        if ch:  # an unknown chain segment is skipped, never guessed (verification would query the wrong node)
            out.setdefault(m.group(2).lower(), {"chain": ch, "hash": m.group(2).lower(), "explorer_url": m.group(0)})
    return list(out.values())


def x_statuses(text: str) -> list[tuple[str, str]]:
    return sorted({(u.lower(), sid) for u, sid in X_STATUS_RE.findall(text or "")})


def entity_key(name: str | None) -> str | None:
    """First significant token of a victim name: 'AlpsCon AI Trade Hub' → 'alpscon', '@WAX_io' → 'wax'."""
    if not name:
        return None
    s = re.sub(r"\(.*?\)", " ", name)                 # 'Ledger (Supply Chain)' → 'Ledger'
    # handle suffixes: '_io' in any case, or a capitalised camel suffix ('BeefyFi'). Case-sensitive on purpose: with
    # IGNORECASE a plain word ending in one ('Hifi' → 'Hi') lost its name and the victim got no key at all (live
    # 2026-10-29: DeFiLlama's and SlowMist's "Hifi Finance" stayed two events)
    s = re.sub(r"(?<=[A-Za-z0-9])(?:_(?i:io|xyz|fi|hq|app|official)|(?:IO|Io|XYZ|Xyz|FI|Fi|HQ|Hq|APP|App|Official))\b", "", s)
    for tok in re.findall(r"[A-Za-z0-9]+", s):
        t = tok.lower()
        if len(t) >= 3 and t not in _ENTITY_STOP and not t.isdigit():
            return t
    return None


# Free-text web3 tokens that name no victim (live 2026-10-29 wrong merges): one shared word of this kind proved nothing,
# yet it attached — "682 ETH … Tornado Cash" (10-27) absorbed CertiK/X100/zkLink reports and then the Binance hot-wallet
# theft through tok:eth / cash / tornado / certik / report; a Tranche Vault event absorbed zkLink, Polymarket and Circle's
# USDC freeze through tok:usdc / slowmist / cause. Kinds: assets and tickers, chains, mixers, the security firms and news
# desks that *report* hacks, tweet boilerplate. Matching only — they never were victim names.
MATCH_STOP = frozenset(
    # assets / tickers
    ["eth", "weth", "steth", "btc", "wbtc", "usdt", "usdc", "usde", "usd1", "usd", "dai", "bnb", "sol", "trx", "xrp",
     "uni", "link", "arb", "op", "ena", "pepe", "pol", "matic", "avax", "xaut", "rlusd", "erc20", "nft", "nfts",
     "stablecoin", "stablecoins", "cryptocurrency", "bitcoin", "ether",
     # chains
     "ethereum", "base", "arbitrum", "avalanche", "optimism", "polygon", "solana", "tron", "bsc", "sui", "aptos",
     "ton", "linea", "blast", "scroll", "sonic", "gnosis", "mainnet",
     # mixers / generic laundering words
     "tornado", "cash", "mixer", "railgun", "exploiter", "drainer", "hot", "cold", "whale", "address", "addresses",
     "fund", "funds", "eip", "eip7702",
     # reporters: security firms, trackers, news desks (they report many hacks; they are not the victim)
     "certik", "certikalert", "certikinsight", "slowmist", "peckshield", "peckshieldalert", "misttrack", "lookonchain",
     "bubblemaps", "zachxbt", "cyvers", "hacken", "blocksec", "phalcon", "phylax", "chainalysis", "elliptic",
     "arkham", "nansen", "panews", "odaily", "bwenews", "tree", "treenews", "watcherguru", "wublockchain",
     "theblock", "coindesk", "cointelegraph", "decrypt", "bleepingcomputer",
     # boilerplate
     "report", "dashboard", "read", "stay", "cause", "root", "powered", "confirmed", "attention", "watch", "more",
     "over", "our", "your", "that", "this", "another", "same", "someone", "data", "ceo", "founder", "news", "market",
     "digital", "oct", "today", "loss", "total", "approximately", "approx", "appreci", "appreciate", "thanks", "please",
     "beware", "warning", "suspected", "potential", "possible",
     # time zones / clock words: 「… reported at 03:14 UTC」 glued SlowMist's TranchePool alert to the Initia event
     # (live 2026-11-11, tok:utc), and its attack tx then pulled the FenceTranchePool records in
     "utc", "gmt", "est", "edt", "pst", "pdt", "cet", "cest", "bst", "ist", "hkt", "sgt", "jst", "kst", "aest",
     # incident vocabulary every alert template capitalises (SlowMist TI 「Root Cause: … Vulnerable …」 glued the
     # TranchePool alert to Yapeswap through tok:vulnerable, live 2026-11-11) — it names what happened, never who
     "vulnerable", "vulnerability", "vulnerabilities", "exploit", "exploits", "exploited", "attack", "attacks",
     "attacked", "attacker", "attackers", "hack", "hacks", "hacked", "hacker", "hackers", "alert", "alerts", "contract",
     "contracts", "flash", "loan", "loans", "governance", "proposal", "malicious", "compromised", "drained", "incident"])

# Common English words that title case or a sentence start capitalises ("One Fish, Multiple Meals", "After the attack",
# "On October 29") — never a name; live 2026-11-02 they glued SlowMist's zkLink analysis to the Binance event. Months,
# weekdays, function words, report vocabulary, generic token standards.
COMMON_WORDS = frozenset(
    ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november",
     "december", "jan", "feb", "mar", "apr", "jun", "jul", "aug", "sep", "sept", "nov", "dec",
     "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
     "one", "two", "three", "four", "five", "first", "second", "third", "last", "next", "every", "each", "all", "any",
     "some", "many", "multiple", "several", "most", "other", "others", "these", "those", "such", "both", "either",
     "after", "before", "during", "while", "when", "where", "what", "which", "who", "why", "how", "then", "than",
     "since", "until", "into", "onto", "upon", "about", "above", "below", "between", "through", "across", "against",
     "instead", "however", "also", "still", "just", "only", "even", "very", "now", "here", "there", "its", "their",
     "his", "her", "they", "them", "we", "you", "not", "but", "yet", "was", "were", "has", "had", "have", "are", "will",
     "can", "could", "would", "should", "may", "might", "must", "did", "does", "been", "being",
     "analysis", "background", "summary", "overview", "conclusion", "recommendations", "prerequisites", "point",
     "points", "full", "used", "using", "use", "team", "official", "independently", "combined", "executed", "check",
     "reset", "reused", "flow", "bind", "queried", "exploitation", "transient", "solidity", "merkle", "cross",
     "erc", "bep20", "trc20", "spl"])

# Chinese names of exchanges ⇒ the token their English reports carry (Chinese titles otherwise yield no token at all,
# so 「Tether在疑似币安黑客攻击中冻结…」 could only attach through tok:usdt).
CEX_ZH: dict[str, str] = {"币安": "binance", "欧易": "okx", "火币": "htx", "抹茶": "mexc", "库币": "kucoin",
                          "芝麻开门": "gate", "派网": "pionex"}

_URL_RE = re.compile(r"https?://\S+")
# Capitalised words and lowercase-led camel names (zkLink, dYdX). ASCII lookarounds instead of \b: in a Chinese headline
# 「Polymarket疑似…」 the CJK neighbour is a word character, so \b never fired and the name was lost.
_CAP_WORD = re.compile(r"(?<![A-Za-z0-9])(?:[A-Z][A-Za-z0-9]{2,}|[a-z]{1,3}[A-Z][A-Za-z0-9]+)(?![A-Za-z0-9])")


def entity_tokens(text: str) -> set[str]:
    """Candidate entity tokens in free text (handles, $TICKERS, capitalised words, Chinese exchange names) for matching
    against existing events. Matching, not discovery: a token only matters if an event has it. URLs are dropped first
    (t.co path ids looked like capitalised words)."""
    text = _URL_RE.sub(" ", text or "")
    toks: set[str] = set()
    for m in re.findall(r"[@$]([A-Za-z0-9_]{2,30})", text):
        k = entity_key(m)
        if k:
            toks.add(k)
    for m in _CAP_WORD.findall(text):
        t = m.lower()
        if t not in _ENTITY_STOP:
            toks.add(t)
    toks |= {v for zh, v in CEX_ZH.items() if zh in text}
    return toks - MATCH_STOP - COMMON_WORDS


# ASCII lookarounds for the same reason (「PHP2Shell漏洞遭利用」 yielded no token)
_NAMED = re.compile(r"(?<![A-Za-z0-9])(?:[A-Za-z]+\d[A-Za-z0-9]*|[A-Z][a-z]+[A-Z][A-Za-z]+|[A-Z]{2,}[a-z]{2,}[A-Za-z]*)"
                    r"(?![A-Za-z0-9])")
_WORD = re.compile(r"(?<![A-Za-z0-9])[A-Za-z][A-Za-z0-9]{2,}(?![A-Za-z0-9])")


def is_title_case(title: str) -> bool:
    """A headline in Title Case (most of its ASCII words capitalised): there capitalisation says nothing about names."""
    t = _URL_RE.sub(" ", title or "")
    # only an English headline: in 「Liquid Network跨链桥被盗3.2亿美元，手法与Bitget事件相似」 every ASCII word IS a name
    letters = [c for c in t if not c.isspace() and not c.isdigit()]
    if not letters or sum(c.isascii() for c in letters) / len(letters) < 0.7:
        return False
    words = _WORD.findall(t)
    return len(words) >= 4 and sum(w[0].isupper() for w in words) / len(words) >= 0.7


def _capitalised_mid_sentence(word: str, body: str) -> bool:
    for m in re.finditer(rf"(?<![A-Za-z0-9]){re.escape(word)}(?![A-Za-z0-9])", body):
        before = body[:m.start()].rstrip(" \t\"'“‘(")
        if before and before[-1] not in ".!?\n:：。！？":
            return True
    return False


def headline_names(title: str, body: str) -> set[str]:
    """entity_tokens of a headline — in a Title Case headline only words that look like names: a name-like shape
    (zkLink, X100), a handle / $ticker / Chinese exchange name, or capitalised mid-sentence in the body too. Live
    2026-11-04: Decrypt's 「Mystery $106 Million Crypto Theft Hits EU Entity Days After Binance Hack」 made mystery /
    million / theft / hits / entity / days "names"; filed under Binance, they became its words and the report kept
    returning there instead of to its own 1.06亿 story."""
    toks = entity_tokens(title)
    if not is_title_case(title):
        return toks
    keep = {entity_key(m) for m in re.findall(r"[@$]([A-Za-z0-9_]{2,30})", title or "")} | {
        v for zh, v in CEX_ZH.items() if zh in (title or "")}
    for w in _CAP_WORD.findall(_URL_RE.sub(" ", title or "")):
        if w.lower() in toks and (w[0].islower() or _NAMED.fullmatch(w) or _capitalised_mid_sentence(w, body or "")):
            keep.add(w.lower())
    return toks & keep


def named_tokens(text: str) -> set[str]:
    """Named vulnerabilities/campaigns ('PHP2Shell', 'CitrixBleed', 'MOVEit'): letters+digits or camel
    case, ≥5 chars. Plain capitalised vendor names ('Microsoft') are excluded on purpose — they would merge
    unrelated stories about the same vendor."""
    out = set()
    text = text or ""
    for mm in _NAMED.finditer(text):
        # an advisory number's prefix is not a name: 「ALAS2023-2026-3389」, 「AV26-1135」 — corpus 2026-11-13: 18 Amazon
        # Linux advisories for 18 packages were one event through tok:alas2023
        if re.match(r"-\d", text[mm.end():mm.end() + 2]):
            continue
        t = mm.group(0).lower()
        if len(t) >= 5 and not t.startswith(("cve", "ghsa", "0x")) and not t.isdigit():
            out.add(t)
    return out
