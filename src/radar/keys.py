"""Deterministic extraction: ids, canonical URLs, blocking keys. No LLM here — every function has one
correct answer and a unit test."""

from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)
TX_URL_RE = re.compile(r"https?://(?:www\.)?([a-z0-9.-]+)/tx/(0x[0-9a-fA-F]{64})")
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
    return list(out.values())


def x_statuses(text: str) -> list[tuple[str, str]]:
    return sorted({(u.lower(), sid) for u, sid in X_STATUS_RE.findall(text or "")})


def entity_key(name: str | None) -> str | None:
    """First significant token of a victim name: 'AlpsCon AI Trade Hub' → 'alpscon', '@WAX_io' → 'wax'."""
    if not name:
        return None
    s = re.sub(r"\(.*?\)", " ", name)                 # 'Ledger (Supply Chain)' → 'Ledger'
    s = re.sub(r"(?<=[a-z])_?(io|xyz|fi|hq|app|official)\b", "", s, flags=re.IGNORECASE)
    for tok in re.findall(r"[A-Za-z0-9]+", s):
        t = tok.lower()
        if len(t) >= 3 and t not in _ENTITY_STOP and not t.isdigit():
            return t
    return None


def entity_tokens(text: str) -> set[str]:
    """Candidate entity tokens in free text (handles, $TICKERS, capitalised words) for matching against
    entity keys of existing events. Matching, not discovery: a token only matters if an event has it."""
    toks: set[str] = set()
    for m in re.findall(r"[@$]([A-Za-z0-9_]{2,30})", text or ""):
        k = entity_key(m)
        if k:
            toks.add(k)
    for m in re.findall(r"\b[A-Z][A-Za-z0-9]{2,}\b", text or ""):
        t = m.lower()
        if t not in _ENTITY_STOP:
            toks.add(t)
    return toks


_NAMED = re.compile(r"\b(?:[A-Za-z]+\d[A-Za-z0-9]*|[A-Z][a-z]+[A-Z][A-Za-z]+|[A-Z]{2,}[a-z]{2,}[A-Za-z]*)\b")


def named_tokens(text: str) -> set[str]:
    """Named vulnerabilities/campaigns ('PHP2Shell', 'CitrixBleed', 'MOVEit'): letters+digits or camel
    case, ≥5 chars. Plain capitalised vendor names ('Microsoft') are excluded on purpose — they would merge
    unrelated stories about the same vendor."""
    out = set()
    for m in _NAMED.findall(text or ""):
        t = m.lower()
        if len(t) >= 5 and not t.startswith(("cve", "ghsa", "0x")) and not t.isdigit():
            out.add(t)
    return out
