"""Web3 attack-class registry + indicator (IOC) extraction for the respond station (D-class, no LLM).

Two ways a Web3 incident reaches *your* code:
  · IOC  — an address the evidence names verbatim (attacker, victim, leaked dev account) appears in your repo
           ⇒ exact hit (you trust, integrate with, or whitelist the very account in the incident)
  · class — the incident's attack class (reentrancy, spot-price oracle, self-attested auth, public dev key …)
           has a code shape ⇒ heuristic candidate lines; the AWS agents decide whether it is exploitable.

Adding an attack class = one entry + one test; never a new code path."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass

_ADDR = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
CODE_GLOBS = ("*.sol", "*.ts", "*.js", "*.json", "*.toml", "*.yml", "*.yaml", "*.env*", "*.py")


@dataclass(frozen=True)
class Shape:
    glob: str
    pattern: str
    exact: bool         # True ⇒ the line is itself the vulnerability (e.g. a published private key)


@dataclass(frozen=True)
class AttackClass:
    class_id: str
    name: str
    title: str                      # regex over event title + evidence titles
    evaluation: str                 # requirement evaluation text (what Security Agent must check)
    remediation: str
    shapes: tuple[Shape, ...]
    cwe: str = "1357"   # OCSF vulnerability needs cve|cwe|advisory (live validator); 1357 = untrustworthy component


# Hardhat/Anvil default account #0 — its private key is printed by every `npx hardhat node`, i.e. public.
# Split on purpose: this repo is itself a scan target, and a detector must not match its own source.
HARDHAT_ACCOUNT0 = "0x" + "f39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
HARDHAT_KEY0 = "0x" + "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

CLASSES: tuple[AttackClass, ...] = (
    AttackClass("public-dev-key", "Publicly known dev/test key trusted in production",
                r"Hardhat default|default (?:test )?account|publicly known private key|Private Key Leak|Key Compromise",
                "Fail if any contract, whitelist, role grant, deploy script or network config references a well-known "
                "development account or embeds a private key (Hardhat/Anvil defaults, keys committed to the repo).",
                "Remove the account from every allowlist/role, rotate any key that was ever committed, load deployer keys "
                "from a secrets manager or hardware signer.",
                (Shape("*", re.escape(HARDHAT_ACCOUNT0), True), Shape("*", re.escape(HARDHAT_KEY0), True),
                 Shape("*.ts", r"accounts:\s*\[\s*[\"']0x[0-9a-fA-F]{64}", True),
                 Shape("*.js", r"accounts:\s*\[\s*[\"']0x[0-9a-fA-F]{64}", True),
                 Shape("*.env*", r"PRIVATE_KEY\s*=\s*0x[0-9a-fA-F]{64}", True)), cwe="798"),
    AttackClass("reentrancy", "Reentrancy (external call before state update)", r"[Rr]eentran",
                "Fail if any function sends value or calls an untrusted contract before updating the balances/state the "
                "call depends on, without a reentrancy guard (checks-effects-interactions).",
                "Update state before external calls and add a nonReentrant guard on value-moving functions.",
                (Shape("*.sol", r"\.call\{value:", False),), cwe="841"),
    AttackClass("spot-price-oracle", "Spot-price oracle manipulation", r"Price Manipulation|Oracle Manipulation|flash[- ]?loan",
                "Fail if prices used for minting, borrowing, liquidation or settlement are read from instantaneous AMM "
                "reserves/balances or a single venue's mid price, without TWAP or an independent oracle.",
                "Use a manipulation-resistant oracle (TWAP over a sufficient window, Chainlink-style feeds) and bound "
                "per-block price movement.",
                (Shape("*.sol", r"getReserves\(\)", False), Shape("*.sol", r"balanceOf\(address\(this\)\)\s*\*", False)), cwe="682"),
    AttackClass("self-attested-auth", "Caller-attested authorization", r"Access Control|authenticat\w* (?:its )?caller|self-attestation",
                "Fail if authorization trusts a value the caller itself reports (asking msg.sender whether it is enabled, "
                "tx.origin checks) or forwards an unconstrained call to a caller-supplied target.",
                "Authenticate against state the contract controls (registries, roles); never call arbitrary caller-supplied targets.",
                (Shape("*.sol", r"tx\.origin\s*==", False), Shape("*.sol", r"isModuleEnabled\(\s*address\(this\)\s*\)", False)), cwe="290"),

)
BY_CLASS = {c.class_id: c for c in CLASSES}


def classes_for(texts: list[str]) -> list[AttackClass]:
    blob = " ".join(texts)
    return [c for c in CLASSES if re.search(c.title, blob)]


def _addresses(texts: list[str]) -> list[str]:
    """EVM addresses stated verbatim in the evidence (checksummed spelling preserved, deduped case-insensitively)."""
    seen: dict[str, str] = {}
    for t in texts:
        for a in _ADDR.findall(t):
            seen.setdefault(a.lower(), a)
    return sorted(seen.values(), key=str.lower)


# Domain IOCs: ONLY defanged spellings count. Defanging ("evil[.]com", "hxxps://") is how security writers mark an
# indicator as malicious; a plain domain in an article is almost always a source, a vendor or a victim, and putting it on
# a DNS block list would cut a legitimate service (M3 P0: 0 defanged domains in 343 live events — the bar is high on purpose).
_DEFANGED = re.compile(r"(?i)\b(?:hxxps?|fxp)\[?:\]?//|\[\.\]|\(\.\)|\[dot\]|\(dot\)|\{\.\}")
_DOMAIN_TOKEN = re.compile(r"(?i)(?:hxxps?\[?:\]?//)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\[\.\]|\(\.\)|\[dot\]|\(dot\)|\{\.\}|\.))+"
                           r"[a-z]{2,24})\b")
# never on a block list, whatever an article says (the radar must not take down the services everyone depends on)
NEVER_BLOCK = ("amazonaws.com", "amazon.com", "aws.amazon.com", "cloudfront.net", "github.com", "githubusercontent.com",
               "google.com", "googleapis.com", "microsoft.com", "windows.net", "azure.com", "apple.com", "cloudflare.com",
               "npmjs.org", "npmjs.com", "pypi.org", "etherscan.io", "bscscan.com", "x.com", "twitter.com", "t.me", "telegram.org")


def _domains(texts: list[str]) -> list[str]:
    """Defanged domains stated in the evidence, refanged and lower-cased. A token counts only if it was defanged in the
    text itself; NEVER_BLOCK (and their subdomains) are dropped."""
    out: set[str] = set()
    for t in texts:
        for m in _DOMAIN_TOKEN.finditer(t):
            raw = m.group(0)
            if not _DEFANGED.search(raw):
                continue
            d = re.sub(r"(?i)\[\.\]|\(\.\)|\[dot\]|\(dot\)|\{\.\}", ".", m.group(1)).lower().strip(".")
            if "." not in d or any(d == n or d.endswith("." + n) for n in NEVER_BLOCK):
                continue
            out.add(d)
    return sorted(out)


@dataclass(frozen=True)
class Indicators:
    addresses: list[str]    # EVM addresses, verbatim (respond: located in contract code)
    domains: list[str]      # defanged domains, refanged (mitigate: DNS Firewall list)


def indicators(texts: list[str]) -> Indicators:
    """THE indicator extraction entry (M3 contract: one entry for every IOC kind, one verbatim rule for all)."""
    return Indicators(_addresses(texts), _domains(texts))


def scan(files: dict[str, str], class_ids: list[str], addresses: list[str]) -> list[dict]:
    """Line hits in a code base. IOC hits are exact by definition; class shapes carry their own exactness."""
    out = []
    lowered = [a.lower() for a in addresses]
    for path in sorted(files):
        base = path.rsplit("/", 1)[-1]
        code = any(fnmatch.fnmatch(base, g) for g in CODE_GLOBS)
        for n, line in enumerate(files[path].splitlines(), 1):
            low = line.lower()
            if code:
                for a, orig in zip(lowered, addresses):
                    if a in low:
                        out.append({"file": path, "line": n, "match": "exact", "what": f"IOC {orig}", "class_id": None})
            for cid in class_ids:
                for s in BY_CLASS[cid].shapes:
                    if fnmatch.fnmatch(base, s.glob) and re.search(s.pattern, line):
                        out.append({"file": path, "line": n, "match": "exact" if s.exact else "heuristic",
                                    "what": BY_CLASS[cid].name, "class_id": cid})
    # one row per (file, line): the exact reading wins over a heuristic one
    best: dict[tuple[str, int], dict] = {}
    for h in out:
        k = (h["file"], h["line"])
        if k not in best or (h["match"] == "exact" and best[k]["match"] != "exact"):
            best[k] = h
    return [best[k] for k in sorted(best)]


def relevant(files: dict[str, str]) -> bool:
    """A target is a smart-contract code base if it has Solidity or a Hardhat/Foundry config."""
    return any(p.endswith(".sol") or p.rsplit("/", 1)[-1] in ("hardhat.config.ts", "hardhat.config.js", "foundry.toml")
               for p in files)
