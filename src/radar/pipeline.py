"""normalize → cluster → verify → score. Deterministic: same raw items in the same order ⇒ same events,
levels and timeline. No LLM in this module (M2 adds extract/summarize stations around it)."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from difflib import SequenceMatcher
from functools import lru_cache
from typing import Any
from urllib.parse import urlsplit

from radar import anomaly, chain, keys, latency, removals, respond, signals, timeutil
from radar.limits import Limits
from radar.model import EXPLOITATION_ORDER, LEVEL_ORDER, SEVERITY_ORDER, Domain, Event, Item, RawItem, Tier
from radar.registry import (
    BY_ID,
    CATALOG_SOURCES,
    CRYPTO_MEDIA_ORGS,
    EXCHANGE_NAMES,
    ONE_ADVISORY_SOURCES,
    REPORTER_TOKENS,
    Source,
    handle_info,
)
from radar.store import Store

_TIER_RANK = {"T1": 1, "T2": 2, "T3": 3}
# ASCII lookarounds, not \b: next to Chinese text (「1.98万枚ETH」) a CJK character is a word character and \b never fires;
# Chinese exchange names count too (「江卓尔：币安潜在损失…」 was classified incident and missed the Binance event).
_CRYPTO = re.compile(
    r"(?<![A-Za-z0-9])(crypto|defi|web3|blockchain|token|stablecoin|bitcoin|btc|ethereum|eth|solana|bnb|bsc|tron|"
    r"exchange hack\w*|drained|cex|dex|bridge|wallet|smart contract|on-?chain|airdrop|nft|usdt|usdc|"
    r"binance|coinbase|okx|bybit|bitget|kraken)(?![A-Za-z0-9])|加密|区块链|交易所|钱包|代币|链上|跨链|稳定币|币安|欧易|火币",
    re.IGNORECASE,
)
_VULN = re.compile(r"(?<![A-Za-z0-9])CVE-\d{4}"     # lookbehind, not \b: 「厂商发布CVE-2026-1234修复」
                   r"|\b(vulnerabilit(?:y|ies)|zero-?day|0-?day|patch(?:es|ed)?|security update|RCE)\b|漏洞|补丁",
                   re.IGNORECASE)
_STRONG = ("cve:", "ghsa:", "tx:", "attacker:", "xs:", "url:")
# CISA's two phrasings: "Adds Two Known Exploited Vulnerabilities to Catalog" (advisories) and "We added … CVE-… &
# … CVE-… to our KEV Catalog" (X); both list unrelated bugs side by side
# window: CISA's own tweets name vendor + product for each CVE before "to our KEV Catalog" (190 chars live 2026-10-29)
# 「CISA Adds Six Known Exploited Vulnerabilities to Catalog」 / 「We added 4 CVEs to our Known Exploited Vulnerabilities
# Catalog」: a COUNT of added entries is what makes it a list. A story about one flaw that says it was added to KEV
# (「QNAP … Plex2Shell Flaws Are Used to Hack NAS Devices」, live recompute 2026-11-19) has no count and is not one.
LIST_ANNOUNCE_RE = re.compile(
    r"\badd(?:s|ed)?\s+(?:\d+|two|three|four|five|six|seven|eight|nine|ten|several|multiple)\s+(?:new\s+)?"
    r"(?:known exploited vulnerabilit(?:y|ies)\b|(?:vulnerabilit(?:y|ies)|CVEs?|flaws?)\b.{0,80}?\b(?:known exploited|KEV)\b)",
    re.IGNORECASE | re.DOTALL)
KEV_ROUNDUP_RE = re.compile(r"\badd(?:s|ed)?\b.{0,320}?\b(?:known exploited vulnerabilit(?:y|ies)|KEV catalog)\b", re.IGNORECASE | re.DOTALL)
_NAME_KEYS = ("ent:", "tok:", "tt:", "dg:")   # a name shared by text, not a link, tx or figure
_NOT_ARTICLE = {"x.com", "t.co"}   # canonical_url already folds twitter.com / www. / mobile.
_HEADLINE_SLUG = re.compile(r"/(?:[^/-]+-){3,}[^/]*$")   # last path segment of ≥ 4 hyphenated words


@dataclass
class Change:
    event_id: str
    created: bool
    level_changed: bool = False
    severity_changed: bool = False


@dataclass
class IngestResult:
    new_items: int = 0
    updated_items: int = 0
    unchanged_items: int = 0
    changes: dict[str, Change] = field(default_factory=dict)
    # radar.anomaly inputs: each touched event as this cycle first found it, and the events merged into it
    before: dict[str, dict[str, Any]] = field(default_factory=dict)
    absorbed: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    anomalies: list[dict[str, Any]] = field(default_factory=list)
    held: list[list[Any]] = field(default_factory=list)      # radar.latency samples: [tier, minutes] per new report


# ---------------------------------------------------------------- normalize

# CRYPTO_MEDIA_ORGS lives in radar.registry (the sources' facts); imported above.


def _classify(base: Domain | None, text: str, has_cve: bool, crypto_source: bool = False) -> Domain:
    if base == "web3":
        return "vuln" if has_cve and not signals.web3_incident(text) else "web3"
    if base:
        return base
    if _CRYPTO.search(text):
        return "web3"
    vuln = has_cve or bool(_VULN.search(text))
    if crypto_source:   # a crypto outlet's CVE / patch story is a vulnerability, its theft story a theft
        return "vuln" if vuln and not signals.web3_incident(text) else "web3"
    return "vuln" if vuln else "incident"


def amount_keys(losses: list[float]) -> list[str]:
    """amt:<value> for each specific loss figure (≥ AMOUNT_KEY_MIN_USD, not a round AMOUNT_KEY_ROUND_USD multiple); also
    used to re-key stored items in a repair."""
    return [f"amt:{round(v)}" for v in losses
            if v >= Limits.AMOUNT_KEY_MIN_USD and round(v) % Limits.AMOUNT_KEY_ROUND_USD]


def web3_text_keys(title: str, blob: str) -> list[str]:
    """Free-text keys of a web3 item without a structured victim name (also used to re-key stored items in a repair).
    The headline's names come twice, as tok: and tt:: an event sharing one scores it twice, so when a report matches
    several events the one its headline is about outranks one that shares a body word (live 2026-10-29:
    「数据：Polymarket疑似攻击者…」 ranked a Tranche Vault event above the Polymarket one)."""
    body = blob.removeprefix(title)
    head = keys.headline_names(title, body) - REPORTER_TOKENS   # Title Case headlines: only name-like words
    head |= {x for x in EXCHANGE_NAMES if re.search(rf"\b{x}\b", title, re.IGNORECASE)}   # … but an exchange is a name
    toks = (keys.entity_tokens(body) | head) - REPORTER_TOKENS     # a reporter's own name glues its whole feed
    return sorted(f"tok:{t}" for t in toks) + sorted(f"tt:{t}" for t in head)


def cited_article_keys(links: list[str]) -> list[str]:
    """A tweet citing one article registers it, so whichever arrives first the other finds it: an outlet's tweet comes
    20–80 min before its RSS entry, and a link that is only looked up let the later article miss it (live 2026-10-29:
    ENGIE, Tailscale, Volt Typhoon stayed two events each). A homepage names no story; a digest citing several would
    glue them; so does a shortener or listing page reused across tweets (CISA's go.dhs.gov/iEv on every "We issued N
    ICS advisories"), hence only a headline slug counts — a miss only falls back to lookup. `links` are canonical (also
    used to re-key stored tweets in a repair)."""
    cited = {u for u in links if urlsplit(u).hostname not in _NOT_ARTICLE and _HEADLINE_SLUG.search(urlsplit(u).path)}
    return [f"url:{u}" for u in cited] if len(cited) == 1 else []


def normalize(raw: RawItem, source: Source, fetched_at: datetime, aliases: dict[str, str] | None = None) -> Item:
    if (text := timeutil.strip_relative_age(raw.text)) != raw.text:
        raw = replace(raw, text=text)
    if source.parser == "twitterapi":
        h = handle_info(raw.author or "")
        tier, org, base = h.tier, h.org, h.domain or source.domain
    else:
        tier, org, base = source.tier, source.org, source.domain
    blob = f"{raw.title}\n{raw.text}"
    cve_list = sorted((set(keys.cves(blob)) - keys.contrast_only(blob)) | set(raw.extra.get("cves") or []))
    domain = _classify(base, blob, bool(cve_list), source.parser != "twitterapi" and org in CRYPTO_MEDIA_ORGS)
    links = [keys.canonical_url(u) for u in raw.links if u]
    canon = keys.canonical_url(raw.url)

    reg: list[str] = []
    # roundups listing dozens of CVEs must not glue unrelated CVE events together — but one CSAF advisory is one
    # product's advisory, however many CVEs it lists (live 2026-11-06: EPICS Base ICSA-26-300-01 with 4 CVEs got none)
    if len(cve_list) <= 3 or source.parser == "rolie" or (
            source.source_id in ONE_ADVISORY_SOURCES and len(cve_list) <= Limits.ADVISORY_MAX_CVES):
        reg += [f"cve:{c}" for c in cve_list]
    elif (top := keys.dominant(blob, Limits.DOMINANT_MIN_MENTIONS, Limits.DOMINANT_RATIO)) in cve_list:
        reg.append(f"cve:{top}")        # a report about one of the many CVEs it names (keys.dominant)
    ghsa_list = keys.ghsas(blob)
    if len(ghsa_list) <= 3:                       # a roundup listing many advisories glues nothing (as for CVEs)
        reg += [f"ghsa:{g}" for g in ghsa_list]
        # R12: a GHSA the radar has linked to its CVE (radar.ghsa_alias, written by the analyze station) carries that CVE
        # too, so a report naming only the advisory joins the CVE's event — and keeps joining after a revision
        reg += [f"cve:{aliases[g]}" for g in ghsa_list if aliases and g in aliases]
    txs = keys.tx_refs(blob + "\n" + "\n".join(raw.links)) + list(raw.extra.get("attack_tx") or [])
    reg += [f"tx:{t['hash']}" for t in txs]
    reg += [f"attacker:{u.rsplit('/', 1)[-1].lower()}" for u in raw.extra.get("attacker_urls") or []]
    if raw.extra.get("x_status"):
        reg.append(f"xs:{raw.extra['x_status']}")
    if source.url_is_identity:
        reg.append(f"url:{canon}")
    ent = keys.entity_key(raw.extra.get("entity"))
    if ent and domain != "vuln":
        reg.append(f"ent:{ent}")
    if domain == "web3" and not raw.extra.get("entity"):
        reg += web3_text_keys(raw.title, blob)
    elif domain != "web3":
        reg += sorted(f"tok:{t}" for t in keys.named_tokens(raw.title))
    # citing a tweet is a hard link: register it so whichever arrives first, the other finds it
    reg += [f"xs:{sid}" for _, sid in keys.x_statuses(" ".join(raw.links))]
    if source.parser == "twitterapi":
        reg += cited_article_keys(links)

    # a catalogue's or the vendor's own statement (CISA KEV; MSRC "Exploitation Detected") is not left to the text rules
    exploited = "yes" if raw.extra.get("kev") or raw.extra.get("vendor_exploited") else signals.exploited(blob)
    amount = raw.extra.get("amount_usd")
    if amount is None and domain == "web3" and "amount_usd" not in raw.extra:
        amount = signals.loss_amount(raw.title, raw.text) if signals.web3_incident(blob) else None
    # "does it name money at all" keeps deciding whether a web3 report opens an event (unchanged since M1); the STORED
    # figure is only a stated loss (signals.loss_amount)
    names_money = amount is not None or (domain == "web3" and signals.parse_amount(raw.text) is not None)
    # the same specific loss figure in two reports days apart is the same incident (live 2026-11-04: an anonymous
    # 「欧盟实体」 theft opened 4 events — 1.06亿 ×3, then 1.33亿 beside SlowMist's named Crédit Mutuel Arkéa record);
    # a round figure ($100M) is too common to prove anything; a name-like key: same domain, inside the window
    if domain == "web3" and raw.extra.get("amount_usd") is not None:      # a hack database's stated loss
        reg += amount_keys([float(raw.extra["amount_usd"])])
    elif ((domain == "web3" and signals.web3_incident(blob)) or (domain == "incident" and signals.security_event(raw.title))) \
            and "amount_usd" not in raw.extra and not signals.is_roundup_report(raw.title):
        # the headline's figures only: a body cites other thefts for comparison (「继Bitget被盗3.87亿美元后…」 in a
        # Binance story would glue the two)
        reg += amount_keys(signals.loss_amounts(raw.title, None))
    poc = bool(raw.extra.get("poc")) or signals.poc(blob)

    if source.always_eventful:
        eventful = True
    elif source.parser in ("cvelist_delta", "msrc"):
        # the whole CVE List (~130 records a day, mostly low): only a critical one opens an event; the rest are context
        # items carrying their cve: key, so a later report of that CVE meets the record (and its publication time).
        # MSRC is the same shape (~100 CVEs each Patch Tuesday): critical or exploited opens one, the rest corroborate
        eventful = (raw.extra.get("cvss") or 0) >= Limits.CVE_LIST_EVENT_CVSS or exploited == "yes"
    elif domain == "web3":
        eventful = signals.web3_incident(raw.title or raw.text) and (names_money or tier == "T1")
    else:
        eventful = bool(cve_list) or exploited == "yes" or (tier != "T3" and signals.security_event(raw.title))

    published = raw.published_at or fetched_at
    content_hash = hashlib.sha256(f"{raw.title}\x1f{raw.text}\x1f{amount}".encode()).hexdigest()[:16]
    extra = {k: v for k, v in raw.extra.items() if k not in ("attack_tx",)}
    extra["tx"] = txs
    # KEV catalog announcements ("CISA adds two known exploited vulnerabilities …") list unrelated CVEs: the item may
    # attach to one of their events but must not merge them (live 2026-10-27: Adobe Commerce glued into Node2Shell)
    if len(cve_list) >= 2 and KEV_ROUNDUP_RE.search(blob):
        extra = {**extra, "roundup": True}
    if signals.is_digest(raw.title, raw.text):
        extra = {**extra, "digest": True}
    return Item(
        item_id=keys.item_id(source.source_id, raw.guid or canon), source_id=source.source_id, tier=tier, org=org,
        domain=domain, url=raw.url, canonical_url=canon, title=raw.title[:300], text=raw.text[:Limits.ITEM_TEXT_MAX],
        published_at=timeutil.iso(published), fetched_at=timeutil.iso(fetched_at), content_hash=content_hash,
        keys=sorted(set(reg)), links=links, entity=raw.extra.get("entity"), eventful=eventful,
        signals={"exploited": exploited, "kev": bool(raw.extra.get("kev")), "poc": poc, "amount_usd": amount},
        extra=extra)


# ---------------------------------------------------------------- cluster

def _lookup_keys(item: Item) -> list[str]:
    if is_digest(item):      # a digest looks events up in its own key space only
        return _digest_keys(item)
    out = list(item.keys)
    out += [f"url:{u}" for u in item.links]
    out += [f"xs:{sid}" for _, sid in keys.x_statuses(" ".join(item.links))]
    # structured victim names (ent:) and free-text tokens (tok:) look each other up in both directions
    out += [f"tok:{k[4:]}" for k in item.keys if k.startswith("ent:")]
    out += [f"ent:{k[4:]}" for k in item.keys if k.startswith("tok:")]
    # a follow-up repeats the first figure in its body (「总额已超1.33亿…此前损失超1.06亿」): it may FIND the story by it,
    # but lends only its headline figures (normalize) — a body citing another theft for comparison must not glue them
    if item.domain == "web3" and item.eventful and "amount_usd" not in item.extra and not is_roundup(item):
        out += amount_keys(signals.loss_amounts(None, item.text))
    return sorted(set(out))


def _late_name_keys(item: Item) -> set[str]:
    """ent: lookups for the words a Title Case headline drops as names (keys.headline_names keeps one only if the body
    capitalises it mid-sentence too). They may find a story only through _same_loss_later — the figure has to agree.
    Live 2026-11-03: Decrypt's 「Liquid Network Restores Full Bitcoin Backing Two Months After $320M Exploit」 never says
    Liquid in its body, so it lost the name and opened a second Liquid Network event."""
    if item.domain != "web3" or not item.eventful or item.entity or not keys.is_title_case(item.title):
        return set()
    body = item.text.removeprefix(item.title)
    return {f"ent:{t}" for t in keys.entity_tokens(item.title) - keys.headline_names(item.title, body)}


def _same_loss_later(event: Event, item: Item, key: str) -> bool:
    """A web3 report naming the victim (name key) with a loss within LATE_LOSS_TOLERANCE of the event's, up to
    LATE_LOSS_DAYS after the event's latest evidence, is the same theft — a retrospective, an analysis, a backfilled
    database entry (live 2026-11-05: Bitget $387M · TRM's $351.6M · 安全客's 「3.5亿美元一夜蒸发」 five days later were
    three events). The name alone is not enough: one exchange can be robbed twice; the figure has to agree too."""
    # the name must be the EVENT's victim (its title / structured entity) and in the REPORT's headline — not any word the
    # two share: the domain-plan diff caught 安全客's Bitget article joining Liquid Network ($350M vs $320M)
    if event.domain != "web3" or item.domain != "web3" or not key.startswith(("tt:", "ent:")):
        return False
    victim = keys.entity_tokens(event.title) | {keys.entity_key(e) for e in event.entities}
    if key.split(":", 1)[1] not in victim:
        return False
    a, b = item.signals.get("amount_usd"), event.amount_usd_latest
    if not a or not b or abs(a - b) > Limits.LATE_LOSS_TOLERANCE * max(a, b):
        return False
    # the same figure (not just a close one) stays evidence for longer: a recovery or post-mortem months later restates
    # it exactly (「…Two Months After $320M Exploit」), while a second theft of the victim rarely matches it to 2 %
    days = Limits.LATE_LOSS_EXACT_DAYS if abs(a - b) <= Limits.LATE_LOSS_EXACT_TOLERANCE * max(a, b) \
        else Limits.LATE_LOSS_DAYS
    last, at = timeutil.parse(event.last_updated or event.first_seen), timeutil.parse(item.published_at)
    first = timeutil.parse(event.first_seen)
    return bool(last and at and first) and first - timedelta(days=Limits.ENTITY_WINDOW_DAYS) <= at \
        <= last + timedelta(days=days)


def _within(event: Event, item: Item, days: int) -> bool:
    """Name matching window. It rolls with the story: from `days` before the first report to `days` after the latest
    evidence, but never more than ENTITY_SPAN_DAYS after the first report. A fixed window from first_seen split every
    long-running incident (live 2026-11-02: Binance, reported hourly, became two events 3 days after its first report;
    zkLink and X100 likewise) — the cap keeps a quiet name from absorbing a new incident weeks later."""
    first, last, at = (timeutil.parse(event.first_seen), timeutil.parse(event.last_updated or event.first_seen),
                       timeutil.parse(item.published_at))
    if not (first and at):
        return False
    if event.domain == "vuln":   # linked by CVE; a rolling window would keep vendor names (GitLab) open for weeks
        return abs((first - at).total_seconds()) <= days * 86400
    end = min(max(first, last or first) + timedelta(days=days), first + timedelta(days=Limits.ENTITY_SPAN_DAYS))
    return first - timedelta(days=days) <= at <= end


def is_digest(item: Item) -> bool:
    """A newsletter / bulletin / review that tells several stories (signals.is_digest; flag set at normalize, recomputed
    for items stored before it). A digest is never evidence for an event's loss, exploitation, level or title, and a
    new one is not attached to any event."""
    return bool(item.extra.get("digest")) or signals.is_digest(item.title, item.text)


def _digest_keys(item: Item) -> list[str]:
    """The keys of a digest: itself (its url) and one key in a namespace of its own — what kind of digest, of which
    month, and by whom. A digest names many stories and links to all of them; with its ordinary keys it would join one
    of them, or all. In dg: it can only meet another digest of the same thing: twenty outlets' 「Patch Tuesday」 reviews
    of one month are one event (the one kind that is the same thing across outlets), and none of the thousand CVEs'
    events; an outlet's own weekly stays with that outlet."""
    kind = signals.digest_kind(item.title, item.text) or "digest"
    who = "" if kind == "patch-tuesday" else f":{item.org}"
    return sorted({k for k in item.keys if k == f"url:{item.canonical_url}"} | {f"dg:{kind}{who}:{item.published_at[:7]}"})


def lists_cves(item: Item) -> bool:
    """A list of more CVEs than one story has (> Limits.MERGE_BRIDGE_MAX_CVES; a bug chain names 2–3): a vendor re-shipping another vendor's
    product, an OS bulletin, a catalog page. Like a KEV roundup it attaches through its CVEs but lends none and merges
    none. Live 2026-11-18: a Siemens ICS advisory listing 23 PAN-OS CVEs attached to the 09-10 PAN-OS event, lent it
    CVE-2026-0322, and the 10-14 KEV event merged into it through that id."""
    return sum(1 for k in item.keys if k.startswith("cve:")) > Limits.MERGE_BRIDGE_MAX_CVES


def is_list_announcement(item: Item) -> bool:
    """A catalog announcement — a KEV roundup, a CVE list, or 「We added 4 CVEs to our Known Exploited Vulnerabilities
    Catalog」 — is about several vulnerabilities, not one. An event made only of such reports and naming no CVE is no
    single vulnerability, so it is never P0 / P1 (R9.6; live 2026-11-19: 「CISA Adds Four Known Exploited
    Vulnerabilities to Catalog」 and CISA's X post each opened a CVE-less P0 that reached the team channel)."""
    # not is_roundup(): that flag is set by 「≥ 2 CVEs + KEV wording anywhere」 and caught a two-CVE chain story (QNAP
    # Plex2Shell, recompute 2026-11-19) — registered separately; here a list is a count of added entries or > 3 CVEs
    return lists_cves(item) or bool(LIST_ANNOUNCE_RE.search(f"{item.title}\n{item.text[:400]}"))


def is_roundup(item: Item) -> bool:
    """KEV catalog announcement listing several CVEs (flag set at normalize; recomputed for items stored before it)."""
    n = sum(1 for k in item.keys if k.startswith("cve:"))
    return bool(item.extra.get("roundup")) or (n >= 2 and bool(KEV_ROUNDUP_RE.search(f"{item.title}\n{item.text}")))


def indexed_keys(item: Item) -> list[str]:
    """Keys an item contributes to its event (event keys, key index, event CVE list). A roundup attaches through its
    CVEs but contributes none of them — else the next ordinary item of one of those CVEs finds this event through the
    index and merges two unrelated stories after all. A context-only item (not eventful) lends hard keys only: it attaches
    through them, and its names are not this event's (live 2026-11-02: PANews' daily digest lent tok:zklink to Binance,
    and the zkLink exploit reports then found Binance through it)."""
    if is_digest(item):      # … and lends an event nothing else
        return _digest_keys(item)
    return [k for k in item.keys if not (k.startswith("cve:") and (is_roundup(item) or lists_cves(item)))
            and (item.eventful or k.startswith(_STRONG))]


def find_events(item: Item, store: Store, exclude: str | None = None) -> tuple[str | None, list[str]]:
    """Best matching event, plus other events this item proves are the same story (merge candidates):
    matched through a strong key, or — outside web3 — through a named-vulnerability token. `exclude`: an event to ignore
    (split_candidates asks where an event's own first report would go if that event did not exist)."""
    score: dict[str, int] = {}
    strong_hit: set[str] = set()
    own: set[str] = set()       # events whose own victim the report's headline names (_names_event)
    # a body mention is context (「Pando Rings黑客将4000枚ETH通过Tornado转移」 recalls the Binance-led dip in its text)
    headline = keys.entity_tokens(item.title) | {k[3:] for k in item.keys if k.startswith("tt:")} \
        | ({keys.entity_key(item.entity)} if item.entity else set())
    amt_hit: set[str] = set()   # events sharing the report's specific loss figure
    cache: dict[str, Event | None] = {}
    item_cves = {k[4:] for k in item.keys if k.startswith("cve:")}
    base = _lookup_keys(item)
    late = _late_name_keys(item) - set(base)
    for k in base + sorted(late):
        strong = k.startswith(_STRONG)
        if not strong and not item.eventful:
            continue  # context-only items attach through hard links, never through name similarity
        for eid in store.event_ids_for_key(k):
            if eid == exclude:
                continue
            ev = cache.setdefault(eid, store.get_event(eid))
            if ev is None:
                continue
            if k in late and not _same_loss_later(ev, item, k):
                continue
            # a specific loss figure links across web3 / incident: the same theft is a CEX hack to one outlet and a
            # bank breach to another (live 2026-11-04: The Block's 「French bank Crédit Mutuel Arkéa exploited for over
            # $133 million」 read as an incident, the ZachXBT reports as web3)
            same_domain = ev.domain == item.domain or (k.startswith("amt:") and {ev.domain, item.domain} <= {"web3", "incident"})
            if not strong and (not same_domain or not (_within(ev, item, Limits.ENTITY_WINDOW_DAYS)
                                                       or _same_loss_later(ev, item, k))):
                continue
            # a report of a repeat attack is not the earlier incident's: its name matches the old event, its story is new
            if not strong and item.domain == "web3" and signals.repeat_incident(item.title):
                ev_first, item_at = timeutil.parse(ev.first_seen), timeutil.parse(item.published_at)
                if ev_first and item_at and ev_first < item_at - timedelta(days=Limits.ENTITY_WINDOW_DAYS):
                    continue
            # a CVE ties a vulnerability story to a vulnerability story. Live 2026-11-11: a crypto-media article citing
            # Chrome / iOS CVEs gave the Binance theft event CVE keys, and November's Patch Tuesday (MSRC, one item per
            # CVE) then attached through them — 1,097 advisories, the event re-domained to vuln and kept growing.
            if k.startswith("cve:") and ev.domain != item.domain and "vuln" in (ev.domain, item.domain):
                continue
            # a shared name is no evidence against disjoint CVEs: two advisories naming SharePoint with different CVEs are
            # two vulnerabilities (the same live hairball glued per-CVE MSRC items through tok:sharepoint / win32k / …)
            # … and neither is a link: an advisory citing a tweet or an article about another flaw is not about that flaw.
            # Live 2026-11-12: SonicWall (CVE-2026-19868), OpenSSH and MS Paint reports attached through cited pages to
            # the Linux TCP event (CVE-2026-98432) — one event, six unrelated CVEs, 146 reports.
            contradicts = (not strong or k.startswith(("xs:", "url:"))) and item_cves and ev.cves \
                and not (item_cves & set(ev.cves))
            if contradicts:
                continue
            # a record that names its victim belongs to that victim's story. Live 2026-11-11: DeFiLlama / SlowMist
            # records for Mercado Bitcoin, BitMart and Ankr Bridge joined the Binance event through tok:mercado /
            # tok:bitmart / tok:ankr — Binance coverage mentions every exchange — and Ankr's $304,500 became Binance's
            # headline loss (P0 → P1). A named victim the event does not already have is a different incident.
            # Links count as strong but prove nothing about the victim: SlowMist's Ankr / Initia / Across records link the
            # SlowMist tweet, which had joined Binance through a mention — the records followed via xs:, and their
            # victims then let DeFiLlama's records in by name. Only the attack transaction itself overrides a victim.
            if (not strong or k.startswith(("xs:", "url:"))) and item.domain == "web3" and item.entity and ev.entities \
                    and not _same_victim([item.entity], ev.entities):
                continue
            # a specific loss figure outweighs a shared name: an event that gathered hundreds of reports (Binance, 277)
            # shares some word with every story (ZachXBT, USDT, Kraken …) — live 2026-11-04 the 「欧盟实体」 reports scored
            # higher there than on their own 1.06亿 story
            # … and a name that is the event's own victim outweighs one its coverage merely mentions. Live 2026-11-12:
            # one Binance article mentioned Ankr, so the 576-item event held tok:ankr; each Ankr bridge report then scored
            # Binance and the Ankr event alike and went to the earlier one — 12 reports and Ankr's five attack txs sat on
            # the Binance page. Ranking only: the mention still counts, it just loses to the owner of the name.
            # A name is evidence for the event it names, not for every event whose coverage mentions it. Measured on the
            # labelled corpus (scripts/cluster_eval.py, 2026-11-13): the Binance event held 557 reports of which 147 were
            # other stories — UXLINK's and Drift's hackers trading, Mercado, Bitget, a market report — all attached
            # through words Binance coverage had used (tok:hyperliquid, tok:uxlink, tok:coinjoin …). Pairwise precision
            # 0.51 → 0.91 with these two rules, recall 0.98 → 0.94.
            # an agency or an attribution is a name of nobody's incident: it finds an event only together with that
            # event's loss figure (keys.ATTRIBUTION)
            attributed = False
            if not strong and k.startswith(_NAME_KEYS) and item.domain == "web3" and k.split(":", 1)[1] in keys.ATTRIBUTION:
                a, b = item.signals.get("amount_usd"), ev.amount_usd_latest
                if not a or not b or abs(a - b) > Limits.LATE_LOSS_EXACT_TOLERANCE * max(a, b):
                    continue
                attributed = True     # the word plus the figure: evidence of its own, whatever else holds the word
            if not strong and k.startswith(_NAME_KEYS):
                mine = item.domain == "web3" and _names_event(k.split(":", 1)[1], ev)
                # (a) an event with a named victim is found by name only through that victim's name
                if item.domain == "web3" and ev.entities and not mine:
                    continue
                # (b) a word that several web3 events hold names none of them (hyperliquid, tornado, coinjoin). Not
                # outside web3: there the names are vendors (GitLab, SonicWall), and a report without a CVE has
                # nothing else to find its event by — measured: the rule cost recall there and bought no precision
                generic = len(store.event_ids_for_key(k)) >= Limits.GENERIC_NAME_EVENTS and not attributed
                if item.domain == "web3" and not mine and generic:
                    continue
            if k.startswith(_NAME_KEYS) and item.domain == "web3" and _names_event(k.split(":", 1)[1], ev) \
                    and k.split(":", 1)[1] in headline:
                own.add(eid)
            if k.startswith("amt:"):
                amt_hit.add(eid)
            score[eid] = score.get(eid, 0) + (10 if strong else Limits.AMOUNT_KEY_WEIGHT if k.startswith("amt:") else 1)
            # a named-vulnerability token may prove "same story" only when the CVEs do not contradict it: an item
            # with CVEs cannot glue an event whose CVE set is disjoint from its own (live 2026-10-27: a late PHP2Shell
            # advisory merged Node2Shell — CVE-2026-111497 — into PHP2Shell through tok:php2shell)
            if strong or item.domain != "web3":
                strong_hit.add(eid)
    # a report listing more CVEs than one story has joins only an event it shares a CVE with — never one it merely names
    # (live 2026-11-18: USN-9004-2, an OpenJDK 25 regression notice listing other CVEs, joined Java4Shell through
    # 「OpenJDK」 and became its first report; a per-event repair was undone by the next full replay)
    listed = set(keys.cves(f"{item.title}\n{item.text}"))
    if len(listed) > Limits.MERGE_BRIDGE_MAX_CVES and not any(k.startswith("cve:") for k in item.keys):
        score = {e: v for e, v in score.items()
                 if (c := cache.get(e)) is None or not c.cves or set(c.cves) & listed}
    if not score:
        return None, []
    # The own-name bonus, once per event. A shared loss figure still outweighs it: when some candidate shares the
    # report's figure, only those may take the bonus (live: 「Mystery $106 Million Crypto Theft Hits EU Entity Days After
    # Binance…」 is the EU entity's story, which holds amt:106000000; Binance is named in passing).
    for eid in own:
        if eid in score and (not amt_hit or eid in amt_hit):
            score[eid] += Limits.OWN_NAME_BONUS
    ranked = sorted(score, key=lambda e: (-score[e], cache[e].first_seen if cache[e] else ""))
    # a digest links to everything it reviews: live 2026-11-11, ZDI's "November 2026 Security Update Review" linked
    # 1,129 MSRC advisory pages (Talos 168) — each link a strong url: key — and merged every per-CVE advisory into
    # one event. An item that would prove more than a few events identical proves nothing: it attaches, merges none.
    if is_roundup(item) or lists_cves(item) or len(strong_hit) > Limits.MERGE_MAX_EVENTS_PER_ITEM:
        return ranked[0], []
    if not _may_prove_same_story(item):
        return ranked[0], []
    return ranked[0], [e for e in ranked[1:] if e in strong_hit and not _different_stories(cache[ranked[0]], cache[e], item_cves)]


def _may_prove_same_story(item: Item) -> bool:
    """Only a report of an event can show two events are one. A context-only item or a link-heavy one (a newsletter)
    cites stories, it does not equate them. Live 2026-11-12: 「Srsly Risky Biz: Iranian Hacks With Russian
    Characteristics」 (context-only, 34 links) linked a Binance article and a Linux kernel advisory, hit only those two
    events, and merged the 540-report Binance theft into a vulnerability event — 703 items, 21 CVEs, P0 vuln."""
    return item.eventful and len(item.links) <= Limits.MERGE_MAX_LINKS


def _different_stories(a: Event | None, b: Event | None, item_cves: set[str]) -> bool:
    """What no link may override: a theft and a vulnerability (vuln merges only with vuln), two named victims
    (_other_victims), and two CVE sets with nothing in common — unless the item itself names a CVE of each (an advisory
    covering both, 「CVE-A and CVE-B are one bug chain」)."""
    if not a or not b:
        return True
    if a.domain != b.domain and "vuln" in (a.domain, b.domain):
        return True
    # (a long CVE list never gets here: lists_cves merges nothing — live 2026-11-18, a Siemens advisory of 23 PAN-OS CVEs)
    if a.cves and b.cves and not set(a.cves) & set(b.cves) and not (item_cves & set(a.cves) and item_cves & set(b.cves)):
        return True
    # … and even then not across years: one bug chain is disclosed together. Live 2026-11-12: six exploit-catalog
    # entries, each naming CVE-2013-2729 beside a later Acrobat CVE, merged seven KEV events from 2013 to 2023.
    if a.cves and b.cves and not set(a.cves) & set(b.cves) and _years_apart(a.cves, b.cves) >= Limits.MERGE_MAX_CVE_YEARS:
        return True
    return _other_victims(a, b)


def _own_cves(items: list[Item]) -> list[str]:
    """The CVEs that are this event's. A report that names one CVE says which vulnerability the event is; a report
    naming several lends the event only those within MERGE_MAX_CVE_YEARS of one of them — else the first catalog
    entry naming 「CVE-2013-… and CVE-2021-…」 gives the 2021 event the 2013 id, and the next entry merges the two
    events through it (the dry run of the Adobe repair, 2026-11-14: 7 stories came back as 3 events)."""
    named = [sorted(k[4:] for k in indexed_keys(i) if k.startswith("cve:")) for i in items]
    if not any(named):    # an event of lists only (lists_cves lends nothing): it still says which CVEs it is about
        named = [sorted(k[4:] for k in i.keys if k.startswith("cve:")) for i in items if lists_cves(i) and not is_digest(i)]
    every = {c for n in named for c in n}
    core = {n[0] for n in named if len(n) == 1}
    if not core:
        return sorted(every)
    return sorted(c for c in every if c in core or _years_apart([c], sorted(core)) < Limits.MERGE_MAX_CVE_YEARS)


def _years_apart(a: list[str], b: list[str]) -> int:
    """The smallest gap in years between a CVE of one event and a CVE of the other (CVE-YYYY-…)."""
    ya, yb = {int(c[4:8]) for c in a}, {int(c[4:8]) for c in b}
    return min(abs(x - y) for x in ya for y in yb)


def _other_victims(a: Event | None, b: Event | None) -> bool:
    """Two web3 events with named victims and none in common are two incidents, whatever one article links them by.
    Live 2026-11-11: an article on the Initia and Across exploits that also mentioned Binance merged both incidents
    (DeFiLlama / SlowMist records included) into the Binance event — Initia's $615,000 became Binance's headline."""
    if not a or not b or a.domain != "web3" or b.domain != "web3" or not a.entities or not b.entities:
        return False
    return not _same_victim(a.entities, b.entities)


def _names_event(token: str, ev: Event) -> bool:
    """The token is one of the event's named victims (any spelling _same_victim accepts). An event with none has no
    own name: its title is some report's headline (live: a Pando Rings tweet titled 「…3 天前 Binance 被盗…」)."""
    return bool(ev.entities) and _same_victim([token], ev.entities)


def _same_victim(a: list[str], b: list[str]) -> bool:
    """One victim under two spellings: 「ZkLinkNova」 (DeFiHackLabs) and 「zkLink Nova」 (DeFiLlama) key to zklinknova and
    zklink. Same entity key, or one name's letters-and-digits a prefix of the other's (≥ 4 characters)."""
    ka, kb = {keys.entity_key(x) for x in a} - {None}, {keys.entity_key(x) for x in b} - {None}
    if ka & kb:
        return True
    ca = {re.sub(r"[^a-z0-9]", "", x.lower()) for x in a} | ka
    cb = {re.sub(r"[^a-z0-9]", "", x.lower()) for x in b} | kb
    return any(len(min(x, y, key=len)) >= 4 and (x.startswith(y) or y.startswith(x)) for x in ca for y in cb if x and y)



def split_candidates(store: Store, now: datetime, evs: list[Event] | None = None) -> list[dict[str, str]]:
    """Events opened in the last ENTITY_WINDOW_DAYS whose first eventful report belongs to an OLDER event under the
    current rules — a story split in two (a rule that once failed, a window that once closed: live 2026-11-02 Binance,
    zkLink, X100). Listed in #/ops with the repair command; merging stays the explicit, reviewed repair. Bounded: only
    new events are re-matched (a few index reads each), so the check runs every publish."""
    since = timeutil.iso(now - timedelta(days=Limits.ENTITY_WINDOW_DAYS))
    out = []
    # evs = the published events (publish passes them): a backfilled event's last_updated is evidence time, weeks old, so
    # events_updated_since never returns it (live 2026-11-05: three Bitget events)
    pool = evs if evs is not None else store.events_updated_since(since)
    for ev in sorted(pool, key=lambda e: e.first_seen):
        # new = OPENED recently, not first REPORTED recently: a backfilled story (TRM's and 安全客's September Bitget
        # reports, fetched in late October) opens an event whose first_seen is weeks old (live 2026-11-05: three
        # Bitget events slipped past this check)
        opened = next((t["at"] for t in ev.timeline if t.get("kind") == "created"), ev.first_seen)
        if max(ev.first_seen, opened or "") < since:
            continue
        first = next((i for i in sorted(store.get_items(ev.item_ids), key=lambda i: (i.published_at, i.item_id))
                      if i.eventful), None)
        if first is None:
            continue
        best, _ = find_events(first, store, exclude=ev.event_id)
        older = store.get_event(best) if best else None
        if older and older.first_seen < ev.first_seen:
            out.append({"older": older.event_id, "newer": ev.event_id, "domain": ev.domain,
                        "older_title": older.title, "newer_title": ev.title})
    return out

# ---------------------------------------------------------------- verify + score

class _DSU:
    def __init__(self, n: int) -> None:
        self.p = list(range(n))

    def find(self, x: int) -> int:
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: int, b: int) -> None:
        self.p[self.find(a)] = self.find(b)


def _norm_title(t: str) -> str:
    return re.sub(r"[^a-z0-9一-鿿]+", " ", t.lower()).strip()


@lru_cache(maxsize=200_000)
def _similar_titles(a: str, b: str) -> bool:
    """Syndication test, memoised (argument order kept: SequenceMatcher is not symmetric). Live 2026-11-02: progress()
    replays every prefix of an event, so the Binance page (186 reports) ran 1.4 M ratio() calls — 133 s, and the publish
    station timed out at 300 s. real_quick_ratio / quick_ratio are upper bounds of ratio, so the pre-filter never changes
    the answer."""
    sm = SequenceMatcher(None, a, b)
    t = Limits.ECHO_TITLE_SIMILARITY
    return sm.real_quick_ratio() >= t and sm.quick_ratio() >= t and sm.ratio() >= t


def _recompute_order(items: list[Item]) -> list[Item]:
    return sorted(items, key=lambda i: (i.published_at, i.source_id, i.item_id))


def title_edges(items: list[Item]) -> set[tuple[str, str]]:
    """Every syndicated title pair (item ids, in recompute order) of a set of items. Whether two titles match depends
    on those two titles alone, so a subset's pairs are exactly these restricted to it — insights.progress computes them
    once per event instead of once per prefix (live 2026-11-11: 1,198 reports ⇒ 1,189 all-pairs passes, 102 s of one
    page's 123 s)."""
    its = _recompute_order(items)
    titles = [_norm_title(it.title) for it in its]
    thr = Limits.ECHO_TITLE_SIMILARITY
    out: set[tuple[str, str]] = set()
    sm = SequenceMatcher(None)
    for j, b in enumerate(titles):      # b fixed per row: SequenceMatcher indexes seq2 once, set_seq1 is cheap
        if not b:
            continue
        sm.set_seq2(b)
        for i in range(j):
            a = titles[i]
            if a and 2 * min(len(a), len(b)) >= thr * (len(a) + len(b)):
                sm.set_seq1(a)          # same ratio as _similar_titles(a, b): SequenceMatcher(None, a, b)
                if sm.real_quick_ratio() >= thr and sm.quick_ratio() >= thr and sm.ratio() >= thr:
                    out.add((its[i].item_id, its[j].item_id))
    return out


def independent_groups(items: list[Item], edges: set[tuple[str, str]] | None = None) -> list[int]:
    """Group items that are NOT independent: same org, one cites the other, they cite the same X status,
    or near-identical titles (syndication). Returns a group index per item (0..n_groups-1).
    edges = title_edges() of a superset, in the same order (recompute's): used instead of comparing titles."""
    n = len(items)
    dsu = _DSU(n)
    canon = {it.canonical_url: i for i, it in enumerate(items)}
    xs_owner: dict[str, int] = {}
    for i, it in enumerate(items):
        if it.extra.get("x_status"):
            xs_owner[str(it.extra["x_status"])] = i
    by_org: dict[str, int] = {}
    for i, it in enumerate(items):
        if it.org in by_org:
            dsu.union(i, by_org[it.org])
        by_org.setdefault(it.org, i)
        for link in it.links:
            if link in canon:
                dsu.union(i, canon[link])
        for _, sid in keys.x_statuses(" ".join(it.links)):
            if sid in xs_owner:
                dsu.union(i, xs_owner[sid])
    if edges is not None:
        pos = {it.item_id: i for i, it in enumerate(items)}
        for a, b in edges:
            if a in pos and b in pos:
                dsu.union(pos[a], pos[b])
        roots0: dict[int, int] = {}
        return [roots0.setdefault(dsu.find(i), len(roots0)) for i in range(n)]
    titles = [_norm_title(it.title) for it in items]
    lens = [len(t) for t in titles]
    thr = Limits.ECHO_TITLE_SIMILARITY
    # Live 2026-11-11: Publish's now-board ran this for every listed event (hundreds of reports each) and spent
    # minutes in SequenceMatcher. Both skips leave the grouping unchanged: a pair already in one group gains nothing
    # from a union, and 2·min/(la+lb) is real_quick_ratio — an upper bound of ratio — computed without the object.
    for i in range(n):
        if not lens[i]:
            continue
        for j in range(i + 1, n):
            lj = lens[j]
            if not lj or 2 * min(lens[i], lj) < thr * (lens[i] + lj):
                continue
            if dsu.find(i) == dsu.find(j):
                continue
            if _similar_titles(titles[i], titles[j]):
                dsu.union(i, j)
    roots: dict[int, int] = {}
    return [roots.setdefault(dsu.find(i), len(roots)) for i in range(n)]


def _group_tiers(items: list[Item], groups: list[int]) -> list[Tier]:
    best: dict[int, Tier] = {}
    for it, g in zip(items, groups):
        if g not in best or _TIER_RANK[it.tier] < _TIER_RANK[best[g]]:
            best[g] = it.tier
    return list(best.values())


def _level(ev_domain: Domain, items: list[Item], tiers: list[Tier], now: datetime, amount_stable: bool,
           onchain: bool = False) -> tuple[str, str]:
    n_t1 = tiers.count("T1")
    n_t12 = n_t1 + tiers.count("T2")
    sources = {i.source_id for i in items}
    first = min(timeutil.parse(i.published_at) for i in items)
    age_days = (now - first).days
    if ev_domain == "web3":
        has_poc_tx = any(i.source_id == "defihacklabs" and i.extra.get("tx") for i in items)
        aggregators = len(sources & {"defillama_hacks", "slowmist_hacked", "defihacklabs"})
        if (onchain or has_poc_tx or n_t12 >= 2 and n_t1 >= 1) and aggregators >= 2 and amount_stable \
                and age_days >= Limits.FINALIZE_QUIET_DAYS_WEB3:
            return "V4", f"finalized: {aggregators} incident databases agree, amount stable ≥{Limits.FINALIZE_QUIET_DAYS_WEB3}d"
        if onchain:   # C6: the attack transaction itself exists and succeeded (receipt status 0x1 on a public RPC)
            return "V2", "corroborated: attack tx confirmed on-chain (receipt status 1)"
        if has_poc_tx:
            return "V2", "corroborated: reproducible DeFiHackLabs PoC with attack tx (tx not yet confirmed on-chain)"
        if n_t12 >= 2 and n_t1 >= 1:
            return "V2", f"corroborated: {n_t12} independent T1/T2 sources incl. {n_t1} T1"
        if n_t1 >= 1 or n_t12 >= 2:
            return "V1", f"reported: {n_t1} T1 / {n_t12} T1+T2 independent sources"
        if n_t12 == 1:
            return "V1", "reported: single T2 source"
        return "V0", f"rumor: only T3 sources ({len(tiers)} independent)"
    authoritative = [i for i in items if i.tier == "T1"]
    if authoritative:
        if ev_domain == "vuln" and age_days >= Limits.FINALIZE_QUIET_DAYS_VULN:
            return "V4", f"finalized: T1 confirmed and {age_days}d old"
        return "V3", f"confirmed: T1 source ({authoritative[0].source_id})"
    if n_t12 >= 2:
        return "V2", f"corroborated: {n_t12} independent T2 sources"
    if n_t12 == 1:
        return "V1", "reported: single T2 source"
    return "V0", f"rumor: only T3 sources ({len(tiers)} independent)"


def _exploitation(ev_domain: Domain, items: list[Item], level: str) -> str:
    if ev_domain == "web3":
        return "confirmed" if LEVEL_ORDER[level] >= 2 else "reported"
    # a report's "exploited" counts for THIS event only when it is said about this event (signals.exploited_about):
    # a report is in an event through one of its keys, and may speak of exploitation about something else
    named = [{k[4:] for k in i.keys if k.startswith("cve:")} for i in items]

    def says(n: int) -> bool:
        # the event's CVEs as the OTHER reports name them: a digest lends the event every CVE it lists, so "a CVE of
        # the event" judged against the union would always include the digest's own
        rest = _others(named, n)
        i = items[n]
        return i.signals["exploited"] == "yes" and signals.exploited_about(i.title, i.text, named[n], rest)
    told = [n for n in range(len(items)) if items[n].signals["exploited"] == "yes" and says(n)]
    if any(i.signals["kev"] for i in items) or any(items[n].tier == "T1" for n in told):
        return "confirmed"
    if told:
        return "reported"
    return "poc" if any(i.signals["poc"] for i in items) else "none"


def _others(named: list[set[str]], n: int) -> set[str]:
    """The event's CVEs as the OTHER reports name them: a digest lends the event every CVE it lists, so "a CVE of the
    event" judged against the union would always include the report's own (shared by 「exploited」 and 「critical」)."""
    return set().union(*(c for m, c in enumerate(named) if m != n)) if len(named) > 1 else named[n]


def _reporters(items: list[Item], groups: list[int]) -> int:
    """Independent reporting sources (path A's corroboration): syndication groups holding a T1 / T2 report that is not a
    catalog listing (registry.CATALOG_SOURCES)."""
    return len({g for i, g in zip(items, groups, strict=True)
                if i.tier in ("T1", "T2") and i.source_id not in CATALOG_SOURCES and not is_digest(i)})


def _critical(ev_domain: Domain, items: list[Item]) -> bool:
    """Path A to P0 (Neo 2026-11-18): a report of this event says its flaw is critical — unauthenticated RCE or CVSS ≥ 9
    (signals.critical_about, attributed like 「exploited」: a digest's or a newsletter's sentence about another bug does
    not count)."""
    if ev_domain != "vuln":
        return False
    named = [{k[4:] for k in i.keys if k.startswith("cve:")} for i in items]
    for n, i in enumerate(items):
        if not is_digest(i) and signals.critical_about(i.title, i.text, named[n], _others(named, n)):
            return True
    return False


def _severity(ev_domain: Domain, level: str, exploitation: str, amount: float | None, fresh: bool = True,
              critical: bool = False) -> str:
    """P0 means "act now": the impact rule must hold AND the event must be fresh (first seen or escalated
    within Limits.P0_FRESH_HOURS). Stale P0s drop to P1 instead of flooding the board (M2-PLAN A1)."""
    sev = _impact_severity(ev_domain, level, exploitation, amount, critical)
    return "P1" if sev == "P0" and not fresh else sev


def _impact_severity(ev_domain: Domain, level: str, exploitation: str, amount: float | None,
                     critical: bool = False) -> str:
    lv = LEVEL_ORDER[level]
    if ev_domain == "web3":
        if amount is not None and amount >= Limits.WEB3_P0_USD and lv >= 2:
            return "P0"
        if amount is not None and amount >= Limits.WEB3_P1_USD and lv >= 1:
            return "P1"
        return "P2"
    # path A (Neo 2026-11-18): a critical flaw reported by ≥ 2 independent reporting sources (catalog listings do not
    # count) is P0 when it is disclosed — exploitation then updates the notice instead of being the reason for it
    if ev_domain == "vuln" and critical:
        return "P0"
    if exploitation == "confirmed" and lv >= 3:
        return "P0"
    if exploitation == "reported" and lv >= 2:
        return "P0"
    if exploitation in ("reported", "poc") and lv >= 1:
        return "P1"
    return "P2"


def _same(a: float, b: float) -> bool:
    return abs(a - b) <= 1e-6 * max(abs(a), abs(b), 1.0)


def _measure(v: float, mentions: list[tuple[float, str]], body: list[tuple[float, str]], body_losses: list[float],
             whole: str) -> str:
    """Measure of a prose report's stored figure: the headline decides its own figures; a body-only figure is a loss only
    where its clause SAYS so — 「USDT 下降至341亿美元」 is not (live 2026-11-04, four Binance body figures read as losses)."""
    k = next((k for x, k in mentions if _same(x, v)), None)
    if k is not None:
        return k
    if any(_same(x, v) for x in body_losses):
        return "loss"
    k = next((k for x, k in body if _same(x, v)), None)
    return k if k in ("frozen", "context") else ("context" if k == "loss" else whole)


_BY = "_reporter"   # transient key on amount points while _amounts works; never stored (the history keeps its shape)


def _rep(p: dict[str, Any]) -> str:
    """A point's reporter (a point without the transient key — a stored history, a test's — is its source's)."""
    return p.get(_BY, p["source_id"])


def reporter(it: Item) -> str:
    """Who stated a figure: the source — except on X, where one `x_security` source carries every account (T1 ZachXBT
    beside T2 Lookonchain), so the account's organisation (normalize set it from registry.handle_info) is the reporter.
    Grouping X by source_id gave every tweet the last tweet's tier and made all accounts one source (research 07 §2.2:
    ZachXBT $50.2M vs Lookonchain $912.4M ⇒ headline $912.4M, not disputed). X reporters get their own `x:` namespace:
    four handle orgs equal an RSS source_id (watchtowrcyber → watchtowr, thehackersnews → thehackernews …), and one key
    for the T1 watchTowr blog and the T2 watchTowr tweet gave the blog the tweet's tier and stopped them backing each
    other (review of b74b81b: headline $10M instead of the T1 blog's $40M)."""
    src = BY_ID.get(it.source_id)
    return "x:" + it.org if src and src.parser == "twitterapi" else it.source_id


def _mark_outliers(hist: list[dict[str, Any]], structured: set[str]) -> None:
    """A prose loss figure no other source backs and that is either implausible on its own (> MAX_PLAUSIBLE_LOSS_USD)
    or two orders of magnitude off the event's other loss figures is an outlier: kept in the history, never the
    headline (live 2026-11-04: the bank's $235B balance sheet next to its $133M loss). A hack database's structured
    figure is never an outlier; a figure a second source repeats (±1 %) is not either."""
    losses = [p for p in hist if p["kind"] == "loss"]
    for p in losses:
        if _rep(p) in structured:
            continue
        others = [q["value"] for q in losses if q is not p and q["value"] > 0]
        backed = any(_rep(q) != _rep(p) and abs(q["value"] - p["value"]) <= 0.01 * p["value"] for q in losses)
        if backed:
            continue
        # the ratio test needs a consensus to stand against: with one other figure there is no telling which of the two is
        # off (a $6.3B theft beside 「一名用户被盗约100美元」 must not lose its headline to the $100)
        med = sorted(others)[len(others) // 2] if len(others) >= 2 else None
        if p["value"] > Limits.MAX_PLAUSIBLE_LOSS_USD or (med and p["value"] > Limits.AMOUNT_OUTLIER_RATIO * med):
            p["kind"] = "outlier"


def _amounts(items: list[Item]) -> tuple[list[dict[str, Any]], float | None, bool, bool, float | None]:
    """(history, headline loss, disputed, stable, frozen). Every point carries its measure (signals.amount_kind of the
    report's title; a hack database's structured amount is always the loss): the headline and the dispute flag use loss
    points only, freezes are their own measure (the largest reported — freeze totals only grow, and a single-issuer
    freeze such as Arbitrum's $30.5M must not replace the running total), context amounts feed neither."""
    structured = {reporter(it) for it in items if it.extra.get("amount_usd") is not None}
    hist: list[dict[str, Any]] = []
    rep: dict[int, str] = {}             # id(point) → reporter, once the transient key is stripped
    for it in items:
        pts, by = it.extra.get("amount_history") or [], reporter(it)
        if it.extra.get("amount_usd") is not None:
            hist += [{"value": p["value"], "source_id": it.source_id, _BY: by,
                      "observed_at": p["observed_at"], "kind": "loss"} for p in pts]
            continue
        # prose: each number takes the measure of its own clause (a title can state the loss and the freeze); the
        # stored point is the title's largest number, a freeze stated beside it becomes its own point
        # the stored value is parsed from the body (normalize), the headline claims are in the title: a value takes the
        # measure of whichever clause states it (Decrypt: body "$5.57 billion" stolen, title "$5.5 Billion")
        text = it.title or it.text[:200]
        if signals.is_roundup_report(it.title):   # statistics across incidents: context only, no freeze point
            hist += [{"value": p["value"], "source_id": it.source_id, _BY: by,
                      "observed_at": p["observed_at"], "kind": "context"}
                     for p in pts]
            continue
        # a hack database's record IS a loss record, whichever way its line reads (DeFiHackLabs MUS: 「Lost: ~0.4 ETH per
        # cycle …; reported campaign total ~$36.9k」 — no structured field, and the clause split hid the cue)
        if BY_ID.get(it.source_id) and BY_ID[it.source_id].always_eventful:
            hist += [{"value": p["value"], "source_id": it.source_id, _BY: by,
                      "observed_at": p["observed_at"], "kind": "loss"}
                     for p in pts]
            continue
        mentions = signals.amount_mentions(text)
        body = signals.amount_mentions(it.text)
        body_losses = signals.stated_losses(it.text)
        whole = signals.amount_kind(text)
        for p in pts:
            kind = _measure(p["value"], mentions, body, body_losses, whole)
            hist.append({"value": p["value"], "source_id": it.source_id, _BY: by,
                         "observed_at": p["observed_at"], "kind": kind})
        if pts:
            hist += [{"value": v, "source_id": it.source_id, _BY: by,
                      "observed_at": pts[-1]["observed_at"], "kind": "frozen"}
                     for v, k in mentions if k == "frozen" and not any(_same(v, p["value"]) for p in pts)]
    hist.sort(key=lambda p: (p["observed_at"], p["source_id"]))
    _mark_outliers(hist, structured)
    for p in hist:                       # the stored history keeps its shape: the reporter only groups, here
        rep[id(p)] = p.pop(_BY)
    frozen_pts = [p["value"] for p in hist if p["kind"] == "frozen" and p["value"] > 0]
    frozen = max(frozen_pts) if frozen_pts else None
    loss = [p for p in hist if p["kind"] == "loss"]
    if not loss:
        return hist, None, False, True, frozen
    tier_of = {reporter(it): it.tier for it in items}
    # A hack database's structured loss field (DeFiLlama / SlowMist amount) beats any number parsed from prose: prose
    # amounts are often a freeze, a borrow or a sale inside the story (live 2026-10-30: a T1 tweet "Arbitrum Security
    # Council froze $30.5M" displaced DeFiLlama's $5.78B Binance loss as the headline figure).
    pool = [p for p in loss if rep[id(p)] in structured] or loss
    best_rank = min(_TIER_RANK[tier_of[rep[id(p)]]] for p in pool)
    trusted = [p for p in pool if _TIER_RANK[tier_of[rep[id(p)]]] == best_rank]
    latest = trusted[-1]["value"]
    per_source: dict[str, float] = {}
    # the dispute is judged on the same pool as the headline: hack databases' structured figures, when there are any. Live
    # 2026-11-11: Binance coverage carries every side story (Bitget $292M, Mercado $49M …), so some prose source's largest
    # figure was always a side story and DeFiLlama $6.36B / SlowMist $6.34B — agreeing — read as disputed (P0 → P1).
    for p in pool:      # = loss when no structured figure exists
        # a source's largest stated loss is its estimate of the total: flash-news sources report sub-stories after it
        # (live 2026-10-30: odaily's latest Binance "loss" was a $100M side story vs DeFiLlama's $6.36B ⇒ disputed)
        per_source[rep[id(p)]] = max(p["value"], per_source.get(rep[id(p)], 0))
    # live 2026-10-30: a $100 UNI price target in a side story flagged the $6.3B Binance loss as disputed
    top = max(per_source.values(), default=0)
    vals = [v for v in per_source.values() if v > 0 and v >= top * Limits.AMOUNT_DISPUTE_FLOOR]
    disputed = len(vals) >= 2 and max(vals) / min(vals) > Limits.AMOUNT_DISPUTE_RATIO
    stable = all(abs(p["value"] - latest) / latest <= Limits.AMOUNT_STABLE_RATIO for p in trusted[-2:]) if latest else True
    return hist, latest, disputed, stable, frozen


def _title(items: list[Item]) -> str:
    """A structured record names the event — the first one captured: a later database entry may carry a root-cause
    hypothesis in its technique field (live 2026-10-30: SlowMist's "DevOps Engineer's Laptop Compromised", from Binance's
    "may involve", replaced DeFiLlama's "Hot Wallet Key Compromised" because SlowMist is T1). Without one, the best tier."""
    def rank(it: Item) -> tuple[int, str, int, str]:
        structured = bool(BY_ID.get(it.source_id) and BY_ID[it.source_id].always_eventful)
        first = it.extra.get("first_fetched_at") or it.fetched_at
        return (0 if structured else 1, first if structured else "", _TIER_RANK[it.tier], it.published_at)
    return min(items, key=rank).title


def _attribution(items: list[Item]) -> dict[str, Any] | None:
    """Named threat actor: "stated" once a T1/T2 report names it, "suspected" while only community / flash news does."""
    named = [(it, signals.attribution_actor(f"{it.title}\n{it.text[:600]}")) for it in items]
    named = [(it, a) for it, a in named if a]
    if not named:
        return None
    actor = named[0][1]
    hits = [it for it, a in named if a == actor]
    # first naming = evidence time (a date-only entry's 00:00:00Z is "that day", not midnight — evidence_at decides)
    first = first_report(sorted(items, key=lambda i: (i.published_at, i.source_id, i.item_id)))
    return {"actor": actor, "confidence": "stated" if any(it.tier in ("T1", "T2") for it in hits) else "suspected",
            "sources": len({it.source_id for it in hits}), "first_at": min(evidence_at(it, first) for it in hits)}


def day_precision(item: Item) -> bool:
    """A source that only gives a date: 00:00:00Z means "that day", not midnight (timeutil.day_only decides). Not only the
    structured ones (KEV, DeFiLlama): live 2026-11-18 a Datadog Security Labs post dated "2026-11-17" became Java4Shell's
    first report at 00:00, ten hours before the first report with a time (watchTowr 10:22Z)."""
    return timeutil.day_only(item.published_at)


def collected_at(item: Item) -> str:
    """When the radar first captured this report (a revision refreshes fetched_at; first_fetched_at survives it).
    Not its publication time: live 2026-11-03 the CVE-2026-98432 page called THN's 15:57 publication 「雷达首见」 while
    the radar captured it at 16:28."""
    return item.extra.get("first_fetched_at") or item.fetched_at


def sighting(items: list[Item]) -> dict[str, Any] | None:
    """The event's three clocks, decided here once: the first report's publication (by its source), the radar's first
    capture of any report, and the lag between them (minutes, ≥ 0; a backfilled incident has days). The CVE's own
    publication is cvemeta.disclosure."""
    if not items:
        return None
    items = sorted(items, key=lambda i: (i.published_at, i.source_id, i.item_id))
    first = first_report(items)
    seen = min(items, key=lambda i: (collected_at(i), i.item_id))
    got = collected_at(seen)
    a, b = timeutil.parse(first.published_at), timeutil.parse(got)
    lag = round(max(0.0, (b - a).total_seconds()) / 60) if a and b else None

    def name(it: Item) -> str:
        src = BY_ID.get(it.source_id)
        if it.source_id.startswith("x_") and it.url.count("/") >= 4:      # same wording as the evidence list
            return f"X @{it.url.split('/')[3]}"
        return src.name if src else it.source_id
    # the first capture can be another report than the first one (live: THN's tweet at 16:28, its article at 17:08)
    return {"first_report_at": first.published_at, "first_report_source": name(first),
            "first_report_date_only": day_precision(first),
            "first_collected_at": got, "first_collected_source": name(seen), "collect_lag_minutes": lag}


def first_report(items: list[Item]) -> Item:
    """Earliest report (items sorted by published_at). A date-only entry is first only when its day is earlier than
    every timed report; otherwise the earliest timed report is (live 2026-10-30: DeFiLlama's "2026-10-29" put the
    Binance theft at 00:00, 21 h before the first report at 20:51 — out of the wall's 24h loss, 首报 DeFiLlama)."""
    timed = next((i for i in items if not day_precision(i)), None)
    if timed is None or timed.published_at[:10] <= items[0].published_at[:10]:
        return timed or items[0]
    return items[0]


def evidence_at(item: Item, first: Item) -> str:
    """When an item counts as evidence on a timeline: its publication time — except a date-only entry that is not the
    first report. Its true time is unknown inside [first report, end of its day or first capture]; the radar takes the
    latest possible moment, so no stage (second source, corroboration) claims a speed nobody saw (live 2026-10-30:
    DeFiLlama's "2026-10-29" at the first report's second made 第二独立来源 = 首报 on the Binance page)."""
    if not day_precision(item) or item.item_id == first.item_id:
        return item.published_at
    day_end = item.published_at[:10] + "T23:59:59Z"
    seen = item.extra.get("first_fetched_at") or item.fetched_at or day_end
    return max(first.published_at, min(day_end, seen))


def recompute(ev: Event, items: list[Item], now: datetime, title_pairs: set[tuple[str, str]] | None = None) -> Event:
    members = _recompute_order(items)
    # digests attached before they were recognised stay members (the page lists them) but are evidence for nothing;
    # an event made of digests only keeps them — there is nothing else to compute it from (it should not exist: a replay
    # removes it, and scripts/recompute_check.py shows it)
    items = [i for i in members if not is_digest(i)] or members
    digest_only = len(items) == len(members) and all(is_digest(i) for i in members)
    groups = independent_groups(items, title_pairs)
    tiers = _group_tiers(items, groups)
    # a digest's figures and its "exploited" are about the stories it tells, none of them this event
    hist, latest, disputed, stable, frozen = ([], None, False, False, None) if digest_only else _amounts(items)
    # on-chain verdicts live on the event (items only carry the hash): carry them over, then let them count
    seen = {t["hash"]: t for t in ev.tx}
    tx: dict[str, dict[str, Any]] = {}
    for i in items:
        for t in i.extra.get("tx") or []:
            tx.setdefault(t["hash"], {**t, **{k: v for k, v in (seen.get(t["hash"]) or {}).items() if k not in t},
                                      "verified": (seen.get(t["hash"]) or {}).get("verified", "unchecked")})
    level, reason = _level(ev.domain, items, tiers, now, stable, onchain=chain.onchain_confirmed(list(tx.values())))
    exploitation = "none" if digest_only else _exploitation(ev.domain, items, level)
    # escalation time = publication of the newest evidence when urgency rose (not processing time, or a
    # historical backfill would look "fresh"); age-driven V4 finalization is not an escalation
    rose = (LEVEL_ORDER[level] > LEVEL_ORDER[ev.level] and level != "V4") or \
        EXPLOITATION_ORDER[exploitation] > EXPLOITATION_ORDER[ev.exploitation]
    if rose and ev.item_ids:
        newest = max(i.published_at for i in items)
        # an exploitation rise is dated by its evidence: live 2026-11-18, a merge brought a 10-14 KEV entry into a 09-10
        # event and the newest report (11-17) made a five-week-old fact a "fresh" P0. Web3 exploitation follows level.
        if ev.domain != "web3" and EXPLOITATION_ORDER[exploitation] > EXPLOITATION_ORDER[ev.exploitation]:
            said = [i.published_at for i in items if i.signals.get("kev") or i.signals.get("exploited") == "yes"]
            newest_level = newest if LEVEL_ORDER[level] > LEVEL_ORDER[ev.level] and level != "V4" else ""
            ev.escalated_at = max(min(said) if said else newest, newest_level)
        else:
            ev.escalated_at = newest
    ev.item_ids = [i.item_id for i in members]
    ev.title = _title(items)
    first = first_report(items)
    ev.first_seen = first.published_at
    ev.last_updated = max(max(i.published_at for i in members), max((i.extra.get("revised_at") or "") for i in members))
    ev.level, ev.level_reason, ev.exploitation = level, reason, exploitation
    ev.independent_sources = len(tiers)
    src = BY_ID.get(first.source_id)
    ev.first_report_source = src.name if src else first.source_id
    ev.amount_history, ev.amount_usd_latest, ev.amount_disputed = hist, latest, disputed
    ev.amount_frozen_latest = frozen
    ev.attribution = _attribution(items)
    fresh_since = timeutil.iso(now - timedelta(hours=Limits.P0_FRESH_HOURS))
    ev.severity = _severity(ev.domain, level, exploitation, latest,
                            # freshness keeps the earliest timestamp, date-only included: conservative on purpose
                            # (a KEV entry "added 10-20" may be 3 days old) — first_seen moved to the first report
                            fresh=max(items[0].published_at, ev.escalated_at) >= fresh_since,
                            critical=_critical(ev.domain, items) and _reporters(items, groups) >= Limits.P0_PATH_A_REPORTERS)
    ev.cves = _own_cves(items)
    if ev.domain == "vuln" and not ev.cves and items and all(is_list_announcement(i) for i in items):
        ev.severity = "P2"   # R9.6: a catalog announcement naming no CVE is no single vulnerability (is_list_announcement)
    ev.entities = sorted({i.entity for i in items if i.entity})
    ev.tx = list(tx.values())
    ev.chains = sorted({c for i in items for c in (i.extra.get("chains") or [])} | {t["chain"] for t in ev.tx})
    return ev


# ---------------------------------------------------------------- ingest (the station)

def _timeline_diff(before: Event | None, after: Event, at: str, item_id: str | None) -> list[dict[str, Any]]:
    if before is None:
        return [{"at": at, "kind": "created", "from": None, "to": after.level, "item_id": item_id}]
    out = []
    if item_id and item_id not in before.item_ids:
        out.append({"at": at, "kind": "item_added", "from": None, "to": None, "item_id": item_id})
    for kind, a, b in (("level_change", before.level, after.level),
                       ("severity_change", before.severity, after.severity),
                       ("exploitation_change", before.exploitation, after.exploitation)):
        if a != b:
            out.append({"at": at, "kind": kind, "from": a, "to": b, "item_id": item_id})
    if before.amount_usd_latest != after.amount_usd_latest:
        out.append({"at": at, "kind": "amount_change", "from": None if before.amount_usd_latest is None else
                    str(before.amount_usd_latest), "to": None if after.amount_usd_latest is None else
                    str(after.amount_usd_latest), "item_id": item_id})
    return out


def ingest(raws: list[RawItem], store: Store, fetched_at: datetime, now: datetime | None = None) -> IngestResult:
    """Idempotent: re-ingesting identical raw items changes nothing (same ids, same content hash)."""
    now = now or fetched_at
    res = IngestResult()
    from radar import ghsa_alias
    aliases = {g: row["cve"] for g, row in ((store.get_source_state(ghsa_alias.KEY) or {}).get("map") or {}).items()
               if row.get("cve")}
    for raw in raws:
        source = BY_ID[raw.source_id]
        item = normalize(raw, source, fetched_at, aliases)
        prev = store.get_item(item.item_id)
        if prev and prev.content_hash == item.content_hash:
            res.unchanged_items += 1
            continue
        at = timeutil.iso(fetched_at)
        hist = list(prev.extra.get("amount_history") or []) if prev else []
        amt = item.signals["amount_usd"]
        if amt is not None and (not hist or hist[-1]["value"] != amt):
            hist.append({"value": amt, "observed_at": item.published_at if not prev else at})
        item.extra["amount_history"] = hist
        # a revision refreshes fetched_at; "first captured" (_title) must survive it
        item.extra["first_fetched_at"] = (prev.extra.get("first_fetched_at") or prev.fetched_at) if prev else item.fetched_at
        if prev:
            item.extra["revised_at"] = at
            if prev.extra.get("event_pin"):
                item.extra["event_pin"] = prev.extra["event_pin"]
            res.updated_items += 1
        else:
            res.new_items += 1
            if (lag := latency.minutes(item.published_at, now)) is not None:
                res.held.append([item.tier, lag])
        store.put_item(item)
        attach(item, store, at, now, res)
    res.anomalies = anomaly.scan(res.before, res.absorbed, store.get_event, timeutil.iso(now))
    return res


def attach(item: Item, store: Store, at: str, now: datetime, res: IngestResult) -> None:
    """Cluster one stored item: find its event (or found one), merge events it proves are one story, recompute.
    Shared by ingest and scripts/recluster_web3.py (a repair replays stored items through exactly this)."""
    # a report an operator moved (radar.moves) stays where it was put: a revision or a replay does not re-ask the rules
    pin = item.extra.get("event_pin")
    eid, merge_ids = (pin, []) if pin else find_events(item, store)
    if eid is None and not item.eventful:
        return
    before = store.get_event(eid) if eid else None
    if before is None and pin:
        ev = Event(event_id=pin, domain=item.domain, title=item.title, first_seen=item.published_at,
                   last_updated=item.published_at, item_ids=[], keys=[])   # a replay reaches the pin before its event
    elif before is None:
        seed = next((k for k in item.keys if k.startswith(_STRONG[:4])), item.item_id)
        eid = keys.event_id(seed)
        # "find_events found nothing" is not "nobody holds this id": a roundup seeds its event with a cve: key it does
        # not index, so the next report of that CVE derived the same id and overwrote that event (research 07 §2.1)
        salt = item.item_id
        while store.get_event(eid) is not None:
            eid, salt = keys.event_id(f"{seed}#{salt}"), salt + "#"
        ev = Event(event_id=eid, domain=item.domain, title=item.title, first_seen=item.published_at,
                   last_updated=item.published_at, item_ids=[], keys=[])
    else:
        ev = Event.from_dict(before.to_dict())
    # Known gap, deliberately left (research 07 B10 / §2.6): a revision (same url) rewritten to tell another incident
    # still reaches its old event through its own url: key, so that event — with any other reports it holds — merges
    # into the new one. Not fixed automatically: refusing the merge leaves the item listed in both events
    # (double-counted sources). The manual repair is radar.moves.move_item.
    merged = [m for m in (store.get_event(x) for x in merge_ids) if m]
    if before is not None:
        res.before.setdefault(ev.event_id, anomaly.snap(before))
    for m in merged:
        # what the absorbed event was when the cycle found it, not what earlier merges of this cycle made of it
        res.absorbed.setdefault(ev.event_id, []).append(res.before.pop(m.event_id, None) or anomaly.snap(m))
        res.absorbed[ev.event_id] += res.absorbed.pop(m.event_id, [])
    ids = list(dict.fromkeys(ev.item_ids + [i for m in merged for i in m.item_ids] + [item.item_id]))
    ev = recompute(ev, store.get_items(ids), now)
    ev.keys = sorted(k for k in set(ev.keys) | set(indexed_keys(item)) | {k for m in merged for k in m.keys}
                     if not k.startswith("cve:") or k[4:] in ev.cves)      # a CVE that is not the event's finds it no more
    ev.timeline = (before.timeline if before else []) + _timeline_diff(before, ev, at, item.item_id)
    for m in merged:
        ev.timeline.append({"at": at, "kind": "merged", "from": m.event_id, "to": ev.event_id, "item_id": item.item_id})
        store.add_keys(ev.event_id, m.keys)
        # R2: the absorbed event's AWS job records / findings / patches follow the story to the survivor.
        # Safe here: Respond runs after Process in the same cycle, so nothing writes response state concurrently.
        if (gone := store.get_response(m.event_id)) is not None:
            store.put_response(ev.event_id, respond.merge_states(ev.event_id, store.get_response(ev.event_id),
                                                                 m.event_id, gone))
            store.delete_response(m.event_id)
        store.delete_event(m.event_id)
        # its index rows now point at nothing (live 2026-11-02: 49 such rows over 9 merged events); the survivor
        # already holds every one of those keys (add_keys above)
        store.remove_keys(m.event_id, m.keys)
        res.changes.pop(m.event_id, None)
    # the site still holds their search rows and detail pages; publish prunes them (radar.removals)
    removals.record(store, [(m.event_id, m.first_seen[:7], ev.event_id) for m in merged], at)
    ev.timeline.sort(key=lambda t: t["at"])
    store.put_event(ev)
    store.add_keys(ev.event_id, [k for k in indexed_keys(item) if k in ev.keys])
    ch = res.changes.setdefault(ev.event_id, Change(ev.event_id, created=before is None))
    if before is not None:
        ch.level_changed |= LEVEL_ORDER[before.level] != LEVEL_ORDER[ev.level]
        ch.severity_changed |= SEVERITY_ORDER[before.severity] != SEVERITY_ORDER[ev.severity]


def verify_onchain(store: Store, now: datetime, call: Any = chain.rpc_call,
                   since_days: int = Limits.PUBLISH_WINDOW_DAYS) -> list[str]:
    """C6 station step: due attack txs of recent web3 events → on-chain verdicts (≤ CHAIN_CHECKS_PER_CYCLE RPC calls,
    P0/P1 first), then recompute so a confirmed tx raises the level. Returns the events that changed."""
    since = timeutil.iso(now - timedelta(days=since_days))
    cands = [e for e in store.events_updated_since(since) if e.domain == "web3" and any(chain.due(t, now) for t in e.tx)]
    cands.sort(key=lambda e: e.last_updated, reverse=True)       # newest first …
    cands.sort(key=lambda e: -SEVERITY_ORDER[e.severity])         # … within severity: P0, P1, P2 (stable sort)
    budget, changed = Limits.CHAIN_CHECKS_PER_CYCLE, []
    for ev in cands:
        if budget <= 0:
            break
        before = Event.from_dict(ev.to_dict())
        ev.tx, used = chain.check_txs(ev.tx, now, budget, call)
        budget -= used
        after = recompute(ev, store.get_items(ev.item_ids), now)
        diff = [d for d in _timeline_diff(before, after, timeutil.iso(now), None) if d["kind"] != "item_added"]
        after.timeline = before.timeline + diff
        store.put_event(after)
        if diff or [t.get("verified") for t in before.tx] != [t.get("verified") for t in after.tx]:
            changed.append(after.event_id)
    return changed


def refresh(store: Store, now: datetime, since_days: int = Limits.PUBLISH_WINDOW_DAYS) -> list[str]:
    """Time-driven recompute (V4 finalization depends on age, not on new items)."""
    changed = []
    since = timeutil.iso(now - timedelta(days=since_days))
    for ev in store.events_updated_since(since):
        before = Event.from_dict(ev.to_dict())
        after = recompute(ev, store.get_items(ev.item_ids), now)
        diff = [d for d in _timeline_diff(before, after, timeutil.iso(now), None) if d["kind"] != "item_added"]
        # any derived field counts, not only the timeline's: a corrected rule (title, frozen, dispute, attribution) must
        # reach an event that is already open (live 2026-10-30: the fixed Binance figures waited for the next new item)
        if diff or _derived(before) != _derived(after):
            after.timeline = before.timeline + diff
            store.put_event(after)
            changed.append(after.event_id)
    return changed


def _derived(ev: Event) -> dict[str, Any]:
    d = ev.to_dict()
    d.pop("timeline", None)
    return d
