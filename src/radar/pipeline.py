"""normalize → cluster → verify → score. Deterministic: same raw items in the same order ⇒ same events,
levels and timeline. No LLM in this module (M2 adds extract/summarize stations around it)."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from difflib import SequenceMatcher
from typing import Any

from radar import chain, keys, respond, signals, timeutil
from radar.limits import Limits
from radar.model import EXPLOITATION_ORDER, LEVEL_ORDER, SEVERITY_ORDER, Domain, Event, Item, RawItem, Tier
from radar.registry import BY_ID, Source, handle_info
from radar.store import Store

_TIER_RANK = {"T1": 1, "T2": 2, "T3": 3}
_CRYPTO = re.compile(
    r"\b(crypto|defi|web3|blockchain|token|stablecoin|bitcoin|btc|ethereum|eth|solana|bnb|bsc|tron|"
    r"exchange hack\w*|drained|cex|dex|bridge|wallet|smart contract|on-?chain|airdrop|nft|usdt|usdc|"
    r"binance|coinbase|okx|bybit|bitget|kraken)\b|加密|区块链|交易所|钱包|代币|链上|跨链|稳定币",
    re.IGNORECASE,
)
_VULN = re.compile(r"\b(CVE-\d{4}|vulnerabilit(?:y|ies)|zero-?day|0-?day|patch(?:es|ed)?|security update|RCE)\b|漏洞|补丁",
                   re.IGNORECASE)
_STRONG = ("cve:", "tx:", "attacker:", "xs:", "url:")
# CISA's two phrasings: "Adds Two Known Exploited Vulnerabilities to Catalog" (advisories) and "We added … CVE-… &
# … CVE-… to our KEV Catalog" (X); both list unrelated bugs side by side
KEV_ROUNDUP_RE = re.compile(r"\badd(?:s|ed)?\b.{0,160}?\b(?:known exploited vulnerabilit(?:y|ies)|KEV catalog)\b", re.IGNORECASE | re.DOTALL)
_WEAK = ("ent:", "tok:")


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


# ---------------------------------------------------------------- normalize

def _classify(base: Domain | None, text: str, has_cve: bool) -> Domain:
    if base == "web3":
        return "vuln" if has_cve and not signals.web3_incident(text) else "web3"
    if base:
        return base
    if _CRYPTO.search(text):
        return "web3"
    return "vuln" if has_cve or _VULN.search(text) else "incident"


def normalize(raw: RawItem, source: Source, fetched_at: datetime) -> Item:
    if source.parser == "twitterapi":
        h = handle_info(raw.author or "")
        tier, org, base = h.tier, h.org, h.domain or source.domain
    else:
        tier, org, base = source.tier, source.org, source.domain
    blob = f"{raw.title}\n{raw.text}"
    cve_list = sorted(set(keys.cves(blob)) | set(raw.extra.get("cves") or []))
    domain = _classify(base, blob, bool(cve_list))
    links = [keys.canonical_url(u) for u in raw.links if u]
    canon = keys.canonical_url(raw.url)

    reg: list[str] = []
    if len(cve_list) <= 3:  # roundups listing dozens of CVEs must not glue unrelated CVE events together
        reg += [f"cve:{c}" for c in cve_list]
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
        reg += sorted(f"tok:{t}" for t in keys.entity_tokens(blob))
    elif domain != "web3":
        reg += sorted(f"tok:{t}" for t in keys.named_tokens(raw.title))
    # citing a tweet is a hard link: register it so whichever arrives first, the other finds it
    reg += [f"xs:{sid}" for _, sid in keys.x_statuses(" ".join(raw.links))]

    exploited = "yes" if raw.extra.get("kev") else signals.exploited(blob)
    amount = raw.extra.get("amount_usd")
    if amount is None and domain == "web3" and "amount_usd" not in raw.extra:
        amount = signals.parse_amount(raw.text) if signals.web3_incident(blob) else None
    poc = bool(raw.extra.get("poc")) or signals.poc(blob)

    if source.always_eventful:
        eventful = True
    elif domain == "web3":
        eventful = signals.web3_incident(raw.title or raw.text) and (amount is not None or tier == "T1")
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
    return Item(
        item_id=keys.item_id(source.source_id, raw.guid or canon), source_id=source.source_id, tier=tier, org=org,
        domain=domain, url=raw.url, canonical_url=canon, title=raw.title[:300], text=raw.text[:4000],
        published_at=timeutil.iso(published), fetched_at=timeutil.iso(fetched_at), content_hash=content_hash,
        keys=sorted(set(reg)), links=links, entity=raw.extra.get("entity"), eventful=eventful,
        signals={"exploited": exploited, "kev": bool(raw.extra.get("kev")), "poc": poc, "amount_usd": amount},
        extra=extra)


# ---------------------------------------------------------------- cluster

def _lookup_keys(item: Item) -> list[str]:
    out = list(item.keys)
    out += [f"url:{u}" for u in item.links]
    out += [f"xs:{sid}" for _, sid in keys.x_statuses(" ".join(item.links))]
    # structured victim names (ent:) and free-text tokens (tok:) look each other up in both directions
    out += [f"tok:{k[4:]}" for k in item.keys if k.startswith("ent:")]
    out += [f"ent:{k[4:]}" for k in item.keys if k.startswith("tok:")]
    return sorted(set(out))


def _within(event: Event, item: Item, days: int) -> bool:
    a, b = timeutil.parse(event.first_seen), timeutil.parse(item.published_at)
    return abs((a - b).total_seconds()) <= days * 86400 if a and b else False


def is_roundup(item: Item) -> bool:
    """KEV catalog announcement listing several CVEs (flag set at normalize; recomputed for items stored before it)."""
    n = sum(1 for k in item.keys if k.startswith("cve:"))
    return bool(item.extra.get("roundup")) or (n >= 2 and bool(KEV_ROUNDUP_RE.search(f"{item.title}\n{item.text}")))


def indexed_keys(item: Item) -> list[str]:
    """Keys an item contributes to its event (event keys, key index, event CVE list). A roundup attaches through its
    CVEs but contributes none of them — else the next ordinary item of one of those CVEs finds this event through the
    index and merges two unrelated stories after all."""
    return [k for k in item.keys if not (k.startswith("cve:") and is_roundup(item))]


def find_events(item: Item, store: Store) -> tuple[str | None, list[str]]:
    """Best matching event, plus other events this item proves are the same story (merge candidates):
    matched through a strong key, or — outside web3 — through a named-vulnerability token."""
    score: dict[str, int] = {}
    strong_hit: set[str] = set()
    cache: dict[str, Event | None] = {}
    item_cves = {k[4:] for k in item.keys if k.startswith("cve:")}
    for k in _lookup_keys(item):
        strong = k.startswith(_STRONG)
        if not strong and not item.eventful:
            continue  # context-only items attach through hard links, never through name similarity
        for eid in store.event_ids_for_key(k):
            ev = cache.setdefault(eid, store.get_event(eid))
            if ev is None:
                continue
            if not strong and (ev.domain != item.domain or not _within(ev, item, Limits.ENTITY_WINDOW_DAYS)):
                continue
            score[eid] = score.get(eid, 0) + (10 if strong else 1)
            # a named-vulnerability token may prove "same story" only when the CVEs do not contradict it: an item
            # with CVEs cannot glue an event whose CVE set is disjoint from its own (live 2026-10-27: a late PHP2Shell
            # advisory merged Node2Shell — CVE-2026-111497 — into PHP2Shell through tok:php2shell)
            contradicts = not strong and item_cves and ev.cves and not (item_cves & set(ev.cves))
            if (strong or item.domain != "web3") and not contradicts:
                strong_hit.add(eid)
    if not score:
        return None, []
    ranked = sorted(score, key=lambda e: (-score[e], cache[e].first_seen if cache[e] else ""))
    if is_roundup(item):
        return ranked[0], []
    return ranked[0], [e for e in ranked[1:] if e in strong_hit]


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


def independent_groups(items: list[Item]) -> list[int]:
    """Group items that are NOT independent: same org, one cites the other, they cite the same X status,
    or near-identical titles (syndication). Returns a group index per item (0..n_groups-1)."""
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
    titles = [_norm_title(it.title) for it in items]
    for i in range(n):
        for j in range(i + 1, n):
            if titles[i] and titles[j] and \
                    SequenceMatcher(None, titles[i], titles[j]).ratio() >= Limits.ECHO_TITLE_SIMILARITY:
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
    if any(i.signals["kev"] or (i.tier == "T1" and i.signals["exploited"] == "yes") for i in items):
        return "confirmed"
    if any(i.signals["exploited"] == "yes" for i in items):
        return "reported"
    return "poc" if any(i.signals["poc"] for i in items) else "none"


def _severity(ev_domain: Domain, level: str, exploitation: str, amount: float | None, fresh: bool = True) -> str:
    """P0 means "act now": the impact rule must hold AND the event must be fresh (first seen or escalated
    within Limits.P0_FRESH_HOURS). Stale P0s drop to P1 instead of flooding the board (M2-PLAN A1)."""
    sev = _impact_severity(ev_domain, level, exploitation, amount)
    return "P1" if sev == "P0" and not fresh else sev


def _impact_severity(ev_domain: Domain, level: str, exploitation: str, amount: float | None) -> str:
    lv = LEVEL_ORDER[level]
    if ev_domain == "web3":
        if amount is not None and amount >= Limits.WEB3_P0_USD and lv >= 2:
            return "P0"
        if amount is not None and amount >= Limits.WEB3_P1_USD and lv >= 1:
            return "P1"
        return "P2"
    if exploitation == "confirmed" and lv >= 3:
        return "P0"
    if exploitation == "reported" and lv >= 2:
        return "P0"
    if exploitation in ("reported", "poc") and lv >= 1:
        return "P1"
    return "P2"


def _amounts(items: list[Item]) -> tuple[list[dict[str, Any]], float | None, bool, bool]:
    hist: list[dict[str, Any]] = []
    for it in items:
        for p in it.extra.get("amount_history") or []:
            hist.append({"value": p["value"], "source_id": it.source_id, "observed_at": p["observed_at"]})
    hist.sort(key=lambda p: (p["observed_at"], p["source_id"]))
    if not hist:
        return [], None, False, True
    tier_of = {it.source_id: it.tier for it in items}
    best_rank = min(_TIER_RANK[tier_of[p["source_id"]]] for p in hist)
    trusted = [p for p in hist if _TIER_RANK[tier_of[p["source_id"]]] == best_rank]
    latest = trusted[-1]["value"]
    per_source: dict[str, float] = {}
    for p in hist:
        per_source[p["source_id"]] = p["value"]
    vals = [v for v in per_source.values() if v > 0]
    disputed = len(vals) >= 2 and max(vals) / min(vals) > Limits.AMOUNT_DISPUTE_RATIO
    stable = all(abs(p["value"] - latest) / latest <= Limits.AMOUNT_STABLE_RATIO for p in trusted[-2:]) if latest else True
    return hist, latest, disputed, stable


def _title(items: list[Item]) -> str:
    def rank(it: Item) -> tuple[int, int, str]:
        structured = 0 if BY_ID.get(it.source_id) and BY_ID[it.source_id].always_eventful else 1
        return (structured, _TIER_RANK[it.tier], it.published_at)
    return min(items, key=rank).title


def recompute(ev: Event, items: list[Item], now: datetime) -> Event:
    items = sorted(items, key=lambda i: (i.published_at, i.source_id, i.item_id))
    groups = independent_groups(items)
    tiers = _group_tiers(items, groups)
    hist, latest, disputed, stable = _amounts(items)
    # on-chain verdicts live on the event (items only carry the hash): carry them over, then let them count
    seen = {t["hash"]: t for t in ev.tx}
    tx: dict[str, dict[str, Any]] = {}
    for i in items:
        for t in i.extra.get("tx") or []:
            tx.setdefault(t["hash"], {**t, **{k: v for k, v in (seen.get(t["hash"]) or {}).items() if k not in t},
                                      "verified": (seen.get(t["hash"]) or {}).get("verified", "unchecked")})
    level, reason = _level(ev.domain, items, tiers, now, stable, onchain=chain.onchain_confirmed(list(tx.values())))
    exploitation = _exploitation(ev.domain, items, level)
    # escalation time = publication of the newest evidence when urgency rose (not processing time, or a
    # historical backfill would look "fresh"); age-driven V4 finalization is not an escalation
    rose = (LEVEL_ORDER[level] > LEVEL_ORDER[ev.level] and level != "V4") or \
        EXPLOITATION_ORDER[exploitation] > EXPLOITATION_ORDER[ev.exploitation]
    if rose and ev.item_ids:
        ev.escalated_at = max(i.published_at for i in items)
    ev.item_ids = [i.item_id for i in items]
    ev.title = _title(items)
    ev.first_seen = items[0].published_at
    ev.last_updated = max(max(i.published_at for i in items), max((i.extra.get("revised_at") or "") for i in items))
    ev.level, ev.level_reason, ev.exploitation = level, reason, exploitation
    ev.independent_sources = len(tiers)
    src = BY_ID.get(items[0].source_id)
    ev.first_report_source = src.name if src else items[0].source_id
    ev.amount_history, ev.amount_usd_latest, ev.amount_disputed = hist, latest, disputed
    fresh_since = timeutil.iso(now - timedelta(hours=Limits.P0_FRESH_HOURS))
    ev.severity = _severity(ev.domain, level, exploitation, latest,
                            fresh=max(ev.first_seen, ev.escalated_at) >= fresh_since)
    ev.cves = sorted({k[4:] for i in items for k in indexed_keys(i) if k.startswith("cve:")})
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
    for raw in raws:
        source = BY_ID[raw.source_id]
        item = normalize(raw, source, fetched_at)
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
        if prev:
            item.extra["revised_at"] = at
            res.updated_items += 1
        else:
            res.new_items += 1
        store.put_item(item)

        eid, merge_ids = find_events(item, store)
        if eid is None and not item.eventful:
            continue
        before = store.get_event(eid) if eid else None
        if before is None:
            seed = next((k for k in item.keys if k.startswith(_STRONG[:4])), item.item_id)
            eid = keys.event_id(seed)
            ev = Event(event_id=eid, domain=item.domain, title=item.title, first_seen=item.published_at,
                       last_updated=item.published_at, item_ids=[], keys=[])
        else:
            ev = Event.from_dict(before.to_dict())
        merged = [m for m in (store.get_event(x) for x in merge_ids) if m]
        ids = list(dict.fromkeys(ev.item_ids + [i for m in merged for i in m.item_ids] + [item.item_id]))
        ev = recompute(ev, store.get_items(ids), now)
        ev.keys = sorted(set(ev.keys) | set(indexed_keys(item)) | {k for m in merged for k in m.keys})
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
            res.changes.pop(m.event_id, None)
        ev.timeline.sort(key=lambda t: t["at"])
        store.put_event(ev)
        store.add_keys(ev.event_id, indexed_keys(item))
        ch = res.changes.setdefault(ev.event_id, Change(ev.event_id, created=before is None))
        if before is not None:
            ch.level_changed |= LEVEL_ORDER[before.level] != LEVEL_ORDER[ev.level]
            ch.severity_changed |= SEVERITY_ORDER[before.severity] != SEVERITY_ORDER[ev.severity]
    return res


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
        if diff:
            after.timeline = before.timeline + diff
            store.put_event(after)
            changed.append(after.event_id)
    return changed
