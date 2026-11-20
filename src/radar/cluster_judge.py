"""C4 · cluster_judge (M2-PLAN §3, T-class): "are these two events the same incident?" for the pairs the clustering
rules did not merge — advisory by default; a merge happens only when code evidence agrees and Limits.CLUSTER_AUTO_MERGE.

Veto measurement (live, 14 days to 2026-10-29): 40 candidate pairs (same domain, first seen ≤ 72 h apart, no shared
key, title similarity ≥ 0.55 or a shared entity); of the 15 most similar, 4 were the same incident (all P2 press
copies: Quest Diagnostics, Hive affiliate sentence, Tailscale SSH, the AI-assistant file trick) and 11 were not (three
Plex CVEs, Swell vs CoinDCX, templated "— Smart Contract Vulnerability" titles). A wrong merge is expensive (10-27:
Node2Shell + Adobe folded into PHP2Shell, a PR attached to the wrong event) and precision is unmeasured ⇒ v1 only
annotated `possible_duplicates`.

v2 (Neo 2026-11-17) after a missed duplicate: live 11-16 Lighter's theft was two web3 events — "Lighter Perps — API Key
Compromised" and one titled by a tweet ("https://t.co/… > We are actively investigating a security incident…", no
entities). v1 needed a similar title or a shared entity, and skipped every pair sharing ANY key on the assumption that
the rules had already decided it — but the two shared tok:lighter and the rules still kept them apart. So, web3:
  code  candidates from what the reports say (a shared name key, loss figures within ±15 %, a shared strong key — the
        rules kept them apart anyway), ≤ CLUSTER_WINDOW_H apart; contradiction guards (disjoint CVE sets / disjoint tx
        hashes ⇒ different, no call); pair key, cache, per-cycle cap, storage
  LLM   one Haiku call per remaining pair, shown ≤ 5 report headlines per side → verdict + the victim + one quote per side
  code  grounding: a 'same' whose victim is not named on both sides, or whose quotes are not in the headlines, is
        'unsure' (by="grounding"); would_merge = grounded 'same' + ≥ CLUSTER_MIN_EVIDENCE code evidences (merge_evidence)
  code  merge(): only with CLUSTER_AUTO_MERGE, ≤ CLUSTER_MERGES_PER_CYCLE pairs, each returning its undo commands
vuln / incident keep v1's candidates (72 h, no shared key, similar title or a shared entity).
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from datetime import datetime, timedelta
from difflib import SequenceMatcher
from typing import Any

from radar import keys, llm, timeutil
from radar.limits import Limits
from radar.model import Event, Item

PROMPT_VERSION = "cluster-judge-v2"
MAX_PAIRS_PER_CYCLE = 5
WINDOW_H = 72               # vuln / incident (v1); web3 uses Limits.CLUSTER_WINDOW_H
TITLE_SIMILARITY = 0.55
MAX_TOKENS = 1500   # 400 cut 119 verdicts as `model incomplete` (3.5 % of Haiku calls, live 11-19)
MAX_ERROR_RETRIES = 3   # an `error` row is judged again next cycle, at most this many attempts
VERDICTS = ("same", "different", "unsure")
NAME_PREFIXES = ("ent:", "tok:", "tt:")       # names a report's text gave (pipeline._NAME_KEYS minus dg:, a digest tag)
# restated from pipeline._STRONG (the authority; pipeline is not imported here to keep publish's import light)
STRONG_PREFIXES = ("cve:", "ghsa:", "tx:", "attacker:", "xs:", "url:")
ADDRESS_PREFIX = "attacker:"
# words that name no victim (keys.py explains each list): a shared "USDC" proves nothing (Kava vs Lighter)
NOT_NAMES = keys.MATCH_STOP | keys.COMMON_WORDS | keys.ATTRIBUTION


def pair_key(a: Event, b: Event) -> str:
    x, y = sorted([(a.event_id, a.title), (b.event_id, b.title)])
    return hashlib.sha256(f"{PROMPT_VERSION}\x1f{x}\x1f{y}".encode()).hexdigest()[:20]


def _names(e: Event) -> set[str]:
    return ({k.split(":", 1)[1] for k in e.keys if k.startswith(NAME_PREFIXES)} | {x.lower() for x in e.entities}) \
        - NOT_NAMES


# words every vulnerability title shares: a title-similarity pair must also share a word that is NOT one of these —
# a product, vendor or project name (live 11-19: 51,011 vuln candidates, most "<repo> exploit" vs "<repo> exploit"
# from PoC listings, similar only through the suffix; 49,589 unjudged, web3 pairs waiting ~13 days behind them)
_GENERIC_WORDS = (
    "exploit exploits poc proof concept vulnerability vulnerabilities vuln cve security update updates patch patches "
    "patched fixes fixed advisory advisories bulletin critical high medium low important moderate remote code execution "
    "rce injection command cross site scripting xss sql sqli denial service dos authentication bypass privilege "
    "escalation elevation information disclosure buffer overflow arbitrary file upload unauthenticated authenticated "
    "allows attacker attackers could issue flaw bug missing improper multiple several new zero-day zero day released "
    "release version versions before after through with from that this into plugin theme module library package "
    "linux kernel windows server microsoft google")
_GENERIC = frozenset(_GENERIC_WORDS.split())
_TOKEN = re.compile(r"[a-z0-9][a-z0-9._-]{3,}")
_ID_LIKE = re.compile(r"(?:cve|ghsa|usn|dsa|rhsa|sg|cnvd|jvn|bdu)-[\w-]+|\d[\d.]*")


def distinct_words(title: str) -> set[str]:
    return {w for w in _TOKEN.findall(title.lower()) if w not in _GENERIC and not _ID_LIKE.fullmatch(w)}


def close_loss(a: Event, b: Event) -> bool:
    x, y = a.amount_usd_latest or 0, b.amount_usd_latest or 0
    return x > 0 and y > 0 and abs(x - y) <= Limits.CLUSTER_LOSS_TOLERANCE * max(x, y)


def candidates(evs: list[Event]) -> list[tuple[Event, Event]]:
    """Same-domain pairs not contradicted by code. web3: first seen ≤ CLUSTER_WINDOW_H apart and sharing a name key,
    a strong key, or a loss figure (±15 %), or with a similar title. vuln / incident: ≤ WINDOW_H, no shared key, a
    shared entity or a similar title. A sweep over events sorted by first_seen (only neighbours inside the window are
    compared) with times, key and entity sets computed once — the all-pairs loop with per-pair parsing took 5.5 min of
    every Analyze run once the CVE List filled the window (live 2026-11-11, ~1,500 events: ~1.1 M pairs).
    SequenceMatcher runs only when no cheaper trigger fired and its upper bounds can reach TITLE_SIMILARITY. Same
    result as the all-pairs loop (test)."""
    prep = []
    for i, e in enumerate(evs):
        t = timeutil.parse(e.first_seen)
        if t:
            ks = set(e.keys)
            prep.append((t, i, e, ks, {x.lower() for x in e.entities}, e.title.lower(), set(e.cves),
                         {x["hash"] for x in e.tx}, _names(e), {k for k in ks if k.startswith(STRONG_PREFIXES)}))
    prep.sort(key=lambda r: (r[0], r[1]))
    w3 = timedelta(hours=Limits.CLUSTER_WINDOW_H)
    win = timedelta(hours=WINDOW_H)    # the sweep's bound is the vuln window; web3's (≤ it) is checked per pair
    out = []
    for j, (tb, ib, b, kb, eb, lb, cb, xb, nb, sb) in enumerate(prep):
        k = j - 1
        while k >= 0 and tb - prep[k][0] <= win:
            ta, ia, a, ka, ea, la, ca, xa, na, sa = prep[k]
            k -= 1
            if a.domain != b.domain:
                continue
            if (ca and cb and not ca & cb) or (xa and xb and not xa & xb):
                continue    # contradiction(): code already says different — not a pair to judge (107,811 → few)
            if b.domain == "web3":
                if tb - ta > w3:
                    continue
                # v1 skipped any pair sharing a key ("the rules decided") — the rules kept these two apart anyway
                if na & nb or sa & sb or close_loss(a, b):
                    out.append((a, b) if ia < ib else (b, a))
                    continue
            else:
                if ka & kb:
                    continue
                if ea & eb:
                    out.append((a, b) if ia < ib else (b, a))
                    continue
            if b.domain != "web3" and not distinct_words(la) & distinct_words(lb):
                continue    # similar only in vulnerability vocabulary (the "<repo> exploit" listings)
            sm = SequenceMatcher(None, la, lb)
            if sm.real_quick_ratio() >= TITLE_SIMILARITY and sm.quick_ratio() >= TITLE_SIMILARITY \
                    and sm.ratio() >= TITLE_SIMILARITY:
                out.append((a, b) if ia < ib else (b, a))
    order = {id(e): i for i, e in enumerate(evs)}
    out.sort(key=lambda p: (order[id(p[0])], order[id(p[1])]))           # the all-pairs loop's order …
    # … then most severe first (stable): a P0/P1 duplicate matters more than a P2 press copy
    out.sort(key=lambda p: -max({"P0": 2, "P1": 1}.get(p[0].severity, 0), {"P0": 2, "P1": 1}.get(p[1].severity, 0)))
    return out


def contradiction(a: Event, b: Event) -> str | None:
    """Code decides 'different' when the facts already disagree — no call, no chance of a wrong 'same'."""
    if a.cves and b.cves and not set(a.cves) & set(b.cves):
        return "different CVE ids"
    ta, tb = {t["hash"] for t in a.tx}, {t["hash"] for t in b.tx}
    if ta and tb and not ta & tb:
        return "different attack transactions"
    return None


def _clean(title: str) -> str:
    """A headline as the model sees it and the grounding check reads it: links out (a tweet's t.co prefix names
    nothing), whitespace collapsed, ≤ 200 chars."""
    return " ".join(re.sub(r"https?://\S+", " ", title or "").split())[:200]


def headlines(ev: Event, get_items: Callable[[list[str]], list[Item]] | None = None) -> list[str]:
    """≤ CLUSTER_HEADLINES distinct report headlines, oldest first, from ≤ CLUSTER_ITEMS_READ reports (the first and
    the last halves of the event: the first report and the latest follow-ups). The event title when none is readable."""
    ids, n = ev.item_ids, Limits.CLUSTER_ITEMS_READ
    pick = ids if len(ids) <= n else [*ids[: n // 2], *ids[-(n - n // 2):]]
    out: list[str] = []
    for it in sorted(get_items(pick) if get_items and pick else [], key=lambda i: (i.published_at, i.item_id)):
        h = _clean(it.title)
        if h and h not in out:
            out.append(h)
        if len(out) >= Limits.CLUSTER_HEADLINES:
            break
    return out or [_clean(ev.title)]


def render_prompt(a: Event, b: Event, ha: list[str] | None = None, hb: list[str] | None = None) -> str:
    def side(e: Event, h: list[str]) -> dict[str, Any]:
        return {"headlines": h, "domain": e.domain, "first_seen": e.first_seen, "amount_usd": e.amount_usd_latest,
                "entities": e.entities[:6], "cves": e.cves[:6], "chains": e.chains[:4]}
    return ("Two security news events were not merged by the rules. Are they the SAME real-world incident?\n"
            "Answer 'same' only if they describe one incident (same victim / product and same occurrence), 'different' if "
            "they are separate incidents (e.g. different CVEs, different victims, a templated title), else 'unsure'.\n"
            "For 'same', name the shared victim exactly as a headline writes it (a company / protocol / product — never "
            "a token, a chain or a reporter), and quote a few words copied exactly from one headline of each side.\n"
            'Output JSON only: {"verdict": "same|different|unsure", "why": "<one short sentence>", '
            '"victim": "<the shared victim name exactly as written>", "evidence_a": "<an exact substring of one A '
            'headline>", "evidence_b": "<an exact substring of one B headline>"}\n\n'
            f"A: {json.dumps(side(a, ha or [_clean(a.title)]), ensure_ascii=False)}\n"
            f"B: {json.dumps(side(b, hb or [_clean(b.title)]), ensure_ascii=False)}")


def _named_in(victim: str, h: str) -> bool:
    """Whole-word, case-insensitive: 'Lighter' is in "Lighter confirms …", not in "Highlighter"."""
    return bool(re.search(rf"(?<![A-Za-z0-9]){re.escape(victim)}(?![A-Za-z0-9])", h, re.IGNORECASE))


def grounding(d: dict[str, Any], ha: list[str], hb: list[str]) -> str | None:
    """Why a 'same' is not backed by the headlines (None = grounded): the victim must be a name (not a token / chain /
    reporter word), named in a headline of BOTH sides, and each quote must be copied from a headline of its side."""
    v = str(d.get("victim") or "").strip()
    qa, qb = str(d.get("evidence_a") or "").strip(), str(d.get("evidence_b") or "").strip()
    if len(v) < 2 or v.lower() in NOT_NAMES:
        return f"victim {v!r} is not a name"
    if not any(_named_in(v, h) for h in ha) or not any(_named_in(v, h) for h in hb):
        return f"victim {v!r} not named on both sides"
    if len(qa) < 3 or not any(qa in h for h in ha):
        return "evidence_a is not in an A headline"
    if len(qb) < 3 or not any(qb in h for h in hb):
        return "evidence_b is not in a B headline"
    return None


def merge_evidence(a: Event, b: Event, ha: list[str], hb: list[str], victim: str) -> list[dict[str, str]]:
    """The code's own reasons to believe a 'same' (each independent of the model's prose)."""
    out = []
    v = victim.strip()
    na, nb = (sum(_named_in(v, h) for h in hs) if v else 0 for hs in (ha, hb))
    if na >= 2 and nb >= 2:
        out.append({"kind": "name", "detail": f"「{v}」见于 A 的 {na}/{len(ha)} 条、B 的 {nb}/{len(hb)} 条标题"})
    if close_loss(a, b):
        out.append({"kind": "loss", "detail": f"损失 ${a.amount_usd_latest:,.0f} vs ${b.amount_usd_latest:,.0f}"
                                              f"（±{Limits.CLUSTER_LOSS_TOLERANCE:.0%} 内）"})
    ta, tb = timeutil.parse(a.first_seen), timeutil.parse(b.first_seen)
    if ta and tb and abs(ta - tb) <= timedelta(hours=Limits.CLUSTER_MERGE_TIME_H):
        out.append({"kind": "time", "detail": f"首见相隔 {abs(ta - tb).total_seconds() / 3600:.1f} 小时"})
    addr = sorted({k for k in a.keys if k.startswith(ADDRESS_PREFIX)} & {k for k in b.keys if k.startswith(ADDRESS_PREFIX)})
    if addr:
        out.append({"kind": "address", "detail": f"共同攻击者地址 {addr[0][len(ADDRESS_PREFIX):]}"})
    return out


def judge(a: Event, b: Event, call: Any = None, model: str = llm.MODEL_FAST, ha: list[str] | None = None,
          hb: list[str] | None = None) -> dict[str, Any]:
    why = contradiction(a, b)
    if why:
        return {"verdict": "different", "why": why, "by": "code", "would_merge": False, "evidence": []}
    ha, hb = ha or [_clean(a.title)], hb or [_clean(b.title)]
    res = (call or llm.converse)(render_prompt(a, b, ha, hb), model, MAX_TOKENS)
    if res.status != "ok":
        return {"verdict": "unsure", "why": f"model {res.status}", "by": "error", "would_merge": False, "evidence": []}
    m = re.search(r"\{.*\}", res.text or "", re.DOTALL)
    try:
        d = json.loads(m.group(0)) if m else {}
    except json.JSONDecodeError:
        d = {}
    d = d if isinstance(d, dict) else {}
    verdict = d.get("verdict") if d.get("verdict") in VERDICTS else "unsure"   # anything else is not a 'same'
    row = {"verdict": verdict, "why": str(d.get("why") or "")[:200], "by": res.model or model,
           "victim": str(d.get("victim") or "")[:80], "evidence_a": str(d.get("evidence_a") or "")[:200],
           "evidence_b": str(d.get("evidence_b") or "")[:200]}
    if verdict == "same" and (ungrounded := grounding(d, ha, hb)):
        # not a silent 'unsure': the row says the model said same and why code did not believe it
        row.update(verdict="unsure", by="grounding", why=f"model said same; {ungrounded}"[:200])
    ev = merge_evidence(a, b, ha, hb, row["victim"]) if row["verdict"] == "same" else []
    row.update(evidence=ev, would_merge=row["verdict"] == "same" and len(ev) >= Limits.CLUSTER_MIN_EVIDENCE)
    return row


def run(evs: list[Event], state: dict[str, Any], now_iso: str, call: Any = None,
        get_items: Callable[[list[str]], list[Item]] | None = None) -> tuple[dict[str, Any], int]:
    """Judge new candidate pairs (≤ MAX_PAIRS_PER_CYCLE model calls). state = {pair_key: verdict row}; returns
    (state, model calls made). Rows of pairs no longer candidates are dropped (the window moved on). Reports are read
    (get_items) only for the events of pairs about to be judged — ≤ 2 × MAX_PAIRS_PER_CYCLE events a cycle."""
    pairs = candidates(evs)
    live = {pair_key(a, b): (a, b) for a, b in pairs}
    state = {k: v for k, v in state.items() if k in live}
    calls = 0
    seen: dict[str, list[str]] = {}

    def heads(e: Event) -> list[str]:
        if e.event_id not in seen:
            seen[e.event_id] = headlines(e, get_items)
        return seen[e.event_id]
    # web3 first: before 11-19 the first waiting web3 pair sat at position 352 behind templated vuln pairs (~12 h)
    for k, (a, b) in sorted(live.items(), key=lambda kv: kv[1][0].domain != "web3"):
        prev = state.get(k)
        if prev is not None and not (prev.get("by") == "error" and int(prev.get("attempts") or 1) < MAX_ERROR_RETRIES):
            continue
        guarded = contradiction(a, b) is not None
        if not guarded and calls >= MAX_PAIRS_PER_CYCLE:
            continue
        row = judge(a, b, call, ha=None if guarded else heads(a), hb=None if guarded else heads(b))
        calls += 0 if row["by"] == "code" else 1
        state[k] = {**row, "a": a.event_id, "b": b.event_id, "at": now_iso,
                    "since": min(a.first_seen, b.first_seen)[:10],
                    **({"attempts": int((prev or {}).get("attempts") or 1) + (1 if prev else 0)} if row["by"] == "error" else {})}
    return state, calls


def undo_commands(moved: list[str], into: str, back: str | None = None) -> list[str]:
    """How to take a merge back with scripts/move_item.py. back = the smaller event when it still exists (a merge
    stopped part-way). After a full merge it does not: the last move deleted it (moves.move_item removes an emptied
    event), so the first command re-opens an event and the others follow into it."""
    cmd = "uv run python scripts/move_item.py --item {} --from {} --to {} --apply"
    if back:
        return [cmd.format(i, into, back) for i in moved]
    if not moved:
        return []
    return [cmd.format(moved[0], into, "new"), *(cmd.format(i, into, "<the event the first command opened>")
                                                   for i in moved[1:])]


def merge(store: Any, state: dict[str, Any], now: datetime, enabled: bool | None = None) -> list[dict[str, Any]]:
    """Merge would_merge pairs — only when enabled (default Limits.CLUSTER_AUTO_MERGE, False = shadow), at most
    Limits.CLUSTER_MERGES_PER_CYCLE pairs a run, oldest verdict first. The event holding fewer reports moves into the
    other through radar.moves (both recomputed, keys follow the reports, reports pinned). Each result (also written on
    its row as "merged") carries the undo commands. A move refused part-way is recorded on the row with the undo of the
    moves already made, never skipped silently."""
    if not (Limits.CLUSTER_AUTO_MERGE if enabled is None else enabled):
        return []
    from radar import moves  # pipeline-heavy: only when a merge really happens
    out: list[dict[str, Any]] = []
    for k, row in sorted(state.items(), key=lambda kv: (kv[1].get("at") or "", kv[0])):
        if len(out) >= Limits.CLUSTER_MERGES_PER_CYCLE:
            break
        if not row.get("would_merge") or row.get("merged"):
            continue
        a, b = store.get_event(row["a"]), store.get_event(row["b"])
        if a is None or b is None or contradiction(a, b):
            continue                  # one side already gone (or the facts changed): the pair leaves the board next run
        big, small = sorted((a, b), key=lambda e: (-len(e.item_ids), e.first_seen, e.event_id))
        moved: list[str] = []
        res: dict[str, Any] = {"pair": k, "into": big.event_id, "from": small.event_id, "at": timeutil.iso(now)}
        try:
            for iid in list(small.item_ids):
                moves.move_item(store, iid, small.event_id, big.event_id, now)
                moved.append(iid)
        except moves.MoveError as e:
            res["error"] = e.detail
        res.update(items=moved, undo=undo_commands(moved, big.event_id, small.event_id if "error" in res else None))
        row["merged"] = res
        out.append(res)
    return out


SHARDS = 16


def _shard(key: str, pair: str) -> str:
    return f"{key}#{int(hashlib.sha1(pair.encode(), usedforsecurity=False).hexdigest(), 16) % SHARDS}"


def load(store: Any, key: str) -> dict[str, Any]:
    """Every remembered verdict: the legacy single record (read-merged until the first save) plus the shards."""
    out = dict((store.get_source_state(key) or {}).get("pairs") or {})
    for part in store.get_source_states([f"{key}#{i}" for i in range(SHARDS)]).values():
        out.update((part or {}).get("pairs") or {})
    return out


def save(store: Any, key: str, pairs: dict[str, Any]) -> None:
    """Live 2026-11-11: one record held 1,658 pairs in 399,029 bytes and the next write failed with 413, every cycle.
    Only model verdicts are kept — a code verdict (contradiction()) is recomputed for free on every run — and they are
    sharded so no record nears DynamoDB's 400 KB. A shard is rewritten only when it changed (pairs leave as the window moves on)."""
    kept = {k: v for k, v in pairs.items() if v.get("by") != "code"}
    for i in range(SHARDS):
        sh = f"{key}#{i}"
        new = {"pairs": {k: v for k, v in kept.items() if _shard(key, k) == sh}}
        if store.get_source_state(sh) != new:   # R2.6: only a shard that changed is written (read is cached per run)
            store.put_source_state(sh, new)
    if store.get_source_state(key):
        store.put_source_state(key, {})


def possible_duplicates(event_id: str, state: dict[str, Any], titles: dict[str, str],
                        labels: dict[str, Any] | None = None) -> list[dict[str, str]]:
    """What the event page shows: the other side of every 'same' verdict that is still on the board. An operator's
    label (radar.duplabels, item 6) beats the model: 'different' hides the hint, 'same' shows it whatever the verdict."""
    labels = labels or {}
    why: dict[str, str] = {}
    for row in state.values():
        if row.get("verdict") == "same" and event_id in (row.get("a"), row.get("b")):
            why[row["b"] if row["a"] == event_id else row["a"]] = row.get("why", "")
    for k, lab in labels.items():
        a, b = k.split("|")
        if event_id in (a, b):
            other = b if a == event_id else a
            if lab.get("label") == "same":
                why[other] = f"人工确认：{lab.get('note') or LABEL_SAME_DEFAULT}"
            else:
                why.pop(other, None)
    return sorted(({"event_id": o, "title": titles[o], "why": w} for o, w in why.items() if o in titles),
                  key=lambda d: d["event_id"])


LABEL_SAME_DEFAULT = "同一事件"


# --- delayed truth (Neo 11-19, step 2: measure the shadow judge without a person labelling) ---
# Days after a verdict, facts the code can read decide many pairs by themselves: the two events now share an attack
# transaction, an attacker address or a CVE (or the pipeline merged them) ⇒ same; their CVEs or transactions are
# disjoint ⇒ different. Pairs no fact decides stay unscored — never guessed.
TRUTH_KEYS = ("tx:", "attacker:", "cve:", "ghsa:")


def delayed_truth(a: Event | None, b: Event | None, a_now: str | None = None, b_now: str | None = None,
                  ra: set[tuple[str, str]] | None = None, rb: set[tuple[str, str]] | None = None) -> str | None:
    """same / different / None for a judged pair, from the events as they are now. a_now / b_now = the event each
    side's first report is in today (None when the report is gone): one event ⇒ the pipeline merged them.
    ra / rb = (source_id, item_id) of each side's hack-database records (Source.always_eventful): a database lists an
    incident once, so two events holding DIFFERENT records of the SAME database are different incidents, one shared
    record is the same incident. Records of two different databases decide nothing (live: one Safe multisig on
    Avalanche is a DefiLlama row and a SlowMist row under different names). Live 11-19: 59 pairs decided this way."""
    if a_now and b_now and a_now == b_now:
        return "same"
    if a is None or b is None:
        return None
    if contradiction(a, b):
        return "different"
    if ra and rb:
        if ra & rb:
            return "same"
        if {s for s, _ in ra} & {s for s, _ in rb}:
            return "different"
    ka = {k for k in a.keys if k.startswith(TRUTH_KEYS)}
    kb = {k for k in b.keys if k.startswith(TRUTH_KEYS)}
    return "same" if ka & kb else None


def truth_report(state: dict[str, Any], events: dict[str, Event], first_item_event: dict[str, str],
                 now_iso: str, min_age_days: float = 2,
                 records: dict[str, set[tuple[str, str]]] | None = None) -> dict[str, Any]:
    """Score model verdicts older than min_age_days against delayed truth. first_item_event: {event_id judged →
    event id holding that event's first report today}. Returns counts, precision of `same`, and the decided rows."""
    from radar import timeutil
    now = timeutil.parse(now_iso)
    rows = []
    for row in state.values():
        if row.get("by") in ("code", "error") or row.get("verdict") not in ("same", "different", "unsure"):
            continue
        at = timeutil.parse(row.get("at") or "")
        if not at or not now or (now - at).total_seconds() < min_age_days * 86400:
            continue
        a, b = events.get(row["a"]), events.get(row["b"])
        truth = delayed_truth(a, b, first_item_event.get(row["a"]), first_item_event.get(row["b"]),
                              (records or {}).get(row["a"]), (records or {}).get(row["b"]))
        if truth:
            rows.append({"a": row["a"], "b": row["b"], "verdict": row["verdict"], "truth": truth,
                         "would_merge": bool(row.get("would_merge"))})
    said = [r for r in rows if r["verdict"] == "same"]
    wm = [r for r in rows if r["would_merge"]]
    return {"decided": len(rows), "same_said": len(said),
            "same_precision": round(sum(r["truth"] == "same" for r in said) / len(said), 3) if said else None,
            "would_merge": len(wm),
            "would_merge_wrong": sum(r["truth"] != "same" for r in wm),
            "missed_same": sum(r["truth"] == "same" and r["verdict"] != "same" for r in rows), "rows": rows}
