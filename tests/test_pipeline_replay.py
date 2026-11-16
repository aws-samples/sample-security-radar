"""Replay criteria: real 2026-10-23 snapshots through the whole deterministic pipeline.

Expected levels follow DESIGN §6 and are derived from facts in docs/research/03 + 05 — e.g. WAX is
SlowMist (Hacked DB + its own tweet = ONE origin) + DeFiLlama ⇒ 2 independent sources, not 3."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from radar import keys, parsers, pipeline, timeutil
from radar.model import RawItem
from radar.store import MemoryStore

SNAP = Path(__file__).parent / "fixtures" / "snapshots" / "2026-10-23"
TW = Path(__file__).parent / "fixtures" / "x_search" / "advanced_search_3handles_20261023.json"
FETCHED = datetime(2026, 10, 23, 4, 0, tzinfo=UTC)

FEEDS = {"bleeping.xml": "bleepingcomputer", "thn.xml": "thehackernews", "securityweek.xml": "securityweek",
         "anquanke.xml": "anquanke", "odaily.xml": "odaily", "panews.xml": "panews",
         "fortinet.xml": "fortinet_psirt", "chrome.xml": "chrome_releases", "cisa_adv.xml": "cisa_advisories"}


def snapshot_raws() -> list[RawItem]:
    r = lambda n: (SNAP / n).read_text()
    raws = parsers.kev(r("kev.json"), "cisa_kev") + parsers.defillama(r("defillama.json"), "defillama_hacks")
    raws += parsers.slowmist(r("slowmist.html"), "slowmist_hacked")
    raws += parsers.slowmist(r("slowmist_exchange.html"), "slowmist_hacked")
    dhl = parsers.defihacklabs(r("defihacklabs.md"), "defihacklabs")
    poc = parsers.defihacklabs_poc(r("AlpsCon_exp.sol"))  # what the collector does for new entries
    for it in dhl:
        if it.extra["entity"] == "AlpsCon":
            it.extra.update(attack_tx=poc["attack_tx"], attacker_urls=poc["attacker_urls"])
    raws += dhl
    raws += parsers.twitterapi(json.dumps(json.loads(TW.read_text())["body"]), "x_security")
    for name, sid in FEEDS.items():
        raws += parsers.feed(r(name), sid)
    # arrival order = publication order (ties keep source order) — what a live system sees
    return sorted(raws, key=lambda x: x.published_at or FETCHED)


@pytest.fixture(scope="module")
def replayed():
    store = MemoryStore()
    res = pipeline.ingest(snapshot_raws(), store, FETCHED)
    return store, res


def events_with_entity(store, prefix):
    out = [e for e in store.events.values() if any(n.lower().startswith(prefix.lower()) for n in e["entities"])]
    assert out, f"no event for {prefix}"
    return out


def test_alpscon_three_sources_one_event_v2(replayed):
    store, _ = replayed
    [ev] = events_with_entity(store, "AlpsCon")
    srcs = {store.items[i]["source_id"] for i in ev["item_ids"]}
    assert srcs == {"defillama_hacks", "slowmist_hacked", "defihacklabs"}
    assert ev["level"] == "V2" and "PoC" in ev["level_reason"]
    assert ev["tx"][0]["hash"].startswith("0x824b83f9") and ev["tx"][0]["chain"] == "bsc"
    assert ev["amount_disputed"] is False and 150_000 < ev["amount_usd_latest"] < 155_000
    assert ev["severity"] == "P1"


def test_wax_slowmist_tweet_is_not_independent_of_slowmist_db(replayed):
    store, _ = replayed
    [ev] = events_with_entity(store, "WAX")
    srcs = sorted(store.items[i]["source_id"] for i in ev["item_ids"])
    # PANews' 「WAX多链桥遭攻击…约7.5万美元」 is the same story (joined since the 2026-11-04 amount rules): 3 groups —
    # DeFiLlama, SlowMist (database + its own tweet = one org), PANews
    assert srcs == ["defillama_hacks", "panews", "slowmist_hacked", "x_security"]
    assert ev["independent_sources"] == 3
    assert ev["level"] == "V2" and ev["severity"] == "P2"  # $90.5K is below the P1 line


def test_bitget_2026_is_p0_and_separate_from_2025_bitget(replayed):
    store, _ = replayed
    evs = events_with_entity(store, "Bitget")
    big = [e for e in evs if e["first_seen"].startswith("2026-09-24")]
    assert len(big) == 1
    ev = big[0]
    # 安全客's 09-29 retrospective 「3.5亿美元一夜蒸发！…Bitget…」 is the same theft (same victim, loss within 20 %,
    # since 2026-11-05 — it was its own event); the 2025 Bitget incident still stays apart
    assert {store.items[i]["source_id"] for i in ev["item_ids"]} == {"defillama_hacks", "slowmist_hacked", "anquanke"}
    # 29 days old, in two incident DBs, amount stable ⇒ finalized (DESIGN §6 V4); no longer "act now" ⇒ P1
    assert ev["level"] == "V4" and ev["severity"] == "P1"
    assert ev["amount_usd_latest"] == 387_500_000  # T1 (SlowMist) value wins over T2


def test_ledger_supply_chain_single_t2_is_only_reported(replayed):
    store, _ = replayed
    ev = next(e for e in events_with_entity(store, "Ledger") if e["first_seen"].startswith("2026-10-09"))
    assert ev["level"] == "V1" and ev["severity"] == "P1"


def test_kev_entries_are_confirmed_and_only_fresh_ones_are_p0(replayed):
    store, _ = replayed
    kev_items = [i for i in store.items.values() if i["source_id"] == "cisa_kev"]
    assert len(kev_items) == 98
    for it in kev_items:
        ev = next(e for e in store.events.values() if it["item_id"] in e["item_ids"])
        assert ev["exploitation"] == "confirmed" and ev["level"] in ("V3", "V4")
        fresh = it["published_at"] >= "2026-10-20T04:00:00Z"   # FETCHED − 72h
        assert ev["severity"] == ("P0" if fresh else "P1"), (it["title"], it["published_at"], ev["severity"])


def test_fortinet_itw_advisory_is_confirmed(replayed):
    store, _ = replayed
    it = next(i for i in store.items.values()
              if i["source_id"] == "fortinet_psirt" and "exploited in the wild" in i["text"])
    ev = next(e for e in store.events.values() if it["item_id"] in e["item_ids"])
    # advisory dated 2026-10-01 ⇒ confirmed in-the-wild but 22 days old ⇒ P1, not "act now"
    assert ev["exploitation"] == "confirmed" and ev["severity"] == "P1"


def test_php2shell_named_and_cve_clusters_merge_and_thn_counts_once(replayed):
    """THN ran 4 PHP2Shell stories without CVE ids; BleepingComputer's story names both PHP2Shell and
    CVE-2026-109618 ⇒ the named cluster and the CVE cluster are one event. 4 THN stories = 1 source."""
    store, _ = replayed
    php = [e for e in store.events.values() if "CVE-2026-109618" in e["cves"]]
    assert len(php) == 1
    ev = php[0]
    items = [pipeline.Item.from_dict(store.items[i]) for i in ev["item_ids"]]
    assert sum(i.source_id == "thehackernews" for i in items) == 4
    groups = pipeline.independent_groups(sorted(items, key=lambda i: (i.published_at, i.source_id, i.item_id)))
    sorted_items = sorted(items, key=lambda i: (i.published_at, i.source_id, i.item_id))
    assert len({g for g, i in zip(groups, sorted_items) if i.source_id == "thehackernews"}) == 1
    assert not any("php2shell" in e["title"].lower() for e in store.events.values() if e is not ev)
    # exploitation reported by media, not yet confirmed by a T1 ⇒ "reported"; corroborated ⇒ P0
    assert ev["exploitation"] == "reported" and ev["severity"] == "P0"


def test_replay_is_idempotent(replayed):
    store, _ = replayed
    before = json.dumps(store.events, sort_keys=True)
    res = pipeline.ingest(snapshot_raws(), store, FETCHED)
    assert (res.new_items, res.updated_items, res.changes) == (0, 0, {})
    assert json.dumps(store.events, sort_keys=True) == before


# ---------------------------------------------------------------- negative / control cases (synthetic)

def _raw(source_id, title, text="", url=None, author=None, extra=None, when="2026-10-20T10:00:00Z", links=()):
    from radar import timeutil
    return RawItem(source_id=source_id, url=url or f"https://example.com/{keys.short_hash(source_id, title)}",
                   title=title, text=text, published_at=timeutil.parse(when), guid=None, author=author,
                   links=list(links), extra=extra or {})


def test_unknown_account_rumor_stays_v0_p2():
    store = MemoryStore()
    pipeline.ingest([_raw("x_security", "FooBarX exchange hacked, $50M drained!!", "FooBarX exchange hacked, $50M drained",
                          author="random_anon_123", extra={"x_status": "1"})], store, FETCHED)
    [ev] = store.events.values()
    assert ev["level"] == "V0" and ev["severity"] == "P2"


def test_syndicated_copies_count_once_but_independent_reports_corroborate():
    title = "CVE-2026-99999 Acme VPN zero-day exploited in the wild"
    echo = MemoryStore()
    pipeline.ingest([_raw(s, title, title) for s in ("bleepingcomputer", "securityweek", "thehackernews")], echo, FETCHED)
    [ev] = echo.events.values()
    assert ev["independent_sources"] == 1 and ev["level"] == "V1"

    indep = MemoryStore()
    pipeline.ingest([
        _raw("bleepingcomputer", "Acme patches VPN flaw CVE-2026-99999 under active attack", "actively exploited"),
        _raw("securityweek", "CISA warns of exploitation of Acme gateway bug (CVE-2026-99999)", "exploited in the wild"),
    ], indep, FETCHED)
    [ev2] = indep.events.values()
    assert ev2["independent_sources"] == 2 and ev2["level"] == "V2" and ev2["severity"] == "P0"


def test_vendor_saying_no_exploitation_is_not_confirmed():
    store = MemoryStore()
    pipeline.ingest([_raw("fortinet_psirt", "FortiOS heap overflow CVE-2026-88888",
                          "There is no evidence of exploitation in the wild at this time.")], store, FETCHED)
    [ev] = store.events.values()
    assert ev["exploitation"] == "none" and ev["severity"] == "P2" and ev["level"] == "V3"


def test_amount_revision_is_a_time_series_with_timeline_entry():
    store = MemoryStore()
    base = {"source_id": "defillama_hacks", "title": "Bitget — Hot Wallet", "when": "2026-09-24"}
    pipeline.ingest([_raw(**base, url="https://defillama.com/hacks#Bitget",
                          extra={"entity": "Bitget", "amount_usd": 351_600_000})], store, FETCHED)
    later = datetime(2026, 9, 26, tzinfo=UTC)
    pipeline.ingest([_raw(**base, url="https://defillama.com/hacks#Bitget",
                          extra={"entity": "Bitget", "amount_usd": 387_000_000})], store, later)
    [ev] = store.events.values()
    assert [p["value"] for p in ev["amount_history"]] == [351_600_000, 387_000_000]
    assert ev["amount_usd_latest"] == 387_000_000
    assert any(t["kind"] == "amount_change" for t in ev["timeline"])


def test_unrelated_stories_from_one_outlet_do_not_merge(replayed):
    """Regression (found 2026-10-23): capitalised words ('Hackers', 'Deliver') were used as weak keys for
    incident news and glued 11 unrelated THN/Bleeping stories into one event."""
    store, _ = replayed
    def event_of(fragment):
        it = next(i for i in store.items.values() if fragment in i["title"])
        return next(e["event_id"] for e in store.events.values() if it["item_id"] in e["item_ids"])
    ids = {event_of(t) for t in ("Rank Math PRO", "LiteLLM Compromised", "Lazarus hackers", "State Bank of India")}
    assert len(ids) == 4
    big = [e for e in store.events.values() if len(e["item_ids"]) > 5 and "CVE-2026-109618" not in e["cves"]]
    assert big == []


def test_uncx_amount_dispute_is_flagged_not_merged(replayed):
    """Real dispute (research/03 §8 #3): DeFiLlama $86K vs SlowMist $1.49M for the same UNCX incident."""
    store, _ = replayed
    ev = next(e for e in events_with_entity(store, "UNCX Network") if len(e["amount_history"]) >= 2)
    assert ev["amount_disputed"] is True
    assert sorted(p["value"] for p in ev["amount_history"]) == [86_000, 1_490_000]


def signals_is_digest(title):
    from radar import signals
    return signals.is_digest(title)


def test_cve_roundup_does_not_glue_unrelated_cves():
    # not a digest by its headline (a 「Patch Tuesday」 title is one, and then signals.is_digest decides first — CI
    # 2026-11-14: with that title the ≤ 3 CVE rule's mutation survived): a plain report that lists five CVEs
    roundup = "Vendor ships fixes for CVE-2026-1001, CVE-2026-1002, CVE-2026-1003, CVE-2026-1004 and CVE-2026-1005"
    assert not signals_is_digest(roundup)
    store = MemoryStore()
    pipeline.ingest([_raw("cisa_kev", "CVE-2026-1001 Foo", "x", extra={"cves": ["CVE-2026-1001"], "kev": True}),
                     _raw("cisa_kev", "CVE-2026-1002 Bar", "y", extra={"cves": ["CVE-2026-1002"], "kev": True}),
                     _raw("bleepingcomputer", roundup, roundup)], store, FETCHED)
    kev_events = [e for e in store.events.values() if any(store.items[i]["source_id"] == "cisa_kev" for i in e["item_ids"])]
    assert len(kev_events) == 2


def test_p0_means_act_now_on_live_snapshot(replayed):
    """M2 A1: P0 only for events first seen or escalated within 72h ⇒ the board stays short."""
    store, _ = replayed
    p0 = [e for e in store.events.values() if e["severity"] == "P0"]
    assert 0 < len(p0) <= 10, [e["title"][:50] for e in p0]
    assert any("CVE-2026-109618" in e["cves"] for e in p0)  # PHP2Shell, 2 days old


def test_bitget_was_p0_when_it_happened():
    raws = [r for r in snapshot_raws() if (r.extra.get("entity") or "").startswith("Bitget")
            and r.published_at and r.published_at.year == 2026]
    store = MemoryStore()
    pipeline.ingest(raws, store, datetime(2026, 9, 25, 12, 0, tzinfo=UTC))
    [ev] = store.events.values()
    assert ev["severity"] == "P0"


def test_old_event_escalated_now_is_p0_again():
    store = MemoryStore()
    pipeline.ingest([_raw("bleepingcomputer", "Acme gateway flaw CVE-2026-77777", "a bug", when="2026-10-01T00:00:00Z")],
                    store, datetime(2026, 10, 2, tzinfo=UTC))
    later = datetime(2026, 10, 23, 4, 0, tzinfo=UTC)
    pipeline.ingest([_raw("cisa_kev", "CVE-2026-77777 Acme gateway", "x", extra={"cves": ["CVE-2026-77777"], "kev": True},
                          when="2026-10-23T00:00:00Z")], store, later)
    [ev] = store.events.values()
    assert ev["exploitation"] == "confirmed" and ev["severity"] == "P0"


def test_p0_decays_to_p1_on_refresh_after_72h():
    store = MemoryStore()
    t0 = datetime(2026, 10, 20, tzinfo=UTC)
    pipeline.ingest([_raw("cisa_kev", "CVE-2026-66666 Foo", "x", extra={"cves": ["CVE-2026-66666"], "kev": True},
                          when="2026-10-20T00:00:00Z")], store, t0)
    assert next(iter(store.events.values()))["severity"] == "P0"
    pipeline.refresh(store, datetime(2026, 10, 24, tzinfo=UTC))
    ev = next(iter(store.events.values()))
    assert ev["severity"] == "P1"
    assert any(t["kind"] == "severity_change" and t["from"] == "P0" and t["to"] == "P1" for t in ev["timeline"])


def test_refresh_carries_a_rule_change_to_events_already_open():
    """Live 2026-10-30: after the title / frozen / dispute fixes were deployed, the Binance event kept its stale
    derived fields — refresh only stored an event when its timeline (level, severity, headline amount) changed, so a
    corrected rule reached an open event only with its next new item. Any derived field now counts; a second refresh
    with nothing new writes nothing."""
    store = MemoryStore()
    t0 = datetime(2026, 10, 30, 3, tzinfo=UTC)
    pipeline.ingest([_raw("defillama_hacks", "Binance CEX — Hot Wallet Key Compromised", when="2026-10-29T00:00:00Z",
                          url="https://defillama.com/hacks#Binance", extra={"entity": "Binance CEX", "amount_usd": 6_360_000_000})], store, t0)
    [eid] = store.events
    store.events[eid] = {**store.events[eid], "title": "stale title", "amount_frozen_latest": 6_360_000_000}   # rules of the past
    assert pipeline.refresh(store, datetime(2026, 10, 30, 4, tzinfo=UTC)) == [eid]
    assert store.events[eid]["title"] == "Binance CEX — Hot Wallet Key Compromised"
    assert store.events[eid]["amount_frozen_latest"] is None
    assert pipeline.refresh(store, datetime(2026, 10, 30, 4, 10, tzinfo=UTC)) == []


def test_merge_carries_the_absorbed_events_response_state():
    """Roadmap R2: a merged event's AWS job records / findings / patches used to be orphaned under the deleted id."""
    store = MemoryStore()
    pipeline.ingest([_raw("bleepingcomputer", "Acme VPN CVE-2026-11111 exploited in the wild", "actively exploited",
                          when="2026-10-20T08:00:00Z"),
                     _raw("securityweek", "Zeta mail server CVE-2026-22222 exploited", "exploited in the wild",
                          when="2026-10-20T09:00:00Z")], store, FETCHED)
    first, second = sorted(store.events, key=lambda e: store.events[e]["first_seen"])
    store.put_response(second, {"issues": [{"issue_id": "i1"}], "delivered_prs": {"i1": "https://x/pull/1"}})
    pipeline.ingest([_raw("thehackernews", "CVE-2026-11111 and CVE-2026-22222 are the same bug, chained",
                          "exploited in the wild", when="2026-10-20T10:00:00Z")], store, FETCHED)
    [survivor] = store.events
    gone = second if survivor == first else first
    assert store.get_response(gone) is None
    st = store.get_response(survivor)
    assert st["s3"]["issues"] == [{"issue_id": "i1"}] and st["delivered_prs"] == {"i1": "https://x/pull/1"}


def test_merge_drops_the_absorbed_events_index_rows():
    """Live 2026-11-02: 49 key-index rows pointed at 9 events deleted by merges (ev_1119fbc978f9f673's CVE-2026-98432
    rows among them). Readers skipped them, but every lookup paid for them and audits showed a ghost event."""
    store = MemoryStore()
    pipeline.ingest([_raw("bleepingcomputer", "Acme VPN CVE-2026-11111 exploited in the wild", "actively exploited",
                          when="2026-10-20T08:00:00Z"),
                     _raw("securityweek", "Zeta mail server CVE-2026-22222 exploited", "exploited in the wild",
                          when="2026-10-20T09:00:00Z")], store, FETCHED)
    pipeline.ingest([_raw("thehackernews", "CVE-2026-11111 and CVE-2026-22222 are the same bug, chained",
                          "exploited in the wild", when="2026-10-20T10:00:00Z")], store, FETCHED)
    [survivor] = store.events
    pointed = {e for ids in store.keys.values() for e in ids}
    assert pointed == {survivor}
    assert store.event_ids_for_key("cve:CVE-2026-22222") == [survivor]


def test_a_named_token_cannot_glue_an_event_whose_cves_contradict_the_item():
    """Live 2026-10-27 13:48Z: Node2Shell's event had picked up tok:php2shell (a Node2Shell story mentioning PHP2Shell,
    outside the 3-day token window then). A late Fortinet PSIRT item on PHP2Shell (PHP CVEs + tok:php2shell, published
    inside Node2Shell's window) matched PHP2Shell by CVE and Node2Shell by token — and the token pulled Node2Shell into
    a merge. Two different bugs, one event (and Node2Shell's PR #4 showed on the PHP2Shell page)."""
    store = MemoryStore()
    pipeline.ingest([
        _raw("bleepingcomputer", "PHP2Shell: PHP core RCE CVE-2026-109618 exploited", "PHP2Shell CVE-2026-109618 actively exploited",
             when="2026-10-17T08:00:00Z"),
        _raw("securityweek", "Brotli flaw CVE-2026-111497 gives RCE on Node.js", "CVE-2026-111497 exploited in the wild",
             when="2026-10-23T08:00:00Z")], store, FETCHED)
    php, node = sorted(store.events, key=lambda e: store.events[e]["first_seen"])
    pipeline.ingest([_raw("thehackernews", "Node2Shell CVE-2026-111497 is the new PHP2Shell", "Node2Shell CVE-2026-111497, a week after PHP2Shell",
                          when="2026-10-24T08:00:00Z")], store, FETCHED)
    assert set(store.events) == {php, node}                                      # token outside the window then
    pipeline.ingest([_raw("fortinet_psirt", "PHP2Shell core RCE vulnerability patches (CVE-2026-109618)",
                          "PHP2Shell CVE-2026-109618 patches", when="2026-10-21T07:00:00Z")], store, FETCHED)
    assert set(store.events) == {php, node}, "a token hit merged an event whose CVEs contradict the item"
    late = next(i for i, it in store.items.items() if it["source_id"] == "fortinet_psirt")
    assert late in store.events[php]["item_ids"]


def test_kev_catalog_announcement_listing_two_cves_does_not_merge_their_events():
    """Live 2026-10-27 20:18Z: 'CISA Adds Two Known Exploited Vulnerabilities to Catalog' (Adobe Commerce CVE-2026-48356
    + Google Brotli CVE-2026-111497) glued the Adobe Commerce event into the Brotli/Node2Shell story."""
    store = MemoryStore()
    pipeline.ingest([
        _raw("cisa_kev", "CVE-2026-48356 Adobe Commerce: Unrestricted Upload", "x", extra={"cves": ["CVE-2026-48356"], "kev": True}),
        _raw("cisa_kev", "CVE-2026-111497 Google Brotli: Unchecked Return Value", "y", extra={"cves": ["CVE-2026-111497"], "kev": True}),
    ], store, FETCHED)
    before = set(store.events)
    pipeline.ingest([_raw("cisa_advisories", "CISA Adds Two Known Exploited Vulnerabilities to Catalog",
                          "CISA has added two new vulnerabilities to its Known Exploited Vulnerabilities (KEV) Catalog. "
                          "CVE-2026-48356 Adobe Commerce Unrestricted Upload CVE-2026-111497 Google Brotli Unchecked Return Value")],
                    store, FETCHED)
    assert set(store.events) == before and len(before) == 2


def test_a_roundup_attaches_without_indexing_its_cves_so_a_later_item_cannot_re_merge():
    """The roundup flag alone was not enough: the announcement's CVE keys were still indexed on the event it attached
    to, so the next ordinary Adobe item found both events through cve:CVE-2026-48356 and merged them."""
    store = MemoryStore()
    pipeline.ingest([
        _raw("cisa_kev", "CVE-2026-48356 Adobe Commerce: Unrestricted Upload", "x", extra={"cves": ["CVE-2026-48356"], "kev": True}),
        _raw("cisa_kev", "CVE-2026-111497 Google Brotli: Unchecked Return Value", "y", extra={"cves": ["CVE-2026-111497"], "kev": True}),
        _raw("cisa_advisories", "CISA Adds Two Known Exploited Vulnerabilities to Catalog",
             "CISA has added two new vulnerabilities to its Known Exploited Vulnerabilities (KEV) Catalog. "
             "CVE-2026-48356 Adobe Commerce CVE-2026-111497 Google Brotli"),
        _raw("x_security", "We added Adobe Commerce vulnerability CVE-2026-48356 & Google Brotli vulnerability CVE-2026-111497 "
             "to our KEV Catalog.", "We added Adobe Commerce vulnerability CVE-2026-48356 & Google Brotli vulnerability "
             "CVE-2026-111497 to our KEV Catalog.", author="CISACyber", extra={"x_status": "2115168078837276846"}),
        _raw("bleepingcomputer", "Adobe Commerce CVE-2026-48356 exploited to plant web shells", "CVE-2026-48356 actively exploited",
             when="2026-10-21T10:00:00Z")], store, FETCHED)
    assert len(store.events) == 2
    assert sorted(len(e["cves"]) for e in store.events.values()) == [1, 1]


def test_a_hack_database_loss_beats_a_sub_amount_in_a_t1_tweet():
    """Live 2026-10-30: DeFiLlama listed the Binance theft at $5.78B; then a T1 tweet about the Arbitrum Security Council
    freezing $30.5M of it became the event's headline amount (latest value of the best tier won)."""
    store = MemoryStore()
    pipeline.ingest([_raw("defillama_hacks", "Binance CEX — Hot Wallet Key Compromised", when="2026-10-29T00:00:00Z",
                          url="https://defillama.com/hacks#Binance", extra={"entity": "Binance CEX", "amount_usd": 5_780_000_000})],
                    store, FETCHED)
    pipeline.ingest([_raw("x_security", "BREAKING: Arbitrum Security Council froze $30.5M of the Binance hack funds",
                          "BREAKING: Arbitrum Security Council froze $30.5M of the Binance hack funds, stolen in the exploit",
                          author="PeckShieldAlert", extra={"x_status": "9"}, when="2026-10-30T00:14:00Z")],
                    store, datetime(2026, 10, 30, 0, 20, tzinfo=UTC))
    [ev] = store.events.values()
    assert len(ev["item_ids"]) == 2
    assert ev["amount_usd_latest"] == 5_780_000_000


def test_a_hack_database_loss_beats_an_early_loss_estimate_in_a_t1_tweet():
    """The structured-loss guard on its own: once freezes are their own measure (D2) the $30.5M tweet above no longer
    competes, but an early prose LOSS estimate from a better-ranked source still would (the first Binance reports said
    $2.5B; DeFiLlama's record is $5.78B)."""
    store = MemoryStore()
    pipeline.ingest([_raw("defillama_hacks", "Binance CEX — Hot Wallet Key Compromised", when="2026-10-29T00:00:00Z",
                          url="https://defillama.com/hacks#Binance", extra={"entity": "Binance CEX", "amount_usd": 5_780_000_000})],
                    store, FETCHED)
    pipeline.ingest([_raw("x_security", "BREAKING: Binance hot wallet drained, about $2.5B stolen",
                          "BREAKING: Binance hot wallet drained, about $2.5B stolen in the exploit",
                          author="PeckShieldAlert", extra={"x_status": "10"}, when="2026-10-30T00:14:00Z")],
                    store, datetime(2026, 10, 30, 0, 20, tzinfo=UTC))
    [ev] = store.events.values()
    assert len(ev["item_ids"]) == 2
    assert ev["amount_usd_latest"] == 5_780_000_000


@pytest.mark.parametrize(("db_date", "first"), [("2026-10-29T00:00:00Z", "2026-10-29T20:51:00Z"),   # same day: the timed report
                                                ("2026-10-28T00:00:00Z", "2026-10-28T00:00:00Z")])  # a day earlier: the database
def test_a_date_only_database_entry_is_first_only_when_its_day_is_earlier(db_date, first):
    """Live 2026-10-30: DeFiLlama's "2026-10-29" put the Binance theft at 00:00 — 21 h before the first report — so the
    wall's 24h loss dropped it and the event read 首报 DeFiLlama."""
    store = MemoryStore()
    pipeline.ingest([_raw("panews", "币安热钱包疑似遭攻击，约25亿美元资产被转出", "币安热钱包疑似遭攻击，约25亿美元资产被盗",
                          when="2026-10-29T20:51:00Z")], store, datetime(2026, 10, 29, 21, tzinfo=UTC))
    pipeline.ingest([_raw("defillama_hacks", "Binance CEX — Hot Wallet Key Compromised", when=db_date,
                          url="https://defillama.com/hacks#Binance", extra={"entity": "Binance CEX", "amount_usd": 5_780_000_000})],
                    store, datetime(2026, 10, 30, 0, 18, tzinfo=UTC))
    [ev] = store.events.values()
    assert ev["first_seen"] == first
    assert ev["first_report_source"] == ("PANews" if first.endswith("20:51:00Z") else "DeFiLlama Hacks")


def test_amount_measures_are_kept_apart():
    """Live 2026-10-30: one headline number mixed the loss with freezes ($30.5M), borrows / sales ($27.9M) and an
    estimate of user assets ($165.12B, parsed from 「占用户资产比例为1.6%」). The headline is the loss; freezes are
    their own measure; context amounts feed neither, nor the dispute flag."""
    store = MemoryStore()
    t = lambda h, m=0: datetime(2026, 10, 29, h, m, tzinfo=UTC)
    pipeline.ingest([_raw("panews", "币安热钱包疑似遭攻击，约25亿美元资产被转出", "币安热钱包疑似遭攻击，约25亿美元资产被盗",
                          when="2026-10-29T20:51:00Z")], store, t(20, 55))
    for title, when in [("Tether在疑似币安黑客攻击中冻结价值 9.71 亿美元的 USDT", "2026-10-29T21:14:00Z"),
                        ("涉币安疑似被盗事件的稳定币冻结额升至约21.07亿美元", "2026-10-29T21:29:00Z"),
                        ("江卓尔：币安潜在损失占用户资产比例为1.6%，预计不会出现大规模提币潮", "2026-10-29T22:21:00Z"),
                        ("数据：币安疑似被盗关联地址从Aave借出约1.98万枚ETH", "2026-10-29T22:25:00Z"),
                        # later and smaller: one issuer's freeze must not replace the running total
                        ("Arbitrum安全委员会冻结币安黑客约3050万美元资产", "2026-10-29T22:50:00Z")]:
        body = {"江卓尔": "币安黑客攻击后，用户资产约1651.2亿美元，潜在损失占比1.6%", "数据：币安": "币安黑客关联地址借出约4470万美元ETH"}
        text = next((v for k, v in body.items() if title.startswith(k)), title)
        pipeline.ingest([_raw("odaily", title, text, when=when)], store, t(23))
    pipeline.ingest([_raw("defillama_hacks", "Binance CEX — Hot Wallet Key Compromised", when="2026-10-29T00:00:00Z",
                          url="https://defillama.com/hacks#Binance", extra={"entity": "Binance CEX", "amount_usd": 5_780_000_000})],
                    store, datetime(2026, 10, 30, 0, 18, tzinfo=UTC))
    [ev] = store.events.values()
    assert ev["amount_usd_latest"] == 5_780_000_000
    assert ev["amount_frozen_latest"] == 2_107_000_000
    assert ev["amount_disputed"] is False            # 2.5B vs 5.78B < 3×; the $165B and $44.7M never enter the comparison
    kind = lambda v: next(p["kind"] for p in ev["amount_history"] if abs(p["value"] - v) / v < 1e-6)
    assert kind(971_000_000) == "frozen" and kind(165_120_000_000) == "context" and kind(44_700_000) == "context"


def test_a_title_with_both_loss_and_freeze_does_not_make_the_loss_a_freeze():
    """Live 2026-10-30: 「损失约63亿美元，已冻结约30亿美元资产」 was one "frozen" point of $6.3B (largest number, measure of
    the whole title) ⇒ amount_frozen_latest = the loss. Each number takes the measure of its clause."""
    store = MemoryStore()
    t = datetime(2026, 10, 30, 3, tzinfo=UTC)
    pipeline.ingest([_raw("panews", "币安热钱包疑似遭攻击，约25亿美元资产被转出", "币安热钱包疑似遭攻击，约25亿美元资产被盗",
                          when="2026-10-29T20:51:00Z")], store, t)
    for title, when in [("Specter：目前已冻结币安黑客资金总额达到28.29亿美元", "2026-10-30T01:00:00Z"),
                        ("币安披露安全事件初步调查结果：损失约63亿美元，已冻结约30亿美元资产，将全额赔付", "2026-10-30T02:30:00Z")]:
        pipeline.ingest([_raw("odaily", title, title, when=when)], store, t)
    [ev] = store.events.values()
    assert ev["amount_frozen_latest"] == 3_000_000_000
    assert ev["amount_usd_latest"] == 6_300_000_000
    kinds = {(p["value"], p["kind"]) for p in ev["amount_history"]}
    assert (6_300_000_000, "loss") in kinds and (3_000_000_000, "frozen") in kinds and (6_300_000_000, "frozen") not in kinds


def test_a_later_structured_entry_does_not_rewrite_the_title():
    """Live 2026-10-30: DeFiLlama's "Binance CEX — Hot Wallet Key Compromised" (00:18) was replaced as the title by SlowMist's
    later "Binance — DevOps Engineer's Laptop Compromised" — Binance's own wording was "may involve": a hypothesis became
    the headline because SlowMist outranks DeFiLlama. The first structured record captured names the event."""
    store = MemoryStore()
    pipeline.ingest([_raw("defillama_hacks", "Binance CEX — Hot Wallet Key Compromised", when="2026-10-29T00:00:00Z",
                          url="https://defillama.com/hacks#Binance", extra={"entity": "Binance CEX", "amount_usd": 5_780_000_000})],
                    store, datetime(2026, 10, 30, 0, 18, tzinfo=UTC))
    pipeline.ingest([_raw("slowmist_hacked", "Binance — DevOps Engineer’s Laptop Compromised", when="2026-10-29T00:00:00Z",
                          url="https://hacked.slowmist.io/#binance", extra={"entity": "Binance", "amount_usd": 6_300_000_000})],
                    store, datetime(2026, 10, 30, 2, 48, tzinfo=UTC))
    [ev] = store.events.values()
    assert ev["title"] == "Binance CEX — Hot Wallet Key Compromised"


def test_a_revised_structured_record_keeps_its_first_capture_time():
    """Live 2026-10-30 07:22: DeFiLlama revised its Binance record ("Hot Wallet Key Compromised" → "Key Leaked via
    Infrastructure"); the revision refreshed the item's fetched_at, so SlowMist's record became "first captured" and
    renamed the event to its laptop hypothesis again. The first capture time survives revisions."""
    store = MemoryStore()
    db = lambda title, amt: _raw("defillama_hacks", title, when="2026-10-29T00:00:00Z", url="https://defillama.com/hacks#Binance",
                                 extra={"entity": "Binance CEX", "amount_usd": amt})
    pipeline.ingest([db("Binance CEX — Hot Wallet Key Compromised", 5_780_000_000)], store, datetime(2026, 10, 30, 0, 18, tzinfo=UTC))
    pipeline.ingest([_raw("slowmist_hacked", "Binance — DevOps Engineer’s Laptop Compromised", when="2026-10-29T00:00:00Z",
                          url="https://hacked.slowmist.io/#binance", extra={"entity": "Binance", "amount_usd": 6_300_000_000})],
                    store, datetime(2026, 10, 30, 2, 48, tzinfo=UTC))
    pipeline.ingest([db("Binance CEX — Key Leaked via Infrastructure", 6_300_000_000)], store, datetime(2026, 10, 30, 7, 0, tzinfo=UTC))
    [ev] = store.events.values()
    assert ev["title"] == "Binance CEX — Key Leaked via Infrastructure"


def test_a_number_from_the_body_takes_the_measure_of_its_body_clause():
    """Live 2026-10-30: Decrypt's title "Drained of $5.5 Billion …, Tether and Circle Freeze $1.8 Billion" — the stored
    amount is parsed from the body ($5.57 billion), matched no title clause, and fell back to the whole title's
    measure ("frozen") ⇒ 已冻结 $5.57B."""
    store = MemoryStore()
    t = datetime(2026, 10, 29, 22, tzinfo=UTC)
    pipeline.ingest([_raw("panews", "币安热钱包疑似遭攻击，约25亿美元资产被转出", "币安热钱包疑似遭攻击，约25亿美元资产被盗",
                          when="2026-10-29T20:51:00Z")], store, t)
    pipeline.ingest([_raw("decrypt", "Binance Drained of $5.5 Billion in Suspected Hack, Tether and Circle Freeze $1.8 Billion",
                          "Binance was drained of $5.57 billion in a suspected hack. Tether and Circle froze $1.8 billion.",
                          when="2026-10-29T21:36:00Z")], store, t)
    [ev] = store.events.values()
    kinds = {(p["value"], p["kind"]) for p in ev["amount_history"]}
    assert (5_570_000_000, "loss") in kinds and (5_570_000_000, "frozen") not in kinds
    assert ev["amount_frozen_latest"] == 1_800_000_000


def test_a_price_in_a_side_story_does_not_make_the_loss_disputed():
    """Live 2026-10-30: Cointelegraph's "…UNI token reaching $100 by 2030" was a $100 "loss" point; against $6.3B the
    max/min ratio flagged the Binance loss as disputed. Only figures within 1% of the headline compete."""
    store = MemoryStore()
    t = datetime(2026, 10, 30, 4, tzinfo=UTC)
    pipeline.ingest([_raw("panews", "币安：预计总损失约63亿美元", "币安黑客攻击预计总损失约63亿美元", when="2026-10-30T02:00:00Z")], store, t)
    pipeline.ingest([_raw("cointelegraph", "Binance hack could accelerate shift to DEXs: Standard Chartered",
                          "Kendrick says the Binance hack could strengthen his case for Uniswap’s UNI token reaching $100 by 2030.",
                          when="2026-10-30T03:47:00Z")], store, t)
    [ev] = store.events.values()
    assert len(ev["item_ids"]) == 2 and any(p["value"] == 100 for p in ev["amount_history"])
    assert ev["amount_disputed"] is False
    # since 2026-11-04 that price is context anyway (an unstated body figure); the floor itself must still hold for a
    # tiny figure a headline STATES as a loss — 「一名用户被盗约100美元」 beside the 63亿 loss is no rival estimate
    pipeline.ingest([_raw("odaily", "币安被盗后续：一名用户钓鱼被盗约100美元", "一名币安用户钓鱼被盗约100美元",
                          when="2026-10-30T03:50:00Z")], store, t)
    [ev] = store.events.values()
    assert any(p["value"] == 100 and p["kind"] == "loss" for p in ev["amount_history"]) and ev["amount_disputed"] is False


def test_a_sub_story_amount_is_not_a_rival_loss_estimate():
    """A flash-news source reports the total, then a side story about one address; its latest figure is not its estimate."""
    store = MemoryStore()
    t = datetime(2026, 10, 30, 5, tzinfo=UTC)
    pipeline.ingest([_raw("defillama_hacks", "Binance CEX — Hot Wallet Key Compromised", when="2026-10-29T00:00:00Z",
                          url="https://defillama.com/hacks#Binance", extra={"entity": "Binance CEX", "amount_usd": 6_360_000_000})], store, t)
    for title, when in [("币安被盗约63亿美元", "2026-10-30T02:00:00Z"), ("币安黑客某关联地址被盗约1亿美元", "2026-10-30T04:00:00Z")]:
        pipeline.ingest([_raw("odaily", title, title, when=when)], store, t)
    [ev] = store.events.values()
    assert len(ev["item_ids"]) == 3
    assert ev["amount_disputed"] is False


def test_attribution_is_stated_only_by_a_t1_t2_source():
    store = MemoryStore()
    t = datetime(2026, 10, 30, 1, tzinfo=UTC)
    pipeline.ingest([_raw("panews", "币安热钱包疑似遭攻击，约25亿美元资产被转出", "币安热钱包疑似遭攻击，约25亿美元资产被盗",
                          when="2026-10-29T20:51:00Z")], store, t)
    pipeline.ingest([_raw("odaily", "分析：朝鲜黑客疑为币安被盗幕后黑手", "朝鲜黑客疑为币安被盗约25亿美元幕后黑手",
                          when="2026-10-29T23:00:00Z")], store, t)
    [ev] = store.events.values()
    assert ev["attribution"] == {"actor": "North Korea (Lazarus / TraderTraitor)", "confidence": "suspected", "sources": 1,
                                 "first_at": "2026-10-29T23:00:00Z"}
    pipeline.ingest([_raw("bleepingcomputer", "Binance $6.3 billion hack linked to North Korean hackers",
                          "Binance hack of $6.3 billion linked to North Korea's Lazarus group", when="2026-10-30T00:40:00Z")],
                    store, datetime(2026, 10, 30, 1, 10, tzinfo=UTC))
    [ev] = store.events.values()
    assert ev["attribution"]["confidence"] == "stated" and ev["attribution"]["sources"] == 2


def test_a_two_flaw_kev_story_does_not_merge_two_kev_entries():
    """Live: ev_cc06a43cd18d1b00 held Arista VeloCloud (CVE-2026-114625) and Collabora Online (CVE-2026-110447) —
    merged 2026-10-24 by THN's "CISA Flags Two Actively Exploited Critical Flaws in Collabora Online and Arista
    VeloCloud" (cve:110447 + tok:velocloud), before the CVE-contradiction guard (2026-10-27). Replayed with the real
    titles, in arrival order: two events."""
    store = MemoryStore()
    t = lambda h: datetime(2026, 10, 23, h, tzinfo=UTC) if h < 24 else datetime(2026, 10, 24, h - 24, tzinfo=UTC)
    seq = [("bleepingcomputer", "Arista patches new VeloCloud Orchestrator zero-day exploited in attacks", {}, 5),
           ("cisa_kev", "CVE-2026-114625 Arista VeloCloud Orchestrator: Arista VeloCloud Orchestrator SQL Injection Vulnerability",
            {"cves": ["CVE-2026-114625"], "kev": True}, 17),
           ("cisa_kev", "CVE-2026-110447 Collabora Collabora Online – Built-in CODE Server: Collabora Online Built-in CODE Server",
            {"cves": ["CVE-2026-110447"], "kev": True}, 20),
           ("thehackernews", "CISA Flags Two Actively Exploited Critical Flaws in Collabora Online and Arista VeloCloud",
            {}, 31)]
    for src, title, extra, h in seq:
        text = title + (" CVE-2026-110447 (CVSS score: 9.2) exploited in the wild" if src == "thehackernews" else " exploited in the wild")
        pipeline.ingest([_raw(src, title, text, extra=extra, when=timeutil.iso(t(h)))], store, t(h))
    cves = sorted(tuple(e["cves"]) for e in store.events.values() if e["cves"])
    assert cves == [("CVE-2026-110447",), ("CVE-2026-114625",)]


def test_cisas_own_kev_tweet_listing_two_vendors_is_a_roundup():
    """Live: ev_3905bf053b684805 (P0) held GitLab CVE-2026-97229 and Cisco ASA CVE-2026-76418, glued by @CISACyber's
    "We added GitLab … CVE-2026-97229 & Cisco … CVE-2026-76418 to our KEV Catalog" — 190 characters between "added"
    and "KEV Catalog", past the roundup pattern's 160-character window."""
    tweet = ("🛡️We added GitLab Community Edition &amp; Enterprise Edition vulnerability CVE-2026-97229 &amp; Cisco Secure "
             "Firewall ASA Software and Cisco Secure FTD Software vulnerability CVE-2026-76418 to our KEV Catalog. "
             "Visit https://t.co/myxOwap1Tf for more. #Cybersecurity #InfoSec")
    store = MemoryStore()
    t = datetime(2026, 10, 29, 12, tzinfo=UTC)
    pipeline.ingest([_raw("cisa_kev", "CVE-2026-97229 GitLab Community Edition and Enterprise Edition: GitLab Improper Input Validation",
                          "GitLab CE/EE contains an improper input validation vulnerability exploited in the wild",
                          extra={"cves": ["CVE-2026-97229"], "kev": True}, when="2026-10-29T00:00:00Z"),
                     _raw("cisa_kev", "CVE-2026-76418 Cisco Secure Firewall ASA Software and Cisco Secure FTD Software: Cisco Secure Firewall",
                          "Cisco ASA contains a vulnerability exploited in the wild",
                          extra={"cves": ["CVE-2026-76418"], "kev": True}, when="2026-10-29T00:00:00Z")], store, t)
    pipeline.ingest([_raw("x_security", tweet[:120], tweet, author="CISACyber", extra={"x_status": "77"},
                          when="2026-10-29T13:00:00Z")], store, datetime(2026, 10, 29, 13, 5, tzinfo=UTC))
    cves = sorted(tuple(e["cves"]) for e in store.events.values())
    assert cves == [("CVE-2026-76418",), ("CVE-2026-97229",)]


ENGIE = "https://www.bleepingcomputer.com/news/security/energy-giant-engie-discloses-data-breach-affecting-customers/"


def _engie_tweet(links):
    return _raw("x_security", "Energy giant ENGIE discloses data breach affecting customers",
                "Energy giant ENGIE discloses data breach affecting customers https://t.co/abc", author="BleepinComputer",
                extra={"x_status": "1983"}, when="2026-10-29T09:28:00Z", links=links)


def test_a_tweet_seen_before_the_article_it_cites_is_found_by_that_article():
    """C4 F1 (docs/research/12 §10): the outlet's tweet arrives 20–80 min before its own RSS entry; the article's url:
    key must find the tweet's event — live 2026-10-29: ENGIE, Tailscale, Volt Typhoon stayed two events each."""
    store = MemoryStore()
    pipeline.ingest([_engie_tweet([ENGIE])], store, datetime(2026, 10, 29, 9, 30, tzinfo=UTC))
    pipeline.ingest([_raw("bleepingcomputer", "Energy giant ENGIE discloses data breach affecting customers",
                          "ENGIE disclosed a data breach", url=ENGIE, when="2026-10-29T09:48:00Z")],
                    store, datetime(2026, 10, 29, 9, 50, tzinfo=UTC))
    [ev] = store.events.values()
    assert len(ev["item_ids"]) == 2


@pytest.mark.parametrize("links", [
    ["https://www.bleepingcomputer.com/"],                                    # a homepage names no story
    ["https://go.dhs.gov/iEv"],                       # CISA's shortener to the advisory listing, on every ICS tweet
    ["https://www.cisa.gov/news-events/cybersecurity-advisories"],            # a listing page
    ["https://x.com/BleepinComputer/status/1"],                               # tweets link up through xs:
    [ENGIE, "https://www.bleepingcomputer.com/news/security/acme-discloses-ransomware-attack/"],  # a digest cites several stories
])
def test_a_tweet_registers_no_url_key_for_a_homepage_a_tweet_or_a_digest(links):
    item = pipeline.normalize(_engie_tweet(links), registry_source("x_security"), FETCHED)
    assert [k for k in item.keys if k.startswith("url:")] == [f"url:{item.canonical_url}"]   # only its own


def registry_source(sid):
    from radar import registry
    return next(s for s in registry.SOURCES if s.source_id == sid)


ROUNDUP = ("PANews 11月1日消息，据 PeckShieldAlert 统计，2026 年 10 月加密行业共发生 56 起重大黑客攻击，总损失约 64.8 亿美元。"
           "其中币安事件（约 63 亿美元，已冻结 30 亿美元）跃居年内最大盗窃案首位。截至 10 月 31 日，年度前十大黑客事件合计损失"
           "占全年总损失（86 亿美元）的 92.3%（未扣除已冻结及返还资金）。")


def test_an_industry_roundup_report_states_no_amount_of_the_event():
    """Live 2026-11-01: PANews' "October: 56 hacks, $6.48B" attached to the Binance event; its "全年总损失（86 亿美元）
    （未扣除已冻结…）" became Binance's frozen headline ($8.6B > the $6.3B loss). Statistics across incidents are context."""
    store = MemoryStore()
    pipeline.ingest([_raw("defillama_hacks", "Binance CEX — Hot Wallet Key Compromised", when="2026-10-29T20:51:00Z",
                          url="https://defillama.com/hacks#Binance", extra={"entity": "Binance CEX", "amount_usd": 6_300_000_000}),
                     _raw("odaily", "币安已冻结约30亿美元被盗资产", "币安已冻结约30亿美元被盗资产", when="2026-10-30T06:00:00Z")],
                    store, datetime(2026, 10, 30, 6, 5, tzinfo=UTC))
    pipeline.ingest([_raw("panews", "10月加密行业重大黑客事件达56起，损失达64.8亿美元", ROUNDUP, when="2026-11-01T05:01:38Z")],
                    store, datetime(2026, 11, 1, 5, 5, tzinfo=UTC))
    [ev] = [e for e in store.events.values() if "Binance" in e["title"]]
    assert len(ev["item_ids"]) == 3                                   # it does attach (the live path), and
    assert ev["amount_frozen_latest"] == 3_000_000_000 and ev["amount_usd_latest"] == 6_300_000_000
    assert {p["kind"] for p in ev["amount_history"] if p["source_id"] == "panews"} == {"context"}


@pytest.mark.parametrize(("text", "kind"), [
    ("占全年总损失（86 亿美元）的 92.3%（未扣除已冻结及返还资金）", "loss"),     # a negated freeze is no freeze
    ("Tether 已冻结 9.71 亿美元 USDT", "frozen"),
])
def test_a_negated_freeze_word_is_not_a_freeze(text, kind):
    from radar import signals
    [(_, k)] = [m for m in signals.amount_mentions(text)]
    assert k == kind


@pytest.mark.parametrize(("title", "roundup"), [
    ("10月加密行业重大黑客事件达56起，损失达64.8亿美元", True),
    ("2026年DeFi价格操纵攻击已达43起，超过2022年全年纪录", True),
    ("Chainalysis：朝鲜相关攻击占今年加密黑客损失近89%，2021年为15%", True),      # live 2026-11-01: $22.34B on the wall
    ("Crypto hacks in October top $6.5 billion", True),
    ("Binance CEX — Hot Wallet Key Compromised", False),
    ("币安热钱包疑似遭攻击，约25亿美元资产被转出", False),
    ("Pando Rings黑客2小时前买入7548枚ETH，约合1672万美元", False),
    ("Arbitrum安全委员会冻结币安黑客约3050万美元资产", False),
])
def test_an_industry_statistics_title_is_a_roundup_and_an_incident_title_is_not(title, roundup):
    from radar import signals
    assert signals.is_roundup_report(title) is roundup


def test_a_context_digest_does_not_lend_its_names_to_the_event_it_attaches_to():
    """Live 2026-11-02: PANews' daily digest 「昨夜今晨重要资讯」 (context only, 50+ names) sat in the Binance event and
    lent every name it mentions — tok:zklink among them — to the Binance keys; two days later the zkLink exploit reports
    found the Binance event through tok:zklink. A context-only item lends hard keys only (it still attaches through them)."""
    from radar import registry
    digest = pipeline.normalize(_raw("panews", "昨夜今晨重要资讯（10月29日-10月30日）",
                                     "币安热钱包遭攻击；Polymarket 推出新功能；zkLink Nova 更新路线图；OKX 上线新币。",
                                     when="2026-10-30T02:38:00Z"), registry.BY_ID["panews"], FETCHED)
    assert digest.eventful is False and any(k.startswith("tok:") for k in digest.keys)
    lent = pipeline.indexed_keys(digest)
    assert lent and all(k.startswith(("url:", "cve:", "tx:", "xs:", "attacker:")) for k in lent)
    report = pipeline.normalize(_raw("slowmist_medium", "One Fish, Multiple Meals — Analysis of the $780K zkLink Exploit",
                                     "zkLink Nova exploited for $780K", when="2026-10-31T12:30:00Z"),
                                registry.BY_ID["slowmist_medium"], FETCHED)
    assert any(k.startswith("tok:") for k in pipeline.indexed_keys(report))       # an eventful report still lends names


def _web3(source, title, when, now):
    """An eventful web3 report (a context-only one would neither open an event nor match by name)."""
    from radar import registry
    raw = _raw(source, title, title, when=when)
    assert pipeline.normalize(raw, registry.BY_ID[source], now).eventful, title
    return raw


def _binance_open_event(store):
    pipeline.ingest([_raw("defillama_hacks", "Binance CEX — Hot Wallet Key Compromised", when="2026-10-29T20:51:00Z",
                          url="https://defillama.com/hacks#Binance", extra={"entity": "Binance CEX", "amount_usd": 6_300_000_000})],
                    store, datetime(2026, 10, 30, 0, tzinfo=UTC))
    t = datetime(2026, 11, 1, 19, tzinfo=UTC)
    pipeline.ingest([_web3("cointelegraph", "Binance hack: attacker moves another $40M stolen from hot wallets",
                           "2026-11-01T18:54:00Z", t)], store, t)


def _web3_events(store):
    return sorted((e for e in store.events.values() if e["domain"] == "web3"), key=lambda e: e["first_seen"])


def test_an_incident_still_being_reported_keeps_collecting_its_reports():
    """Live 2026-11-02: Binance (first seen 10-29 20:51, reports every hour) split in two at 11-01 20:51 — the name
    window ran from first_seen; Cointelegraph's "Binance net outflows surge … after record hack" opened a new event with
    12 more follow-ups. The window rolls from the latest evidence (still capped by a total span)."""
    store = MemoryStore()
    _binance_open_event(store)
    t = datetime(2026, 11, 2, tzinfo=UTC)
    pipeline.ingest([_web3("theblock", "Binance hack: $250K of stolen funds deposited to Gate, 2 accounts frozen",
                           "2026-11-01T23:59:00Z", t)], store, t)
    [ev] = _web3_events(store)
    assert len(ev["item_ids"]) == 3


def test_a_name_seen_again_long_after_the_story_went_quiet_is_a_new_event():
    store = MemoryStore()
    _binance_open_event(store)
    t = datetime(2026, 11, 8, 10, 5, tzinfo=UTC)                                     # 6.6 days after the last report
    pipeline.ingest([_web3("cointelegraph", "Binance hot wallet hacked again, $40M drained", "2026-11-08T10:00:00Z", t)], store, t)
    assert len(_web3_events(store)) == 2


def test_the_rolling_window_has_a_total_span_cap():
    store = MemoryStore()
    _binance_open_event(store)
    day = datetime(2026, 11, 1, 18, 54, tzinfo=UTC)
    for n in range(1, 10):                                                           # a report every 2.5 days …
        t = day + timedelta(days=2.5 * n)
        pipeline.ingest([_web3("cointelegraph", f"Binance hack: attacker moves ${n}0M more stolen funds", timeutil.iso(t), t)], store, t)
    evs = _web3_events(store)
    assert len(evs) == 2 and evs[1]["first_seen"] > "2026-11-19"                     # … opens a new event past 21 days


def test_a_vulnerability_event_does_not_stay_open_to_its_vendor_name():
    """Vulnerability stories are linked by CVE (a hard key); a rolling window would keep a vendor name like GitLab open
    for weeks (live dry run 2026-11-02: "Alpine Linux rebuilds GitLab after attempted RCE attack" — no CVE named —
    joined the CVE-2026-97229 KEV event). The rolling window is for web3 / incident stories only."""
    store = MemoryStore()
    pipeline.ingest([_raw("bleepingcomputer", "GitLab CVE-2026-97229 exploited in the wild, CISA adds to KEV",
                          "GitLab CVE-2026-97229 exploited in the wild", when="2026-10-29T09:05:00Z")], store, datetime(2026, 10, 29, 10, tzinfo=UTC))
    pipeline.ingest([_raw("securityweek", "GitLab CVE-2026-97229 patches rushed out as exploitation grows",
                          "CVE-2026-97229 exploited in the wild", when="2026-10-31T09:00:00Z")], store, datetime(2026, 10, 31, 10, tzinfo=UTC))
    pipeline.ingest([_raw("bleepingcomputer", "Alpine Linux rebuilds GitLab after attempted RCE attack",
                          "Hackers attempted to exploit a critical GitLab vulnerability", when="2026-11-01T15:11:00Z")],
                    store, datetime(2026, 11, 1, 16, tzinfo=UTC))
    assert len([e for e in store.events.values() if e["domain"] == "vuln"]) == 2



def test_attribution_first_at_is_evidence_time_not_a_date_only_midnight():
    """A date-only structured entry (DeFiLlama "2026-10-29") naming the actor is not 「首次点名」 at 00:00 — it is
    pipeline.evidence_at, the one rule for date vs moment (04-reconstruction.md B5)."""
    store = MemoryStore()
    t = datetime(2026, 10, 30, 3, tzinfo=UTC)
    pipeline.ingest([_raw("panews", "币安热钱包疑似遭攻击，约25亿美元资产被转出", "币安热钱包疑似遭攻击，约25亿美元资产被盗",
                          when="2026-10-29T20:51:50Z")], store, t)
    pipeline.ingest([_raw("defillama_hacks", "Binance CEX — Hot Wallet Key Compromised", "Attributed to Lazarus",
                          when="2026-10-29T00:00:00Z", url="https://defillama.com/hacks#Binance",
                          extra={"entity": "Binance CEX", "amount_usd": 5_780_000_000})], store, t)
    [ev] = store.events.values()
    assert ev["attribution"]["confidence"] == "stated"
    assert ev["attribution"]["first_at"] == "2026-10-29T23:59:59Z"


def test_patch_tuesday_advisories_do_not_attach_to_a_theft_event_that_cites_a_cve():
    """Live 2026-11-11: a crypto-media article citing a Chrome CVE gave the Binance theft event a CVE key; November's
    Patch Tuesday (MSRC, one advisory per CVE) then attached through it — 1,097 advisories, the event re-domained to
    vuln. A CVE links vulnerability stories only."""
    store = MemoryStore()
    pipeline.ingest([
        _raw("panews", "币安热钱包遭攻击，约25亿美元资产被转出", "币安热钱包被盗，攻击者转出约25亿美元",
             url="https://panews.example/a1", when="2026-10-29T20:58:00Z"),
        _raw("odaily", "币安被盗事件追踪：攻击者再转出7.8亿枚USDC", "币安热钱包被盗事件，资金继续转出",
             url="https://odaily.example/a2", when="2026-10-29T22:00:00Z"),
    ], store, FETCHED)
    (theft,) = store.events
    pipeline.ingest([_raw("panews", "币安被盗约25亿美元：攻击者利用 Chrome 漏洞 CVE-2026-777001 入侵员工电脑",
                          "币安热钱包被盗约25亿美元，攻击者利用 CVE-2026-777001 入侵运维人员电脑", url="https://panews.example/a3",
                          when="2026-10-30T08:00:00Z")], store, FETCHED)
    # the live precondition: the theft event is reachable through the CVE it cited (key index)
    assert set(store.events) == {theft} and store.event_ids_for_key("cve:CVE-2026-777001") == [theft]
    assert store.events[theft]["domain"] == "web3"
    pipeline.ingest([_raw("msrc_update", "CVE-2026-777001 Chromium: Use after free in V8", "CVE-2026-777001",
                          url="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-777001",
                          when="2026-11-10T18:15:00Z")], store, FETCHED)
    adv = next(i for i, it in store.items.items() if it["source_id"] == "msrc_update")
    assert adv not in store.events[theft]["item_ids"], "a vulnerability advisory attached to a theft event via a CVE"
    assert store.events[theft]["domain"] == "web3"


def test_two_advisories_for_one_product_with_disjoint_cves_stay_two_events():
    """The same hairball glued per-CVE MSRC advisories through product names (tok:sharepoint, win32k, powershell …):
    different CVEs are different vulnerabilities, whatever product they share."""
    store = MemoryStore()
    pipeline.ingest([
        _raw("msrc_update", "CVE-2026-700001 Microsoft SharePoint Server Remote Code Execution Vulnerability", "CVE-2026-700001",
             url="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-700001", when="2026-11-10T18:00:00Z"),
        _raw("msrc_update", "CVE-2026-700002 Microsoft SharePoint Server Spoofing Vulnerability", "CVE-2026-700002",
             url="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-700002", when="2026-11-10T18:00:00Z"),
    ], store, FETCHED)
    cves = sorted(tuple(e["cves"]) for e in store.events.values())
    assert cves == [("CVE-2026-700001",), ("CVE-2026-700002",)], cves


def test_a_review_linking_many_advisories_does_not_merge_them():
    """Live 2026-11-11: ZDI's November Patch Tuesday review linked 1,129 MSRC advisory pages — each a strong url: key —
    and merged every per-CVE advisory into one 1,239-item event. An item proving more than MERGE_MAX_EVENTS_PER_ITEM
    events identical proves nothing — here five breach stories (no CVEs, so only this rule stands between them)."""
    store = MemoryStore()
    orgs = ["Acme Hospital", "Globex Retail", "Initech Port", "Umbrella School", "Hooli Airline"]
    urls = [f"https://bc.example/{n}" for n in range(5)]
    for n, (org, u) in enumerate(zip(orgs, urls, strict=True)):
        pipeline.ingest([_raw("bleepingcomputer", f"Ransomware attack shuts down {org} network",
                              f"Ransomware attack breached {org}, systems offline.", url=u, when=f"2026-11-0{n + 1}T08:00:00Z")],
                        store, FETCHED)
    assert len(store.events) == 5
    pipeline.ingest([_raw("therecord", "Five organisations breached by ransomware crews this month, FBI says",
                          "The FBI says ransomware gangs breached five organisations.", url="https://record.example/five",
                          links=tuple(urls), when="2026-11-10T19:00:00Z")], store, FETCHED)
    assert len(store.events) == 5, "a review that links to every story merged them"


def test_a_hack_database_record_for_another_victim_does_not_join_a_big_incident():
    """Live 2026-11-11: Mercado Bitcoin / BitMart / Ankr records joined the Binance event through names Binance coverage
    mentions (tok:mercado …) and Ankr's $304,500 became Binance's headline loss."""
    store = MemoryStore()
    pipeline.ingest([
        _raw("defillama_hacks", "Binance CEX — Key Leaked via Infrastructure", "Binance CEX hack",
             url="https://defillama.example/binance", extra={"entity": "Binance CEX", "amount_usd": 6.36e9},
             when="2026-10-29T21:00:00Z"),
        _raw("panews", "币安被盗63亿美元后，Mercado Bitcoin 也被盗4900万美元", "币安被盗约63亿美元；Mercado Bitcoin 被盗4900万美元",
             url="https://panews.example/b1", when="2026-10-30T08:00:00Z"),
    ], store, FETCHED)
    (binance,) = [e for e, v in store.events.items() if "Binance CEX" in v["entities"]]
    assert any(k.startswith("amt:") for k in store.events[binance]["keys"])     # the live precondition: Mercado's figure
    pipeline.ingest([_raw("defillama_hacks", "Mercado Bitcoin — Signing Capability Compromise", "Mercado Bitcoin hack",
                          url="https://defillama.example/mercado", extra={"entity": "Mercado Bitcoin", "amount_usd": 4.9e7},
                          when="2026-10-30T12:00:00Z")], store, FETCHED)     # inside the window: Binance is reported hourly
    merc = next(i for i, it in store.items.items() if it["url"] == "https://defillama.example/mercado")
    assert merc not in store.events[binance]["item_ids"], "another victim's hack record joined the Binance event"
    assert store.events[binance]["amount_usd_latest"] == 6.36e9


def test_agreeing_hack_databases_are_not_disputed_by_side_stories_in_prose():
    """Live 2026-11-11: DeFiLlama $6.36B and SlowMist $6.34B agreed on Binance, but prose sources whose largest figure was a
    side story (Bitget $292M) flagged the loss disputed — the headline dropped and P0 became P1."""
    from radar.model import Item
    def it(n, src, title, amount=None, extra=None):
        return Item(item_id=f"it_{n:016x}", source_id=src, tier="T1" if amount else "T2", org=src, domain="web3",
                    url=f"https://e{n}.example", canonical_url=f"https://e{n}.example", title=title, text=title,
                    published_at=f"2026-10-30T{n:02d}:00:00Z", fetched_at=f"2026-10-30T{n:02d}:00:00Z", content_hash="h",
                    keys=[], links=[], entity="Binance CEX" if amount else None, eventful=True,
                    signals={"exploited": "yes", "kev": False, "poc": False, "amount_usd": amount},
                    extra={**({"amount_usd": amount, "amount_history": [{"value": amount, "observed_at": f"2026-10-30T{n:02d}:00:00Z"}]} if amount else {}), **(extra or {})})
    items = [it(1, "defillama_hacks", "Binance CEX — Key Leaked", 6.36e9), it(2, "slowmist_hacked", "Binance — Intrusion", 6.34e9),
             it(3, "panews", "Bitget 被盗2.92亿美元", extra={"amount_history": [{"value": 2.92e8, "observed_at": "2026-10-30T03:00:00Z"}]})]
    _hist, latest, disputed, _stable, _frozen = pipeline._amounts(items)
    assert latest in (6.36e9, 6.34e9) and disputed is False


def test_a_hack_record_does_not_follow_a_linked_tweet_into_another_victims_event():
    """Live 2026-11-11: SlowMist's tweet on the Ankr bridge exploit mentioned Binance and joined the Binance event; SlowMist's
    Ankr record links that tweet (xs:), followed it in, and DeFiLlama's Ankr record then joined by name — Ankr's $304,500
    and Initia's $615,000 became Binance's headline."""
    store = MemoryStore()
    tweet = "https://x.com/SlowMist_Team/status/2119720284093890615"
    pipeline.ingest([
        _raw("defillama_hacks", "Binance CEX — Key Leaked via Infrastructure", "Binance CEX hack",
             url="https://defillama.example/binance", extra={"entity": "Binance CEX", "amount_usd": 6.36e9},
             when="2026-11-09T01:00:00Z"),
        _raw("panews", "币安被盗63亿美元，攻击者资金持续转移", "币安热钱包被盗约63亿美元", url="https://panews.example/c1",
             when="2026-11-09T02:00:00Z"),
        _raw("x_security", "Ankr bridge exploited for $304.5K; attacker swapped and deposited to Binance",
             "Ankr bridge exploited, funds sent to Binance", url=tweet, author="SlowMist_Team", when="2026-11-09T03:00:00Z"),
    ], store, FETCHED)
    (binance,) = [e for e, v in store.events.items() if "Binance CEX" in v["entities"]]
    tw = next(i for i, it in store.items.items() if it["url"] == tweet)
    assert tw in store.events[binance]["item_ids"]                     # the live precondition: the tweet is in Binance
    pipeline.ingest([_raw("slowmist_hacked", "Ankr Ethereum Cross-chain Bridge — Smart Contract Vulnerability", "Ankr bridge",
                          url="https://slowmist.example/ankr", links=(tweet,),
                          extra={"entity": "Ankr Ethereum Cross-chain Bridge", "amount_usd": 304500.0},
                          when="2026-11-09T06:00:00Z")], store, FETCHED)
    rec = next(i for i, it in store.items.items() if it["url"] == "https://slowmist.example/ankr")
    assert rec not in store.events[binance]["item_ids"], "another victim's record followed a tweet into Binance"
    assert store.events[binance]["amount_usd_latest"] == 6.36e9


def test_an_article_linking_two_named_incidents_does_not_merge_them():
    """Live 2026-11-11: an article on the Initia exploit that also mentioned Binance merged the Initia incident (DeFiLlama
    / SlowMist records included) into the Binance event; Initia's $615,000 became Binance's headline."""
    store = MemoryStore()
    t_bin, t_ini = "https://x.com/binance/status/2119000000000000001", "https://x.com/initia/status/2120050740626628972"
    pipeline.ingest([
        _raw("defillama_hacks", "Binance CEX — Key Leaked via Infrastructure", "Binance CEX hack", url="https://defillama.example/b",
             links=(t_bin,), extra={"entity": "Binance CEX", "amount_usd": 6.36e9}, when="2026-11-10T00:00:00Z"),
        _raw("defillama_hacks", "Initia — Infinite Mint", "Initia hack", url="https://defillama.example/i",
             links=(t_ini,), extra={"entity": "Initia", "amount_usd": 615000.0}, when="2026-11-10T00:00:00Z"),
    ], store, FETCHED)
    assert len(store.events) == 2
    pipeline.ingest([_raw("panews", "Initia 被盗61.5万美元，币安冻结部分资金", "Initia 被盗；币安冻结资金",
                          url="https://panews.example/m", links=(t_bin, t_ini), when="2026-11-10T06:00:00Z")], store, FETCHED)
    assert len(store.events) == 2, "an article linking two named incidents merged them"


def test_a_prose_only_event_takes_each_sources_largest_figure_as_its_estimate():
    """M185 without a hack database in the event (the structured pool then decides the dispute): a flash-news source's
    later side story is not its estimate of the total."""
    store = MemoryStore()
    t = datetime(2026, 10, 30, 5, tzinfo=UTC)
    pipeline.ingest([_raw("panews", "币安被盗约63亿美元", "币安被盗约63亿美元", url="https://panews.example/p1",
                          when="2026-10-30T01:00:00Z")], store, t)
    for title, when, url in [("币安被盗约63亿美元", "2026-10-30T02:00:00Z", "https://odaily.example/o1"),
                             ("币安黑客某关联地址被盗约1亿美元", "2026-10-30T04:00:00Z", "https://odaily.example/o2")]:
        pipeline.ingest([_raw("odaily", title, title, url=url, when=when)], store, t)
    [ev] = store.events.values()
    assert len(ev["item_ids"]) == 3 and ev["amount_disputed"] is False


def test_a_prose_only_headline_is_the_loss_not_a_later_freeze():
    """M157 without a hack database in the event: freezes reported after the loss never become the headline loss."""
    store = MemoryStore()
    t = datetime(2026, 10, 30, 5, tzinfo=UTC)
    for title, when, url in [("币安热钱包疑似遭攻击，约25亿美元资产被盗", "2026-10-29T20:51:00Z", "https://panews.example/q1"),
                             ("涉币安疑似被盗事件的稳定币冻结额升至约21.07亿美元", "2026-10-29T21:29:00Z", "https://panews.example/q2"),
                             ("Arbitrum安全委员会冻结币安黑客约3050万美元资产", "2026-10-29T22:50:00Z", "https://panews.example/q3")]:
        pipeline.ingest([_raw("panews", title, title, url=url, when=when)], store, t)
    [ev] = store.events.values()
    assert ev["amount_usd_latest"] == 2_500_000_000 and ev["amount_frozen_latest"] == 2_107_000_000


def test_hack_records_without_a_victim_do_not_merge_through_the_shared_feed_url():
    """M05 now that named records are kept apart by their victims: a record whose victim did not parse still must not
    join another through the database's synthetic shared URL."""
    store = MemoryStore()
    pipeline.ingest([
        _raw("defillama_hacks", "Unknown protocol — Flash Loan Attack", "flash loan", url="https://api.llama.fi/hacks",
             extra={"amount_usd": 1_200_000}, when="2026-11-01T00:00:00Z"),
        _raw("defillama_hacks", "Another protocol — Oracle Manipulation", "oracle", url="https://api.llama.fi/hacks",
             extra={"amount_usd": 3_400_000}, when="2026-11-02T00:00:00Z"),
    ], store, FETCHED)
    assert len(store.events) == 2, "two hack records merged through the shared synthetic URL"


def test_alert_boilerplate_and_time_zones_name_no_victim():
    """Live 2026-11-11: SlowMist's TranchePool alert joined the Initia event through tok:utc (「reported at 03:14 UTC」) and
    later Yapeswap through tok:vulnerable (「Root Cause: Vulnerable …」); its attack tx then pulled FenceTranchePool in."""
    from radar import keys
    toks = keys.entity_tokens("🚨 SlowMist TI Alert 🚨 💸 Loss: ~1.013M USDC from a TranchePool reported at 03:14 UTC. "
                              "🔍 Root Cause: Vulnerable settle logic")
    assert toks == {"tranchepool"}


def test_a_second_attack_on_the_same_victim_is_a_new_incident():
    """Live 2026-11-11: 「Initia confirms second exploit in 3 weeks」 joined the 10-23 Initia event by name."""
    store = MemoryStore()
    pipeline.ingest([_raw("defillama_hacks", "Initia — Infinite Mint", "Initia hack", url="https://defillama.example/i1",
                          extra={"entity": "Initia", "amount_usd": 2.7e6}, when="2026-10-23T00:00:00Z")], store, FETCHED)
    (first,) = store.events
    for n, day in enumerate(("10-25", "10-28", "10-31", "11-03", "11-06", "11-09")):   # follow-ups keep the window open
        pipeline.ingest([_raw("panews", f"Initia 链被盗约270万美元，追踪进展第{n}期", f"Initia 链上被盗资金第{n}次追踪：仍在转移",
                              url=f"https://panews.example/i{n}", when=f"2026-{day}T08:00:00Z")], store, FETCHED)
    assert len(store.events) == 1 and len(next(iter(store.events.values()))["item_ids"]) == 7   # one open story
    pipeline.ingest([_raw("cointelegraph", "Initia blockchain confirms second crypto exploit in 3 weeks, $3.27M stolen",
                          "Initia blockchain second exploit, $3.27 million in crypto stolen", url="https://ct.example/i3",
                          when="2026-11-11T05:52:00Z")], store, FETCHED)
    second = next(i for i, it in store.items.items() if it["url"] == "https://ct.example/i3")
    assert second not in store.events[first]["item_ids"], "a reported second exploit joined the first incident"


def test_one_victim_under_two_spellings_is_one_victim():
    """DeFiHackLabs writes 「ZkLinkNova」, DeFiLlama 「zkLink Nova」 (entity keys zklinknova / zklink)."""
    assert pipeline._same_victim(["ZkLinkNova"], ["zkLink Nova"]) and pipeline._same_victim(["Across"], ["Across Protocol"])
    assert not pipeline._same_victim(["FenceTranchePool"], ["Initia"]) and not pipeline._same_victim(["Ankr Bridge"], ["Binance CEX"])


def _ankr_and_binance(store):
    """Binance open (one of its reports mentions Ankr, so the event holds tok:ankr) and the Ankr bridge's own event."""
    _binance_open_event(store)
    t = datetime(2026, 11, 3, 0, tzinfo=UTC)          # inside Binance's rolling window (reported hourly live)
    pipeline.ingest([_web3("cointelegraph", "Binance hack: attacker moves another $30M as Ankr and Kraken freeze deposits",
                           "2026-11-02T10:00:00Z", t)], store, t)
    pipeline.ingest([_raw("defillama_hacks", "Ankr Ethereum Cross-chain Bridge — Smart Contract Vulnerability", "Ankr bridge",
                          url="https://defillama.example/ankr", extra={"entity": "Ankr Ethereum Cross-chain Bridge",
                                                                      "amount_usd": 304_500}, when="2026-11-03T00:53:00Z")],
                    store, t)
    (binance,) = [e for e, v in store.events.items() if "Binance CEX" in v["entities"]]
    (ankr,) = [e for e, v in store.events.items() if "Ankr Ethereum Cross-chain Bridge" in v["entities"]]
    assert "tok:ankr" in store.events[binance]["keys"]            # the live precondition: a mention lent Binance the name
    return binance, ankr


def test_a_report_naming_a_victim_goes_to_that_victims_event_not_to_one_that_mentions_it():
    """Live 2026-11-12: one Binance article mentioned Ankr; every Ankr bridge report (no structured victim name) then
    scored the 576-item Binance event and the Ankr event alike and went to the earlier one — 12 reports and Ankr's five
    attack transactions sat on the Binance page (and Mercado Bitcoin's whole $49M story likewise)."""
    store = MemoryStore()
    binance, ankr = _ankr_and_binance(store)
    t = datetime(2026, 11, 3, 11, tzinfo=UTC)
    pipeline.ingest([_web3("gn_crypto_hack", "Ankr Bridge Hack: $304K Drained Using Forged Cross-Chain Receipts",
                           "2026-11-03T10:39:00Z", t)], store, t)
    report = next(i for i, it in store.items.items() if it["title"].startswith("Ankr Bridge Hack"))
    assert report in store.events[ankr]["item_ids"], "the Ankr report went to the event that only mentions Ankr"
    assert report not in store.events[binance]["item_ids"]


def test_a_name_in_the_body_only_is_context_not_the_reports_subject():
    """Live: 「Pando Rings黑客将4000枚ETH通过Tornado转移」 recalls the Binance-led dip in its text; it stays with Pando."""
    store = MemoryStore()
    _binance_open_event(store)
    t = datetime(2026, 11, 2, 4, 10, tzinfo=UTC)
    pipeline.ingest([_web3("panews", "Pando Rings黑客抄底买入7548枚ETH，约合1672万美元", "2026-11-02T04:04:00Z", t)], store, t)
    pando = next(e for e, v in store.events.items() if "Pando" in v["title"])
    pipeline.ingest([_raw("odaily", "价值约922万美元，Pando Rings黑客将4000枚ETH通过Tornado转移",
                          "4 年前盗取 Pando Rings 的黑客，在币安被盗引发的市场下跌中抄底 ETH，并将 4000 枚 ETH 转入 Tornado Cash。",
                          url="https://odaily.example/pando", when="2026-11-02T04:05:00Z")], store, t)
    report = next(i for i, it in store.items.items() if it["url"] == "https://odaily.example/pando")
    assert report in store.events[pando]["item_ids"], "a body mention of Binance outranked the headline's Pando Rings"


def test_a_shared_loss_figure_outranks_a_name_mentioned_in_passing():
    """Live: 「Mystery $106 Million Crypto Theft Hits EU Entity Days After Binance…」 is the EU entity's story (it holds
    amt:106000000); Binance is a time reference, however the headline names it."""
    store = MemoryStore()
    _binance_open_event(store)
    t = datetime(2026, 11, 2, 21, 30, tzinfo=UTC)
    pipeline.ingest([_web3("panews", "ZachXBT：一欧盟实体疑从多个交易所账户被盗逾1.06亿美元", "2026-11-02T12:32:00Z", t)], store, t)
    eu = next(e for e, v in store.events.items() if "欧盟" in v["title"])
    assert "amt:106000000" in store.events[eu]["keys"]
    pipeline.ingest([_raw("thedefiant", "Mystery $106 Million Crypto Theft Hits EU Entity Days After Binance Hack",
                          "An EU entity lost $106 million days after the Binance hack.", url="https://defiant.example/eu",
                          when="2026-11-02T21:16:00Z")], store, t)
    report = next(i for i, it in store.items.items() if it["url"] == "https://defiant.example/eu")
    assert report in store.events[eu]["item_ids"], "a passing mention of Binance outranked the shared $106M figure"


def test_an_event_without_a_named_victim_has_no_own_name():
    """Its title is one report's headline — live, a Pando Rings tweet titled 「…在 3 天前 Binance 被盗引发的市场下跌中…」
    drew Binance follow-ups once its title's names counted as its own."""
    from radar.model import Event
    ev = Event.from_dict({**_binance_like_event(), "entities": [],
                          "title": "4 年前从 Pando Rings 盗取资产的黑客，在 3 天前 Binance 被盗引发的市场下跌中抄底"})
    assert not pipeline._names_event("binance", ev) and not pipeline._names_event("pando", ev)
    assert pipeline._names_event("binance", Event.from_dict(_binance_like_event()))


def _binance_like_event():
    store = MemoryStore()
    _binance_open_event(store)
    return next(iter(store.events.values()))


def test_a_capitalised_word_two_unrelated_incident_stories_share_does_not_merge_them():
    """Outside web3 a capitalised headline word is no name (live 2026-10-23: 'Hackers' / 'Deliver' glued 11 unrelated THN
    stories). The replay test above no longer reaches this rule — its glue words are stopwords since 2026-11-11 — so this
    pins it with one that is not: both stories mention Discord."""
    store = MemoryStore()
    pipeline.ingest([_raw("thehackernews", "Ransomware Crews Deliver Payloads Through Fake Zoom Installers",
                          "Ransomware operators breached hospitals using installers shared on Discord.", when="2026-10-20T08:00:00Z"),
                     _raw("thehackernews", "Ransomware Gangs Deliver Encryptors to Brazilian Banks, Customer Data Stolen",
                          "A ransomware attack breached Brazilian banks; stolen customer data was sold on Discord.", when="2026-10-20T09:00:00Z")], store, FETCHED)
    assert all("tok:discord" not in it["keys"] for it in store.items.values())
    assert len([e for e in store.events.values() if e["domain"] != "web3"]) == 2


# --- what may prove two events are one story (live 2026-11-12: the Binance theft merged into a vulnerability event) ---

_BINANCE_NEWS = "https://example.com/" + keys.short_hash("panews", "Binance hack: attacker moves $40M stolen from hot wallets")


def _theft_and_flaw(store):
    """A theft event and a vulnerability event, each holding the url: key of one article."""
    pipeline.ingest([
        _raw("defillama_hacks", "Binance CEX — Key Leaked via Infrastructure", "Binance CEX hack",
             url="https://defillama.example/binance", extra={"entity": "Binance CEX", "amount_usd": 6.36e9},
             when="2026-10-29T21:00:00Z"),
        _raw("thehackernews", "Linux Kernel TCP Flaw CVE-2026-98432 exploited in the wild", "actively exploited",
             url="https://thn.example/linux-tcp", when="2026-10-29T15:57:00Z"),
    ], store, FETCHED)
    pipeline.ingest([_web3("panews", "Binance hack: attacker moves $40M stolen from hot wallets", "2026-10-29T22:00:00Z", FETCHED)],
                    store, FETCHED)                       # a news report: its url is a key of the theft event
    theft = next(e for e, v in store.events.items() if v["domain"] == "web3")
    flaw = next(e for e, v in store.events.items() if v["domain"] == "vuln")
    return theft, flaw


def _two_incidents(store):
    urls = ["https://bc.example/acme", "https://sw.example/globex"]
    pipeline.ingest([_raw("bleepingcomputer", "Ransomware attack shuts down Acme Hospital network",
                          "Ransomware attack breached Acme Hospital, systems offline.", url=urls[0], when="2026-11-10T08:00:00Z"),
                     _raw("securityweek", "Data breach at Globex exposes 2 million customer records",
                          "Hackers breached Globex and stole customer data.", url=urls[1], when="2026-11-10T09:00:00Z")], store, FETCHED)
    assert len(store.events) == 2
    return urls


def test_a_newsletter_linking_two_stories_does_not_merge_them():
    """「Srsly Risky Biz: Iranian Hacks With Russian Characteristics」: context-only, 34 links, two of them into events.
    The same two links in a report of an event do merge (the control: this test can fail)."""
    store = MemoryStore()
    urls = _two_incidents(store)
    pipeline.ingest([_raw("risky", "Srsly Risky Biz: Iranian Hacks With Russian Characteristics", "A weekly look at policy.",
                          url="https://risky.example/srsly", links=urls + [f"https://ref.example/{n}" for n in range(3)],
                          when="2026-11-12T03:40:00Z")], store, FETCHED)
    assert len(store.events) == 2, "a context-only newsletter merged two stories"
    pipeline.ingest([_raw("securityweek", "In Other News: hospital ransomware, retail breach, port outage, school leak, airline hack",
                          "Attackers breached several organisations this week; ransomware attack confirmed.",
                          url="https://sw.example/other-news", links=urls + [f"https://ref.example/{n}" for n in range(10)],
                          when="2026-11-12T04:00:00Z")], store, FETCHED)
    assert len(store.events) == 2, "a report citing 12 pages merged two stories"
    pipeline.ingest([_raw("therecord", "Acme Hospital and Globex were breached by the same ransomware crew, FBI says",
                          "The FBI says one ransomware gang breached both.", url="https://record.example/same", links=urls,
                          when="2026-11-12T05:00:00Z")], store, FETCHED)
    assert len(store.events) == 1                                   # a report of the event, two links: it may


def test_a_theft_and_a_vulnerability_never_merge_through_one_report():
    """Even an eventful report with two links: a theft and a flaw are different kinds of story."""
    store = MemoryStore()
    theft, flaw = _theft_and_flaw(store)
    pipeline.ingest([_raw("thehackernews", "Linux kernel TCP flaw CVE-2026-98432: exploit published, attacks under way", "actively exploited in the wild",
                          url="https://thn.example/both", links=[_BINANCE_NEWS, "https://thn.example/linux-tcp"],
                          when="2026-10-30T10:00:00Z")], store, FETCHED)
    assert {theft, flaw} <= set(store.events)


def test_an_advisory_does_not_follow_a_cited_page_into_another_flaws_event():
    """Live 2026-11-12: SonicWall (CVE-2026-19868), OpenSSH and MS Paint reports attached through cited pages to the
    Linux TCP event (CVE-2026-98432) — six unrelated CVEs in one event."""
    store = MemoryStore()
    _theft, flaw = _theft_and_flaw(store)
    pipeline.ingest([_raw("bleepingcomputer", "SonicWall SSL-VPN flaw CVE-2026-19868 exploited to bypass MFA", "actively exploited",
                          url="https://bc.example/sonicwall", links=["https://thn.example/linux-tcp"],
                          when="2026-10-30T10:00:00Z")], store, FETCHED)
    sonic = next(i for i, it in store.items.items() if it["url"] == "https://bc.example/sonicwall")
    assert sonic not in store.events[flaw]["item_ids"] and store.events[flaw]["cves"] == ["CVE-2026-98432"]


def test_two_flaws_with_no_cve_in_common_do_not_merge_through_a_report_naming_neither():
    store = MemoryStore()
    _theft, flaw = _theft_and_flaw(store)
    pipeline.ingest([_raw("bleepingcomputer", "SonicWall SSL-VPN flaw CVE-2026-19868 exploited to bypass MFA", "actively exploited",
                          url="https://bc.example/sonicwall", when="2026-10-30T10:00:00Z")], store, FETCHED)
    n = len(store.events)
    pipeline.ingest([_raw("securityweek", "Attackers exploit unpatched edge devices and servers this week", "exploited in the wild",
                          url="https://sw.example/week", links=["https://bc.example/sonicwall", "https://thn.example/linux-tcp"],
                          when="2026-10-31T10:00:00Z")], store, FETCHED)
    assert len(store.events) == n and flaw in store.events


# --- a name is evidence for the event it names (measured on the corpus, 2026-11-13: precision 0.51 → 0.91) ------------

def test_a_report_about_someone_else_does_not_join_an_event_that_only_mentioned_the_name():
    """Corpus: 「UXLINK黑客开始平多价值1.48亿美元的多仓」 and 19 more sat in the Binance event — Binance coverage had
    mentioned UXLINK and Hyperliquid, and no UXLINK event existed to win the report."""
    store = MemoryStore()
    _binance_open_event(store)
    t = datetime(2026, 11, 2, 10, tzinfo=UTC)
    pipeline.ingest([_web3("cointelegraph", "Binance hack: $40M of stolen funds move through Hyperliquid, where the UXLINK hacker also trades",
                           "2026-11-02T09:00:00Z", t)], store, t)
    (binance,) = store.events
    assert {"tok:uxlink", "tok:hyperliquid"} <= set(store.events[binance]["keys"])     # the precondition: mentions lent
    pipeline.ingest([_raw("panews", "UXLINK黑客开始平多价值1.48亿美元的多仓，预计亏损330万美元",
                          "UXLINK 被盗事件的黑客开始平掉其在 Hyperliquid 上价值 1.48 亿美元的多仓，包括 30,282 枚 ETH，预计亏损 330 万美元。",
                          url="https://panews.example/ux",
                          when="2026-11-02T11:00:00Z")], store, t)
    report = next(i for i, it in store.items.items() if it["url"] == "https://panews.example/ux")
    assert report not in store.events[binance]["item_ids"], "a report about UXLINK's hacker joined the Binance event"
    pipeline.ingest([_web3("theblock", "Binance hack: $250K of stolen funds deposited to Gate, 2 accounts frozen", "2026-11-02T12:00:00Z", t)], store, t)
    assert len(store.events[binance]["item_ids"]) == 4                              # its own name still finds it


def test_an_advisory_numbers_prefix_is_not_a_name():
    """Corpus: 18 Amazon Linux advisories for 18 packages were one event through tok:alas2023 — the advisory-id prefix,
    read as a named vulnerability."""
    assert keys.named_tokens("ALAS2023-2026-3389 (important): kernel") == set()
    assert keys.named_tokens("ALAS2023LIVEPATCH-2026-424 and AV26-1135") == set()
    assert keys.named_tokens("PHP2Shell: two unpatched flaws; Node2Shell-style exploit") == {"php2shell", "node2shell"}
    store = MemoryStore()
    for n, pkg in enumerate(["kernel", "docker", "libreswan", "cups", "rclone"]):
        pipeline.ingest([_raw("alas2023", f"ALAS2023-2026-33{n:02d} (important): {pkg}", f"Update {pkg}: a flaw is actively exploited in the wild",
                              url=f"https://alas.example/ALAS2023-2026-33{n:02d}.html", when=f"2026-11-09T23:{n:02d}:00Z")],
                        store, FETCHED)
    assert len(store.events) == 5


def test_a_word_held_by_several_events_names_none_of_them():
    """A key three web3 events hold is not a name (hyperliquid, tornado, coinjoin): the corpus had UXLINK's, Drift's
    and BlueMove's hackers in one event because each report said Hyperliquid."""
    store = MemoryStore()
    for day, who, usd in (("10-01", "Zeta", 5), ("10-10", "Orbit", 12), ("10-20", "Nimbus", 31)):   # far apart, other sums
        t = datetime(2026, 10, int(day[3:]), 9, tzinfo=UTC)
        pipeline.ingest([_web3("panews", f"{who} hacker moves ${usd}M of stolen funds to Hyperliquid and opens ETH longs",
                               f"2026-{day}T08:00:00Z", t)], store, t)
    assert len(store.events) == 3 and all("tok:hyperliquid" in v["keys"] for v in store.events.values())
    t = datetime(2026, 10, 21, 9, tzinfo=UTC)
    pipeline.ingest([_web3("odaily", "Vega hacker moves $77M of stolen funds to Hyperliquid and opens ETH longs", "2026-10-21T08:00:00Z", t)], store, t)
    assert len(store.events) == 4, "a word three events hold glued a fourth story to one of them"


# ---------------------------------------------------------------- live 2026-11-13: who investigates is not who was robbed

FBI_STORIES = [
    ("odaily", "前FBI特工承认盗取约247万美元加密货币，面临最高20年监禁", "2026-11-07T15:52:00Z"),
    ("gn_crypto_hack", "FBI: North Korean hackers have stolen $400 million in crypto over last 18 months", "2026-11-12T22:52:00Z"),
]


def test_an_agency_or_an_attribution_in_the_headline_does_not_make_two_thefts_one():
    """Live: a P0 web3 event of 21 reports — a Singapore police operation, a former FBI agent's theft, the Binance
    suspect, a cooling-system attack write-up and the FBI's $400M North Korea statement — glued through tok:fbi /
    tok:north / tok:korean. The event had no named victim, so the name rules (which need one) did not apply. The FBI
    investigates every theft: its name is not an incident's. (Attribution words — "North Korean hackers" — were
    measured too: stopping them cost recall on the labelled corpus, 0.9454 → 0.9413, for no precision; left as is.)"""
    store = MemoryStore()
    for src, title, when in FBI_STORIES:
        t = datetime.fromisoformat(when) + timedelta(minutes=5)
        pipeline.ingest([_web3(src, title, when, t)], store, t)
    evs = _web3_events(store)
    assert len(evs) == 2, [e["title"][:40] for e in evs]
    # a third and a fourth event holding the word make it "generic" (GENERIC_NAME_EVENTS) — the figure still counts
    for n, title in enumerate(("Zeta bridge hacked for $31.7 million, FBI says", "Orbit bridge hacked for $58.3 million, FBI says")):
        t = datetime(2026, 11, 13, 10 + n, tzinfo=UTC)
        pipeline.ingest([_web3("gn_crypto_hack", title, f"2026-11-13T{9 + n}:50:00Z", t)], store, t)
    assert len(_web3_events(store)) == 4
    # the same story told again still meets itself: the agency's name together with the story's own figure ($400M is
    # round, so it has no amt: key — without the name the retelling would open another event)
    t = datetime(2026, 11, 13, 22, tzinfo=UTC)
    pipeline.ingest([_web3("gn_exchange_zh", "FBI称朝鲜黑客窃取4亿美元加密货币——The Hill", "2026-11-13T21:40:00Z", t)], store, t)
    evs = _web3_events(store)
    assert len(evs) == 4 and sorted(len(e["item_ids"]) for e in evs) == [1, 1, 1, 2]
    told = next(e for e in evs if len(e["item_ids"]) == 2)
    assert told["amount_usd_latest"] == 400_000_000


def test_a_digest_does_not_make_the_event_it_touches_exploited():
    """Live 2026-11-14: the Apache HTTP/2 event (37 reports, nobody claiming exploitation of it) was P0 「confirmed」
    through a weekly bulletin that names its CVE in one paragraph and an exploited Outlook bug in another."""
    store = MemoryStore()
    t = datetime(2026, 11, 12, 1, tzinfo=UTC)
    cve = "CVE-2026-119618"
    pipeline.ingest([_raw("wiz", f"Critical RCE Vulnerability in Apache HTTP Server ({cve})", f"{cve} is a race condition in mod_http2.",
                          when="2026-11-11T20:00:00Z")], store, t)
    pipeline.ingest([_raw("talos", "Never be afraid to ask questions", f"Apache fixed {cve}. Microsoft warned that a spoofing flaw in "
                          "Outlook (CVE-2026-124194) is already being actively exploited in the wild.", when="2026-11-12T00:00:00Z")], store, t)
    ev = next(e for e in store.events.values() if cve in e["cves"] and "Apache" in e["title"])
    assert ev["exploitation"] == "none" and ev["severity"] != "P0", (ev["exploitation"], ev["severity"])


# ---------------------------------------------------------------- R8.3: a digest is a report of no single event

DIGESTS = ["Risky Bulletin: Chinese APT uses SS7, Diameter attacks", "9th November – Threat Intelligence Report",
           "November Patch Tuesday boasts over 1,000 bugs, one already under attack", "美股盘前要闻一览：美国通胀数据高于预期",
           "Microsoft Patch Tuesday, November 2026 Security Update Review", "This Week in Security: Apache, Outlook and more",
           "安全周报（11.03-11.09）", "Weekly Recap: zero-days and a bridge hack"]
NOT_DIGESTS = ["Android Security Bulletin — November 2026", "NVIDIA Security Bulletin: GPU Display Driver",
               "Critical RCE Vulnerability in Apache HTTP Server", "Binance hot wallet drained for $6.3B",
               "CVE-2026-119618 - Apache HTTP Server: mod_http2", "Digest authentication bypass in nginx (CVE-2026-1)",
               # found on the corpus: the word is the story's subject, not what the piece is
               "SEGA newsletter data breach exposes 2.2 million email addresses", "Ether Nears $2,000 as Weekly Loss Outpaces Bitcoin's",
               "华尔街日报：部分服务商在 FBI 呼吁后仍处理币安被盗交易"]


def test_digests_are_recognised_by_headline_or_by_how_they_open_and_advisories_are_not():
    from radar import signals
    assert [t for t in DIGESTS if not signals.is_digest(t)] == []
    assert [t for t in NOT_DIGESTS if signals.is_digest(t)] == []
    assert signals.is_digest("Never be afraid to ask questions", "Welcome to this week's edition of the Threat Source newsletter. …")
    assert not signals.is_digest("Never be afraid to ask questions", "A long essay. " * 60 + "this week's edition")   # the opening only


def test_a_digest_never_joins_a_storys_event_and_claims_nothing_for_itself():
    """Live 2026-11-14: Talos' newsletter (two CVEs, "actively exploited") was a P0 event of its own; a Risky Bulletin
    in the Apache event gave it a $26M email scam and an exploitation status."""
    store = MemoryStore()
    t = datetime(2026, 11, 12, 1, tzinfo=UTC)
    cve = "CVE-2026-119618"
    pipeline.ingest([_raw("wiz", f"Critical RCE Vulnerability in Apache HTTP Server ({cve})", f"{cve} is a race condition in mod_http2.",
                          when="2026-11-11T20:00:00Z")], store, t)
    [before] = [dict(e) for e in store.events.values()]
    pipeline.ingest([
        _raw("talos", "Never be afraid to ask questions", "Welcome to this week's edition of the Threat Source newsletter. "
             f"Apache fixed {cve}. A flaw in Outlook (CVE-2026-124194) is being actively exploited in the wild.", when="2026-11-12T00:00:00Z"),
        _raw("risky", "Risky Bulletin: Chinese APT uses SS7", f"Apache patched {cve}. US village loses $26m in email scam. "
             "One bug is under active attack.", when="2026-11-12T00:10:00Z")], store, t)
    assert store.events[before["event_id"]] == before                          # the story's event is untouched
    rest = [e for e in store.events.values() if e["event_id"] != before["event_id"]]
    assert len(rest) == 2                                                      # two outlets' digests: each its own
    for e in rest:
        assert e["cves"] == [] and e["exploitation"] == "none" and e["severity"] == "P2" and e["amount_usd_latest"] is None
        assert all(k.startswith(("dg:", "url:")) for k in e["keys"]), e["keys"]


def test_the_same_digest_from_several_outlets_is_one_event_and_an_outlets_weekly_stays_its_own():
    store = MemoryStore()
    t = datetime(2026, 11, 12, 1, tzinfo=UTC)
    pipeline.ingest([
        _raw("bleepingcomputer", "Microsoft November 2026 Patch Tuesday fixes 1,235 flaws, Outlook zero-day", "CVE-2026-124194 is exploited.",
             when="2026-11-11T18:00:00Z"),
        _raw("rapid7", "Patch Tuesday - November 2026", "CVE-2026-124194 and 1,234 more.", when="2026-11-11T19:00:00Z"),
        _raw("thehackernews", "⚡ Weekly Recap: Critical CVEs, Linux DDoS Botnet", "CVE-2026-124194 and more.", when="2026-11-11T20:00:00Z"),
        _raw("secaffairs", "Weekly Recap: what happened in security", "CVE-2026-124194 again.", when="2026-11-11T21:00:00Z")], store, t)
    sizes = sorted(len(e["item_ids"]) for e in store.events.values())
    assert sizes == [1, 1, 2], sizes                                           # Patch Tuesday ×2 together; two weeklies apart
    pt = next(e for e in store.events.values() if len(e["item_ids"]) == 2)
    assert "dg:patch-tuesday:2026-11" in pt["keys"]


def test_a_digest_already_in_an_event_stays_listed_but_is_evidence_for_nothing():
    """Stored events were built before digests were recognised: recompute keeps the member, drops its say."""
    store = MemoryStore()
    t = datetime(2026, 11, 12, 1, tzinfo=UTC)
    cve = "CVE-2026-119618"
    plain = _raw("thehackernews", f"Critical Apache HTTP/2 Flaw ({cve}) Could Let Attackers Run Code", f"{cve} affects mod_http2.",
                 when="2026-11-11T20:00:00Z")
    pipeline.ingest([plain], store, t)
    [ev] = [Event_from(e) for e in store.events.values()]
    digest = pipeline.normalize(_raw("risky", "Risky Bulletin: Chinese APT uses SS7", f"Apache patched {cve}. A flaw in Outlook is being "
                                     "actively exploited in the wild. US village loses $26 million in email scam.", when="2026-11-12T00:10:00Z"),
                                __import__("radar.registry", fromlist=["BY_ID"]).BY_ID["risky"], t)
    digest.extra.pop("digest", None)                                           # as an item stored before the flag existed
    store.put_item(digest)
    members = store.get_items([*ev.item_ids, digest.item_id])
    got = pipeline.recompute(ev, members, t)
    assert digest.item_id in got.item_ids                                      # still listed on the page
    assert got.exploitation == "none" and got.amount_usd_latest is None and "Risky" not in got.title


def Event_from(d):
    from radar.model import Event
    return Event.from_dict(d)


@pytest.mark.parametrize(("title", "eventful"), [
    ("North Korean hackers stole $1.5 billion from Bybit, FBI confirms", True),       # live 2026-11-14: was not an incident
    ("Hacker steals $58.3 million from Orbit bridge", True),
    ("Bitcoin ETF theft fears overblown, analysts say", False),                         # the word without money lost
])
def test_stole_steals_theft_and_heist_are_incident_words(title, eventful):
    from radar import registry
    it = pipeline.normalize(_raw("gn_crypto_hack", title, title, when="2026-11-13T02:00:00Z"), registry.BY_ID["gn_crypto_hack"],
                            datetime(2026, 11, 13, 3, tzinfo=UTC))
    assert it.eventful is eventful


def test_a_report_naming_cves_years_apart_does_not_make_their_events_one():
    """Live 2026-11-12: six exploit-catalog entries, each naming CVE-2013-2729 beside a later Acrobat CVE, merged seven
    KEV events (2013–2023) into one. Measured on the corpus with that event added: precision 0.9220 → 0.9221, recall
    unchanged; "catalog entries never merge" had cost recall instead."""
    store = MemoryStore()
    t = datetime(2026, 11, 12, 18, tzinfo=UTC)
    old, new = "CVE-2013-2729", "CVE-2021-21017"
    for cve in (old, new):
        pipeline.ingest([_raw("cisa_kev", f"{cve} Adobe Acrobat and Reader: Adobe Acrobat and Reader Vulnerability", f"{cve} is exploited.",
                              extra={"kev": True, "cves": [cve]}, when="2026-10-23T00:00:00Z")], store, t)
    pipeline.ingest([_raw("sploitus", "Exploit for Heap-based Buffer Overflow in Adobe Acrobat", f"Works against {old} and {new}.",
                          when="2026-11-12T15:37:00Z")], store, t)
    assert sorted(len(e["item_ids"]) for e in store.events.values()) == [1, 2]            # attached to one, merged none
    # … and it lent the event it joined no CVE from another era: the next entry naming both would otherwise find the
    # two events sharing an id and merge them after all (the dry run of the live repair: 7 stories came back as 3)
    held = next(e for e in store.events.values() if len(e["item_ids"]) == 2)
    assert len(held["cves"]) == 1 and not [k for k in held["keys"] if k.startswith("cve:") and k[4:] not in held["cves"]]
    pipeline.ingest([_raw("sploitus", "Exploit for Use After Free in Adobe Acrobat_Dc", f"Works against {old} and {new} too.",
                          when="2026-11-12T15:38:00Z")], store, t)
    assert len(store.events) == 2
    # negative control: two CVEs of one release, named together, are still one story
    a, b = "CVE-2026-109618", "CVE-2026-109619"
    for cve in (a, b):
        pipeline.ingest([_raw("cisa_kev", f"{cve} PHP Group PHP: PHP Memory Corruption Vulnerability", f"{cve} is exploited.",
                              extra={"kev": True, "cves": [cve]}, when="2026-10-23T00:00:00Z")], store, t)
    pipeline.ingest([_raw("bleepingcomputer", f"PHP patches {a} and {b}, both exploited", f"{a} and {b} are one chain.",
                          when="2026-11-12T16:00:00Z")], store, t)
    php = [e for e in store.events.values() if a in e["cves"]]
    assert len(php) == 1 and b in php[0]["cves"]
