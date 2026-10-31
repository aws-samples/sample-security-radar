"""Replay criteria: real 2026-10-23 snapshots through the whole deterministic pipeline.

Expected levels follow DESIGN §6 and are derived from facts in docs/research/03 + 05 — e.g. WAX is
SlowMist (Hacked DB + its own tweet = ONE origin) + DeFiLlama ⇒ 2 independent sources, not 3."""

import json
from datetime import UTC, datetime
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
    assert srcs == ["defillama_hacks", "slowmist_hacked", "x_security"]
    assert ev["independent_sources"] == 2
    assert ev["level"] == "V2" and ev["severity"] == "P2"  # $90.5K is below the P1 line


def test_bitget_2026_is_p0_and_separate_from_2025_bitget(replayed):
    store, _ = replayed
    evs = events_with_entity(store, "Bitget")
    big = [e for e in evs if e["first_seen"].startswith("2026-09-24")]
    assert len(big) == 1
    ev = big[0]
    assert {store.items[i]["source_id"] for i in ev["item_ids"]} == {"defillama_hacks", "slowmist_hacked"}
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


def test_cve_roundup_does_not_glue_unrelated_cves():
    roundup = "Patch Tuesday fixes CVE-2026-1001, CVE-2026-1002, CVE-2026-1003, CVE-2026-1004 and CVE-2026-1005"
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
    assert st["issues"] == [{"issue_id": "i1"}] and st["delivered_prs"] == {"i1": "https://x/pull/1"}


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
