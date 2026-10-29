"""Replay criteria: real 2026-10-23 snapshots through the whole deterministic pipeline.

Expected levels follow DESIGN §6 and are derived from facts in docs/research/03 + 05 — e.g. WAX is
SlowMist (Hacked DB + its own tweet = ONE origin) + DeFiLlama ⇒ 2 independent sources, not 3."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from radar import keys, parsers, pipeline
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
