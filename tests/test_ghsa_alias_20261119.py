"""R12: GHSA ↔ CVE, replaying Ruby2Shell (live 11-19): the reports named the repository advisory GHSA-34m4-m9fh-gqp5
(global lookup 404, repository record with no CVE); the CVE came as another, unreviewed advisory GHSA-8452-w857-wpmw whose
references hold the repository advisory's URL."""
import datetime as dt

import pytest

from radar import ghsa_alias, pipeline
from radar.model import Event, Item, RawItem
from radar.store import MemoryStore

G, CVE = "GHSA-34m4-m9fh-gqp5", "CVE-2026-132825"
REPO_URL = f"https://github.com/ruby/ruby/security/advisories/{G}"


def ruby_api(url):
    if url.endswith(f"/advisories/{G}"):
        return 404, None
    if url.endswith(f"/repos/ruby/ruby/security-advisories/{G}"):
        return 200, {"ghsa_id": G, "cve_id": None, "severity": "critical", "identifiers": [{"type": "GHSA", "value": G}]}
    if "/advisories?type=unreviewed" in url:
        return 200, [{"ghsa_id": "GHSA-8452-w857-wpmw", "cve_id": CVE, "references": [REPO_URL, "https://nvd.nist.gov/x"]},
                     {"ghsa_id": "GHSA-xxxx", "cve_id": "CVE-2026-1111", "references": ["https://other"]}]
    return 500, None


def test_the_repository_advisory_is_read_when_the_global_one_is_missing_and_says_no_cve():
    r = ghsa_alias.resolve(G, ghsa_alias.repo_advisories([f"see {REPO_URL}"]), ruby_api)
    assert (r["cve"], r["via"], r["repo"]) == (None, "repo", "ruby/ruby")
    assert ghsa_alias.resolve(G, {}, ruby_api) == {"cve": None, "via": "not_found", "status": 404}


def test_the_unreviewed_record_whose_references_name_the_ghsa_gives_the_cve():
    assert ghsa_alias.scan_unreviewed({G}, "2026-11-17T00:00:00Z", ruby_api) == {G: CVE}
    assert ghsa_alias.scan_unreviewed(set(), "2026-11-17T00:00:00Z", ruby_api) == {}


def test_a_global_advisory_with_a_cve_resolves_directly():
    get = lambda url: (200, {"cve_id": None, "identifiers": [{"type": "GHSA", "value": G}, {"type": "CVE", "value": CVE}]})
    assert ghsa_alias.resolve(G, {}, get)["cve"] == CVE


def test_a_linked_ghsa_gives_a_new_report_its_cve_key():
    raw = RawItem(source_id="aikido", url="https://x/r", title=f"Ruby2Shell: critical Ruby RCE ({G})", text="",
                  published_at=dt.datetime(2026, 11, 19, tzinfo=dt.UTC), guid="g")
    it = pipeline.normalize(raw, pipeline.BY_ID["aikido"], dt.datetime(2026, 11, 19, tzinfo=dt.UTC), {G: CVE})
    assert f"cve:{CVE}" in it.keys and f"ghsa:{G}" in it.keys
    bare = pipeline.normalize(raw, pipeline.BY_ID["aikido"], dt.datetime(2026, 11, 19, tzinfo=dt.UTC))
    assert f"cve:{CVE}" not in bare.keys


@pytest.fixture
def station(monkeypatch):
    for k, v in {"AWS_DEFAULT_REGION": "ap-northeast-1", "AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "x"}.items():
        monkeypatch.setenv(k, v)
    from radar import handlers as h
    store = MemoryStore()
    monkeypatch.setattr(h, "_store", store)
    return h, store


def _item(iid, src, title, at, keys):
    return Item(item_id=iid, source_id=src, tier="T2", org=src, domain="vuln", url=f"https://x/{iid}", canonical_url=f"https://x/{iid}",
                title=title, text=f"see {REPO_URL}" if "Ruby2Shell" in title else "", published_at=at, fetched_at=at,
                content_hash=iid, keys=keys, links=[], entity=None, eventful=True,
                signals={"exploited": "unclear", "kev": False, "poc": False, "amount_usd": None}, extra={})


def test_the_station_links_the_ghsa_event_to_the_cve_event_and_they_become_one(station):
    h, store = station
    now = dt.datetime(2026, 11, 19, 12, tzinfo=dt.UTC)
    a = _item("it_cve", "cvefeed", f"{CVE} - Ruby Heap-Based Buffer Overflow", "2026-11-19T07:17:11Z", [f"cve:{CVE}"])
    b = _item("it_gh", "aikido", f"Ruby2Shell: critical Ruby RCE ({G})", "2026-11-19T09:42:00Z", [f"ghsa:{G}"])
    for it in (a, b):
        store.put_item(it)
    store.put_event(Event(event_id="ev_cve", domain="vuln", title=a.title, first_seen=a.published_at, last_updated=a.published_at,
                          item_ids=["it_cve"], keys=list(a.keys), severity="P1", cves=[CVE]))
    store.put_event(Event(event_id="ev_gh", domain="vuln", title=b.title, first_seen=b.published_at, last_updated=b.published_at,
                          item_ids=["it_gh"], keys=list(b.keys), severity="P0"))
    for e in ("ev_cve", "ev_gh"):
        store.add_keys(e, store.get_event(e).keys)
    touched = h._ghsa_alias(now, get=ruby_api)
    assert touched == ["ev_gh"]
    holders = {store.get_event(e) is not None and e for e in ("ev_cve", "ev_gh")} - {False}
    merged = [store.get_event(e) for e in holders]
    assert len(merged) == 1 and set(merged[0].item_ids) == {"it_cve", "it_gh"} and CVE in merged[0].cves
    st = store.get_source_state(ghsa_alias.KEY)
    assert st["map"][G]["cve"] == CVE and st["map"][G]["via"] == "unreviewed_reference"


def test_without_a_token_the_state_says_not_configured(station, monkeypatch):
    h, store = station
    store.put_item(_item("it_gh", "aikido", f"Ruby2Shell ({G})", "2026-11-19T09:42:00Z", [f"ghsa:{G}"]))
    store.put_event(Event(event_id="ev_gh", domain="vuln", title="t", first_seen="2026-11-19T09:42:00Z",
                          last_updated="2026-11-19T09:42:00Z", item_ids=["it_gh"], keys=[f"ghsa:{G}"], severity="P0"))
    monkeypatch.delenv("GHSA_TOKEN_SECRET_ARN", raising=False)
    assert h._ghsa_alias(dt.datetime(2026, 11, 19, 12, tzinfo=dt.UTC)) == []
    assert store.get_source_state(ghsa_alias.KEY)["status"] == "not_configured"


def test_ops_warns_when_the_lookup_cannot_run_and_before_the_token_expires():
    from radar import ops
    (w,) = ops._ghsa_alias({"ghsa_alias": {"status": "not_configured", "pending": 2, "at": "2026-11-19T00:00:00Z"}})
    assert w["level"] == "warn" and "set-ghsa-token.sh" in w["detail"]
    assert ops._ghsa_alias({"ghsa_alias": {"status": "not_configured", "pending": 0, "at": "2026-11-19T00:00:00Z"}}) == []
    soon = {"status": "ok", "pending": 0, "at": "2026-11-19T00:00:00Z", "token_expires": "2026-12-01 13:57:12 UTC"}
    (exp,) = ops._ghsa_alias({"ghsa_alias": soon})
    assert "2026-12-01" in exp["title"]
    assert ops._ghsa_alias({"ghsa_alias": {**soon, "token_expires": "2027-02-17 13:57:12 UTC"}}) == []


# --- security review 2026-11-20: one line of third-party text must not stop the Analyze step ---

def test_a_non_ascii_or_dotted_owner_is_not_a_repository():
    texts = ["see https://github.com/Ünïcode/x/security/advisories/GHSA-34m4-m9fh-gqp5",
             "and https://github.com/../x/security/advisories/GHSA-8452-w857-wpmw",
             "and https://github.com/acme/../security/advisories/GHSA-8452-w857-wpmw"]
    assert ghsa_alias.repo_advisories(texts) == {}


def test_a_network_or_json_failure_is_a_failed_lookup_not_an_exception(monkeypatch):
    import urllib.error

    from radar import fetch

    def boom(*_a, **_k):
        raise urllib.error.URLError("timed out")

    monkeypatch.setattr(fetch, "urlopen", boom)
    get = ghsa_alias.github_get("t")
    assert get("https://api.github.com/advisories/GHSA-34m4-m9fh-gqp5") == (0, None)
    assert get.seen["last_error"] == "URLError"


def test_the_analyze_step_survives_a_failing_lookup(station, monkeypatch):
    h, store = station

    def broken(*_a, **_k):
        raise UnicodeEncodeError("ascii", "Ü", 0, 1, "ordinal not in range")

    monkeypatch.setattr(h, "_ghsa_alias", broken)
    monkeypatch.setattr(h, "_daily_digest", lambda *_: None)
    monkeypatch.setattr(h, "_cluster_judge", lambda *_: [])
    monkeypatch.setattr(h, "_retitle_shadow", lambda *_: None)
    out = h.analyze_events({"changed": []})
    assert out["changed"] == []
    assert store.get_source_state(ghsa_alias.KEY)["last_error"]["error"] == "UnicodeEncodeError"
