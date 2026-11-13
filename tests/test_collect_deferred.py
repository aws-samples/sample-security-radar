"""R2.1 — work a collector puts off is done on the next run, not when the upstream list happens to change.

Audit 01 #1, #2, #4 (reproduced there):
- a run that deferred entries stored the list's ETag, so the next run got 304 and parsed nothing — a CSAF feed version
  with 25 new advisories handed over 10; the other 15 waited until the feed changed again;
- a CVE whose record could not be read (or was over the per-run cap) was dropped from SEEN, but the next delta.json was
  either unchanged (304) or a new window without it: the CVE was lost, not retried;
- "is this a block?" read the error string, which contains the source URL: every HTTP error of a source whose URL
  contains "block" (theblock, wublock, blockbeats …) was retried through the paid fallback."""
from datetime import UTC, datetime, timedelta

from radar import collect, fetch, parsers
from radar.limits import Limits
from radar.model import RawItem
from radar.registry import BY_ID

NOW = datetime(2026, 11, 12, 12, 0, tzinfo=UTC)


def test_a_dead_url_that_contains_the_word_block_is_not_sent_to_the_paid_fallback():
    src = BY_ID["theblock"]
    assert "block" in src.url
    gone = fetch.FetchError("http_error", "HTTP Error 404: Not Found", 404, src.url)
    limited = fetch.FetchError("http_error", "HTTP Error 429: Too Many Requests", 429, src.url)
    blocked = fetch.FetchError("http_error", "HTTP Error 400: Blocked", 400, src.url)
    assert not collect._fallback_ok(src, gone, {}, NOW) and not collect._fallback_ok(src, limited, {}, NOW)
    assert collect._fallback_ok(src, blocked, {}, NOW)                 # the server said so: that is a block
    assert gone.reason == "HTTP Error 404: Not Found" and src.url[:40] in str(gone)   # the text keeps the URL; reason does not


def _rolie(n):
    return [RawItem(source_id="cisa_csaf_ot", url=f"https://cisa.example/a{k}", title=f"ICSA-26-300-{k:02d}", text="",
                    published_at=NOW - timedelta(hours=k), guid=f"ICSA-26-300-{k:02d}",
                    extra={"csaf_url": f"https://www.cisa.gov/a{k}.json", "advisory_id": f"ICSA-26-300-{k:02d}"}) for k in range(n)]


def _run(monkeypatch, raws, state=None):
    """One collect() of the CSAF source with the list fetch replaced: status 200, an ETag, these entries."""
    src = BY_ID["cisa_csaf_ot"]
    monkeypatch.setattr(collect, "_fetch_parse", lambda s, st, now: (fetch.Response(200, "", etag='"v2"', last_modified="Thu"), list(raws)))
    monkeypatch.setattr(fetch, "http_get", lambda url, **k: fetch.Response(200, "{}"))
    monkeypatch.setattr(parsers, "csaf_doc", lambda body: {"text": "t", "cves": ["CVE-2026-1"], "cvss": 9.8, "vendors": ["V"]})
    return collect.collect(src, state or {"etag": '"v1"', "last_modified": "Wed", "last_success": "2026-11-12T11:00:00Z"}, NOW)


def test_a_run_that_put_entries_off_keeps_no_etag_so_the_next_run_reads_the_list_again(monkeypatch):
    out, st = _run(monkeypatch, _rolie(collect.MAX_CSAF_FETCHES + 5))
    assert len(out) == collect.MAX_CSAF_FETCHES and st["deferred"] == 5
    assert "etag" not in st and "last_modified" not in st, "an ETag kept after deferring makes the next run a 304: nothing parsed"
    out, st = _run(monkeypatch, _rolie(3))                             # negative control: nothing put off
    assert len(out) == 3 and st["etag"] == '"v2"' and "deferred" not in st


def test_a_csaf_document_that_could_not_be_read_counts_as_put_off(monkeypatch):
    src = BY_ID["cisa_csaf_ot"]
    monkeypatch.setattr(collect, "_fetch_parse", lambda s, st, now: (fetch.Response(200, "", etag='"v2"'), _rolie(2)))

    def get(url, **k):
        if url.endswith("a1.json"):
            raise fetch.FetchError("http_error", "HTTP Error 503", 503, url)
        return fetch.Response(200, "{}")
    monkeypatch.setattr(fetch, "http_get", get)
    monkeypatch.setattr(parsers, "csaf_doc", lambda body: {"text": "t", "cves": [], "cvss": None, "vendors": []})
    out, st = collect.collect(src, {"last_success": "x"}, NOW)
    assert len(out) == 1 and st["deferred"] == 1 and "etag" not in st


def _cve(n, hours=0):
    return RawItem(source_id="cve_list", url=f"https://www.cve.org/CVERecord?id=CVE-2026-{n}", title=f"CVE-2026-{n}",
                   text="", published_at=NOW - timedelta(hours=hours), guid=f"CVE-2026-{n}",
                   extra={"cves": [f"CVE-2026-{n}"], "record_url": f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/{n}.json",
                          "fetch_time": "2026-11-12T12:00:00Z"})


def _records(monkeypatch, bad=()):
    def get(url, **k):
        if any(url.endswith(f"/{n}.json") for n in bad):
            raise fetch.FetchError("http_error", "HTTP Error 503", 503, url)
        return fetch.Response(200, url)
    monkeypatch.setattr(fetch, "http_get", get)
    monkeypatch.setattr(parsers, "cve_record", lambda body: {"title": "t", "text": "x", "cvss": 9.8, "severity": "CRITICAL",
                                                             "vendor": "V", "product": "P", "published": None, "assigner": "a"})


def test_a_cve_whose_record_could_not_be_read_is_fetched_by_the_next_run_even_from_an_unchanged_list(monkeypatch):
    src, st = BY_ID["cve_list"], {}
    _records(monkeypatch, bad={2})
    out = collect._cve_records(src, [_cve(1), _cve(2)], st, NOW, {})
    assert [r.guid for r in out] == ["CVE-2026-1"] and [p["guid"] for p in st["cve_pending"]] == ["CVE-2026-2"]
    _records(monkeypatch)                                              # the record is readable now; delta.json answered 304
    out = collect._cve_records(src, [], st, NOW + timedelta(minutes=5), {})
    assert [r.guid for r in out] == ["CVE-2026-2"] and out[0].extra["cvss"] == 9.8 and "cve_pending" not in st


def test_cves_over_the_cap_wait_in_the_pending_list_and_a_record_that_never_reads_is_given_up_and_said(monkeypatch, caplog):
    src, st = BY_ID["cve_list"], {}
    _records(monkeypatch)
    out = collect._cve_records(src, [_cve(n, hours=n) for n in range(Limits.MAX_CVE_RECORDS + 3)], st, NOW, {})
    assert len(out) == Limits.MAX_CVE_RECORDS and len(st["cve_pending"]) == 3
    assert len(collect._cve_records(src, [], st, NOW, {})) == 3 and "cve_pending" not in st
    _records(monkeypatch, bad={7})
    for _ in range(Limits.CVE_PENDING_RETRIES):
        collect._cve_records(src, [_cve(7)] if "cve_pending" not in st else [], st, NOW, {})
    assert "cve_pending" not in st and "cve_record_gave_up" in caplog.text
