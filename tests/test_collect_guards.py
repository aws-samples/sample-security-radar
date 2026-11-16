"""Collect / fetch safety (docs/research/action/07 B3, 05 §3.6–3.7): a failed run never advances SEEN, one PoC that
cannot be read degrades only its entry, gzip bodies are decompressed under a cap, follow-up URLs taken from feed content
stay on each parser's hosts (redirects included)."""

import email.message
import gzip
import io
import json
import logging
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import pytest

from radar import collect, fetch
from radar.limits import Limits
from radar.registry import BY_ID

NOW = datetime(2026, 10, 23, 4, 0, tzinfo=UTC)
SNAP = Path(__file__).parent / "fixtures" / "snapshots" / "2026-10-23"
RAW = "https://raw.githubusercontent.com/"


class _Resp(io.BytesIO):
    """What urllib's urlopen returns, enough for fetch.http_get."""

    def __init__(self, body: bytes, status: int = 200, encoding: str | None = None) -> None:
        super().__init__(body)
        self.status = status
        self.headers = email.message.Message()
        self.headers["Content-Type"] = "text/plain; charset=utf-8"
        if encoding:
            self.headers["Content-Encoding"] = encoding

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _net(monkeypatch, bodies: dict[str, str]) -> list[str]:
    """Route fetch.urlopen by URL (the real http_get runs, guards included); unknown URL ⇒ 404. Returns the URLs opened."""
    import urllib.error
    calls: list[str] = []

    def urlopen(req, timeout, **k):
        url = req.full_url if isinstance(req, urllib.request.Request) else req
        calls.append(url)
        if url in bodies:
            return _Resp(bodies[url].encode())
        raise urllib.error.HTTPError(url, 404, "Not Found", email.message.Message(), None)
    monkeypatch.setattr(fetch, "urlopen", urlopen)
    return calls


# ---------------------------------------------------------------- B3: SEEN and the DeFiHackLabs PoC fetches

def _poc_runs(monkeypatch, sol_ok: list[bool], caplog) -> list[tuple[list, dict, dict]]:
    """Run defihacklabs collect once per entry of `sol_ok` (does TIPMine's .sol answer that run?), carrying SEEN, the
    source state and the item store across runs the way handlers._collect_source does: known_item is True for every
    entry a previous run handed over. Returns (raws, state, seen) per run."""
    from radar import parsers
    src = BY_ID["defihacklabs"]
    alps, gone = "src/test/2026-10/AlpsCon_exp.sol", "src/test/2026-10/TIPMine_exp.sol"
    readme = (SNAP / "defihacklabs.md").read_text()
    sol = (SNAP / "AlpsCon_exp.sol").read_text()
    stored = {r.guid for r in parsers.defihacklabs(readme, src.source_id)} - {alps, gone}   # older, stored items
    seen: dict[str, str] = {}
    st: dict = {"last_success": "2026-10-22T00:00:00Z"}
    out = []
    for ok in sol_ok:
        bodies = {src.url: readme, f"{RAW}SunWeb3Sec/DeFiHackLabs/main/{alps}": sol}
        if ok:
            bodies[f"{RAW}SunWeb3Sec/DeFiHackLabs/main/{gone}"] = sol
        _net(monkeypatch, bodies)
        with caplog.at_level(logging.WARNING):
            raws, st = collect.collect(src, st, NOW, known_item=lambda sid, guid, s=stored: guid in s, seen=seen)
        stored.update(r.guid for r in raws)                 # the batch reached S3 and Process stored it
        out.append((raws, st, dict(seen)))
    return out


def test_one_unreadable_poc_degrades_only_its_entry_and_is_retried(monkeypatch, caplog):
    """Live bug B3 (repro /tmp/sr07/seenloss.py: README ok, a .sol 404 ⇒ 0 raws handed over, SEEN holding all 155).
    Review of the first fix: handing the entry over without attack_tx and dropping it from SEEN was no retry — by the
    next run the item was stored, so known_item skipped the PoC fetch and attack_tx never arrived (ingest's content
    hash ignores attack_tx, so a re-handover would not have updated the item either). The entry now waits a run."""
    alps, gone = "src/test/2026-10/AlpsCon_exp.sol", "src/test/2026-10/TIPMine_exp.sol"
    (r1, st1, seen1), (r2, st2, seen2) = _poc_runs(monkeypatch, [False, True], caplog)
    assert st1["consecutive_failures"] == 0 and len(r1) == 154           # the source did not fail; only TIPMine waits
    by1 = {r.guid: r for r in r1}
    assert gone not in by1 and by1[alps].extra["attack_tx"][0]["hash"].startswith("0x824b83f9")
    assert collect._gh(gone) not in seen1 and len(seen1) == 154
    assert any("poc_unavailable" in m and "TIPMine" in m for m in caplog.messages)
    # next run (TIPMine not stored, so known_item is False): the .sol answers ⇒ handed over with its attack tx, alone
    assert [r.guid for r in r2] == [gone] and r2[0].extra["attack_tx"]
    assert collect._gh(gone) in seen2 and not st2.get("poc_misses")


def test_a_poc_gone_for_good_is_handed_over_without_it_after_the_retries(monkeypatch, caplog):
    """A .sol deleted upstream must not hold its entry back forever (nor take a fetch slot every run): on the
    POC_RETRIES-th failed run the entry is handed over without attack_tx, and the give-up is logged."""
    gone = "src/test/2026-10/TIPMine_exp.sol"
    runs = _poc_runs(monkeypatch, [False] * (Limits.POC_RETRIES + 1), caplog)
    for raws, _, _ in runs[:Limits.POC_RETRIES - 1]:
        assert gone not in {r.guid for r in raws}
    last, st, seen = runs[Limits.POC_RETRIES - 1]
    assert [r.guid for r in last] == [gone] and "attack_tx" not in last[0].extra
    assert collect._gh(gone) in seen and not st.get("poc_misses")
    assert runs[Limits.POC_RETRIES][0] == []                               # stored: not handed over again
    assert any("poc_gave_up" in m and "TIPMine" in m for m in caplog.messages)


def test_a_failed_run_hands_back_seen_untouched(monkeypatch):
    """Any failure after incremental() (here: the CVE record step raising) must leave SEEN as it was — the handler
    stores SEEN whenever it changed, and the failed run handed nothing over."""
    src = BY_ID["cve_list"]
    delta = json.dumps({"fetchTime": "2026-10-23T03:55:00Z", "new": [
        {"cveId": "CVE-2026-1", "githubLink": f"{RAW}CVEProject/cvelistV5/main/cves/2026/1xxx/CVE-2026-1.json",
         "dateUpdated": "2026-10-23T03:50:00Z"}]})
    _net(monkeypatch, {src.url: delta})

    def boom(*a, **k):
        raise fetch.FetchError("network_error", "reset", None, src.url)
    monkeypatch.setattr(collect, "_cve_records", boom)
    seen = {"old": "c0ffee00"}
    raws, st = collect.collect(src, {"last_success": "2026-10-22T00:00:00Z"}, NOW, seen=seen)
    assert raws == [] and st["consecutive_failures"] == 1
    assert seen == {"old": "c0ffee00"}


# ---------------------------------------------------------------- bounded gzip

def test_a_gzip_bomb_is_refused_not_decompressed(monkeypatch):
    monkeypatch.setattr(Limits, "HTTP_MAX_BYTES", 10_000)
    bomb = gzip.compress(b"\0" * 1_000_000)                 # 1 MB out of ~1 KB in: under the cap compressed, 100× over
    assert len(bomb) < 10_000
    monkeypatch.setattr(fetch, "_open", lambda *a, **k: _Resp(bomb, encoding="gzip"))
    with pytest.raises(fetch.FetchError) as e:
        fetch.http_get("https://example.org/feed")
    assert e.value.code == "too_large"


def test_a_normal_gzip_body_still_decodes_every_member(monkeypatch):
    body = gzip.compress(b"first ") + b"\0\0" + gzip.compress(b"second")   # two members, padded, as gzip.decompress reads
    monkeypatch.setattr(fetch, "_open", lambda *a, **k: _Resp(body, encoding="gzip"))
    assert fetch.http_get("https://example.org/feed").body == "first second"


def test_a_truncated_gzip_body_is_a_failed_fetch_not_a_short_one(monkeypatch):
    """Review of the bounded gunzip: a stream cut before its end-of-stream marker (a dropped connection, a CDN cut)
    came back as the partial output — 42,056 of 100,000 bytes, no error — so a truncated feed parsed into a partial
    batch that looked like a successful run. gzip.decompress raised EOFError there; now it is a FetchError."""
    whole = gzip.compress(b"x" * 100_000)
    for body in (whole[:len(whole) // 2], gzip.compress(b"first ") + gzip.compress(b"second")[:-6]):
        monkeypatch.setattr(fetch, "_open", lambda *a, b=body, **k: _Resp(b, encoding="gzip"))
        with pytest.raises(fetch.FetchError) as e:
            fetch.http_get("https://example.org/feed")
        assert e.value.code == "bad_gzip" and "truncated" in str(e.value)
    # corrupt data is a FetchError too (zlib.error would escape collect's handler and skip the source's state update)
    monkeypatch.setattr(fetch, "_open", lambda *a, **k: _Resp(whole[:20] + b"\xff" * 40, encoding="gzip"))
    with pytest.raises(fetch.FetchError) as e:
        fetch.http_get("https://example.org/feed")
    assert e.value.code == "bad_gzip" and "corrupt" in str(e.value)


# ---------------------------------------------------------------- follow-up host allowlist

def test_a_follow_up_url_off_the_allowlist_is_never_requested(monkeypatch, caplog):
    src = BY_ID["cisa_csaf_ot"]
    feed = {"feed": {"entry": [{"id": "ICSA-26-290-01", "title": "x", "updated": "2026-10-22T00:00:00Z",
                                "link": [{"rel": "self", "href": "https://169.254.169.254/latest/meta-data/"}]}]}}
    calls = _net(monkeypatch, {src.url: json.dumps(feed)})
    with caplog.at_level(logging.WARNING):
        raws, _ = collect.collect(src, {}, NOW)
    assert calls == [src.url] and raws == []
    assert any("csaf_doc_unavailable" in m and "host_not_allowed" in m for m in caplog.messages)


def test_a_cve_record_url_off_the_allowlist_is_never_requested(monkeypatch, caplog):
    src = BY_ID["cve_list"]
    delta = json.dumps({"fetchTime": "2026-10-23T03:55:00Z", "new": [
        {"cveId": "CVE-2026-1", "githubLink": "http://127.0.0.1:9001/2018-06-01/runtime/invocation/next",
         "dateUpdated": "2026-10-23T03:50:00Z"}]})
    calls = _net(monkeypatch, {src.url: delta})
    seen: dict[str, str] = {}
    with caplog.at_level(logging.WARNING):
        raws, st = collect.collect(src, {"last_success": "2026-10-22T00:00:00Z"}, NOW, seen=seen)
    assert calls == [src.url] and raws == [] and st["consecutive_failures"] == 0
    assert any("cve_record_unavailable" in m and "host_not_allowed" in m for m in caplog.messages)


def test_http_get_with_an_allowlist_refuses_other_hosts_and_plain_http(monkeypatch):
    calls = _net(monkeypatch, {})
    hosts = frozenset({"raw.githubusercontent.com"})
    for bad in ("https://169.254.169.254/x", "http://raw.githubusercontent.com/x", "https://raw.githubusercontent.com.evil.io/x",
                "http://127.0.0.1:9001/2018-06-01/runtime/invocation/next"):
        with pytest.raises(fetch.FetchError) as e:
            fetch.http_get(bad, allow_hosts=hosts)
        assert e.value.code == "host_not_allowed"
    assert calls == []


@pytest.mark.parametrize("target", ["https://169.254.169.254/latest/", "http://raw.githubusercontent.com/x",
                                    "ftp://raw.githubusercontent.com/x"])
def test_a_redirect_off_the_allowlist_is_refused(monkeypatch, target):
    """The guarded opener is what http_get uses for an allowlisted fetch, and its redirect handler refuses the hop."""
    used: list[object] = []

    class Opener:
        def __init__(self, *handlers):
            self.handlers = handlers

        def open(self, req, timeout):
            used.append(self)
            [h] = [h for h in self.handlers if isinstance(h, urllib.request.HTTPRedirectHandler)]
            assert isinstance(h, fetch._GuardedRedirect), "an allowlisted fetch went through the general redirect policy"
            return h.redirect_request(req, None, 302, "Found", email.message.Message(), target)
    monkeypatch.setattr(fetch.urllib.request, "build_opener", Opener)
    with pytest.raises(fetch.FetchError) as e:
        fetch.http_get(f"{RAW}cisagov/CSAF/x.json", allow_hosts=frozenset({"raw.githubusercontent.com"}))
    assert e.value.code == "redirect_refused" and used


def test_a_redirect_within_the_allowlist_is_followed():
    h = fetch._GuardedRedirect(frozenset({"raw.githubusercontent.com"}))
    req = urllib.request.Request(f"{RAW}a.json")
    nxt = h.redirect_request(req, None, 301, "Moved", email.message.Message(), f"{RAW}b.json")
    assert nxt is not None and nxt.full_url == f"{RAW}b.json"


def test_a_poc_held_back_for_lack_of_time_is_never_given_up(monkeypatch, caplog):
    """R2.5: the source budget ran out before this .sol — the PoC is not gone, the run was slow. It waits without
    counting a miss, so slow runs alone never hand an entry over without its attack tx."""
    gone = "src/test/2026-10/TIPMine_exp.sol"
    real = fetch.http_get

    def get(url, **k):
        if url.endswith("TIPMine_exp.sol"):
            raise fetch.FetchError("source_budget", "the source's budget is spent", None, url)
        return real(url, **k)
    monkeypatch.setattr(fetch, "http_get", get)
    runs = _poc_runs(monkeypatch, [False] * (Limits.POC_RETRIES + 1), caplog)
    assert all(gone not in {r.guid for r in raws} for raws, _, _ in runs)
    assert [sum((st.get("poc_misses") or {}).values()) for _, st, _ in runs] == [0] * len(runs)
