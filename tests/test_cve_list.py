"""The CVE Program's cvelistV5 feed (delta.json, ~7-min windows): every new CVE becomes an item; only a critical one
(CNA/ADP CVSS ≥ 9.0, or stated exploitation) opens an event — the rest are context items keyed by cve:, so a later
news report meets the record and its publication time. Records are fetched per CVE; a failure is retried, a missed
window is backfilled from deltaLog.json."""
import json
from datetime import UTC, datetime
from pathlib import Path

from radar import collect, fetch, parsers, pipeline
from radar.registry import BY_ID

FX = Path(__file__).parent / "fixtures" / "snapshots" / "2026-11-10"
REC = (FX / "cve-record.json").read_text()
NOW = datetime(2026, 11, 10, 0, 10, tzinfo=UTC)
SRC = BY_ID["cve_list"]


def _delta(ft, *cves):
    return json.dumps({"fetchTime": ft, "numberOfChanges": len(cves), "updated": [], "error": [],
                       "new": [{"cveId": c, "cveOrgLink": f"https://www.cve.org/CVERecord?id={c}",
                                "githubLink": f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/x/{c}.json",
                                "dateUpdated": "2026-11-10T00:00:27.929Z"} for c in cves]})


def _record(cvss):
    r = json.loads(REC)
    r["containers"]["cna"]["metrics"] = [{"cvssV3_1": {"baseScore": cvss, "baseSeverity": "CRITICAL" if cvss >= 9 else "MEDIUM"}}]
    return json.dumps(r)


def _http(monkeypatch, bodies, calls=None):
    def get(url, **k):
        if calls is not None:
            calls.append(url)
        for frag, body in bodies.items():
            if url.endswith(frag):
                if isinstance(body, Exception):
                    raise body
                return fetch.Response(200, body, None, None)
        raise fetch.FetchError("http_error", "Not Found", 404, url)
    monkeypatch.setattr(fetch, "http_get", get)


def test_a_record_reads_title_text_cvss_and_vendor():
    d = parsers.cve_record(REC)
    assert d["title"].startswith("SourceCodester Smart Attendance") and d["cvss"] == 5.3 and d["vendor"] == "SourceCodester"


def test_only_a_critical_cve_list_entry_opens_an_event(monkeypatch):
    _http(monkeypatch, {"delta.json": _delta("2026-11-10T00:05:01Z", "CVE-2026-1", "CVE-2026-2"),
                        "CVE-2026-1.json": _record(9.8), "CVE-2026-2.json": _record(5.3)})
    raws, _ = collect.collect(SRC, {}, NOW, seen={})
    items = {r.guid: pipeline.normalize(r, SRC, NOW) for r in raws}
    assert items["CVE-2026-1"].eventful and not items["CVE-2026-2"].eventful
    assert "cve:CVE-2026-2" in items["CVE-2026-2"].keys          # still meets a later report of that CVE


def test_an_empty_window_is_not_an_error(monkeypatch):
    _http(monkeypatch, {"delta.json": _delta("2026-11-10T00:05:01Z")})
    raws, st = collect.collect(SRC, {}, NOW, seen={})
    assert raws == [] and st["consecutive_failures"] == 0


def test_an_unreadable_record_is_retried_next_run_not_lost(monkeypatch):
    seen = {}
    _http(monkeypatch, {"delta.json": _delta("2026-11-10T00:05:01Z", "CVE-2026-3"),
                        "CVE-2026-3.json": fetch.FetchError("http_error", "boom", 503, "x")})
    raws, st = collect.collect(SRC, {}, NOW, seen=seen)
    assert raws == []
    _http(monkeypatch, {"delta.json": _delta("2026-11-10T00:05:01Z", "CVE-2026-3"), "CVE-2026-3.json": _record(7.0)})
    raws, _ = collect.collect(SRC, st, NOW, seen=seen)
    assert [r.guid for r in raws] == ["CVE-2026-3"]


def test_a_missed_window_is_backfilled_from_the_delta_log(monkeypatch):
    log = json.dumps([json.loads(_delta("2026-11-10T00:12:00Z", "CVE-2026-5")),
                      json.loads(_delta("2026-11-10T00:19:00Z", "CVE-2026-6"))])
    calls = []
    _http(monkeypatch, {"/delta.json": _delta("2026-11-10T00:26:00Z", "CVE-2026-7"), "deltaLog.json": log,
                        "CVE-2026-5.json": _record(5.0), "CVE-2026-6.json": _record(5.0), "CVE-2026-7.json": _record(5.0)},
          calls)
    raws, st = collect.collect(SRC, {"cve_fetch_time": "2026-11-10T00:05:00Z", "last_success": "x"}, NOW, seen={})
    assert sorted(r.guid for r in raws) == ["CVE-2026-5", "CVE-2026-6", "CVE-2026-7"]
    assert any(u.endswith("deltaLog.json") for u in calls) and st["cve_fetch_time"] == "2026-11-10T00:26:00Z"
