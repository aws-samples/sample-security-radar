"""radar.pocs: the nuclei-templates enrichment — YAML subset reader, checksum-gated index, SHA-pinned templates,
bounded rows, allowlisted fetch, degradation that never reads as "no template"."""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from radar import fetch, pocs
from radar.limits import Limits
from radar.store import MemoryStore

FIX = Path(__file__).parent / "fixtures" / "nuclei"
NOW = datetime(2026, 11, 11, 3, 0, tzinfo=UTC)
SHA = "c68b0d0460" + "0" * 30


@pytest.mark.parametrize("path", sorted(FIX.glob("*.yaml")), ids=lambda p: p.name)
def test_yaml_subset_reads_like_pyyaml(path):
    text = path.read_text()
    assert json.dumps(pocs.load_yaml(text), sort_keys=True) == json.dumps(yaml.safe_load(text), sort_keys=True)


@pytest.mark.parametrize("text", ["a: &x 1\nb: *x\n", "a: {b: 1}\n", "a: >\n  folded\n", "a:\n\t- tab\n", "a: 1\na: 2\n"])
def test_yaml_outside_the_subset_raises(text):
    with pytest.raises(pocs.UnsupportedYaml):
        pocs.load_yaml(text)


def test_template_lines_and_probes():
    t = pocs.parse_template((FIX / "CVE-2026-87902.yaml").read_text())
    lines = (FIX / "CVE-2026-87902.yaml").read_text().split("\n")
    probe, attack = t.requests
    assert probe.probe and not attack.probe
    assert lines[attack.line - 1].strip().startswith("GET /?page_id=")
    assert t.name_line and "Path Traversal" in lines[t.name_line - 1]


def _index(rows: dict[str, str]) -> str:
    return "\n".join(json.dumps({"ID": c, "Info": {}, "file_path": p}) for c, p in rows.items()) + "\n"


class Net:
    """A fake GitHub: records every URL; templates served only at the pinned SHA."""

    def __init__(self, rows: dict[str, str], sha: str = SHA, texts: dict[str, str] | None = None) -> None:
        self.rows, self.sha, self.calls, self.fail = rows, sha, [], set()
        self.texts = texts or {}
        self.body = _index(rows)
        self.checksum = hashlib.md5(self.body.encode(), usedforsecurity=False).hexdigest()

    def __call__(self, url: str) -> str:
        self.calls.append(url)
        for f in self.fail:
            if f in url:
                raise fetch.FetchError("http_error", "boom", 503, url)
        if url == pocs.CHECKSUM_URL:
            return self.checksum + "\n"
        if url == pocs.INDEX_URL:
            return self.body
        if url.startswith(pocs.COMMITS_URL):
            return json.dumps([{"sha": self.sha}])
        if url.startswith(pocs.RAW_URL + self.sha + "/"):
            path = url.removeprefix(pocs.RAW_URL + self.sha + "/")
            return self.texts.get(path, "id: x\n")
        raise AssertionError(f"unexpected URL {url}")


def test_checksum_gates_the_index_and_templates_are_fetched_at_the_pinned_sha():
    st, net = MemoryStore(), Net({"CVE-2026-87902": "http/cves/2026/CVE-2026-87902.yaml"})
    out = pocs.refresh(st, ["CVE-2026-87902", "CVE-2026-1"], NOW, net)
    assert out["CVE-2026-87902"]["state"] == "found" and out["CVE-2026-87902"]["sha"] == SHA
    assert out["CVE-2026-1"]["state"] == "no_template"
    assert pocs.RAW_URL + SHA + "/http/cves/2026/CVE-2026-87902.yaml" in net.calls
    assert not any("/main/http/" in u for u in net.calls)        # never a template from a branch
    # same day: nothing fetched again; next day, same checksum: only the 33-byte file
    net.calls.clear()
    pocs.refresh(st, ["CVE-2026-87902"], NOW + timedelta(hours=1), net)
    assert net.calls == []
    pocs.refresh(st, ["CVE-2026-87902"], NOW + timedelta(days=1), net)
    assert net.calls == [pocs.CHECKSUM_URL]


def test_a_torn_index_read_is_refused_and_recorded():
    st, net = MemoryStore(), Net({"CVE-2026-87902": "http/cves/2026/CVE-2026-87902.yaml"})
    net.checksum = "0" * 32
    stats: dict = {}
    out = pocs.refresh(st, ["CVE-2026-87902"], NOW, net, stats=stats)
    assert "MD5" in stats["poc_degraded"]
    # the index was never read ⇒ unavailable, NOT no_template (the page must not say 「无模板」)
    assert out["CVE-2026-87902"]["state"] == "unavailable"
    assert st.get_source_state(pocs.INDEX_KEY)["error"]


def test_a_failed_template_lookup_keeps_the_old_pin_and_says_so():
    st, net = MemoryStore(), Net({"CVE-2026-87902": "http/cves/2026/CVE-2026-87902.yaml"})
    pocs.refresh(st, ["CVE-2026-87902"], NOW, net)
    net.fail.add("api.github.com")
    stats: dict = {}
    out = pocs.refresh(st, ["CVE-2026-87902"], NOW + timedelta(days=Limits.POC_RECHECK_DAYS + 1), net, stats=stats)
    e = out["CVE-2026-87902"]
    assert e["state"] == "found" and e["sha"] == SHA and "boom" in e["error"] and stats["poc_failed"] == 1


def test_lookups_are_budgeted_per_hour():
    rows = {f"CVE-2026-{1000 + i}": f"http/cves/2026/CVE-2026-{1000 + i}.yaml" for i in range(50)}
    st, net = MemoryStore(), Net(rows)
    stats: dict = {}
    pocs.refresh(st, list(rows), NOW, net, stats=stats)
    assert sum(u.startswith(pocs.COMMITS_URL) for u in net.calls) == Limits.POC_LOOKUPS_PER_RUN
    assert stats["poc_backlog"] == 50 - Limits.POC_LOOKUPS_PER_RUN
    for k in range(10):
        pocs.refresh(st, list(rows), NOW + timedelta(minutes=5 * (k + 1)), net)
    assert sum(u.startswith(pocs.COMMITS_URL) for u in net.calls) == Limits.POC_LOOKUPS_PER_HOUR


def test_no_row_exceeds_the_cap_even_with_a_huge_index():
    rows = {f"CVE-2026-{100000 + i}": f"http/cves/2026/CVE-2026-{100000 + i}-some-long-product-name.yaml" for i in range(40_000)}
    st, net = MemoryStore(), Net(rows)
    pocs.refresh(st, ["CVE-2026-100000"], NOW, net)
    sizes = {k: len(json.dumps(v, ensure_ascii=False).encode()) for k, v in st.sources.items()}
    assert len([k for k in sizes if k.startswith(pocs.INDEX_KEY + "#")]) == Limits.POC_INDEX_SHARDS
    assert max(sizes.values()) <= Limits.POC_ROW_MAX_BYTES, max(sizes.items(), key=lambda kv: kv[1])


def test_an_oversize_row_is_refused_before_the_put():
    st = MemoryStore()
    with pytest.raises(pocs.RowTooLarge) as e:
        pocs._put(st, "k", {"x": "a" * (Limits.POC_ROW_MAX_BYTES + 1)})
    assert json.loads(str(e.value))["max_bytes"] == Limits.POC_ROW_MAX_BYTES and "k" not in st.sources


def test_a_too_large_template_is_not_stored():
    path = "http/cves/2026/CVE-2026-2000.yaml"
    st, net = MemoryStore(), Net({"CVE-2026-2000": path}, texts={path: "#" * (Limits.POC_TEMPLATE_MAX_BYTES + 1)})
    out = pocs.refresh(st, ["CVE-2026-2000"], NOW, net)
    assert out["CVE-2026-2000"]["state"] == "too_large" and pocs.TPL_KEY + "CVE-2026-2000" not in st.sources


def test_every_fetch_is_confined_to_the_github_allowlist(monkeypatch):
    for u in (pocs.CHECKSUM_URL, pocs.INDEX_URL, pocs.COMMITS_URL, pocs.RAW_URL):
        assert fetch._on_allowlist(u, pocs.HOSTS), u
    opened: list = []
    monkeypatch.setattr(fetch, "urlopen", lambda *a, **k: opened.append(a) or (_ for _ in ()).throw(AssertionError("opened")))
    with pytest.raises(fetch.FetchError) as e:
        pocs.get("https://evil.example/cves.json")
    assert e.value.code == "host_not_allowed" and opened == []
    with pytest.raises(fetch.FetchError):
        pocs.get("http://raw.githubusercontent.com/x")          # https only


def test_an_unsafe_index_path_is_left_out_visibly_and_a_stored_one_is_never_fetched():
    """Review of p1/rulepack: a `../` file_path from cves.json reached RAW_URL + sha + path (same host, other bytes)."""
    st = MemoryStore()
    net = Net({"CVE-2026-87902": "../../evil/repo/main/x.yaml", "CVE-2026-42018": "http/cves/2026/CVE-2026-42018.yaml"})
    stats: dict = {}
    out = pocs.refresh(st, ["CVE-2026-87902", "CVE-2026-42018"], NOW, net, stats=stats)
    assert out["CVE-2026-42018"]["state"] == "found" and not any(".." in u for u in net.calls)
    assert st.get_source_state(pocs.INDEX_KEY)["unsafe_paths"]["n"] == 1 and "unsafe file_path" in stats["poc_degraded"]
    # an index row written before the gate existed: error, no lookup, no link
    st.put_source_state(pocs._index_shard("CVE-2026-87902"), {"CVE-2026-87902": "../../evil/repo/main/x.yaml"})
    net.calls.clear()
    out = pocs.refresh(st, ["CVE-2026-87902"], NOW, net, stats={})
    assert out["CVE-2026-87902"]["state"] == "error" and out["CVE-2026-87902"]["path"] is None and net.calls == []


def test_the_schema_path_pattern_is_the_code_grammar():
    schema = json.loads((Path(__file__).parents[1] / "schemas" / "site-data.schema.json").read_text())
    tpl = schema["$defs"]["RulePackQuote"]["oneOf"][0]
    assert tpl["properties"]["path"]["pattern"] == "^" + pocs.TEMPLATE_PATH.pattern + "$"
