"""AWS's own fix status (radar.awsfix) — Neo 2026-11-18: 「AWS 的消息对我们来说也很重要，发现 AWS 已经有修复了要 highlight」.
Fixture: the affected-packages table of explore.alas.aws.amazon.com/CVE-2026-114938.html (Java4Shell), 2026-11-18."""
from datetime import UTC, datetime, timedelta
from pathlib import Path

from radar import awsfix, notify
from radar.store import MemoryStore

PAGE = (Path(__file__).parent / "fixtures" / "awsfix" / "CVE-2026-114938.html").read_text()
NOW = datetime(2026, 11, 18, 2, tzinfo=UTC)


class _HTTP404(Exception):
    status = 404


def test_the_page_says_which_aws_builds_are_fixed_pending_or_not_affected():
    rows = awsfix.parse(PAGE)
    assert len(rows) == 22 and {r["status"] for r in rows} == {"fixed", "not_affected", "no_fix"}
    s = awsfix.summary(rows)
    assert [x["package"] for x in s["fixed"]] == ["Corretto 17", "Corretto 21", "Corretto 25", "Corretto 27"]
    assert "pending" not in s                       # AL2 Corretto 17 was Pending Fix at 01:50Z, Fixed by 02:01Z
    assert {"Corretto 8", "Corretto 11"} <= {x["package"] for x in s["not_affected"]}
    assert {"ALAS2-2026-4123", "ALAS2023-2026-3478", "ALAS2023-2026-3481"} <= set(s["advisories"])


def test_the_notice_line_highlights_what_aws_fixed_first():
    store = MemoryStore()
    awsfix.refresh(store, ["CVE-2026-114938"], NOW, lambda url: PAGE)
    line = awsfix.line(awsfix.load(store)["CVE-2026-114938"])
    assert line == "🟧 AWS 已修复：Corretto 17/21/25/27 ｜ 不受影响：Corretto 8/11、Graviton"
    assert not awsfix.arm_spared(PAGE.replace("ARM64 systems are not affected", "ARM64 systems are affected"))
    pending = PAGE.replace("<td>Fixed</td>", "<td>Pending Fix</td>", 1)
    assert "待修复：Corretto 17" in awsfix.line({"state": "FOUND", "summary": awsfix.summary(awsfix.parse(pending))})


def test_refresh_reads_due_pages_only_and_rereads_a_pending_one():
    store, asked = MemoryStore(), []

    pending = PAGE.replace("<td>Fixed</td>", "<td>Pending Fix</td>", 1)

    def get(url):
        asked.append(url)
        if "129448" in url:
            raise _HTTP404()
        return pending
    changed = awsfix.refresh(store, ["CVE-2026-114938", "CVE-2026-129448"], NOW, get)
    led = awsfix.load(store)
    assert changed == {"CVE-2026-114938", "CVE-2026-129448"} and led["CVE-2026-129448"]["state"] == "NOT_FOUND"
    assert awsfix.refresh(store, ["CVE-2026-114938"], NOW + timedelta(hours=1), get) == set() and len(asked) == 2
    awsfix.refresh(store, ["CVE-2026-114938"], NOW + timedelta(hours=7), get)       # AL2 Corretto 17 is still pending
    assert len(asked) == 3


def test_a_page_without_the_table_is_not_read_as_not_affected():
    store = MemoryStore()
    awsfix.refresh(store, ["CVE-2026-1"], NOW, lambda url: "<html>maintenance</html>")
    e = awsfix.load(store)["CVE-2026-1"]
    assert e["state"] == "NO_TABLE" and awsfix.line(e) is None


def test_a_failed_read_leaves_no_entry_and_is_counted():
    store, stats = MemoryStore(), {}

    def boom(url):
        raise OSError("timeout")
    awsfix.refresh(store, ["CVE-2026-114938"], NOW, boom, stats=stats)
    assert awsfix.load(store) == {} and stats["aws_fix_failed"] == 1


def test_a_vulnerability_p0_carries_the_aws_line_a_web3_one_never_does():
    line = awsfix.line({"state": "FOUND", "summary": awsfix.summary(awsfix.parse(PAGE))})
    row = {"event_id": "ev_00000000000000a7", "title": "Java4Shell: RCE in OpenJDK (CVE-2026-114938)", "severity": "P0",
           "domain": "vuln", "level": "V3", "exploitation": "reported", "first_seen": "2026-11-17T10:22:00Z",
           "cves": ["CVE-2026-114938"], "aws_fix_line": line,
           "aws_fix_url": "https://explore.alas.aws.amazon.com/CVE-2026-114938.html"}
    v = notify.view(row, False, [])
    m = notify.plan(v, {}, "https://site")[0]
    assert line in m["text"] and notify.gate(m, v, "https://site", []) == []
    # its source as a hyperlink (Neo 2026-11-18); any other address is never linked
    assert "🟧 <https://explore.alas.aws.amazon.com/CVE-2026-114938.html|AWS> 已修复：" in m["slack"]
    assert "AWS 安全中心" not in m["slack"]
    assert m["text"].count("（https://explore.alas.aws.amazon.com/CVE-2026-114938.html）") == 1
    odd = notify.plan(notify.view({**row, "aws_fix_url": "https://evil.example/x"}, False, []), {}, "https://site")[0]
    assert "evil.example" not in odd["slack"] and "🟧 AWS 已修复：" in odd["slack"]
    w = notify.view({**row, "domain": "web3", "amount_usd_latest": 2e6}, False, [])
    assert "🟧" not in notify.plan(w, {}, "https://site")[0]["text"]


def test_publish_asks_aws_only_for_p0_p1_vulnerability_cves_and_the_page_carries_the_status():
    from radar import publish
    from radar.model import Event
    store = MemoryStore()
    at = "2026-11-17T22:00:00Z"
    for eid, sev, dom, cve in (("ev_00000000000000a1", "P0", "vuln", "CVE-2026-114938"),
                               ("ev_00000000000000a2", "P2", "vuln", "CVE-2026-900001"),
                               ("ev_00000000000000a3", "P0", "web3", "CVE-2026-900002")):
        store.put_event(Event(event_id=eid, domain=dom, title=f"{cve} thing", first_seen=at, last_updated=at,
                              item_ids=[], keys=[], severity=sev, cves=[cve]))
    asked: list[str] = []

    def aws(cves):
        asked.extend(cves)
        return awsfix.refresh(store, cves, NOW, lambda url: PAGE)
    docs = publish.build(store, NOW, None, aws_fix=aws)
    assert asked == ["CVE-2026-114938"]
    fix = docs["events/ev_00000000000000a1.json"]["aws_fix"]
    assert fix["cve"] == "CVE-2026-114938" and fix["line"].startswith("🟧 AWS 已修复：")
    assert docs["events/ev_00000000000000a3.json"]["aws_fix"] is None


def test_an_entry_read_before_the_description_was_parsed_is_read_once_more():
    store, asked = MemoryStore(), []
    store.put_source_state(awsfix._shard("CVE-2026-114938"), {"CVE-2026-114938": {
        "state": "FOUND", "summary": awsfix.summary(awsfix.parse(PAGE)), "checked_at": "2026-11-18T01:00:00Z",
        "first_checked_at": "2026-11-18T01:00:00Z"}})

    def get(url):
        asked.append(url)
        return PAGE
    awsfix.refresh(store, ["CVE-2026-114938"], NOW, get)
    assert len(asked) == 1 and awsfix.load(store)["CVE-2026-114938"]["summary"]["arm64_not_affected"] is True
    awsfix.refresh(store, ["CVE-2026-114938"], NOW + timedelta(hours=1), get)
    assert len(asked) == 1                                   # all final now: not read again


def test_p0_cves_are_read_before_p1_cves():
    """Live 2026-11-18: the first full publish queued ~750 P0 / P1 CVEs; Java4Shell (P0) waited behind P1s."""
    store, asked = MemoryStore(), []
    awsfix.refresh(store, ["CVE-2026-900009", "CVE-2026-100001"], NOW, lambda url: asked.append(url) or PAGE, limit=1)
    assert asked == [awsfix.URL.format(cve="CVE-2026-900009")]      # the caller's order, not the alphabet
