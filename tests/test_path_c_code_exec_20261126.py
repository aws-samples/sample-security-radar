"""Path C to P0 (2026-11-26): a flaw that executes code in a mainstream cloud component, with a public exploit, carried
by ≥ 2 independent reporters, is P0 even when it needs authentication — PostgreSQL CVE-2026-6460 (CVSS 8.8, a
database user runs OS commands) sat at P1 for 13 days and was never pushed."""
from __future__ import annotations

import pytest

from radar import pipeline, signals


def _it(n, src, title, text, tier="T2", cve="CVE-2026-6460", entity=None):
    from radar.model import Item
    return Item(item_id=f"it_{n}", source_id=src, tier=tier, org=src, domain="vuln", url=f"https://x/{n}",
                canonical_url=f"https://x/{n}", title=title, text=text, published_at="2026-11-13T16:53:08Z",
                fetched_at="2026-11-13T16:53:08Z", content_hash=str(n), keys=[f"cve:{cve}"], links=[], entity=entity,
                eventful=True, signals={"exploited": "unclear", "kev": False, "poc": True, "amount_usd": None}, extra={})


PG = [_it(1, "thehackernews", "PostgreSQL Patches 52 Flaws, Including 22-Year-Old Bug Enabling Authenticated RCE",
          "A type confusion flaw in PostgreSQL CVE-2026-6460 lets a database user who can create objects run code on the server."),
      _it(2, "x_security", "PostgreSQL patches 52 security flaws — including a 22-year-old bug allowing remote code execution",
          "Tracked as CVE-2026-6460 (CVSS 8.8), the flaw lets authenticated users with object-creation privileges execute code.")]


@pytest.mark.parametrize("text,want", [
    ("lets a database user run code on the server", "yes"),
    ("The flaw enables remote code execution.", "yes"),
    ("攻击者可执行任意系统命令", "yes"),
    ("The bug does not lead to code execution.", "no"),
    ("A denial of service in the parser.", "unclear"),
])
def test_the_code_execution_sentence(text, want):
    assert signals._code_exec_sentence(text) == want


def test_postgres_6460_is_path_c():
    assert pipeline._code_exec_cloud("vuln", PG, "poc", 2, PG[1].title)


@pytest.mark.parametrize("why,kw", [
    ("a catalog listing alone is not a reporter", {"reporters": 0}),
    ("no public exploit", {"exploitation": "none"}),
    ("a theft is not a vulnerability", {"domain": "web3"}),
])
def test_each_condition_is_needed(why, kw):
    args = {"domain": "vuln", "exploitation": "poc", "reporters": 2} | kw
    assert not pipeline._code_exec_cloud(args["domain"], PG, args["exploitation"], args["reporters"], PG[1].title), why


def test_a_non_cloud_product_is_not_path_c():
    items = [_it(1, "thehackernews", "WinRAR flaw lets attackers execute arbitrary code", "execute arbitrary code", cve="CVE-2026-9"),
             _it(2, "cvefeed", "CVE-2026-9 WinRAR remote code execution", "remote code execution", cve="CVE-2026-9")]
    assert not pipeline._code_exec_cloud("vuln", items, "poc", 2, items[1].title)


def test_path_c_makes_p0():
    assert pipeline._impact_severity("vuln", "V2", "poc", None, critical=True) == "P0"


def test_the_live_shape_is_p0_end_to_end():
    """The live event: The Hacker News and its X repost are ONE reporter (syndication); the exploit is the second leg."""
    from datetime import UTC, datetime

    from radar.model import Event
    items = [PG[0], _it(3, "sploitus", "Exploit for CVE-2026-6460", "Proof-of-concept exploit for CVE-2026-6460. CVSS 8.8.")]
    ev = Event(event_id="ev_pg1", domain="vuln", title="", first_seen="2026-11-13T16:53:08Z",
               last_updated="2026-11-13T16:53:08Z", item_ids=[i.item_id for i in items], keys=["cve:CVE-2026-6460"])
    out = pipeline.recompute(ev, items, datetime(2026, 11, 14, 0, 0, tzinfo=UTC))
    assert out.severity == "P0"


def test_the_event_is_p0_end_to_end():
    from datetime import UTC, datetime

    from radar.model import Event
    ev = Event(event_id="ev_pg", domain="vuln", title="", first_seen="2026-11-13T16:53:08Z",
               last_updated="2026-11-13T16:53:08Z", item_ids=[i.item_id for i in PG], keys=["cve:CVE-2026-6460"])
    out = pipeline.recompute(ev, PG, datetime(2026, 11, 14, 0, 0, tzinfo=UTC))
    assert out.exploitation == "poc" and out.severity == "P0"
