"""The team channel gets P0s about what AWS FSI / web3 customers run (Neo 2026-11-21): mainstream cloud components,
a language's own flaw, web3 nodes and toolchains — not mobile / desktop apps, SAP, appliances, ICS, niche web apps.
The 30-day replay's P0 titles are the cases."""
from __future__ import annotations

import pytest

from radar import cloudstack, notify

KEEP = ["CISA confirms PHP2Shell vulnerabilities now exploited in attacks",
        "CVE-2026-114952 Vulnerability in the MySQL Server, MySQL Cluster product of Oracle MySQL",
        "Multiples vulnérabilités dans F5 NGINX (18 novembre 2026)",
        "CVE-2026-118383 Pre-authentication use-after-free in MongoDB Server replica set primary catch-up",
        "Critical RCE Vulnerability in Apache HTTP Server: Everything You Need To Know",
        "CVE-2026-97229 GitLab Community Edition and Enterprise Edition",
        "漏洞通告 | Ruby 堆缓冲区溢出远程代码执行漏洞",
        "Go standard library net/http request smuggling", "Rust std::process command injection",
        "Geth DoS via a crafted p2p message", "OpenZeppelin Contracts reentrancy guard bypass"]
DROP = ["CVE-2026-102769 A SQL injection vulnerability when the recipient tapped on a specially crafted message (WhatsApp)",
        "New Windows SignDrop Zero-Day Exploit Allows Attackers to Gain SYSTEM Privileges",
        "CVE-2025-42884 SAP NetWeaver: SAP NetWeaver Improper Neutralization of Special Elements",
        "CVE-2026-76466 Cisco Expressway Series: Cisco Expressway Series Use of Hard-coded Credentials",
        "ICSA-26-237-03 Siemens SIMATIC IoT2050 Advanced",
        "CVE-2026-124990 Masteriyo LMS <= 3.5.1 - Unauthenticated PHP Object Injection via 'file' Parameter",
        "CVE-2026-130648 WWBN AVideo from 6.5 Stored XSS via Embed Video videoLink iframe src",
        "Let us go to the meeting app"]


@pytest.mark.parametrize("title", KEEP)
def test_cloud_components_are_kept(title):
    assert cloudstack.is_cloud_stack(title)


@pytest.mark.parametrize("title", DROP)
def test_other_products_are_not(title):
    assert not cloudstack.is_cloud_stack(title)


def test_the_entities_count_too():
    # CVE-2026-129474's title names no product; its entities do
    assert cloudstack.is_cloud_stack("Use-after-free in magic method backtraces can lead to RCE", ["PHP Group", "PHP"])


def test_a_subscription_can_filter_on_it():
    filters, bad = notify._filters({"cloud_stack": True}, "team")
    assert bad is None
    row = {"event_id": "ev_1", "title": DROP[0], "severity": "P0", "domain": "vuln"}
    assert not notify.matches(filters, notify.view(row, False))
    assert notify.matches(filters, notify.view({**row, "title": KEEP[1]}, False))
    # the published field wins over recomputation
    assert notify.matches(filters, notify.view({**row, "cloud_stack": True}, False))
