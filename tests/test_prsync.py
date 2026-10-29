"""C2c: PR links opened by the scheduled deliver_prs.py reach the event pages through the Respond Lambda."""

import sys
from pathlib import Path

from radar import prsync

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import deliver_prs


def test_links_parse_what_deliver_prs_writes():
    """The PR body format is the contract between the two halves — build it with the real pr_body()."""
    p = {"event": "ev_18021be5786d7984", "reason": "r", "target": "node-gateway",
         "issue": {"issue_id": "01a176ae", "severity": "HIGH", "exploitable": "EXPLOITABLE", "name": "n"}}
    pulls = [{"head": {"ref": deliver_prs.branch_of(p)}, "body": deliver_prs.pr_body(p), "html_url": "https://x/pull/4"},
             {"head": {"ref": "feature/other"}, "body": deliver_prs.pr_body(p), "html_url": "https://x/pull/5"},
             {"head": {"ref": "continuum/abcdef12-x"}, "body": "hand-written", "html_url": "https://x/pull/6"}]
    assert prsync.links(pulls) == {"ev_18021be5": {"01a176ae": "https://x/pull/4"}}


def test_apply_reports_change_only_once():
    st = {"delivered_prs": {"old": "https://x/pull/1"}}
    assert prsync.apply(st, {"i": "https://x/pull/4"}) is True
    assert prsync.apply(st, {"i": "https://x/pull/4"}) is False
    assert st["delivered_prs"] == {"old": "https://x/pull/1", "i": "https://x/pull/4"}
