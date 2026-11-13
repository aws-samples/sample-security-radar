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
    mine = {"full_name": "neo/fleet"}
    pulls = [{"head": {"ref": deliver_prs.branch_of(p), "repo": mine}, "body": deliver_prs.pr_body(p), "html_url": "https://x/pull/4"},
             {"head": {"ref": "feature/other", "repo": mine}, "body": deliver_prs.pr_body(p), "html_url": "https://x/pull/5"},
             {"head": {"ref": "continuum/abcdef12-x", "repo": mine}, "body": "hand-written", "html_url": "https://x/pull/6"}]
    assert prsync.links(pulls, "neo/fleet") == {"ev_18021be5": {"01a176ae": "https://x/pull/4"}}


def test_a_pull_request_from_a_fork_is_not_a_radar_patch():
    """Anyone can open a PR whose branch and body look like the radar's; its link was shown as 「补丁 PR 待人审核合并」."""
    p = {"event": "ev_18021be5786d7984", "reason": "r", "target": "node-gateway",
         "issue": {"issue_id": "01a176ae", "severity": "HIGH", "exploitable": "EXPLOITABLE", "name": "n"}}
    fork = {"head": {"ref": deliver_prs.branch_of(p), "repo": {"full_name": "mallory/fleet"}}, "body": deliver_prs.pr_body(p),
            "html_url": "https://x/pull/66"}
    gone = {"head": {"ref": deliver_prs.branch_of(p), "repo": None}, "body": deliver_prs.pr_body(p), "html_url": "https://x/pull/67"}
    assert prsync.links([fork, gone], "neo/fleet") == {} and prsync.ours(fork, "neo/fleet") is None
    assert prsync.ours({**fork, "head": {**fork["head"], "repo": {"full_name": "neo/fleet"}}}, "neo/fleet")


def test_apply_reports_change_only_once():
    st = {"delivered_prs": {"old": "https://x/pull/1"}}
    assert prsync.apply(st, {"i": "https://x/pull/4"}) is True
    assert prsync.apply(st, {"i": "https://x/pull/4"}) is False
    assert st["delivered_prs"] == {"old": "https://x/pull/1", "i": "https://x/pull/4"}
