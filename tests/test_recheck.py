"""R8.1 — what the current rules would make of the stored events is a report, and a deployment that changes the
judgement code asks for it.

Three rule changes in one week were green on fixtures and wrong on the stored events; each was found by a hand-written
recompute of the live table."""
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest
from test_pipeline_replay import FETCHED, snapshot_raws

from radar import pipeline, recheck
from radar.store import MemoryStore

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def world():
    s = MemoryStore()
    pipeline.ingest(snapshot_raws(), s, FETCHED)
    return s


def test_unchanged_rules_change_nothing_and_the_store_is_not_written(world):
    before = json.dumps(world.events, sort_keys=True)
    rep = recheck.diff(world, FETCHED, 3650)
    assert rep["events"] == len(world.events) > 100 and rep["changed"] == [] and rep["unchanged"] == rep["events"]
    assert json.dumps(world.events, sort_keys=True) == before


def test_a_changed_rule_lists_every_event_it_changes_with_before_and_after(world, monkeypatch):
    confirmed = [e for e in world.events.values() if e["exploitation"] == "confirmed" and e["domain"] != "web3"]
    assert confirmed
    real = pipeline._exploitation
    monkeypatch.setattr(pipeline, "_exploitation", lambda d, items, level: "none" if d != "web3" else real(d, items, level))
    before = json.dumps(world.events, sort_keys=True)
    rep = recheck.diff(world, FETCHED, 3650)
    got = {c["event_id"]: c["fields"] for c in rep["changed"]}
    assert {e["event_id"] for e in confirmed} <= set(got)
    assert all(got[e["event_id"]]["exploitation"] == ["confirmed", "none"] for e in confirmed)
    assert rep["unchanged"] + len(rep["changed"]) == rep["events"]
    assert json.dumps(world.events, sort_keys=True) == before                  # still read-only
    # a severity change sorts first: the reader starts with what would leave or enter P0
    sev = [c for c in rep["changed"] if "severity" in c["fields"]]
    assert sev and rep["changed"][: len(sev)] == sev
    text = recheck.summary(rep, limit=2)
    assert f"{len(rep['changed'])} changed" in text and "exploitation: " in text and "→ none" in text and "more (all of them" in text
    assert recheck.diff(world, FETCHED, 3650, domain="web3")["changed"] == []


def test_an_event_whose_reports_are_gone_is_counted_apart():
    s = MemoryStore()
    pipeline.ingest(snapshot_raws()[:40], s, FETCHED)
    eid = next(iter(s.events))
    for i in s.events[eid]["item_ids"]:
        s.items.pop(i)
    rep = recheck.diff(s, FETCHED, 3650)
    assert rep["not_recomputable"] == 1 and rep["events"] == len(s.events) - 1


# --- the deploy guard asks for it ---------------------------------------------------------------------------------

def _pre():
    spec = importlib.util.spec_from_file_location("preflight", ROOT / "scripts" / "preflight.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _repo(tmp_path):
    def git(*a):
        return subprocess.run(["git", "-C", str(tmp_path), *a], check=True, capture_output=True, text=True).stdout.strip()
    git("init", "-q", "-b", "main")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "t")
    (tmp_path / "src" / "radar").mkdir(parents=True)
    (tmp_path / "src" / "radar" / "signals.py").write_text("x = 1\n")
    (tmp_path / "src" / "radar" / "publish.py").write_text("y = 1\n")
    (tmp_path / "build").mkdir()
    (tmp_path / ".gitignore").write_text("build/\n")
    git("add", "-A")
    git("commit", "-q", "-m", "one")
    return git


def test_a_judgement_change_since_the_last_deployment_needs_a_report_of_this_commit(tmp_path):
    pre, git = _pre(), _repo(tmp_path)
    assert pre.recompute_problem(tmp_path) is None                              # no record of a deployment: nothing to compare
    (tmp_path / "build" / "deployed-commit").write_text(git("rev-parse", "HEAD") + "\n")
    (tmp_path / "src" / "radar" / "publish.py").write_text("y = 2\n")
    git("commit", "-q", "-am", "not a judgement file")
    assert pre.recompute_problem(tmp_path) is None
    (tmp_path / "src" / "radar" / "signals.py").write_text("x = 2\n")
    git("commit", "-q", "-am", "a rule")
    head = git("rev-parse", "HEAD")
    p = pre.recompute_problem(tmp_path)
    assert p["error"] == "recompute_report_missing" and p["limit"] == head[:12] and p["actual"] == "no report"
    report = tmp_path / "build" / "recompute-check.json"
    for stale in ({"commit": "0" * 40}, {"commit": head, "dirty": True}, {"commit": head, "domain": "vuln"}):
        report.write_text(json.dumps(stale))
        assert pre.recompute_problem(tmp_path)["error"] == "recompute_report_missing", stale   # another commit / dirty / partial
    report.write_text(json.dumps({"commit": head, "dirty": False, "domain": None}))
    assert pre.recompute_problem(tmp_path) is None


def test_the_deployment_records_what_is_live_only_after_its_checks():
    sh = (ROOT / "scripts" / "deploy-all.sh").read_text()
    assert sh.index("site_diff.py compare") < sh.index("git rev-parse HEAD > build/deployed-commit")
    assert "set -euo pipefail" in sh or "set -e" in sh
    pre = (ROOT / "scripts" / "preflight.py").read_text()
    assert "recompute_problem(ROOT)" in pre and "DEPLOY_SKIP_RECOMPUTE" in pre
