"""R0.4 — a deployment is refused when it should be, and judged by what the site shows before and after.

Audit 05 §6.2 / §6.3 / §9.5: deploy-all.sh ran no test, copied whatever was in the working tree, had no floor for old
commits (R11: nothing before 620b1f5 may be deployed) and no check that the site still made sense afterwards — on
2026-11-12 the top event turned from a theft into a 703-report vulnerability and every check stayed green."""
import importlib.util
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _script(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_").removesuffix(".py"), ROOT / "scripts" / name)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _repo(tmp_path):
    def git(*a):
        return subprocess.run(["git", "-C", str(tmp_path), *a], check=True, capture_output=True, text=True).stdout.strip()
    git("init", "-q", "-b", "main")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "t")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x = 1\n")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "n.md").write_text("n\n")
    git("add", "-A")
    git("commit", "-q", "-m", "one")
    first = git("rev-parse", "HEAD")
    (tmp_path / "src" / "a.py").write_text("x = 2\n")
    git("commit", "-q", "-am", "two")
    return git, first


def test_a_dirty_tree_is_refused_for_what_gets_deployed_only(tmp_path):
    pre = _script("preflight.py")
    _repo(tmp_path)
    assert pre.problems(tmp_path, minimum=None) == []
    (tmp_path / "docs" / "n.md").write_text("changed\n")              # docs are not deployed
    assert pre.problems(tmp_path, minimum=None) == []
    (tmp_path / "src" / "a.py").write_text("x = 3\n")
    (tmp_path / "src" / "new.py").write_text("y = 1\n")               # untracked counts: the asset copies the directory
    (p,) = pre.problems(tmp_path, minimum=None)
    assert p["error"] == "working_tree_dirty" and sorted(p["actual"]) == ["src/a.py", "src/new.py"]
    assert pre.problems(tmp_path, minimum=None, allow_dirty=True) == []


def test_a_commit_older_than_the_floor_is_refused(tmp_path):
    pre = _script("preflight.py")
    git, first = _repo(tmp_path)
    head = git("rev-parse", "HEAD")
    assert pre.problems(tmp_path, minimum=first) == []                # the floor is an ancestor: fine
    assert pre.problems(tmp_path, minimum=head) == []                 # HEAD itself
    git("checkout", "-q", first)
    (p,) = pre.problems(tmp_path, minimum=head)
    assert p["error"] == "commit_older_than_minimum" and p["limit"] == head and p["actual"] == first


def test_the_floor_in_the_repo_is_the_r11_commit_and_exists():
    pre = _script("preflight.py")
    if pre.MIN_DEPLOYABLE is None:
        pytest.skip("public sample: its history starts after the migration, there is no floor commit")
    assert pre.MIN_DEPLOYABLE.startswith("620b1f5")
    assert pre.problems(ROOT, minimum=pre.MIN_DEPLOYABLE, allow_dirty=True) == []


def test_a_floor_that_is_not_in_the_clone_is_unknown_not_too_old():
    # 2026-11-12: CI's shallow clone lacked 620b1f5 and the guard said "older than the minimum" about HEAD
    pre = _script("preflight.py")
    [p] = pre.problems(ROOT, minimum="0" * 40, allow_dirty=True)
    assert p["error"] == "minimum_commit_unknown" and p["limit"] == "0" * 40


@pytest.mark.skipif(not (ROOT / ".gitlab-ci.yml").exists(), reason="public sample: CI is GitHub Actions")
def test_ci_clones_the_full_history_the_guard_needs():
    assert 'GIT_DEPTH: "0"' in (ROOT / ".gitlab-ci.yml").read_text()


def test_deploy_all_runs_the_preflight_and_the_site_comparison():
    sh = (ROOT / "scripts" / "deploy-all.sh").read_text()
    build, pre = sh.index("./scripts/build-lambda.sh"), sh.index("scripts/preflight.py")
    assert pre < build, "the preflight runs before anything is built or deployed"
    assert sh.index("site_diff.py snapshot") < sh.index("npx -y aws-cdk") < sh.index("site_diff.py compare")


# --- what the site showed before and after -------------------------------------------------------------------------

def _doc(events):
    return {"events": [{"event_id": e[0], "domain": e[1], "severity": e[2], "item_count": e[3], "title": e[0]} for e in events]}


BEFORE = _doc([("ev_binance", "web3", "P1", 540), ("ev_linux", "vuln", "P0", 2)] + [(f"ev_{n}", "vuln", "P2", 1) for n in range(98)])


def test_the_2026_11_12_site_change_fails_the_comparison():
    diff = _script("site_diff.py")
    after = _doc([("ev_linux", "vuln", "P0", 703)] + [(f"ev_{n}", "vuln", "P2", 1) for n in range(98)])
    codes = {f["error"] for f in diff.compare(diff.snapshot(BEFORE), diff.snapshot(after))}
    assert {"top_event_gone", "event_grew"} <= codes


def test_an_ordinary_cycle_passes_and_each_limit_has_its_own_failure():
    diff = _script("site_diff.py")
    b = diff.snapshot(BEFORE)
    same = _doc([("ev_binance", "web3", "P1", 548), ("ev_linux", "vuln", "P0", 3), ("ev_new", "vuln", "P0", 1)]
                + [(f"ev_{n}", "vuln", "P2", 1) for n in range(98)])
    assert diff.compare(b, diff.snapshot(same)) == []
    half = _doc([("ev_binance", "web3", "P1", 540), ("ev_linux", "vuln", "P0", 2)] + [(f"ev_{n}", "vuln", "P2", 1) for n in range(30)])
    assert [f["error"] for f in diff.compare(b, diff.snapshot(half))] == ["event_count_changed"]
    p0s = _doc([("ev_binance", "web3", "P1", 540), ("ev_linux", "vuln", "P0", 2)] + [(f"ev_{n}", "vuln", "P0", 1) for n in range(98)])
    assert [f["error"] for f in diff.compare(b, diff.snapshot(p0s))] == ["p0_count_changed"]
    moved = _doc([("ev_binance", "vuln", "P1", 540), ("ev_linux", "vuln", "P0", 2)] + [(f"ev_{n}", "vuln", "P2", 1) for n in range(98)])
    assert [f["error"] for f in diff.compare(b, diff.snapshot(moved))] == ["event_changed_domain"]


def test_no_baseline_is_said_not_passed():
    diff = _script("site_diff.py")
    (f,) = diff.compare(None, diff.snapshot(BEFORE))
    assert f["error"] == "no_baseline" and f["level"] == "skip"


def test_every_function_carries_the_deployed_commit_and_verify_checks_it():
    stack = (ROOT / "infra" / "stack.py").read_text()
    assert '"RADAR_COMMIT": self.node.try_get_context("commit") or "unknown"' in stack
    assert '-c "commit=$(git rev-parse --short HEAD)"' in (ROOT / "scripts" / "deploy-all.sh").read_text()
    assert "deployed commit is HEAD" in (ROOT / "scripts" / "verify.sh").read_text()
