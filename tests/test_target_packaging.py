"""Demo targets reach S3 (build-targets.sh) and the mirror repositories (sync-fleet.py) as their git-tracked files only.

The working tree of a target routinely holds what must never be scanned or pushed: wp-storefront's docker-compose.yml
asks for a `.env` in that directory, and one local `npm install` in node-gateway leaves a node_modules/ — every byte
in a zip or mirror is scanned and paid for.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ROOT / "integrations" / "continuum" / "targets"


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


TF = _load("target_files", "target_files.py")
SF = _load("sync_fleet", "sync-fleet.py")


@pytest.fixture
def target(tmp_path: Path) -> Path:
    """A git repo holding one target: two tracked files, an untracked .env, an ignored node_modules/."""
    repo = tmp_path / "repo"
    t = repo / "targets" / "demo"
    (t / "src").mkdir(parents=True)
    (t / "src" / "server.js").write_text("// tracked\n")
    (t / ".gitignore").write_text("node_modules/\n")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "targets"], check=True)
    (t / ".env").write_text("DB_PASSWORD=not-for-the-scanner\n")         # untracked
    (t / "node_modules" / "x").mkdir(parents=True)
    (t / "node_modules" / "x" / "a.js").write_text("// ignored\n")
    (t / "notes.txt").write_text("untracked scratch\n")
    return t


def test_the_target_zip_holds_only_tracked_files(target, tmp_path):
    out = tmp_path / "demo.zip"
    TF.zip_target(target, out)
    with zipfile.ZipFile(out) as z:
        assert sorted(z.namelist()) == [".gitignore", "src/server.js"]
        assert {i.date_time for i in z.infolist()} == {(2026, 1, 1, 0, 0, 0)}     # reproducible bytes kept


def test_the_mirror_copy_holds_only_tracked_files(target, tmp_path):
    dst = tmp_path / "mirror" / "demo"
    SF.copy_target(target, dst)
    assert sorted(str(p.relative_to(dst)) for p in dst.rglob("*") if p.is_file()) == [".gitignore", "src/server.js"]


def test_a_target_with_no_tracked_files_fails_loudly(tmp_path):
    repo = tmp_path / "repo"
    (repo / "fresh").mkdir(parents=True)
    (repo / "fresh" / "a.txt").write_text("not added yet\n")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    with pytest.raises(SystemExit, match="no git-tracked files"):
        TF.tracked(repo / "fresh")


def test_build_targets_packages_demo_targets_through_the_tracked_file_list(tmp_path):
    # build-targets.sh runs for real in a sandbox repo: one demo target (two tracked files, an untracked .env, an
    # ignored node_modules/) and a stub radar.targets naming only it ⇒ both zips it writes hold the tracked files only
    repo = tmp_path / "repo"
    t = repo / "integrations" / "continuum" / "targets" / "demo"
    (t / "src").mkdir(parents=True)
    (repo / "scripts").mkdir()
    (repo / "src" / "radar").mkdir(parents=True)
    for f in ("build-targets.sh", "target_files.py"):
        (repo / "scripts" / f).write_text((ROOT / "scripts" / f).read_text())
    (repo / "src" / "radar" / "__init__.py").write_text("")
    (repo / "src" / "radar" / "targets.py").write_text(
        'TARGETS = (("demo", "Demo", "s3"),)\n\n\ndef on(channel):\n    return ("demo",)\n')
    (t / "src" / "server.js").write_text("// tracked\n")
    (t / ".gitignore").write_text("node_modules/\n")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    (t / ".env").write_text("DB_PASSWORD=not-for-the-scanner\n")         # untracked
    (t / "node_modules" / "x").mkdir(parents=True)
    (t / "node_modules" / "x" / "a.js").write_text("// ignored\n")
    r = subprocess.run(["bash", str(repo / "scripts" / "build-targets.sh")], check=False, capture_output=True,
                       text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    for out in (repo / "build" / "targets" / "code" / "demo.zip", repo / "build" / "targets-cn" / "demo.zip"):
        with zipfile.ZipFile(out) as z:
            assert sorted(z.namelist()) == [".gitignore", "src/server.js"], out


def test_a_target_whose_ci_runs_npm_ci_has_a_lockfile_matching_its_package_json():
    # `npm ci` exits 1 without package-lock.json ⇒ every Continuum patch would "fail the target's own tests"
    users = [d for d in TARGETS.iterdir() if (d / ".gitlab-ci.yml").is_file() and "npm ci" in (d / ".gitlab-ci.yml").read_text()]
    assert users, "node-gateway's CI runs npm ci"
    for d in users:
        lock = json.loads((d / "package-lock.json").read_text())
        pkg = json.loads((d / "package.json").read_text())
        assert lock["packages"][""]["dependencies"] == pkg["dependencies"], d.name
        for name, ver in pkg["dependencies"].items():
            assert lock["packages"][f"node_modules/{name}"]["version"] == ver, (d.name, name)
        resolved = {v["resolved"] for v in lock["packages"].values() if "resolved" in v}
        assert resolved and all(r.startswith("https://registry.npmjs.org/") for r in resolved), d.name   # public repo
