"""M3.3 Inspector criteria: lockfiles → SBOM, ScanSbom answer → findings, event ∩ findings. Evidence = a real
ScanSbom call on this repo's uv.lock + ui/package-lock.json + two demo pins (2026-10-29)."""

import json
from pathlib import Path

from radar import inspector as I

ROOT = Path(__file__).resolve().parents[1]
FX = ROOT / "tests" / "fixtures" / "inspector"
DEMO = ROOT / "integrations" / "continuum" / "targets"
SCAN = json.loads((FX / "scan-radar-2026-10-29.json").read_text())


def _files(root: Path, prefix: str) -> dict[str, str]:
    return {f"{prefix}/{p.relative_to(root)}": p.read_text() for p in sorted(root.rglob("*"))
            if p.is_file() and "node_modules" not in p.parts and p.suffix in (".json", ".lock", ".txt", ".toml")}


def test_radar_repo_lockfiles_become_components_with_their_source_file():
    # the lockfiles as scanned on 2026-10-29 (paired with scan-radar-2026-10-29.json), not the live ones —
    # the radar upgraded vitest/vite right after that scan (commit 39876b0), and a test must not move with the repo
    files = {"security-radar/uv.lock": (FX / "uv-2026-10-29.lock").read_text(),
             "security-radar/ui/package-lock.json": (FX / "ui-package-lock-2026-10-29.json").read_text(),
             "security-radar/ui/package.json": (ROOT / "ui" / "package.json").read_text()}
    comps = I.components(files)
    by = {c["purl"]: c for c in comps}
    assert "pkg:npm/vitest@2.1.9" in by and by["pkg:npm/vitest@2.1.9"]["file"] == "security-radar/ui/package-lock.json"
    assert any(p.startswith("pkg:pypi/boto3@") for p in by)
    # package.json is not read where its package-lock.json sits next to it (the lock is the truth)
    assert all(c["file"] != "security-radar/ui/package.json" for c in comps)
    assert len(by) == len(comps)   # unique


def test_exact_pins_in_a_bare_package_json_are_read_and_ranges_are_not():
    comps = I.components(_files(DEMO / "node-gateway", "node-gateway"))
    assert [c["purl"] for c in comps] == ["pkg:npm/express@4.21.2"]
    assert I.components({"x/package.json": json.dumps({"dependencies": {"a": "^1.2.3", "b": "1.2.3"}})}) == [
        {"purl": "pkg:npm/b@1.2.3", "name": "b", "version": "1.2.3", "file": "x/package.json"}]


def test_runtime_only_targets_have_no_components():
    # demo-shop pins only the PHP runtime (composer platform) — Inspector cannot judge that (P0 measurement)
    assert I.components(_files(DEMO / "demo-shop", "demo-shop")) == []


def test_findings_parse_the_real_answer_with_per_component_fixed_versions():
    f = I.findings(SCAN)
    crit = [x for x in f if x["severity"] == "critical"]
    assert [(x["id"], x["purl"]) for x in crit] == [("CVE-2026-47429", "pkg:npm/vitest@2.1.9")]
    assert all(x["fixed"] is None or isinstance(x["fixed"], str) for x in f)
    assert any(x["fixed"] for x in f)
    assert [x["severity"] for x in f] == sorted((x["severity"] for x in f), key=I.SEVERITY_ORDER.index)


def test_event_cves_intersect_target_findings():
    f = I.findings(SCAN)
    assert [x["purl"] for x in I.for_event(["CVE-2026-47429", "CVE-2099-1"], f)] == ["pkg:npm/vitest@2.1.9"]
    assert I.for_event(["CVE-2026-109618"], f) == []   # PHP2Shell is a runtime CVE: not Inspector's to judge


def test_sbom_is_cyclonedx_1_5():
    comps = I.components({"x/package.json": json.dumps({"dependencies": {"b": "1.2.3"}})})
    doc = I.sbom(comps, "x")
    assert (doc["bomFormat"], doc["specVersion"]) == ("CycloneDX", "1.5") and doc["components"][0]["purl"] == "pkg:npm/b@1.2.3"


def test_the_lockfile_wins_over_an_exact_pin_in_the_manifest_next_to_it():
    lock = {"lockfileVersion": 3, "packages": {"": {}, "node_modules/left-pad": {"version": "1.3.0"}}}
    files = {"app/package.json": json.dumps({"dependencies": {"left-pad": "1.0.0"}}), "app/package-lock.json": json.dumps(lock)}
    assert [c["purl"] for c in I.components(files)] == ["pkg:npm/left-pad@1.3.0"]
