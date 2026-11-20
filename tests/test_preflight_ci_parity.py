"""Every command CI runs per commit is either run by the preflight first or listed as CI-only with a reason
(Neo 2026-11-19: an axe violation reached the site because only CI ran axe)."""
import importlib.util
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("preflight", ROOT / "scripts" / "preflight.py")
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


def ci_commands() -> list[str]:
    doc = yaml.safe_load((ROOT / ".gitlab-ci.yml").read_text())
    out = []
    for name, job in doc.items():
        if isinstance(job, dict) and "script" in job and name not in ("pages",):
            out += [re.sub(r"\s+#.*$", "", c).strip() for c in job["script"] if isinstance(c, str)]
    return out


SCRIPT = (ROOT / preflight.CI_PARITY_SCRIPT).read_text()


def covered(cmd: str) -> bool:
    core = cmd.removeprefix("cd ui && ").removeprefix("cd .. && ")
    return core in SCRIPT or any(k in cmd for k in preflight.CI_ONLY)


@pytest.mark.skipif(not (ROOT / ".gitlab-ci.yml").exists(), reason="no GitLab pipeline in this copy (the public sample)")
def test_every_ci_command_runs_before_a_deployment_or_says_why_not():
    missing = [c for c in ci_commands() if not covered(c)]
    assert missing == []


def test_axe_and_the_ui_build_are_in_the_preflight():
    names = re.findall(r"^check (\w+) ", SCRIPT, re.MULTILINE)
    assert {"ui_a11y", "ui_build", "ui_test", "ui_typecheck", "ruff", "pyright_ratchet"} <= set(names)
    assert names.index("ui_build") < names.index("ui_a11y")     # axe audits the build it just made
    assert "ci_parity()" in (ROOT / "scripts" / "preflight.py").read_text().split("def main")[1]


def test_the_deployment_synthesizes_with_cdk_nag():
    assert "-c nag=on" in (ROOT / "scripts" / "deploy-all.sh").read_text()


def test_a_copy_without_the_pipeline_deploys_without_the_maintainer_checks(tmp_path, monkeypatch, capsys):
    """The public sample has no .gitlab-ci.yml: its deploy must not need Playwright / shellcheck, and must say so."""
    monkeypatch.setattr(preflight, "ROOT", tmp_path)
    assert preflight.ci_parity() is None
    assert "SKIPPED" in capsys.readouterr().out
