"""scripts/destroy-stage.sh must hand its cleanup program to Python and then reach `cdk destroy`.

#13: a `#` comment placed before `"$name" "$pack" "$space" <<'PY'` swallowed the arguments and the heredoc, so the
Python lines ran as shell commands (`import: command not found`, exit 127) and the stage was never destroyed.
Run the real script with `uv` and `npx` stubbed on PATH: no AWS call is made."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

UV_STUB = """#!/usr/bin/env bash
# uv run -q python -I <args>: `-c` snippets (lib.sh) run for real, the stdin program (`-`) is recorded, not run
while [ "$1" != python ]; do shift; done; shift
if [ "$2" = - ]; then
  shift 2
  printf '%s\\n' "$@" > "$LOG/py-args"; cat > "$LOG/py-stdin"
else
  exec python3 "$@"
fi
"""
NPX_STUB = """#!/usr/bin/env bash
printf '%s\\n' "$@" > "$LOG/npx-args"
"""


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_destroy_stage_runs_the_cleanup_program_then_cdk_destroy(tmp_path):
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    (repo / "infra").mkdir()
    (repo / "build").mkdir()
    for name in ("destroy-stage.sh", "lib.sh"):
        shutil.copy(ROOT / "scripts" / name, repo / "scripts" / name)
    outputs = {"SecurityRadarDemo": {"RequirementPackId": "pack-1", "AgentSpaceId": "space-1"}}
    (repo / "build" / "outputs-demo.json").write_text(json.dumps(outputs))

    bin_dir, log = tmp_path / "bin", tmp_path / "log"
    bin_dir.mkdir()
    log.mkdir()
    for name, body in (("uv", UV_STUB), ("npx", NPX_STUB)):
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)

    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "LOG": str(log),
           "STAGE": "demo", "AWS_PROFILE": "test-not-used"}
    run = subprocess.run(["bash", "scripts/destroy-stage.sh"], cwd=repo, env=env, stdin=subprocess.DEVNULL,
                         capture_output=True, text=True, timeout=60, check=False)

    assert run.returncode == 0, run.stderr
    assert (log / "py-args").read_text().split() == ["security-radar-demo", "pack-1", "space-1"]
    assert (log / "py-stdin").read_text().startswith("import sys, boto3")
    npx = (log / "npx-args").read_text().split()
    assert "destroy" in npx and "SecurityRadarDemo" in npx and "stage=demo" in npx
