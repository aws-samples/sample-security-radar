"""destroy-stage.sh runs end to end with uv / npx stubbed on PATH (GitHub issue #13: a comment on the `uv run` line
swallowed the arguments and the heredoc, the Python ran as shell, and neither the cleanup nor `cdk destroy` ran).
Nothing leaves the machine: the stubs log what they were handed."""
from __future__ import annotations

import re
import shutil
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

UV = r'''#!/usr/bin/env bash
printf '%s\n' "$*" >> "$CAP/uv"
if [ "$*" = "run -q python -I - security-radar-t1 PACK SPACE" ]; then cat > "$CAP/heredoc"; fi
case "$*" in *"-c"*) printf '%s' "${OUT_VALUE:-}";; esac
exit 0
'''
NPX = '#!/usr/bin/env bash\nprintf \'%s\\n\' "$*" >> "$CAP/npx"\n'


def _sandbox(tmp: Path) -> tuple[Path, dict[str, str]]:
    repo, bin_, cap = tmp / "repo", tmp / "bin", tmp / "cap"
    (repo / "scripts").mkdir(parents=True)
    (repo / "infra").mkdir()
    bin_.mkdir(); cap.mkdir()
    shutil.copy(ROOT / "scripts" / "destroy-stage.sh", repo / "scripts")
    (repo / "scripts" / "lib.sh").write_text('SUFFIX="-$STAGE"\nout() { case "$1" in RequirementPackId) echo PACK;; '
                                             'AgentSpaceId) echo SPACE;; esac; }\n')
    for name, body in (("uv", UV), ("npx", NPX)):
        f = bin_ / name
        f.write_text(body); f.chmod(f.stat().st_mode | stat.S_IEXEC)
    env = {"PATH": f"{bin_}:/usr/bin:/bin", "CAP": str(cap), "STAGE": "t1", "HOME": str(tmp)}
    return repo, env


def test_destroy_stage_runs_its_cleanup_program_and_reaches_cdk_destroy(tmp_path):
    repo, env = _sandbox(tmp_path)
    r = subprocess.run(["bash", "scripts/destroy-stage.sh"], cwd=repo, env=env, stdin=subprocess.DEVNULL, check=False,
                       capture_output=True, text=True, timeout=30)
    cap = Path(env["CAP"])
    assert r.returncode == 0, r.stderr
    assert "command not found" not in r.stderr
    prog = (cap / "heredoc").read_text()                       # the Python went to python's stdin, with its args
    assert prog.startswith("import sys, boto3") and "delete_environment" in prog
    assert "destroy SecurityRadar-t1 SecurityRadarMitigateDemo-t1 SecurityRadarContinuum-t1 -c stage=t1 --force" \
        in (cap / "npx").read_text()


def test_destroy_stage_refuses_the_live_deployment(tmp_path):
    repo, env = _sandbox(tmp_path)
    r = subprocess.run(["bash", "scripts/destroy-stage.sh"], cwd=repo, env={**env, "STAGE": ""},
                       stdin=subprocess.DEVNULL, check=False, capture_output=True, text=True, timeout=30)
    assert r.returncode == 1 and "refusing" in r.stderr and not (Path(env["CAP"]) / "npx").exists()


# a trailing comment that holds what looks like the command's own arguments or a heredoc operator: bash drops it
_SWALLOWED = re.compile(r'^\s*[^#\s][^#]*\s#[^\n]*(<<-?\s*[\'"]?\w+|"\$\{?\w+)')


def test_no_shell_script_hides_arguments_or_a_heredoc_inside_a_trailing_comment():
    bad = []
    for f in sorted([*ROOT.glob("scripts/**/*.sh"), *ROOT.glob("integrations/**/*.sh")]):
        for n, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
            if _SWALLOWED.match(line) and "'" not in line.split("#", 1)[0][-1:]:
                bad.append(f"{f.relative_to(ROOT)}:{n}: {line.strip()[:120]}")
    assert not bad, "a trailing comment swallows arguments / a heredoc (issue #13):\n" + "\n".join(bad)


def test_the_lint_catches_the_issue_13_line():
    assert _SWALLOWED.match('''uv run -q python -I -   # boto3 env "$name" "$pack" "$space" <<'PY\'''')
    assert not _SWALLOWED.match('''uv run -q python -I - "$name" <<'PY'   # boto3''')
    assert not _SWALLOWED.match("# a full-line comment mentioning <<'PY' is fine")
