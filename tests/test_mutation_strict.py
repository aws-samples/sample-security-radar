"""R8.6: the strict-mutation hook (tests/conftest.py) — a run whose failures are all does-not-run crashes exits 0
under RADAR_MUTATION_STRICT=1, a real assertion failure still exits 1, and ordinary runs are untouched."""
import os
import subprocess
import sys
import textwrap

import pytest
from conftest import crash_only


@pytest.mark.parametrize(("msgs", "crash"), [
    (["NameError: name 'x' is not defined"], True),
    (["ImportError: cannot import name 'y' from 'radar.z'"], True),
    (["AttributeError: module 'radar.fetch' has no attribute '_open'"], True),
    (["AttributeError: 'NoneType' object has no attribute 'group'"], False),     # a real behaviour change
    (["AssertionError: assert 1 == 2"], False),
    (["NameError: n", "AssertionError: a"], False),                              # one real failure is enough
    ([], False),
])
def test_crash_only(msgs, crash):
    assert crash_only(msgs) is crash


def _run(tmp_path, body, strict):
    (tmp_path / "test_x.py").write_text(textwrap.dedent(body))
    (tmp_path / "conftest.py").write_text((__import__("pathlib").Path(__file__).parent / "conftest.py").read_text())
    env = {**os.environ, "RADAR_MUTATION_STRICT": "1" if strict else ""}
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "no:xdist", str(tmp_path)],
                          cwd=tmp_path, env=env, capture_output=True, text=True, check=False).returncode


def test_a_crash_only_run_is_not_red_under_strict_and_is_red_otherwise(tmp_path):
    body = "def test_a():\n    undefined_name()\n"
    assert _run(tmp_path, body, strict=True) == 0
    assert _run(tmp_path, body, strict=False) == 1


def test_an_assertion_failure_stays_red_under_strict(tmp_path):
    assert _run(tmp_path, "def test_a():\n    assert 1 == 2\n", strict=True) == 1


def test_a_tool_skip_fails_in_ci_and_other_skips_do_not(tmp_path):
    body = ("import pytest\n"
            "@pytest.mark.skipif(True, reason='jq not installed')\ndef test_tool(): pass\n"
            "@pytest.mark.skipif(True, reason='live AWS check: set RADAR_LIVE=1')\ndef test_live(): pass\n")
    (tmp_path / "test_x.py").write_text(body)
    (tmp_path / "conftest.py").write_text((__import__("pathlib").Path(__file__).parent / "conftest.py").read_text())
    def run(flag):
        env = {**os.environ, "RADAR_NO_TOOL_SKIPS": flag, "RADAR_MUTATION_STRICT": ""}
        return subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "no:xdist", str(tmp_path)],
                              cwd=tmp_path, env=env, capture_output=True, text=True, check=False)
    strict, lax = run("1"), run("")
    assert strict.returncode == 1 and "RADAR_NO_TOOL_SKIPS" in strict.stdout and "1 skipped" in strict.stdout
    assert lax.returncode == 0
