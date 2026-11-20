"""A failed deploy check says why (live 11-19: the rule-pack quote check failed once, passed on the re-run, and its
output had been thrown away — which quote failed could not be told)."""
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_a_failing_check_prints_its_last_lines_and_a_passing_one_does_not():
    fn = subprocess.run(["sed", "-n", "/^check() {/,/^}/p", str(ROOT / "scripts" / "verify.sh")], capture_output=True,
                        text=True, check=True).stdout
    script = fn + 'fails=0\ncheck "ok" "echo quiet"\ncheck "bad" "echo first; echo the-reason; false"\necho "fails=$fails"\n'
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True).stdout
    assert "PASS  ok" in out and "quiet" not in out
    assert "FAIL  bad" in out and "the-reason" in out and "fails=1" in out
