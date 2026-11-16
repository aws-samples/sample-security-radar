"""R6.4: the secret scan fires on every credential shape it lists, never prints the value, and the repo is clean."""
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("secret_scan", ROOT / "scripts" / "secret_scan.py")
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)

# built at runtime: the repository itself must never contain a token-shaped string
SAMPLES = {
    "aws_access_key": "AKIA" + "Q" * 16,
    "bedrock_api_key": "ABSK" + "Qm9n" * 6,
    "github_token": "ghp" + "_" + "a1" * 18,
    "gitlab_token": "glpat" + "-" + "x" * 20,
    "slack_token": "xox" + "b-" + "1234567890-abc",
    "anthropic_key": "sk-" + "ant-" + "z" * 24,
    "firecrawl_key": "fc-" + "0a" * 16,
    "private_key": "-----BEGIN " + "RSA PRIVATE KEY-----",
}


@pytest.mark.parametrize("name", sorted(scan.PATTERNS))
def test_every_listed_shape_is_caught_by_name_without_its_value(name):
    hits = scan.scan_text(f"line one\nconfig = '{SAMPLES[name]}'\n")
    assert hits == [(2, name)]


def test_ordinary_text_is_not_a_hit():
    assert scan.scan_text("ask- task fc-123 ABSKY glpat ghp_short AKIAshort\n0x" + "ab" * 32) == []


def test_the_repository_is_clean():
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "secret_scan.py")], check=False, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout[-600:]
