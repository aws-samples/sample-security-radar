"""A credentialed request never follows a redirect off its host (the 2026-11 security review: the X API call,
deliver_prs.py and sync-fleet.py still did). urllib's redirect handler copies the request headers to the new URL, so
an Authorization / PRIVATE-TOKEN / x-api-key header would reach whatever host the answer names.

Structural, so a new credentialed call cannot forget it: in every file that builds a credential header, every
fetch.urlopen / http_get call passes `allow_hosts` (empty = no redirect at all; a host set = that host only). The agent
kit uses its own _NoRedirect opener (no fetch import) and is checked by name.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CRED = re.compile(r"""["'](?:Authorization|PRIVATE-TOKEN|x-api-key)["']""", re.IGNORECASE)
FILES = sorted(p for d in ("src", "scripts", "integrations") for p in (ROOT / d).rglob("*.py") if CRED.search(p.read_text()))


def test_the_scan_sees_the_known_credentialed_files():
    names = {p.name for p in FILES}
    assert {"fetch.py", "notify.py", "prsync.py", "deliver_prs.py", "sync-fleet.py", "client.py"} <= names


def _opens(tree: ast.AST):
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            f = n.func
            name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
            if name in ("urlopen", "http_get"):
                yield n


@pytest.mark.parametrize("path", FILES, ids=lambda p: str(p.relative_to(ROOT)))
def test_every_open_in_a_credentialed_file_bounds_its_redirects(path):
    src = path.read_text()
    tree = ast.parse(src)
    if path.parent.name == "agentkit":
        assert "_NoRedirect" in src and "fetch.urlopen" not in src
        return
    missing = [n.lineno for n in _opens(tree) if not any(k.arg == "allow_hosts" for k in n.keywords)]
    assert missing == [], f"{path.name}: urlopen / http_get without allow_hosts at lines {missing}"

