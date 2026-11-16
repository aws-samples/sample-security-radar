"""Token-shaped strings in tracked files fail CI (roadmap R6.4; global rule: grep for sk- / ghp_ / ABSK before a push).
Pattern-based, like a minimal gitleaks: the shapes of the credentials this project actually handles. No allowlist —
a test fixture that needs a token builds it at runtime (tests/test_secret_scan.py), so the repo never holds one.

  uv run python scripts/secret_scan.py      # exit 1 and file:line (never the match) on a hit
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = {
    "aws_access_key": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    "bedrock_api_key": r"\bABSK[A-Za-z0-9+/=]{20,}",
    "github_token": r"\b(?:ghp|gho|ghs|ghu)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}",
    "gitlab_token": r"\bglpat-[A-Za-z0-9_-]{20,}",
    "slack_token": r"\bxox[abpr]-[0-9A-Za-z-]{10,}",
    "anthropic_key": r"\bsk-ant-[A-Za-z0-9_-]{20,}",
    "firecrawl_key": r"\bfc-[a-f0-9]{32}\b",
    "private_key": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
}
RX = re.compile("|".join(f"(?P<{k}>{v})" for k, v in PATTERNS.items()))


def scan_text(text: str) -> list[tuple[int, str]]:
    """(line number, pattern name) per hit — never the matched value (a log line must not leak what it found)."""
    return [(n, m.lastgroup or "?") for n, line in enumerate(text.splitlines(), 1) for m in RX.finditer(line)]


def main() -> int:
    files = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True, check=True).stdout.split(b"\0")
    hits = []
    for f in filter(None, files):
        p = ROOT / f.decode()
        try:
            text = p.read_text("utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue                        # binary / submodule / deleted in the tree: not text a token could sit in
        hits += [f"{f.decode()}:{n}: {name}" for n, name in scan_text(text)]
    for h in hits:
        print(h)
    print(f"secret scan: {len(hits)} hit(s) in {len(files)} tracked files")
    return 1 if hits else 0


if __name__ == "__main__":
    raise SystemExit(main())
