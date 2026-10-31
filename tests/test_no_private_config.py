"""The operator's own channel configuration never enters the repository (Neo 2026-10-31: 「我的这些私有的信息不要推送到
线上去 … Slack 和 Lark 都不要推送上去」). Identifiers and tokens live in ~/.env and AWS Secrets Manager only
(scripts/set-notify.sh); a tracked file carrying one fails here, before any push."""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = {
    "lark app id": re.compile(r"\bcli_[0-9a-f]{16}\b"),
    "lark chat id": re.compile(r"\boc_[0-9a-f]{32}\b"),
    "lark user open_id": re.compile(r"\bou_[0-9a-f]{32}\b"),
    "slack token": re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}"),
    "slack webhook": re.compile(r"hooks\.slack\.com/(?:services|workflows)/[A-Za-z0-9/]+"),
}


def tracked() -> list[Path]:
    out = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
    return [ROOT / f for f in out if f and not f.endswith((".png", ".jpg", ".webp", ".gz", ".woff2"))]


def test_no_operator_channel_identifiers_are_tracked():
    hits = []
    for p in tracked():
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
        hits += [f"{p.relative_to(ROOT)}: {name}" for name, rx in PRIVATE.items() if rx.search(text)]
    assert not hits, hits


def test_the_patterns_catch_what_they_name():
    # assembled at run time so no token- / webhook-shaped literal sits in the source (public secret scanners)
    samples = {"lark app id": "cli_" + "a" * 16, "lark chat id": "oc_" + "b" * 32, "lark user open_id": "ou_" + "c" * 32,
               "slack token": "xox" + "b-" + "1" * 12, "slack webhook": ".".join(("hooks", "slack", "com")) + "/services/T0/B0/x"}  # noqa: FLY002 — no webhook literal in source
    assert all(PRIVATE[k].search(v) for k, v in samples.items())
