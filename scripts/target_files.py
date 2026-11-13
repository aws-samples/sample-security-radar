"""The files of one demo target that may leave this machine: its git-tracked files, nothing else.

  uv run -q python -I scripts/target_files.py zip <target-dir> <out.zip>     # build-targets.sh

Both ways a target leaves — the S3 zip (build-targets.sh) and the mirror repositories (sync-fleet.py) — go through
`tracked()`. The working tree is not the target: wp-storefront's docker-compose.yml asks for a `.env` in its directory
and a local `npm install` leaves node_modules/, and every byte that leaves is scanned and paid for.
"""
from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

FIXED_MTIME = (2026, 1, 1, 0, 0, 0)   # sorted names + fixed mtime ⇒ the same tree gives the same zip bytes


def tracked(target: Path) -> list[Path]:
    """Paths (relative to `target`) of the files git tracks under it that exist in the working tree, sorted."""
    # git prints paths relative to its cwd and limited to it; -z ⇒ names with spaces / newlines survive
    out = subprocess.run(["git", "ls-files", "-z"], cwd=target, check=True, capture_output=True).stdout
    files = sorted(Path(p) for p in out.decode("utf-8").split("\0") if p and (target / p).is_file())
    if not files:
        raise SystemExit(f"[target_files] no git-tracked files in {target} — `git add` the target first")
    return files


def zip_target(target: Path, out: Path) -> None:
    # python zipfile, not the zip CLI: CI images do not all ship it
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for rel in tracked(target):
            z.writestr(zipfile.ZipInfo(rel.as_posix(), FIXED_MTIME), (target / rel).read_bytes())


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[0] != "zip":
        raise SystemExit("usage: target_files.py zip <target-dir> <out.zip>")
    zip_target(Path(argv[1]), Path(argv[2]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
