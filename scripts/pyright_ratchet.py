"""pyright on src/radar may only get better (roadmap R6.4). 140 errors at the start (2026-11-15), mostly Optional
narrowing; the few in other categories were read and are false positives (a name bound under the same `if` it is used
under, a single-valued bs4 attribute). Fixing them all at once is a large blind change; a ratchet stops new ones.

  uv run python scripts/pyright_ratchet.py            # CI: fails if the count rose
  uv run python scripts/pyright_ratchet.py --update   # after fixing some: lower the baseline (never raises it)
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "tests" / "fixtures" / "pyright-baseline.json"


def verdict(errors: int, baseline: int) -> tuple[bool, str]:
    """(ok, message): more than the baseline fails; fewer passes and says the baseline can come down."""
    if errors > baseline:
        return False, f"pyright: {errors} errors in src/radar > baseline {baseline} — fix the new ones"
    if errors < baseline:
        return True, f"pyright: {errors} < baseline {baseline} — lower it: scripts/pyright_ratchet.py --update"
    return True, f"pyright: {errors} errors = baseline"


def main() -> int:
    base = json.loads(BASELINE.read_text())
    r = subprocess.run(["uv", "run", "--with", f"pyright=={base['pyright']}", "pyright", "src/radar", "--outputjson"],
                       cwd=ROOT, capture_output=True, text=True, check=False)
    try:
        errors = json.loads(r.stdout)["summary"]["errorCount"]
    except (json.JSONDecodeError, KeyError):
        print(f"pyright did not run: {r.stderr[-400:]}", file=sys.stderr)   # unmeasured is a failure, not a pass
        return 2
    if "--update" in sys.argv:
        if errors < base["errors"]:
            BASELINE.write_text(json.dumps({**base, "errors": errors}) + "\n")
            print(f"baseline {base['errors']} → {errors}")
        return 0
    ok, msg = verdict(errors, base["errors"])
    print(msg)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
