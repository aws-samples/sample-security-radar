"""Generate the stage enum's copies from radar.stages.STAGES (the one source; 04-reconstruction W1 / B7):

  schemas/site-data.schema.json   $defs.AttackStage
  ui/src/generated/stages.ts      the UI stage table

  uv run python scripts/gen_stages.py            # rewrite both (then `cd ui && npm run -s gen:types`)
  uv run python scripts/gen_stages.py --check    # exit 1 if either is stale (tests/test_stages.py runs the same check)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

SCHEMA = ROOT / "schemas" / "site-data.schema.json"
UI = ROOT / "ui" / "src" / "generated" / "stages.ts"


def render() -> dict[Path, str]:
    """{path: wanted content} — the schema keeps every other byte, only $defs.AttackStage is replaced."""
    from radar import stages
    schema = json.loads(SCHEMA.read_text())
    schema["$defs"]["AttackStage"] = stages.schema_def()
    return {SCHEMA: json.dumps(schema, indent=2, ensure_ascii=False) + "\n", UI: stages.ui_module()}


def stale() -> list[Path]:
    return [p for p, want in render().items() if not p.exists() or p.read_text() != want]


def main() -> int:
    if "--check" in sys.argv:
        bad = stale()
        for p in bad:
            print(f"stale: {p.relative_to(ROOT)} — run `uv run python scripts/gen_stages.py`", file=sys.stderr)
        return 1 if bad else 0
    for p, want in render().items():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(want)
        print(f"wrote {p.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
