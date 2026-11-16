"""`python -m radar.agentkit.cli <tool> [--name value …]` — one JSON document on stdout; exit 1 with the error as JSON.

  python -m radar.agentkit.cli recent_events --severity P0 --hours 24
  python -m radar.agentkit.cli cve_status --cve CVE-2026-12345
  python -m radar.agentkit.cli --list
"""
from __future__ import annotations

import argparse
import json
import sys

from radar.agentkit.client import TOOLS, Radar, RadarError, call


def main(argv: list[str] | None = None, radar: Radar | None = None) -> int:
    ap = argparse.ArgumentParser(prog="radar.agentkit.cli")
    ap.add_argument("--list", action="store_true", help="print the tools and their arguments")
    sub = ap.add_subparsers(dest="tool")
    for name, (desc, props, required) in TOOLS.items():
        p = sub.add_parser(name, help=desc)
        for arg, spec in props.items():
            p.add_argument(f"--{arg}", required=arg in required, type=int if spec["type"] == "integer" else str)
    a = ap.parse_args(argv)
    if a.list or not a.tool:
        print(json.dumps({n: {"description": d, "arguments": p, "required": r} for n, (d, p, r) in TOOLS.items()},
                         ensure_ascii=False, indent=1))
        return 0
    args = {k: v for k, v in vars(a).items() if k not in ("tool", "list") and v is not None}
    try:
        print(json.dumps(call(radar or Radar(), a.tool, args), ensure_ascii=False, indent=1))
        return 0
    except RadarError as e:
        print(json.dumps(e.detail, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
