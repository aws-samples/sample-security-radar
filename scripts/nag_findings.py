"""cdk-nag findings → infra/nag_findings.json, the per-resource exemption list (roadmap R5.4).

  uv run python scripts/nag_findings.py            # re-run cdk-nag without exemptions and rewrite the list

Each (rule, resource path) in the list is exempted with the rule's reason from infra/nag.py REASONS; a resource or a
rule not in the list fails `cdk synth -c nag=on`, so a new finding has to be looked at (and the list regenerated
deliberately). The list replaced a whole-stack exemption that also silenced every future resource.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "infra" / "nag_findings.json"
_HEAD = re.compile(r"^(?:ERROR|WARNING) (AwsSolutions-[A-Z0-9]+)(?:\[[^\]]*\])?:")


def parse(log: str) -> dict[str, list[str]]:
    """cdk-nag's synth log → {rule: [resource path, …]} (the path is the first indented line after a finding)."""
    hits: dict[str, set[str]] = defaultdict(set)
    lines = log.splitlines()
    for i, ln in enumerate(lines):
        m = _HEAD.match(ln)
        if not m:
            continue
        for nxt in lines[i + 1:i + 4]:
            p = nxt.strip()
            if p and "/" in p and not p.startswith(("Rule", "Acknowledge")):
                hits[m.group(1)].add("/" + p.lstrip("/"))
                break
    return {k: sorted(v) for k, v in sorted(hits.items())}


def main() -> int:
    r = subprocess.run(["npx", "--yes", "aws-cdk@2.1146.1", "synth", "--all", "-c", "nag=on", "-q"], cwd=ROOT / "infra",
                       env={**os.environ, "NAG_RAW": "1"}, capture_output=True, text=True, check=False)
    found = parse(r.stdout + r.stderr)
    if not found:
        print("no findings parsed — refusing to write an empty list", file=sys.stderr)
        return 2
    OUT.write_text(json.dumps(found, indent=1) + "\n")
    print(f"{sum(map(len, found.values()))} findings in {len(found)} rules → {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
