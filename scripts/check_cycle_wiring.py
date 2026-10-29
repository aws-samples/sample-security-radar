"""Synth-time check of the Cycle state machine: a manual `{"full": true}` run must reach Publish.

  (cd infra && npx aws-cdk synth -q) && uv run python scripts/check_cycle_wiring.py [infra/cdk.out/SecurityRadar.template.json]

Every top-level station whose input is narrowed by a Payload/Parameters object must forward `full` (live 2026-10-24:
Process received only `results`, so a full republish silently became an incremental one — roadmap R5). Runs in the
infra-synth CI job because only that job has a synthesized template."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def definition(template: dict[str, Any]) -> dict[str, Any]:
    sm = next(r for r in template["Resources"].values() if r["Type"] == "AWS::StepFunctions::StateMachine")
    d = sm["Properties"]["DefinitionString"]
    if isinstance(d, dict):  # Fn::Join over literal chunks + intrinsics (ARNs) ⇒ intrinsics become placeholders
        d = "".join(p if isinstance(p, str) else "ARN" for p in d["Fn::Join"][1])
    return json.loads(d)


def violations(defn: dict[str, Any]) -> list[str]:
    bad = []
    for name, s in defn["States"].items():
        narrowed = s.get("Parameters") or s.get("Arguments") or {}
        narrowed = narrowed.get("Payload", narrowed) if isinstance(narrowed, dict) else {}
        if s.get("Type") == "Task" and narrowed and "full.$" not in narrowed and "full" not in narrowed:
            bad.append(f"{name}: input narrowed to {sorted(narrowed)} — `full` is dropped")
    return bad


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "infra/cdk.out/SecurityRadar.template.json")
    bad = violations(definition(json.loads(path.read_text())))
    for b in bad:
        print(f"FAIL  {b}")
    print("FAIL" if bad else "PASS  every narrowed station forwards `full`")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
