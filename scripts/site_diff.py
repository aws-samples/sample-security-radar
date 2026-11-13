#!/usr/bin/env python3
"""Did the deployment change what the site shows beyond what one cycle does? (roadmap R0.4)

  site_diff.py snapshot <events.json> > before.json      # before deploying (missing file ⇒ no baseline)
  site_diff.py compare before.json <events.json>          # after the verification cycle; exit 1 on a failure

Live 2026-11-12: the top event changed from a theft (540 reports) to a vulnerability with 703 reports and every
acceptance check stayed green. The comparison is deliberately coarse: it catches a site that changed shape, not a
single wrong report (that is radar.anomaly, every cycle).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

EVENT_COUNT_RATIO = 0.3     # listed events may move this much
P0_COUNT_ABS, P0_COUNT_RATIO = 5, 0.5
TOP_N = 5                   # the largest events must still be there, in the same domain …
GROWTH = 2                  # … and not have doubled (from at least GROWTH_MIN reports)
GROWTH_MIN = 20


def snapshot(doc: dict[str, Any]) -> dict[str, Any]:
    evs = doc.get("events") or []
    return {"events": len(evs), "p0": sum(1 for e in evs if e.get("severity") == "P0"),
            "by_id": {e["event_id"]: {"domain": e.get("domain"), "items": e.get("item_count") or 0,
                                      "title": (e.get("title") or "")[:80]} for e in evs}}


def _fail(code: str, message: str, actual: Any, limit: Any, level: str = "fail") -> dict[str, Any]:
    return {"error": code, "level": level, "message": message, "actual": actual, "limit": limit}


def compare(before: dict[str, Any] | None, after: dict[str, Any]) -> list[dict[str, Any]]:
    if before is None:
        return [_fail("no_baseline", "no snapshot from before the deployment — nothing compared", None, "a snapshot", "skip")]
    out = []
    b, a = before["events"], after["events"]
    if b and abs(a - b) > EVENT_COUNT_RATIO * b:
        out.append(_fail("event_count_changed", "the number of listed events moved", f"{b} → {a}", f"±{EVENT_COUNT_RATIO:.0%}"))
    pb, pa = before["p0"], after["p0"]
    if abs(pa - pb) > max(P0_COUNT_ABS, P0_COUNT_RATIO * pb):
        out.append(_fail("p0_count_changed", "the number of P0 events moved", f"{pb} → {pa}",
                         f"±max({P0_COUNT_ABS}, {P0_COUNT_RATIO:.0%})"))
    top = sorted(before["by_id"].items(), key=lambda kv: -kv[1]["items"])[:TOP_N]
    for eid, was in top:
        if was["items"] < GROWTH_MIN:
            continue
        now = after["by_id"].get(eid)
        if now is None:
            out.append(_fail("top_event_gone", f"a top event is no longer listed: {was['title']}", eid, "still listed"))
        elif now["domain"] != was["domain"]:
            out.append(_fail("event_changed_domain", f"a top event changed domain: {was['title']}",
                             f"{was['domain']} → {now['domain']}", "same domain"))
    for eid, now in after["by_id"].items():
        was = before["by_id"].get(eid)
        if was and now["items"] >= GROWTH_MIN and now["items"] >= GROWTH * max(was["items"], GROWTH_MIN // GROWTH):
            out.append(_fail("event_grew", f"an event multiplied in size: {now['title']}",
                             f"{was['items']} → {now['items']}", f"×{GROWTH}"))
    return out


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[1] == "snapshot":
        p = Path(argv[2])
        print(json.dumps(snapshot(json.loads(p.read_text())) if p.exists() and p.stat().st_size else None))
        return 0
    if len(argv) == 4 and argv[1] == "compare":
        found = compare(json.loads(Path(argv[2]).read_text()), snapshot(json.loads(Path(argv[3]).read_text())))
        for f in found:
            print(f"{'SKIP' if f['level'] == 'skip' else 'FAIL'}  site: {f['error']} — {f['message']} "
                  f"(actual {f['actual']!r}, limit {f['limit']!r})")
        if not found:
            print("PASS  site shows the same shape as before the deployment")
        return 1 if any(f["level"] == "fail" for f in found) else 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
