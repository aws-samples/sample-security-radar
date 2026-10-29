"""R15: the respond station end to end — moto DynamoDB + a fake continuum_aws, three cycles of one real event.

The pieces (decide / apply / prune_plan / the scan clock) are unit-tested; this checks the wiring between them in
handlers.respond_events: channel routing from targets.CHANNEL, the per-environment 24 h scan clock, ledger counters,
the daily rule prune, and that state survives between cycles through the store."""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from test_handlers import env  # noqa: F401  (fixture)
from test_store_contract import table as _table  # noqa: F401  (fixture used by env)

from radar import continuum_aws as A
from radar import respond, timeutil
from radar.model import Event, Item

ROOT = Path(__file__).resolve().parents[1]
FX = ROOT / "tests" / "fixtures" / "events" / "php2shell.json"
DEMO = ROOT / "integrations" / "continuum" / "targets"
EVENT_FIELDS = set(Event.__dataclass_fields__)


def _seed(store) -> str:
    d = json.loads(FX.read_text())
    ev = d["event"]
    items = [Item(item_id=i["item_id"], source_id=i["source_id"], tier=i["tier"], org=i["source_name"], domain=ev["domain"],
                  url=i["url"], canonical_url=i["url"], title=i["title"], text=i.get("excerpt") or "", published_at=i["published_at"],
                  fetched_at=i["published_at"], content_hash=i["item_id"], keys=[], links=[], entity=None, eventful=True,
                  signals=i.get("signals") or {}, extra={}) for i in d["items"]]
    for it in items:
        store.put_item(it)
    store.put_event(Event(**{k: v for k, v in ev.items() if k in EVENT_FIELDS},
                          item_ids=[i.item_id for i in items], keys=[], analysis=d.get("analysis")))
    return ev["last_updated"]


class FakeAws:
    """Records every executed op; answers like the live API did."""

    def __init__(self) -> None:
        self.ops: list[tuple[str, str | None]] = []
        self.pack = ["radar-ev-merged-away-long-ago"]
        self.deleted: list[str] = []

    def ensure_environment(self, _ids: list[str], github_retry: bool = True) -> dict[str, Any]:
        return {"integration_id": "i-s3", "environment_id": "e-s3", "github_integration_id": "i-gh",
                "github_environment_id": "e-gh", "github_repo": "o/fleet"}

    def load_targets(self, rows: list[tuple[str, str, str]]) -> list[respond.Target]:
        ids = [r[0] for r in rows]
        return [respond.Target(t, t, t, {f"{t}/{p.relative_to(DEMO / t)}": p.read_text()
                                         for p in sorted((DEMO / t).rglob("*")) if p.is_file()} if (DEMO / t).exists() else {},
                               uploaded_at="2026-10-28T00:00:00Z") for t in ids]

    def execute(self, op: respond.Op, *_: Any) -> dict[str, Any]:
        self.ops.append((op.kind, op.target_id))
        k = op.kind
        if k.startswith("submit_finding"):
            return {"finding_id": f"f-{op.payload['uid'][-6:]}", "status": "SUBMITTED", "title": "t"}
        if k.startswith("request_scan"):
            return {"scan_run_id": f"s-{len(self.ops)}", "status": "BUILDING"}
        if k.startswith("poll_continuum"):
            return {"findings": [], "issues": [], "issues_complete": False, "scan": {"status": "SUCCEEDED"}}
        if k == "start_review":
            return {"code_review_id": "cr", "job_id": "j", "status": "SUBMITTED"}
        if k == "poll_review":
            return {"status": "IN_PROGRESS", "findings": None}
        return {"ok": True}

    def resources(self, _e: dict[str, Any]) -> list[dict[str, Any]]:
        return []

    def requirement_names(self) -> list[str]:
        return list(self.pack)

    def delete_requirements(self, names: list[str]) -> list[str]:
        self.deleted += names
        return []


@pytest.fixture
def station(env, monkeypatch):  # noqa: F811
    h, _s3 = env
    for k, v in {"SA_AGENT_SPACE_ID": "as", "SA_PACK_ID": "pk", "CN_GITHUB_REPO": "o/fleet"}.items():
        monkeypatch.setenv(k, v)
    fake = FakeAws()
    for name in ("ensure_environment", "load_targets", "execute", "resources", "requirement_names", "delete_requirements"):
        monkeypatch.setattr(A, name, getattr(fake, name))
    monkeypatch.setattr(h, "_sync_prs", lambda led, now: [])
    monkeypatch.setattr(h, "_notify", lambda led, now: None)
    monkeypatch.setattr(h.cost, "due", lambda led, now: False)
    start = datetime.fromisoformat(_seed(h._store)) + timedelta(minutes=10)
    clock = {"now": start}
    monkeypatch.setattr(timeutil, "now", lambda: clock["now"])
    return h, fake, clock


def test_three_cycles_route_scan_once_per_day_and_prune_daily(station):
    h, fake, clock = station
    h.respond_events({"changed": []})
    first = list(fake.ops)
    # PHP2Shell locates demo-shop, which is on the GitHub channel: its findings go there and nowhere else
    assert ("submit_finding_gh", "demo-shop") in first and not [o for o in first if o[0] == "submit_finding"]
    assert not [o for o in first if o[0].startswith("request_scan")]     # nothing accepted yet ⇒ no scan
    led = h._store.get_source_state(h.CONTINUUM_KEY)
    assert led["counters"]["github_findings_submitted"] >= 1 and led["requirements"]   # the synced rule has a clock
    assert led["requirements_pruned_on"] == clock["now"].isoformat()[:10]
    assert "radar-ev-merged-away-long-ago" in led["requirements"] and not fake.deleted  # first seen ⇒ grace, kept

    clock["now"] += timedelta(minutes=10)
    h.respond_events({"changed": []})
    second = fake.ops[len(first):]
    assert [o for o in second if o[0] == "request_scan_gh"] and not [o for o in second if o[0].startswith("submit_finding")]

    clock["now"] += timedelta(minutes=10)
    eid = json.loads(FX.read_text())["event"]["event_id"]
    st = h._store.get_response(eid)              # a finding accepted after that scan (e.g. a new pin): it wants a scan…
    next(iter(st["github"]["findings"].values()))["submitted_at"] = timeutil.iso(clock["now"])
    h._store.put_response(eid, st)
    n = len(fake.ops)
    h.respond_events({"changed": []})
    assert not [o for o in fake.ops[n:] if o[0].startswith("request_scan")]   # …but ≤ 1 scan per environment per 24 h
    st = h._store.get_response(eid)
    assert st["github"]["findings"] and st["github"]["scan"]["scan_run_id"]

    clock["now"] += timedelta(hours=25)                                        # the clock has run out: the waiting finding scans
    n = len(fake.ops)
    h.respond_events({"changed": []})
    assert [o for o in fake.ops[n:] if o[0] == "request_scan_gh"]

    clock["now"] += timedelta(days=15)                                         # a stale rule ages out of the pack
    h.respond_events({"changed": []})
    assert fake.deleted == ["radar-ev-merged-away-long-ago"]
