"""radar.decisions — the one response decision table: every gate decides, respond fires exactly the table's fire rows,
and every text that restates the table (design doc §2, coverage, schema enums) is generated from it."""
from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from respond_world import ROOT, doc, targets_of

from radar import coverage, decisions, respond
from radar import targets as T
from radar.limits import Limits

NOW = "2026-10-23T18:00:00Z"
NOW_DT = datetime(2026, 10, 23, 18, tzinfo=UTC)
ALL_GATES = [(a.key, g) for a in decisions.ACTIONS for g in decisions.gates(a.key)]


# ------------------------------------------------------------------ the table itself

@pytest.mark.parametrize(("action", "gate"), ALL_GATES, ids=[f"{a}-{g.code}" for a, g in ALL_GATES])
def test_each_gate_decides_when_its_fact_fails(action, gate):
    """Flip exactly this gate's fact (every earlier gate passes): the table answers with this gate's code and outcome.
    Reordering gates or dropping one turns a case red."""
    ctx = {"domain": "incident", "severity": "P1", "exploitation": "reported", "subject": "PHP", "channel": "GitHub"}
    row = decisions.decide(action, decisions.failing_at(action, gate.code), ctx)
    assert (row["outcome"], row["gate"]) == (gate.outcome, gate.code)
    assert "{" not in row["reason"]


@pytest.mark.parametrize("action", [a.key for a in decisions.ACTIONS])
def test_every_gate_passing_fires(action):
    row = decisions.decide(action, {g.fact: True for g in decisions.gates(action)})
    assert row == {"action": action, "scope": None, "outcome": "fire", "gate": None,
                   "reason": decisions.BY_KEY[action].fire_text, "at": None}


def test_a_fact_the_caller_did_not_give_raises_instead_of_passing():
    """Degradation must look different from success: a missing fact is never a silent True (it would buy a scan)."""
    facts = {g.fact: True for g in decisions.gates("cn_scan")}
    facts.pop("scan_clock_open")
    with pytest.raises(KeyError):
        decisions.decide("cn_scan", facts)


def test_codes_are_unique_and_every_limit_is_a_real_limit():
    seen: dict[str, decisions.Gate] = {}
    for _a, g in ALL_GATES:
        assert seen.setdefault(g.code, g) is g, f"{g.code} names two different gates"
        assert g.outcome in decisions.OUTCOMES
        if g.limit:
            assert isinstance(getattr(Limits, g.limit), int | float)
    assert isinstance(getattr(Limits, decisions.SPEND_LINE[0]), int | float)
    # a gate that can only ever be held by a budget is "blocked"; every not-evaluated gate starts with N_/M_/W_UNCHECKED
    assert {g.code for _a, g in ALL_GATES if g.outcome == "blocked"} == {"B_SCAN_INTERVAL", "B_SCAN_THIS_CYCLE",
                                                                           "B_REVIEWS_DAY", "B_NOTIFY_PENDING"}


def test_the_ledger_keys_are_the_stations_own():
    import re

    from radar import mitigate_station, notify_station
    src = (ROOT / "src" / "radar" / "handlers.py").read_text()   # importing handlers builds the DynamoDB store
    key = lambda name: re.search(rf'^{name} = "([^"]+)"', src, re.MULTILINE).group(1)
    assert decisions.LEDGERS == {"respond": key("CONTINUUM_KEY"), "mitigate": mitigate_station.MITIGATE_KEY,
                                 "notify": notify_station.STATUS_KEY}


# ------------------------------------------------------------------ generated restatements

@pytest.mark.skipif(not decisions.DOC.exists(), reason="public sample: the design document is internal")
def test_design_doc_section_is_the_generated_table():
    """CONTINUUM-INTEGRATION.md §2 is `python -m radar.decisions --explain`; a hand edit (or a table change without
    --write) is drift. The stale hand-written lines (new-P0 scans, 6 h debounce, >$500 stop) are gone."""
    text = decisions.DOC.read_text()
    assert decisions.doc_section(text) == decisions.explain()
    assert decisions.check() == []
    assert "6h 去抖" not in text and "有新 finding 或新 P0" not in text
    assert f"{Limits.CONTINUUM_SCAN_MIN_INTERVAL_H} 小时" in decisions.explain()


@pytest.mark.skipif(not decisions.DOC.exists(), reason="public sample: the design document is internal")
def test_check_reports_drift(monkeypatch, tmp_path):
    doc_copy = tmp_path / "doc.md"
    doc_copy.write_text(decisions.DOC.read_text().replace("`B_SCAN_INTERVAL` | `blocked`", "`B_SCAN_INTERVAL` | `not_fire`"))
    monkeypatch.setattr(decisions, "DOC", doc_copy)
    assert decisions.check() and decisions.main(["--check"]) == 1
    monkeypatch.undo()
    schema = json.loads(decisions.SCHEMA.read_text())
    schema["$defs"]["ResponseDecision"]["properties"]["gate"]["enum"].remove("B_SCAN_INTERVAL")
    schema_copy = tmp_path / "schema.json"
    schema_copy.write_text(json.dumps(schema))
    monkeypatch.setattr(decisions, "SCHEMA", schema_copy)
    assert decisions.check() == ["schema ResponseDecision.gate enum differs from the table"]


def test_schema_enums_are_the_table():
    s = json.loads((ROOT / "schemas" / "site-data.schema.json").read_text())
    props = s["$defs"]["ResponseDecision"]["properties"]
    assert props["action"]["enum"] == [a.key for a in decisions.ACTIONS]
    assert props["gate"]["enum"] == [*decisions.codes(), None]
    assert props["outcome"]["enum"] == list(decisions.OUTCOMES)
    # on the event document itself, not inside response: an event with no response state has decisions too
    assert s["oneOf"][1]["properties"]["decisions"]["items"] == {"$ref": "#/$defs/ResponseDecision"}
    assert "decisions" not in s["$defs"]["Response"]["properties"]
    assert set(decisions.DECISION_FIELDS) == set(props)


def test_coverage_trigger_text_comes_from_the_table():
    detail = {c.key: c.detail for c in coverage.CAPABILITIES}
    assert detail["code_scan"] == decisions.describe("cn_scan")
    assert detail["context"] == decisions.describe("cn_context")
    assert detail["code_review"].endswith(decisions.describe("sa_review"))
    assert detail["eligibility"] == decisions.describe_eligibility()
    assert "6 小时" not in detail["code_scan"] and f"{Limits.CONTINUUM_SCAN_MIN_INTERVAL_H} 小时" in detail["code_scan"]
    assert "在野利用" in detail["code_review"]   # coverage used to say 「P0 且…」 only


# ------------------------------------------------------------------ respond fires exactly the table's fire rows

def _scope_of(op: respond.Op) -> tuple[str, str | None]:
    action = next(a.key for a in decisions.ACTIONS if op.kind in a.op_kinds)
    cv = respond._channel_op(op.kind)
    scope = cv[0] if cv and cv[1] == "request_scan" else op.target_id
    return action, scope


def _closure(st: dict, ops: list[respond.Op]) -> None:
    fired = {(r["action"], r["scope"]) for r in st["decisions"].values() if r["outcome"] == "fire"}
    issued = {_scope_of(o) for o in ops if not o.kind.startswith("poll_")}
    assert issued == fired


def _submitted(st: dict, ops: list[respond.Op]) -> dict:
    for o in ops:
        if not o.kind.startswith("poll_") and o.kind != "start_review":
            st = respond.apply(st, o, {"finding_id": f"cf-{o.payload.get('uid', '')[-6:]}", "status": "SUBMITTED",
                                       "scan_run_id": "s1"}, "2026-10-23T12:00:00Z")
    return st


@pytest.mark.parametrize("event", ["php2shell", "node2shell", "php2shell_p1", "php2shell_cooled", "alpscon"])
@pytest.mark.parametrize("scan_ok", [True, False])
def test_respond_issues_an_op_exactly_for_each_fire_row(event, scan_ok):
    """Closure: on real fixtures, the ops decide issues (polls aside) are exactly the table's fire rows, first cycle
    and second cycle (findings submitted ⇒ a scan wanted)."""
    ev, items, analysis = doc(event) if event != "alpscon" else _alpscon()
    budget = respond.Budget(6, scan_ok, "2026-10-23", s3_targets=T.on("s3"), routes=dict(T.CHANNEL), now=NOW)
    st, ops = respond.decide(ev, items, analysis, None, targets_of("fleet"), budget)
    _closure(st, ops)
    st2, ops2 = respond.decide(ev, items, analysis, _submitted(st, ops), targets_of("fleet"),
                               respond.Budget(6, scan_ok, "2026-10-23", s3_targets=T.on("s3"), routes=dict(T.CHANNEL),
                                              now=NOW))
    _closure(st2, ops2)
    if st["eligibility"]["eligible"]:   # the rule and the context document went out in cycle 1: up to date now
        assert st["decisions"]["sa_requirement"]["outcome"] == st["decisions"]["cn_context"]["outcome"] == "fire"
        assert {st2["decisions"][k]["gate"] for k in ("sa_requirement", "cn_context")} == \
            {"U_REQUIREMENT_CURRENT", "U_CONTEXT_SAME"}


@pytest.mark.parametrize(("change", "code"), [
    ({"domain": "incident"}, "E_DOMAIN"),
    ({"severity": "P1", "exploitation": "reported"}, "E_SEVERITY"),
    ({"title": "Cisco IOS XE web UI privilege escalation", "entities": ["cisco"]}, "E_NO_PRODUCT"),
    (None, None),
])
def test_eligibility_codes_follow_the_table(change, code):
    ev, items, _ = doc("php2shell")
    if change and "title" in change:
        items = [{"title": change["title"], "excerpt": ""}]
    out = respond.eligibility({**ev, **(change or {})}, items)
    assert out.get("code") == code and out["eligible"] == (code is None)
    if code:
        gate = next(g for g in decisions.RESPOND_PRE if g.code == code)
        assert out["reason"] == decisions.reason(gate, {"domain": change.get("domain", ev["domain"]),
                                                        "severity": change.get("severity", ev["severity"]),
                                                        "exploitation": change.get("exploitation", ev["exploitation"])})


def test_web3_without_attack_class_or_address_is_e_no_web3_anchor():
    ev, _items, _ = _alpscon()
    out = respond.eligibility({**ev, "title": "Protocol paused after incident"}, [{"title": "paused", "excerpt": ""}])
    assert out["code"] == "E_NO_WEB3_ANCHOR" and not out["eligible"]


def _alpscon():
    d = json.loads((ROOT / "tests" / "fixtures" / "events" / "alpscon.json").read_text())
    return d["event"], d["items"], d.get("analysis")


def _php_world(budget: respond.Budget) -> tuple[dict, list[respond.Op]]:
    ev, items, analysis = doc("php2shell")
    st, ops = respond.decide(ev, items, analysis, None, targets_of("targets"),
                             respond.Budget(6, False, "2026-10-23", now="2026-10-23T11:00:00Z"))
    return respond.decide(ev, items, analysis, _submitted(st, ops), targets_of("targets"), budget)


def test_a_scan_held_by_the_24h_clock_is_blocked_not_skipped():
    st, ops = _php_world(respond.Budget(6, False, "2026-10-23", now=NOW))
    row = st["decisions"]["cn_scan:s3"]
    assert (row["outcome"], row["gate"], row["limit"]) == ("blocked", "B_SCAN_INTERVAL", Limits.CONTINUUM_SCAN_MIN_INTERVAL_H)
    assert not any(o.kind == "request_scan" for o in ops)
    st, ops = _php_world(respond.Budget(6, True, "2026-10-23", now=NOW))
    assert st["decisions"]["cn_scan:s3"]["outcome"] == "fire" and any(o.kind == "request_scan" for o in ops)


def test_the_second_event_of_a_cycle_is_held_by_the_one_scan_per_cycle_gate():
    b = respond.Budget(6, True, "2026-10-23", now=NOW)
    first, _ = _php_world(b)
    assert first["decisions"]["cn_scan:s3"]["outcome"] == "fire"
    second, ops = _php_world(b)   # same budget object = same station cycle
    row = second["decisions"]["cn_scan:s3"]
    assert (row["outcome"], row["gate"]) == ("blocked", "B_SCAN_THIS_CYCLE")
    assert not any(o.kind == "request_scan" for o in ops)


def test_nothing_waiting_is_not_fire_even_with_the_clock_open():
    """Without a submitted finding the scan is not wanted at all — the page must not say 'held by the 24 h clock'."""
    ev, items, analysis = doc("php2shell")
    st, _ops = respond.decide(ev, items, analysis, None, targets_of("targets"), respond.Budget(6, False, "2026-10-23"))
    row = st["decisions"]["cn_scan:s3"]
    assert (row["outcome"], row["gate"]) == ("not_fire", "S_NOTHING_WAITING")


def test_a_target_sent_nowhere_differs_from_a_target_whose_channel_is_not_wired():
    ev, items, analysis = doc("php2shell")
    tg = targets_of("targets")
    off = respond.Budget(6, False, "2026-10-23", s3_targets=(), routes={"demo-shop": "none", "security-radar": "none"})
    st, ops = respond.decide(ev, items, analysis, None, tg, off)
    assert st["decisions"]["cn_finding:demo-shop"]["gate"] == "T_NO_CHANNEL"
    assert st["decisions"]["cn_finding:demo-shop"]["outcome"] == "not_fire"
    unwired = respond.Budget(6, False, "2026-10-23", s3_targets=(), routes={"demo-shop": "github", "security-radar": "none"})
    st, ops = respond.decide(ev, items, analysis, None, tg, unwired)
    row = st["decisions"]["cn_finding:demo-shop"]
    assert (row["outcome"], row["gate"]) == ("not_evaluated", "N_CHANNEL_NOT_WIRED") and "GitHub" in row["reason"]
    assert st["decisions"]["cn_scan:github"]["outcome"] == "not_evaluated"
    assert not any(o.kind.startswith("submit_finding") for o in ops)


def test_a_cooled_event_records_its_eligibility_gate_for_every_respond_action():
    ev, items, analysis = doc("php2shell_cooled")
    st, ops = respond.decide(ev, items, analysis, None, targets_of("targets"), respond.Budget(6, True, "2026-10-23"))
    assert st["eligibility"]["code"] == "E_SEVERITY"
    rows = st["decisions"].values()
    assert {r["action"] for r in rows} == {a.key for a in decisions.ACTIONS if a.decided_by == "respond"}
    assert {(r["outcome"], r["gate"]) for r in rows} == {("not_fire", "E_SEVERITY")}
    assert not [o for o in ops if not o.kind.startswith("poll_")]


def test_a_budget_blocked_review_is_blocked_with_the_enforced_limit_and_keeps_its_time():
    ev, items, analysis = doc("php2shell")
    st, _ops = respond.decide(ev, items, analysis, None, targets_of("targets"), respond.Budget(6, False, "2026-10-23", now=NOW))
    assert st["decisions"]["sa_review:demo-shop"]["outcome"] == "fire"   # requested; the station funds it in phase 2
    blocked = respond.block_review(st, "demo-shop", 2, NOW)
    row = blocked["decisions"]["sa_review:demo-shop"]
    assert (row["outcome"], row["gate"], row["limit"], row["at"]) == ("blocked", "B_REVIEWS_DAY", 2, NOW)
    assert "2/天" in row["reason"] and blocked["targets"]["demo-shop"]["review_blocked"] == row["reason"]
    # next cycle, still blocked: the row keeps its first time (no rewrite / republish every 5 minutes)
    later = "2026-10-23T18:05:00Z"
    st2, _ = respond.decide(ev, items, analysis, blocked, targets_of("targets"), respond.Budget(6, False, "2026-10-23", now=later))
    again = respond.block_review(st2, "demo-shop", 2, later, before=blocked)
    assert again["decisions"]["sa_review:demo-shop"]["at"] == NOW


def test_an_unchanged_decision_keeps_its_time_so_the_state_does_not_churn():
    ev, items, analysis = doc("php2shell")
    st, _ = respond.decide(ev, items, analysis, None, targets_of("targets"), respond.Budget(6, False, "2026-10-23", now=NOW))
    st = {**st, "requirement": {"hash": "x", "synced_day": "2026-10-23"}}   # make the rule look synced / changed once
    a, _ = respond.decide(ev, items, analysis, st, targets_of("targets"), respond.Budget(6, False, "2026-10-23", now=NOW))
    b, _ = respond.decide(ev, items, analysis, a, targets_of("targets"),
                          respond.Budget(6, False, "2026-10-23", now="2026-10-23T18:05:00Z"))
    assert a["decisions"] == b["decisions"]


def test_cycle_cap_text_is_the_tables():
    note = respond.cycle_cap_note(8, NOW)
    gate = next(g for g in decisions.RESPOND_PRE if g.code == "N_CYCLE_CAP")
    assert note["reason"] == decisions.reason(gate, {"limit": 8})


# ------------------------------------------------------------------ publish-time evaluation

def _ev(**kw) -> dict:
    return {"event_id": "E1", "domain": "vuln", "severity": "P0", "exploitation": "confirmed",
            "last_updated": "2026-10-23T10:00:00Z", "title": "t", "level_reason": "r", **kw}


def _rows(ev, st, ledgers, resp=None):
    return {decisions.key(r): r for r in decisions.evaluate(ev, st, ledgers, NOW_DT, resp)}


ON = {decisions.STATION_KEY: {"status": decisions.STATION_ON, "at": NOW}}   # the station recorded: configured


def test_station_off_is_not_evaluated_for_every_respond_action():
    """The defect: SA_AGENT_SPACE_ID removed ⇒ the station stops, the ledger and last cycle's rows stay. The rows
    must read N_STATION_OFF — not 已触发 from the last cycle — and so must delivery (respond runs it). Notify is its own
    station since P3 and is not held by this one."""
    ev, items, analysis = doc("php2shell")
    st, _ = respond.decide(ev, items, analysis, None, targets_of("targets"), respond.Budget(6, True, "2026-10-23", now=NOW))
    assert any(r["outcome"] == "fire" for r in st["decisions"].values())
    old_ledger = {"counters": {"inventory_scans": 9}, "notify": {"slack": {"status": "ok", "at": NOW}}}
    for led in ({**old_ledger, decisions.STATION_KEY: {"status": decisions.STATION_OFF_STATUS, "at": NOW}}, old_ledger, {}):
        rows = _rows({**ev, "last_updated": NOW}, st, {"respond": led})
        for a in decisions.ACTIONS:
            if a.decided_by == "respond" or a.key == "delivery":
                assert (rows[a.key]["outcome"], rows[a.key]["gate"]) == ("not_evaluated", "N_STATION_OFF"), (led, a.key)
        assert not [r for r in rows.values() if r["action"] not in ("waf_stage", "notify") and r["outcome"] == "fire"]
    on = _rows({**ev, "last_updated": NOW}, st, {"respond": {**old_ledger, **ON}})
    assert on["sa_requirement"]["outcome"] == "fire"


def test_not_evaluated_is_never_rendered_as_not_fire():
    """A P2 event: evaluated by rule, not fired (E_SEVERITY). An eligible P0 the station has not reached yet: not
    evaluated (N_NOT_YET). The two must differ."""
    led = {"respond": {"counters": {}, **ON}}
    p2 = _rows(_ev(severity="P2", exploitation="reported"), None, led)["sa_review"]
    p0 = _rows(_ev(), None, led)["sa_review"]
    assert (p2["outcome"], p2["gate"]) == ("not_fire", "E_SEVERITY")
    assert (p0["outcome"], p0["gate"]) == ("not_evaluated", "N_NOT_YET")
    assert p0["evaluated_by"] == "publish"


def test_cycle_cap_and_window_override_an_older_cycles_rows():
    ev, items, analysis = doc("php2shell")
    st, _ = respond.decide(ev, items, analysis, None, targets_of("targets"), respond.Budget(6, False, "2026-10-23", now=NOW))
    led = {"respond": {"counters": {}, **ON}}
    capped = {**st, "not_evaluated": respond.cycle_cap_note(8, "2026-10-23T17:00:00Z")}
    rows = _rows({**ev, "last_updated": "2026-10-23T10:00:00Z"}, capped, led)
    assert (rows["cn_scan"]["outcome"], rows["cn_scan"]["gate"], rows["cn_scan"]["at"]) == \
        ("not_evaluated", "N_CYCLE_CAP", "2026-10-23T17:00:00Z")
    old = _rows({**ev, "last_updated": "2026-10-01T00:00:00Z"}, st, led)
    assert old["sa_requirement"]["gate"] == "N_OUT_OF_WINDOW"
    fresh = _rows({**ev, "last_updated": "2026-10-23T10:00:00Z"}, st, led)
    assert fresh["cn_scan:s3"] == {**st["decisions"]["cn_scan:s3"], "label": decisions.BY_KEY["cn_scan"].label,
                                   "service": "continuum", "paid": True, "evaluated_by": "respond"}


def test_an_event_capped_on_its_first_appearance_says_cycle_cap_with_the_caps_time():
    """The common cap case: handlers writes {eligibility, not_evaluated} for an eligible event it never decided. That
    is N_CYCLE_CAP since the cap's `since` — not N_NOT_YET at publish time (the reason and its time were lost)."""
    ev, items, _ = doc("php2shell")
    st = {"eligibility": respond.eligibility(ev, items), "not_evaluated": respond.cycle_cap_note(8, "2026-10-23T17:00:00Z")}
    assert st["eligibility"]["eligible"]
    rows = _rows({**ev, "last_updated": "2026-10-23T10:00:00Z"}, st, {"respond": {"counters": {}, **ON}})
    for a in decisions.ACTIONS:
        if a.decided_by == "respond":
            r = rows[a.key]
            assert (r["outcome"], r["gate"], r["at"], r["limit"]) == ("not_evaluated", "N_CYCLE_CAP", "2026-10-23T17:00:00Z", 8)
    # nothing decided, nothing capped: still "not yet" (an eligibility verdict alone is not a decision)
    fresh = _rows({**ev, "last_updated": "2026-10-23T10:00:00Z"}, {}, {"respond": {"counters": {}, **ON}})
    assert fresh["sa_review"]["gate"] == "N_NOT_YET"


def _plan(**kw) -> dict:
    return {"web_acl": "security-radar-demo", "appliable": True, "state": "staged", **kw}


@pytest.mark.parametrize(("plans", "want"), [
    ([], ("not_fire", "W_NO_PLAN")),
    ([_plan(web_acl=None)], ("not_fire", "W_NO_WEB_ACL")),
    ([_plan(appliable=False)], ("not_fire", "W_ADVISORY")),
    ([_plan(state="unchecked")], ("not_evaluated", "W_UNCHECKED")),
    ([_plan(state="absent")], ("not_fire", "W_NOT_IN_PLACE")),
    ([_plan()], ("fire", None)),
    ([_plan(state="blocking")], ("fire", None)),
])
def test_waf_stage_reads_the_mitigate_ledger(plans, want):
    mled = {"run_at": NOW, "events": {"E1": {"plans": plans}}}
    row = _rows(_ev(), None, {"mitigate": mled})["waf_stage"]
    assert (row["outcome"], row["gate"]) == want and row["at"] == NOW
    # a publish-observed fire is the ledger's done state (rule on the ACL): result ok; no result on any other outcome
    assert row.get("result") == ("ok" if want[0] == "fire" else None)
    assert _rows(_ev(), None, {})["waf_stage"]["gate"] == "M_STATION_OFF"


def test_delivery_says_where_a_patch_is():
    led = {"respond": {"counters": {}, **ON}}
    gh = {"github": {"issues": [{"issue_id": "i1", "patch_path": "p", "pr_url": "https://github.com/o/r/pull/3"}]}}
    assert (_rows(_ev(), gh, led)["delivery:github"]["outcome"], _rows(_ev(), gh, led)["delivery:github"]["result"]) == \
        ("fire", "ok")
    s3 = {"s3": {"issues": [{"issue_id": "i2", "patch_path": "p"}]}}
    assert _rows(_ev(), s3, led)["delivery:s3"]["gate"] == "D_NOT_NATIVE"
    radar_pr = {**s3, "delivered_prs": {"i2": "https://github.com/o/r/pull/9"}}
    assert _rows(_ev(), radar_pr, led)["delivery:s3"]["outcome"] == "fire"   # deliver_prs opened it for S3
    assert _rows(_ev(), {}, led)["delivery"]["gate"] == "D_NO_PATCH"


def test_the_cycle_cap_queues_events_it_does_not_starve_them():
    """Audit 04 §3.1: candidates were sorted P0 first, then most recently updated, the same way every cycle, and every
    evaluated event took a slot every cycle — with more than RESPOND_MAX_EVENTS eligible events the ninth was never
    evaluated. The order now puts the event evaluated longest ago (or never) first within its severity."""
    from radar.model import Event

    def ev(i, sev, updated):
        return Event(event_id=f"ev_{i}", domain="vuln", title="t", first_seen="2026-11-01T00:00:00Z", last_updated=updated,
                     item_ids=[], keys=[], severity=sev)
    evs = [ev(n, "P1", f"2026-11-12T{n:02d}:00:00Z") for n in range(12)] + [ev(99, "P0", "2026-11-01T00:00:00Z")]
    cap, seen, evaluated = 4, [], {}
    for cycle in range(4):
        order = respond.order(evs, evaluated)
        assert order[0].event_id == "ev_99"                              # a P0 is first in every cycle
        batch = order[:cap]
        seen += [e.event_id for e in batch]
        evaluated.update({e.event_id: f"2026-11-12T12:{cycle:02d}:00Z" for e in batch})
    assert {f"ev_{n}" for n in range(12)} <= set(seen), "an event was never evaluated in four cycles"
    never = respond.order(evs, {"ev_3": "2026-11-12T12:00:00Z"})         # among the never-evaluated: most recently updated first
    assert [e.event_id for e in never[:3]] == ["ev_99", "ev_11", "ev_10"] and never[-1].event_id == "ev_3"
