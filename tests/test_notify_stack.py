"""P3: Notify is its own station after Publish — read statically from infra/stack.py (importing it needs aws-cdk-lib)."""

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STACK = (ROOT / "infra" / "stack.py").read_text()


def _calls(name: str) -> list[ast.Call]:
    return [n for n in ast.walk(ast.parse(STACK)) if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name) and n.func.id == "fn" and n.args and getattr(n.args[0], "value", None) == name]


def test_notify_runs_after_publish_in_the_cycle():
    """research/action/03 B1: push ran inside Respond, before Mitigate and Publish — a new P0's link 404'd."""
    chain = re.search(r"rest = \((.*?)\)\n        cycle = ", STACK, re.DOTALL).group(1)
    steps = re.findall(r"\.next\((\w+)", chain)
    assert steps[-2:] == ["publish_task", "notify_step"], steps
    assert "cycle = fan_out.next(collected_only.otherwise(rest))" in STACK    # R2.2: a collect-only cycle ends before Process


def test_notify_is_a_single_writer_with_its_own_secret_grant():
    [call] = _calls("NotifyFn")
    assert call.args[1].value == "notify_events"
    kw = {k.arg: k.value for k in call.keywords}
    assert ast.literal_eval(kw["reserved_concurrent_executions"]) == 1          # one writer of the push state
    assert "notify_cfg.grant_read(notify_fn)" in STACK and "notify_cfg.grant_read(respond_fn)" not in STACK
    assert 'respond_fn.add_environment("NOTIFY_SECRET_ARN"' not in STACK


def test_a_failed_notify_is_caught_and_throttles_wait():
    assert re.search(r'notify_step\.add_catch\(sfn\.Pass\(self, "NotifyFailed"\)', STACK)
    assert 'notify_step = invoke("Notify", notify_fn)' in STACK      # invoke() carries the overlap throttle retry


def test_respond_no_longer_pushes_and_notify_does_not_need_a_security_agent_space():
    tree = ast.parse((ROOT / "src" / "radar" / "handlers.py").read_text())
    fns = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    names = {getattr(n, "id", None) or getattr(n, "attr", None) for n in ast.walk(fns["respond_events"])}
    assert not names & {"notify", "notify_station", "_notify"}
    assert "SA_AGENT_SPACE_ID" not in ast.unparse(fns["notify_events"])
