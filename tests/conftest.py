"""Guard: tests never touch the network. Any real socket connect fails loudly."""

import socket

import pytest


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def deny(*a, **k):
        raise RuntimeError("tests must not open network connections")
    monkeypatch.setattr(socket.socket, "connect", deny)


# ---------------------------------------------------------------- R8.6: a mutant that does not run is not "red"
# A mutation is meant to make an assertion fail. One that only breaks the code — a NameError, an ImportError, a
# missing module attribute at call time — fails every test that touches it, and the runner (touchstone mutate.py:
# exit status ≠ 0 ⇒ red) reports a guard as alive that no assertion checks (M1137 was red only through a NameError).
# With RADAR_MUTATION_STRICT=1 (the CI mutation job only) a run whose every failure is such a crash exits 0, so the
# runner reports the mutant as surviving — and the guard gets a real assertion. Ordinary runs are unaffected.
import os

CRASH_PREFIXES = ("NameError", "UnboundLocalError", "ImportError", "ModuleNotFoundError", "SyntaxError",
                  "IndentationError")
_failures: list[str] = []


def crash_only(messages: list[str]) -> bool:
    """Every failure message names a does-not-run crash (an AttributeError only when it is about a module)."""
    def crash(m: str) -> bool:
        head = m.strip().split(":", 1)[0].split(".")[-1]
        return head in CRASH_PREFIXES or (head == "AttributeError" and "module '" in m)
    return bool(messages) and all(crash(m) for m in messages)


def _message(rep) -> str:
    crash = getattr(getattr(rep, "longrepr", None), "reprcrash", None)
    return crash.message if crash is not None else str(getattr(rep, "longrepr", ""))[-300:]


def pytest_runtest_logreport(report):
    if os.environ.get("RADAR_MUTATION_STRICT") == "1" and report.failed:
        _failures.append(_message(report))


def pytest_collectreport(report):
    if os.environ.get("RADAR_MUTATION_STRICT") == "1" and report.failed:
        _failures.append(_message(report))


def pytest_sessionfinish(session, exitstatus):
    if os.environ.get("RADAR_MUTATION_STRICT") == "1" and exitstatus in (1, 2) and crash_only(_failures):
        print(f"\nRADAR_MUTATION_STRICT: {len(_failures)} failure(s), all crashes ({_failures[0][:120]}) — "
              "reported as not red: no assertion caught this mutant")
        session.exitstatus = 0


# ---------------------------------------------------------------- R6.3: in CI a missing tool is a failure, not a skip
# A guard that skips when jq / node is absent is a guard that silently turns off: python:3.12-bookworm had no jq, the
# secret-script tests skipped and M614–M619 survived; without node, M56 did (pipeline 3818034). With
# RADAR_NO_TOOL_SKIPS=1 (CI's py-test job) such a skip fails the run. Other skips (live AWS, the public sample) stay.
TOOL_SKIP = ("not installed", "not on PATH")


def tool_skip(reason: str) -> bool:
    return any(t in reason for t in TOOL_SKIP)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    out = yield
    rep = out.get_result()
    if os.environ.get("RADAR_NO_TOOL_SKIPS") == "1" and rep.skipped and isinstance(rep.longrepr, tuple):
        reason = str(rep.longrepr[2])
        if tool_skip(reason):
            rep.outcome = "failed"
            rep.longrepr = f"RADAR_NO_TOOL_SKIPS: a guard skipped because a tool is missing in CI — {reason}"
