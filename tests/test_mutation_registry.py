"""Fast landing check for the mutation registries (mutations.txt, ui/mutations.txt): every `find` occurs exactly once
in its file. 2026-10-30, M4: five entries (M153, M160, M163, M28, M30) stopped landing because an edit changed or
duplicated the guarded line — each was found only by a 15-minute full mutation run; a stale anchor is a guard that is
no longer verified. This test is not the mutation run (it does not prove the tests go red), only that every entry
still points at real, unique code — and at a test that exists: 2026-11-11 (review of p1/stages) UW12 / UW14 / UW17 still
named src/test/attackFlow.test.ts after it was renamed to .tsx, and the UI runner (ui/scripts/mutate.mjs) reported them
NOT LANDED while this file stayed green."""
import configparser
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _cfg(registry: Path) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser(interpolation=None)      # the parser touchstone mutate.py uses
    cfg.optionxform = str
    cfg.read_string(registry.read_text())
    return cfg


def entries(registry: Path, base: Path) -> list[tuple[str, Path, str]]:
    cfg = _cfg(registry)
    return [(name, base / cfg[name]["file"], cfg[name]["find"]) for name in cfg.sections()]


def expects(registry: Path, base: Path) -> list[tuple[str, Path, str | None]]:
    """(name, test file, test function or None) of every entry's `expect` (a node id, or a UI test file path)."""
    cfg = _cfg(registry)
    out = []
    for name in cfg.sections():
        file, _, node = cfg[name]["expect"].strip().partition("::")
        out.append((name, base / file, node.split("[", 1)[0] or None))
    return out


ALL = entries(ROOT / "mutations.txt", ROOT) + entries(ROOT / "ui" / "mutations.txt", ROOT / "ui")
EXPECTS = expects(ROOT / "mutations.txt", ROOT) + expects(ROOT / "ui" / "mutations.txt", ROOT / "ui")
# UX1 checks the runner itself: its replacement must fail to compile, the anchor still has to be unique
assert len(ALL) > 200


@pytest.mark.parametrize(("name", "path", "find"), ALL, ids=[e[0] for e in ALL])
def test_every_mutation_anchor_is_unique_in_its_file(name, path, find):
    assert path.exists(), f"{name}: {path} does not exist"
    assert path.read_text().count(find) == 1, f"{name}: anchor found {path.read_text().count(find)}x in {path.name}"


def missing_expect(path: Path, func: str | None) -> str | None:
    """Why an entry's `expect` names no runnable test (None when it does)."""
    if not path.exists():
        return f"expected test file {path} does not exist"
    if func is not None and f"def {func}(" not in path.read_text():
        return f"no test {func} in {path.name}"
    return None


@pytest.mark.parametrize(("name", "path", "func"), EXPECTS, ids=[e[0] for e in EXPECTS])
def test_every_mutation_expects_a_test_that_exists(name, path, func):
    assert missing_expect(path, func) is None, f"{name}: {missing_expect(path, func)}"


def test_a_renamed_test_file_or_function_is_reported(tmp_path):
    """The check is alive: the UW12 shape (a .ts renamed .tsx) and a renamed test function are both named."""
    (tmp_path / "flow.test.tsx").write_text("it('x', () => {})\n")
    (tmp_path / "test_a.py").write_text("def test_b():\n    pass\n")
    assert missing_expect(tmp_path / "flow.test.ts", None) is not None
    assert missing_expect(tmp_path / "test_a.py", "test_a") is not None
    assert missing_expect(tmp_path / "flow.test.tsx", None) is None and missing_expect(tmp_path / "test_a.py", "test_b") is None
