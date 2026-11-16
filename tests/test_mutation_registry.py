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


# --- a mutant must still be a module: red by breakage is not red by judgement (roadmap R8.6) ------------------------

def broken_mutants(registry: Path, base: Path, workdir: Path) -> dict[str, list[str]]:
    """{entry: [what breaks]} for Python mutants that do not compile or reference a name that does not exist. Such a
    mutant fails every test that imports the file — the registry counts it "red" while the assertion it was written
    for is never reached. One ruff run over all mutants (F821 undefined name; a syntax error is reported as such)."""
    import json
    import subprocess
    cfg = _cfg(registry)
    names = {}
    for n, name in enumerate(cfg.sections()):
        path = base / cfg[name]["file"]
        if path.suffix != ".py" or not path.exists():
            continue
        src = path.read_text()
        find, repl = cfg[name]["find"], cfg[name]["replace"]
        if src.count(find) != 1:
            continue                                   # the anchor test reports that
        f = workdir / f"m{n}.py"
        f.write_text(src.replace(find, repl))
        names[f.name] = name
    out = subprocess.run(["ruff", "check", "--isolated", "--select", "F821", "--output-format", "json", str(workdir)],
                         capture_output=True, text=True, check=False).stdout
    bad: dict[str, list[str]] = {}
    for d in json.loads(out or "[]"):
        code = d.get("code") or "syntax"
        if code not in ("F821", "syntax", "invalid-syntax") and d.get("code") is not None:
            continue
        bad.setdefault(names[Path(d["filename"]).name], []).append(f"{code}: {d['message']} (line {d['location']['row']})")
    return bad


def test_no_python_mutant_is_red_only_because_it_no_longer_compiles_or_names_something_undefined(tmp_path):
    """CI 2026-11-14: M1137 had been "red" for weeks because its replacement used `timedelta`, which the file did not
    import — a NameError, not a failed assertion. The day the import was added for another reason, it survived."""
    bad = broken_mutants(ROOT / "mutations.txt", ROOT, tmp_path)
    assert not bad, "mutants that break the module instead of the behaviour:\n" + "\n".join(f"  {k}: {v}" for k, v in sorted(bad.items()))


def test_the_breakage_check_sees_an_undefined_name_and_a_syntax_error(tmp_path):
    (tmp_path / "t.py").write_text("import os\n\n\ndef f():\n    return os.sep\n")
    reg = tmp_path / "reg.txt"
    reg.write_text("[A fine]\nfile = t.py\nfind = return os.sep\nreplace = return os.linesep\nexpect = x\n\n"
                   "[B undefined]\nfile = t.py\nfind = return os.sep\nreplace = return timedelta(1)\nexpect = x\n\n"
                   "[C syntax]\nfile = t.py\nfind = return os.sep\nreplace = return (\nexpect = x\n")
    work = tmp_path / "w"
    work.mkdir()
    bad = broken_mutants(reg, tmp_path, work)
    assert set(bad) == {"B undefined", "C syntax"}, bad


def test_every_mutation_id_is_unique_in_both_registries():
    """touchstone mutate.py (pinned since 2026-11-15) refuses a registry whose first words repeat: `--only M600` would
    silently pick one of two. Six ids were doubled (M540, M600–M603, M610) and renumbered M1422–M1427."""
    import re
    from collections import Counter
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    for reg in (root / "mutations.txt", root / "ui" / "mutations.txt"):
        ids = re.findall(r"^\[(\S+) ", reg.read_text(), re.MULTILINE)
        assert [i for i, n in Counter(ids).items() if n > 1] == [], reg.name
