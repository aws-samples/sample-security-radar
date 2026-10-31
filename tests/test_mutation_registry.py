"""Fast landing check for the mutation registries (mutations.txt, ui/mutations.txt): every `find` occurs exactly once
in its file. 2026-10-30, M4: five entries (M153, M160, M163, M28, M30) stopped landing because an edit changed or
duplicated the guarded line — each was found only by a 15-minute full mutation run; a stale anchor is a guard that is
no longer verified. This test is not the mutation run (it does not prove the tests go red), only that every entry
still points at real, unique code."""
import configparser
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def entries(registry: Path, base: Path) -> list[tuple[str, Path, str]]:
    cfg = configparser.ConfigParser(interpolation=None)      # the parser touchstone mutate.py uses
    cfg.optionxform = str
    cfg.read_string(registry.read_text())
    return [(name, base / cfg[name]["file"], cfg[name]["find"]) for name in cfg.sections()]


ALL = entries(ROOT / "mutations.txt", ROOT) + entries(ROOT / "ui" / "mutations.txt", ROOT / "ui")
# UX1 checks the runner itself: its replacement must fail to compile, the anchor still has to be unique
assert len(ALL) > 200


@pytest.mark.parametrize(("name", "path", "find"), ALL, ids=[e[0] for e in ALL])
def test_every_mutation_anchor_is_unique_in_its_file(name, path, find):
    assert path.exists(), f"{name}: {path} does not exist"
    assert path.read_text().count(find) == 1, f"{name}: anchor found {path.read_text().count(find)}x in {path.name}"
