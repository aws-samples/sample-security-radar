"""R4.7: targets are data (src/radar/targets.json), checked at import with field-level errors."""
import json
from pathlib import Path

import pytest

from radar import targets

ROOT = Path(__file__).resolve().parents[1]
ROW = {"id": "demo-x", "dir": "demo-x", "channel": "s3", "summary": "s"}


def test_the_shipped_file_loads_and_every_target_has_code_or_is_this_repo():
    assert set(targets.NAMES) == {r["id"] for r in json.loads(targets.FILE.read_text())["targets"]}
    for tid, d, _ in targets.TARGETS:
        assert d == "security-radar" or (ROOT / "integrations" / "continuum" / "targets" / d).is_dir(), tid


@pytest.mark.parametrize(("row", "error"), [
    ({**ROW, "id": "Bad Id"}, "bad_id"),
    ({**ROW, "channel": "ftp"}, "bad_channel"),
    ({**ROW, "dir": "../etc"}, "bad_dir"),
])
def test_a_bad_row_is_refused_with_its_field(row, error):
    with pytest.raises(targets.TargetsError) as e:
        targets.load(json.dumps({"targets": [row]}))
    assert e.value.detail["error"] == error


def test_duplicates_and_an_empty_list_are_refused():
    with pytest.raises(targets.TargetsError, match="duplicate_id"):
        targets.load(json.dumps({"targets": [ROW, ROW]}))
    with pytest.raises(targets.TargetsError, match="no_targets"):
        targets.load(json.dumps({"targets": []}))
