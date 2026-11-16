"""R3.3: version.json is how an open page learns a newer UI is live — it must never be cached for a year."""
from pathlib import Path

SCRIPT = (Path(__file__).resolve().parents[1] / "scripts" / "deploy-ui.sh").read_text()


def test_version_json_is_uploaded_no_cache_and_invalidated_never_immutable():
    sync = next(ln for ln in SCRIPT.splitlines() if "s3 sync ui/dist/" in ln)
    assert '--exclude "version.json"' in sync and "immutable" in sync          # the hashed assets stay immutable
    assert any("ui/dist/version.json" in ln and '--cache-control "no-cache"' in ln for ln in SCRIPT.splitlines())
    assert '--paths "/index.html" "/version.json"' in SCRIPT
    assert 'RADAR_BUILD="$(git rev-parse --short HEAD)"' in SCRIPT and "export RADAR_BUILD" in SCRIPT
