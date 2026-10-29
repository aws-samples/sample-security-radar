"""Supply chain: every tool fetched at run time is pinned to one exact version (Holmes CSR scan 7bdaa81f).
A floating `@latest` / `@2` or an ad-hoc `uv run --with <pkg>` resolves whatever is published that day."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SURFACES = [*(ROOT / "scripts").glob("*.sh"), *(ROOT / "scripts").glob("*.py"), ROOT / ".gitlab-ci.yml",
            *(ROOT / ".github" / "workflows").glob("*.yml")]


def test_the_cdk_cli_is_one_exact_version_everywhere():
    found = {m.group(1) for p in SURFACES if p.exists() for m in re.finditer(r"aws-cdk@([\w.]+)", p.read_text())}
    assert len(found) == 1 and re.fullmatch(r"\d+\.\d+\.\d+", next(iter(found))), found


def test_no_unpinned_ad_hoc_python_packages():
    bad = [(p.name, m.group(0)) for p in SURFACES if p.exists()
           for m in re.finditer(r"uv run[^\n]*--with\s+([A-Za-z0-9_.-]+)(?![=<>~])", p.read_text())]
    assert not bad, bad


def test_demo_target_images_come_from_ecr_public():
    for d in (ROOT / "integrations" / "continuum" / "targets").glob("*/Dockerfile"):
        for line in d.read_text().splitlines():
            if line.strip().upper().startswith("FROM "):
                assert line.split()[1].startswith("public.ecr.aws/"), (d, line)
