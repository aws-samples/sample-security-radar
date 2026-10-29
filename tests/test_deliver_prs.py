"""scripts/deliver_prs.py target matching: a repo-relative patch must land on the target whose content it fits."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import deliver_prs

PATCH = """--- a/Dockerfile
+++ b/Dockerfile
@@ -1,2 +1,2 @@
-FROM node:24.22.0-slim
+FROM node:24.23.1-slim
 WORKDIR /app
"""


def _tree(root: Path, name: str, dockerfile: str) -> None:
    (root / name).mkdir()
    (root / name / "Dockerfile").write_text(dockerfile)


def test_patch_goes_to_the_target_whose_content_it_fits_not_the_first_with_that_file(tmp_path):
    _tree(tmp_path, "demo-shop", "FROM php:8.3.30-apache\nWORKDIR /var/www\n")
    _tree(tmp_path, "node-gateway", "FROM node:24.22.0-slim\nWORKDIR /app\n")
    assert deliver_prs.target_of(PATCH, tmp_path) == "node-gateway"


def test_ambiguous_or_unmatched_patch_is_skipped(tmp_path):
    _tree(tmp_path, "a", "FROM node:24.22.0-slim\nWORKDIR /app\n")
    _tree(tmp_path, "b", "FROM node:24.22.0-slim\nWORKDIR /app\n")
    assert deliver_prs.target_of(PATCH, tmp_path) is None
    assert deliver_prs.target_of("--- a/missing\n+++ b/missing\n@@ -1 +1 @@\n-x\n+y\n", tmp_path) is None


def test_an_event_target_that_already_has_a_pr_is_not_delivered_again():
    """Native Continuum PR (GitHub environment) + the S3-environment issue for the same fix ⇒ no second PR."""
    get = {"p/native.patch": PATCH.encode(), "p/s3.patch": PATCH.encode()}.__getitem__
    native = {"issue_id": "gh1", "exploitable": "EXPLOITABLE", "patch_path": "p/native.patch", "pr_url": "https://x/pull/9"}
    s3 = {"issue_id": "s1", "exploitable": "EXPLOITABLE", "patch_path": "p/s3.patch"}
    assert deliver_prs.plan([{"event_id": "ev_1", "reason": "r", "issues": [native, s3]}], get) == []
    assert len(deliver_prs.plan([{"event_id": "ev_1", "reason": "r", "issues": [s3]}], get)) == 1
