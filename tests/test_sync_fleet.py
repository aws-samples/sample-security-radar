"""scripts/sync-fleet.py: one mirror tool for every repository channel (R13)."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from radar import targets as T

spec = importlib.util.spec_from_file_location("sync_fleet", Path(__file__).resolve().parents[1] / "scripts" / "sync-fleet.py")
SF = importlib.util.module_from_spec(spec)
sys.modules["sync_fleet"] = SF                              # @dataclass resolves its module by name
spec.loader.exec_module(SF)  # type: ignore[union-attr]


def test_each_mirror_holds_exactly_its_channels_targets_and_drops_the_rest():
    gh = SF.plan("github", {".git", "demo-shop", "alps-vault", "wp-storefront"})   # the 10-27 five-target mirror
    assert gh.copy == T.on("github") and set(gh.remove) == {"alps-vault", "wp-storefront"}
    gl = SF.plan("gitlab", {".git", "alps-vault"})
    assert gl.copy == T.on("gitlab") and gl.remove == ()


def test_git_metadata_is_never_removed_and_an_unknown_channel_fails_loudly():
    assert ".git" not in SF.plan("github", {".git"}).remove
    with pytest.raises(SystemExit, match="unknown channel"):
        SF.plan("s3", set())                                   # S3 is uploaded by the CDK stack, not mirrored


def test_every_repository_channel_has_a_host_adapter():
    assert set(SF.HOSTS) == set(SF.respond.REPO_CHANNELS)
