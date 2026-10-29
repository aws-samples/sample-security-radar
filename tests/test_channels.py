"""One channel model for S3 / GitHub / GitLab: membership, executors and environment reconcile come from one table."""
from __future__ import annotations

from typing import Any

import pytest
from botocore.exceptions import ClientError

from radar import continuum_aws as A
from radar import respond
from radar import targets as T
from radar.limits import Limits


class FakeCn:
    """Continuum control plane: integrations + environments by name; records creates/updates."""

    def __init__(self, integrations: list[str], envs: dict[str, str] | None = None, fail: set[str] | None = None) -> None:
        self.ints = [{"name": n, "integrationId": f"i-{n}"} for n in integrations]
        self.envs = {n: {"environmentId": f"e-{n}", "freq": f} for n, f in (envs or {}).items()}
        self.fail, self.created, self.updated = fail or set(), [], []

    def list_integrations(self) -> dict[str, Any]:
        return {"items": self.ints}

    def list_environments(self) -> dict[str, Any]:
        return {"items": [{"name": n, "environmentId": e["environmentId"]} for n, e in self.envs.items()]}

    def get_environment(self, environmentId: str) -> dict[str, Any]:
        e = next(e for e in self.envs.values() if e["environmentId"] == environmentId)
        return {"configuration": {"codeConfiguration": {"sourceConfiguration": {"s3Sources": [{"codePrefix": "code/"}]},
                                                        "environmentConfiguration": {"scanFrequency": e["freq"]}}}}

    def create_environment(self, name: str, configuration: dict[str, Any]) -> dict[str, Any]:
        if name in self.fail:
            raise ClientError({"Error": {"Code": "InternalServerException", "Message": "boom"}}, "CreateEnvironment")
        self.created.append((name, configuration))
        self.envs[name] = {"environmentId": f"e-{name}",
                           "freq": configuration["codeConfiguration"]["environmentConfiguration"]["scanFrequency"]}
        return {"environmentId": f"e-{name}"}

    def update_environment(self, environmentId: str, configuration: dict[str, Any]) -> None:
        self.updated.append(environmentId)


@pytest.fixture
def repos(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CN_GITHUB_REPO", "o/fleet")
    monkeypatch.setenv("CN_GITLAB_PROJECT", "u/fleet")


def test_every_op_respond_can_emit_has_an_executor():
    assert respond.CONTINUUM_OPS <= set(A._EXEC)
    assert set(respond.SCAN_OPS) == {"s3", *respond.REPO_CHANNELS} and set(respond.SCAN_OPS.values()) <= set(A._EXEC)
    assert set(A.REPO_SOURCE_ENV) == set(respond.REPO_CHANNELS)
    assert set(T.CHANNELS) == {"s3", "none", *respond.REPO_CHANNELS}            # targets.py and respond agree


def test_budget_channel_answers_exactly_one_environment_per_target():
    b = respond.Budget(0, False, s3_targets=T.on("s3"), github_targets=T.on("github"), gitlab_targets=T.on("gitlab"))
    assert {t: b.channel(t) for t in T.NAMES} == {t: (None if c == "none" else c) for t, c in T.CHANNEL.items()}
    # a repo channel not wired yet (no environment) ⇒ its targets go nowhere, never silently to S3
    b2 = respond.Budget(0, False, s3_targets=T.on("s3"))
    assert all(b2.channel(t) is None for t in T.on("gitlab") + T.on("github"))


def test_repository_environments_are_created_with_the_schedule_off(monkeypatch, repos):
    cn = FakeCn(["security-radar", "security-radar-github", "security-radar-gitlab"], {"security-radar": "PT0H"})
    monkeypatch.setattr(A, "_cn", lambda: cn)
    out = A.ensure_environment(["wp-storefront"])
    assert out["github_environment_id"] == "e-security-radar-github" and out["gitlab_environment_id"] == "e-security-radar-gitlab"
    assert out["gitlab_repo"] == "u/fleet"
    for name, cfg in cn.created:
        assert cfg["codeConfiguration"]["environmentConfiguration"]["scanFrequency"] == Limits.CONTINUUM_SCHEDULED_SCAN
        assert cfg["codeConfiguration"]["sourceConfiguration"]["repositorySources"][0]["repository"] in ("o/fleet", "u/fleet")


def test_every_repository_environment_has_its_schedule_reconciled(monkeypatch, repos):
    """Was GitHub-only: the GitLab copy had no reconcile, so a GitLab env created with P7D would keep a weekly paid scan."""
    cn = FakeCn(["security-radar", "security-radar-github", "security-radar-gitlab"],
                {"security-radar": "PT0H", "security-radar-github": "PT0H", "security-radar-gitlab": "P7D"})
    monkeypatch.setattr(A, "_cn", lambda: cn)
    A.ensure_environment(["wp-storefront"])
    assert cn.updated == ["e-security-radar-gitlab"]


def test_one_failing_repository_channel_does_not_take_the_others_down(monkeypatch, repos):
    cn = FakeCn(["security-radar", "security-radar-github", "security-radar-gitlab"], {"security-radar": "PT0H"},
                fail={"security-radar-github"})
    monkeypatch.setattr(A, "_cn", lambda: cn)
    out = A.ensure_environment(["wp-storefront"])
    assert out["environment_id"] == "e-security-radar" and "InternalServerException" in out["github_error"]
    assert out["gitlab_environment_id"] == "e-security-radar-gitlab" and "gitlab_error" not in out


def test_an_unwired_channel_is_absent_not_an_error(monkeypatch):
    monkeypatch.delenv("CN_GITHUB_REPO", raising=False)
    monkeypatch.setenv("CN_GITLAB_PROJECT", "u/fleet")
    cn = FakeCn(["security-radar"], {"security-radar": "PT0H"})                  # no repository integrations yet
    monkeypatch.setattr(A, "_cn", lambda: cn)
    out = A.ensure_environment(["wp-storefront"])
    assert not [k for k in out if k.startswith(("github_", "gitlab_"))] and not cn.created


def test_gitlab_mr_link_survives_an_sdk_that_does_not_know_the_gitlab_member(monkeypatch):
    """Live 2026-10-28: botocore parsed the delivery target as SDK_UNKNOWN_MEMBER; the raw body had the MR."""
    import json
    raw = {"body": {"patch": {"delivery": {"status": "SUCCEEDED", "target": {"gitlab": {
        "projectPath": "your-org/security-radar-demo-fleet", "mergeRequestNumber": 1, "headSha": "dd0f"}}}}}}
    monkeypatch.setitem(A._RAW, "artifact", json.dumps(raw).encode())
    parsed = {"patch": {"delivery": {"status": "SUCCEEDED", "target": {"SDK_UNKNOWN_MEMBER": {"name": "gitlab"}}}}}
    tgt = A._delivery_target(parsed)
    assert A._gitlab_mr_url(tgt["gitlab"]) == "https://gitlab.com/your-org/security-radar-demo-fleet/-/merge_requests/1"
    known = {"patch": {"delivery": {"target": {"github": {"owner": "o", "repository": "r", "pullRequestNumber": 5}}}}}
    assert A._delivery_target(known) == {"github": {"owner": "o", "repository": "r", "pullRequestNumber": 5}}
    monkeypatch.setitem(A._RAW, "artifact", b"not json")
    assert A._delivery_target(parsed) == {"SDK_UNKNOWN_MEMBER": {"name": "gitlab"}}     # no link, no crash


def test_target_location_names_the_code_the_one_channel_actually_scans(monkeypatch):
    env = {"github_repo": "o/fleet", "gitlab_repo": "u/fleet"}
    assert A.target_location("wp-storefront", "s3", env) == ("code/wp-storefront.zip", None)
    assert A.target_location("demo-shop", "github", env) == ("o/fleet/demo-shop/", "https://github.com/o/fleet/tree/main/demo-shop")
    assert A.target_location("alps-vault", "gitlab", env) == ("u/fleet/alps-vault/", "https://gitlab.com/u/fleet/-/tree/main/alps-vault")
    assert A.target_location("security-radar", "none", env) == ("code/security-radar.zip", None)
    monkeypatch.delenv("CN_GITLAB_PROJECT", raising=False)
    assert A.target_location("alps-vault", "gitlab", None) == ("code/alps-vault.zip", None)    # channel not wired: no fake URL


def test_every_wired_channel_is_listed_as_a_resource(monkeypatch, repos):
    """The #/continuum page listed only the S3 integration + environment while GitHub / GitLab were live (10-28)."""
    cn = FakeCn(["security-radar", "security-radar-github", "security-radar-gitlab"], {"security-radar": "PT0H"})
    monkeypatch.setattr(A, "_cn", lambda: cn)
    env = A.ensure_environment(["wp-storefront"])
    cn.get_environment = lambda environmentId: {"name": environmentId[2:], "status": "ACTIVE"}  # type: ignore[method-assign]
    rows = [(r["kind"], r["name"]) for r in A.resources(env)]
    for ch in ("github", "gitlab"):
        assert ("environment", f"security-radar-{ch}") in rows
        assert any(k == "integration" and n.startswith(f"security-radar-{ch}") for k, n in rows)


def test_a_self_managed_gitlab_url_drives_every_gitlab_link(monkeypatch):
    """R14: the GitLab delivery target has no instanceUrl, so a self-managed instance needs its own web root."""
    monkeypatch.setenv("CN_GITLAB_URL", "https://git.example.com/")
    assert A._gitlab_mr_url({"projectPath": "u/fleet", "mergeRequestNumber": 2}) == "https://git.example.com/u/fleet/-/merge_requests/2"
    assert A.target_location("alps-vault", "gitlab", {"gitlab_repo": "u/fleet"})[1] == "https://git.example.com/u/fleet/-/tree/main/alps-vault"
    assert A.target_location("demo-shop", "github", {"github_repo": "o/fleet"})[1].startswith("https://github.com/")
    monkeypatch.delenv("CN_GITLAB_URL")
    assert A._gitlab_mr_url({"projectPath": "u/fleet", "mergeRequestNumber": 2}).startswith("https://gitlab.com/")
