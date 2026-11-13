"""continuum_aws._capture_diff fetches only AWS-hosted presigned links: the host is checked, not a substring of the URL."""
from __future__ import annotations

import io
from typing import Any

import pytest

from radar import continuum_aws as A


class _S3:
    def __init__(self) -> None:
        self.puts: list[dict[str, Any]] = []

    def put_object(self, **kw: Any) -> None:
        self.puts.append(kw)


@pytest.fixture
def wired(monkeypatch: pytest.MonkeyPatch) -> tuple[list[str], _S3]:
    fetched: list[str] = []
    s3 = _S3()
    monkeypatch.setenv("SITE_BUCKET", "site")
    monkeypatch.setattr(A, "_c", lambda service, region=None: s3)

    def urlopen(url: str, timeout: int = 0) -> io.BytesIO:
        fetched.append(url)
        return io.BytesIO(b"--- a/x\n+++ b/src/server.js\n@@\n")

    monkeypatch.setattr(A.fetch, "urlopen", urlopen)
    return fetched, s3


@pytest.mark.parametrize("url", [
    "https://evil.example/x?a=.amazonaws.com/",      # the substring sits in the query
    "https://amazonaws.com.evil.example/p.diff",     # the suffix is a label of someone else's domain
    "https://evil.example/.amazonaws.com/p.diff",    # ... or a path segment
    "http://bucket.s3.us-east-1.amazonaws.com/p.diff",  # plain http
])
def test_a_link_not_hosted_on_amazonaws_is_neither_fetched_nor_stored(wired, url):
    fetched, s3 = wired
    assert A._capture_diff(url, "continuum/patches/e-f-0.diff") is None
    assert fetched == [] and s3.puts == []


def test_a_presigned_amazonaws_link_is_captured(wired):
    fetched, s3 = wired
    url = "https://bucket.s3.us-east-1.amazonaws.com/p.diff?X-Amz-Signature=abc"
    assert A._capture_diff(url, "continuum/patches/e-f-0.diff") == {
        "path": "continuum/patches/e-f-0.diff", "files_changed": ["src/server.js"]}
    assert fetched == [url] and s3.puts[0]["Key"] == "data/continuum/patches/e-f-0.diff"
