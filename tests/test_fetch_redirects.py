"""R2.8: every fetch without an allowlist still has a redirect policy — no downgrade, no hop into the own network —
and a firecrawl answer is capped like any other body. No network: DNS is replaced, the handler is called directly."""

import email.message
import io
import json
import socket
import urllib.request

import pytest

from radar import fetch
from radar.limits import Limits


def _hop(src: str, dst: str):
    req = urllib.request.Request(src)
    return fetch._SafeRedirect().redirect_request(req, None, 302, "Found", email.message.Message(), dst)


@pytest.fixture
def dns(monkeypatch):
    """name → address; a name not listed does not resolve."""
    table: dict[str, str] = {}

    def gai(host, port, *a, **k):
        if host not in table:
            raise socket.gaierror(8, "nodename nor servname provided")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (table[host], 0))]
    monkeypatch.setattr(fetch.socket, "getaddrinfo", gai)
    return table


@pytest.mark.parametrize("dst,why", [
    ("http://127.0.0.1:9001/2018-06-01/runtime/invocation/next", "internal"),   # from an http source: no downgrade
    ("http://www.example.com/feed", "downgrade"),
    ("ftp://www.example.com/feed", "non-http"),
    ("https://169.254.169.254/latest/meta-data/", "internal"),
    ("https://[::1]/x", "internal"),
    ("https://10.1.2.3/x", "internal"),
    ("https://metadata.google.internal/x", "internal"),
    ("https://localhost/x", "internal"),
    ("https://rebind.example.net/x", "internal"),        # a public-looking name that resolves to a private address
])
def test_a_redirect_the_general_policy_refuses(dns, dst, why):
    dns["www.example.com"] = "93.184.215.14"
    dns["rebind.example.net"] = "10.0.0.7"
    with pytest.raises(fetch.FetchError) as e:
        _hop(("http" if dst.startswith("http:") and why != "downgrade" else "https") + "://www.example.com/feed", dst)
    assert e.value.code == "redirect_refused" and why in e.value.reason, e.value.reason


@pytest.mark.parametrize("src,dst", [
    ("https://www.example.com/feed", "https://cdn.example.org/feed.xml"),   # https → https, another public host
    ("http://www.example.com/feed", "https://www.example.com/feed"),        # an upgrade
    ("http://www.example.com/feed", "http://mirror.example.org/feed"),      # http stays http (the source was http)
    ("https://www.example.com/feed", "https://unresolvable.example/x"),     # the open reports the DNS error itself
])
def test_a_redirect_the_general_policy_follows(dns, src, dst):
    dns["www.example.com"] = dns["cdn.example.org"] = dns["mirror.example.org"] = "93.184.215.14"
    assert _hop(src, dst).full_url == dst


def test_every_open_without_an_allowlist_carries_the_general_policy(monkeypatch):
    seen: list[object] = []
    monkeypatch.setattr(fetch, "_open", lambda req, timeout, redirect: seen.append(redirect) or io.BytesIO(b""))
    fetch.urlopen("https://www.example.com/", timeout=1)
    fetch.urlopen("https://raw.githubusercontent.com/x", timeout=1, allow_hosts=frozenset({"raw.githubusercontent.com"}))
    assert isinstance(seen[0], fetch._SafeRedirect) and isinstance(seen[1], fetch._GuardedRedirect)


def test_a_firecrawl_answer_past_the_cap_is_refused_not_parsed(monkeypatch):
    monkeypatch.setattr(fetch, "secrets", lambda: {"FIRECRAWL_API_KEYS": ["k"]})
    monkeypatch.setattr(Limits, "HTTP_MAX_BYTES", 64)
    big = json.dumps({"data": {"rawHtml": "x" * 200}}).encode()

    class R(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr(fetch, "_open", lambda *a, **k: R(big))
    with pytest.raises(fetch.FetchError) as e:
        fetch.firecrawl_raw("https://www.freebuf.com/feed")
    assert e.value.code == "too_large"
