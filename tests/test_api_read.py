"""R7.1 — token access: the read API serves published documents to a caller whose token carries radar/read, and
nothing else; tokens are issued and verified by Amazon Cognito + API Gateway, never by the radar's own code."""
import importlib.util
import json
import re
import stat
from pathlib import Path

import pytest

from radar import api
from radar.agentkit import client

ROOT = Path(__file__).resolve().parents[1]
STACK = (ROOT / "infra" / "stack.py").read_text()
DOCS = {"data/events.json": b'{"kind": "events"}', "data/feeds/p0.atom": b"<feed/>", "data/events/ev_1.json": b"{}"}


def ev(path, scope="radar/read", method="GET"):
    return {"httpMethod": method, "pathParameters": {"proxy": path},
            "requestContext": {"authorizer": {"claims": {"scope": scope, "client_id": "c1"}}}}


def test_a_token_with_the_read_scope_reads_a_published_document(capsys):
    r = api.handler(ev("data/events.json"), read=DOCS.get)
    assert r["statusCode"] == 200 and json.loads(r["body"]) == {"kind": "events"}
    assert r["headers"]["Cache-Control"] == "no-store" and r["headers"]["Content-Type"].startswith("application/json")
    assert json.loads(capsys.readouterr().out) == {"type": "api_read", "client_id": "c1", "path": "data/events.json", "bytes": 18}
    assert api.handler(ev("data/feeds/p0.atom"), read=DOCS.get)["headers"]["Content-Type"].startswith("application/atom+xml")


@pytest.mark.parametrize(("event", "status", "code"), [
    (ev("data/events.json", scope=""), 403, "scope_missing"),
    (ev("data/events.json", scope="radar/readwrite other"), 403, "scope_missing"),     # a scope is a word, not a prefix
    ({"httpMethod": "GET", "pathParameters": {"proxy": "data/events.json"}}, 403, "scope_missing"),   # no authorizer: closed
    (ev("data/events.json", method="PUT"), 405, "method_not_allowed"),
    (ev("index.html"), 400, "bad_path"),
    (ev("data/../index.html"), 400, "bad_path"),
    (ev("data/events/../../assets/x.json"), 400, "bad_path"),
    (ev("data/events.json\n"), 400, "bad_path"),
    (ev("data//events.json"), 400, "bad_path"),
    (ev("data/EVENTS.json"), 400, "bad_path"),
    (ev("data/nope.json"), 404, "not_found"),
])
def test_everything_else_is_refused_with_a_code(event, status, code):
    def read(key):
        assert key in ("data/nope.json",), f"read {key}"       # a refused request never reaches the bucket
    r = api.handler(event, read=read)
    assert r["statusCode"] == status and json.loads(r["body"])["error"] == code


def test_a_document_too_large_for_one_response_is_said_not_truncated():
    r = api.handler(ev("data/events.json"), read=lambda k: b"x" * (api.MAX_BYTES + 1))
    assert r["statusCode"] == 413 and json.loads(r["body"])["limit"] == api.MAX_BYTES


def test_the_stack_gates_the_api_with_cognito_and_the_scope_and_grants_only_a_read():
    assert 'authorization_type=apigw.AuthorizationType.COGNITO, authorization_scopes=["radar/read"]' in STACK
    assert "apigw.CognitoUserPoolsAuthorizer(" in STACK and "self_sign_up_enabled=False" in STACK
    assert 'site.grant_read(api_fn, "data/*")' in STACK
    grants = re.findall(r"(\w+)\.grant\w*\(api_fn", STACK)
    assert grants == ["site"], grants                                      # one bucket read; no table, no secret
    assert "add_proxy(any_method=False)" in STACK and '"GET", apigw.LambdaIntegration(api_fn), authorizer=api_auth' in STACK
    beh = STACK[STACK.index('additional_behaviors={"api/*"'):STACK.index("default_behavior=")]
    assert "CACHING_DISABLED" in beh and "HTTPS_ONLY" in beh


def test_the_write_routes_need_their_own_scope_and_the_writer_touches_one_secret():
    assert STACK.count(".add_method(") == 3                                 # GET proxy · GET/POST subscriptions (loop) · DELETE
    assert '"authorization_scopes": ["radar/subscribe"]' in STACK and "**write)" in STACK
    assert re.findall(r"(\w+)\.grant\w*\(subscribe_fn", STACK) == ["self_subs", "self_subs"]
    assert "reserved_concurrent_executions=1, environment={\"SELF_SUBSCRIPTIONS_ARN\"" in STACK    # one read-modify-write at a time
    assert "self_subs.grant_read(notify_fn)" in STACK and "self_subs.grant_write(notify_fn)" not in STACK


def test_the_radar_mints_and_verifies_no_token_of_its_own():
    src = (ROOT / "src" / "radar" / "api.py").read_text()
    assert not re.search(r"\b(jwt|hmac|hashlib|secrets)\b", src)            # verification is API Gateway's


# --- the client side ---------------------------------------------------------------------------------------------

ENV = {"RADAR_CLIENT_ID": "cid", "RADAR_CLIENT_SECRET": "sec", "RADAR_TOKEN_URL": "https://auth.example/oauth2/token"}


def test_the_client_exchanges_its_credential_once_and_caches_the_token_privately(tmp_path):
    calls, clock = [], [1000.0]

    def post(url, body, headers):
        calls.append((url, body, headers))
        return json.dumps({"access_token": f"tok{len(calls)}", "expires_in": 3600}).encode()
    cache = tmp_path / "c" / "t.json"
    assert client.fetch_token(ENV, post, lambda: clock[0], cache) == "tok1"
    url, body, headers = calls[0]
    assert url == ENV["RADAR_TOKEN_URL"] and body == b"grant_type=client_credentials&scope=radar%2Fread"
    assert headers["Authorization"].startswith("Basic ") and "sec" not in body.decode()
    assert stat.S_IMODE(cache.stat().st_mode) == 0o600 and "sec" not in cache.read_text()
    clock[0] += 3500
    assert client.fetch_token(ENV, post, lambda: clock[0], cache) == "tok1" and len(calls) == 1     # still valid: no request
    clock[0] += 60
    assert client.fetch_token(ENV, post, lambda: clock[0], cache) == "tok2"                         # 60 s before expiry: renew


def test_token_configuration_errors_are_said_and_the_secret_only_goes_to_https(tmp_path):
    with pytest.raises(client.RadarError) as e:
        client.fetch_token({"RADAR_CLIENT_ID": "cid"}, cache=tmp_path / "t")
    assert e.value.detail["error"] == "token_config_incomplete" and e.value.detail["actual"] == ["RADAR_CLIENT_SECRET", "RADAR_TOKEN_URL"]
    with pytest.raises(client.RadarError) as e:
        client.fetch_token({**ENV, "RADAR_TOKEN_URL": "http://auth.example/token"}, cache=tmp_path / "t")
    assert e.value.detail["error"] == "bad_radar_token_url"
    with pytest.raises(client.RadarError) as e:
        client.fetch_token(ENV, lambda *a: b'{"error": "invalid_client"}', cache=tmp_path / "t")
    assert e.value.detail["error"] == "token_malformed"


def test_a_token_reads_through_the_api_path_and_basic_auth_through_the_site(monkeypatch):
    seen = []

    class Opener:
        def open(self, req, timeout):
            seen.append((req.full_url, req.get_header("Authorization")))
            raise client.RadarError("stop", "", None, None)
    monkeypatch.setattr(client.urllib.request, "build_opener", lambda *a: Opener())
    for env in ({"RADAR_URL": "https://r.example", "RADAR_TOKEN": "t"},
                {"RADAR_URL": "https://r.example", "RADAR_USER": "u", "RADAR_PASSWORD": "p"}):
        with pytest.raises(client.RadarError):
            client.http_get(env)("data/ops.json")
    assert seen[0] == ("https://r.example/api/data/ops.json", "Bearer t")
    assert seen[1][0] == "https://r.example/data/ops.json" and seen[1][1].startswith("Basic ")


def test_the_operator_script_never_prints_the_secret_and_names_are_checked():
    spec = importlib.util.spec_from_file_location("radar_token", ROOT / "scripts" / "radar-token.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    text = m.env_text("https://r", "https://t", "cid", "s3cret")
    assert set(re.findall(r"^(\w+)=", text, re.MULTILINE)) == {"RADAR_URL", "RADAR_TOKEN_URL", "RADAR_CLIENT_ID", "RADAR_CLIENT_SECRET"}
    src = (ROOT / "scripts" / "radar-token.py").read_text()
    assert "ClientSecret" in src and not re.search(r"print\([^)]*ClientSecret", src) and "0o600" in src and "O_EXCL" in src
    assert m.NAME.fullmatch("team-a") and not m.NAME.fullmatch("Team A") and not m.NAME.fullmatch("a\n")
    assert 'AllowedOAuthFlows=["client_credentials"]' in src and "AllowedOAuthScopes=[SCOPE, *([WRITE_SCOPE] if a.subscribe else [])]" in src and m.SCOPE == api.SCOPE
    from radar import subscribe_api
    assert m.WRITE_SCOPE == subscribe_api.SCOPE


def test_a_client_without_the_permission_is_told_so_not_called_revoked(tmp_path):
    import io
    import urllib.error

    def post(url, body, headers):
        raise urllib.error.HTTPError(url, 400, "Bad Request", {}, io.BytesIO(b'{"error":"invalid_scope"}'))
    with pytest.raises(client.RadarError) as e:
        client.fetch_token(ENV, post, cache=tmp_path / "t", scope="radar/subscribe")
    assert e.value.detail["error"] == "scope_not_granted" and e.value.detail["actual"] == "radar/subscribe"

    def gone(url, body, headers):
        raise urllib.error.HTTPError(url, 400, "Bad Request", {}, io.BytesIO(b'{"error":"invalid_client"}'))
    with pytest.raises(client.RadarError) as e:
        client.fetch_token(ENV, gone, cache=tmp_path / "t")
    assert e.value.detail["error"] == "token_refused"


def test_usage_names_the_clients_that_read_and_shows_the_ones_that_did_not():
    """R8.7: "who is using it" is a number — the roadmap's veto line for R7 depends on it."""
    spec = importlib.util.spec_from_file_location("radar_token", ROOT / "scripts" / "radar-token.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    res = [[{"field": "client_id", "value": "c1"}, {"field": "reads", "value": "42"}, {"field": "last", "value": "2026-11-14 08:00:00.000"}],
           [{"field": "client_id", "value": "gone"}, {"field": "reads", "value": "3"}, {"field": "last", "value": "2026-11-10 00:00:00.000"}]]
    rows = m.usage_rows(res, {"team-a": "c1", "team-b": "c2"})
    assert [(r["name"], r["reads"]) for r in rows] == [("team-a", 42), ("(revoked)", 3), ("team-b", 0)]
    assert 'type = "api_read"' in m.USAGE_QUERY and "by client_id" in m.USAGE_QUERY
    assert '"type": "api_read", "client_id"' in (ROOT / "src" / "radar" / "api.py").read_text()     # the log line the query reads
