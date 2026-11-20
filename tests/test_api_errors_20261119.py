"""Neo 2026-11-19: 「令牌地址是无效的，是吗？」 — a feed's token address opened in a browser read {"message":"Unauthorized"}.
The API's 401 / 403 now say what is missing and where to get it; the authorizer itself is unchanged."""
from pathlib import Path

STACK = (Path(__file__).resolve().parents[1] / "infra" / "stack.py").read_text()


def _block(kind: str) -> str:
    return STACK.split(f"type=apigw.ResponseType.{kind}", 1)[1].split("ensure_ascii=False)})", 1)[0]


def test_401_says_a_token_is_needed_and_where_it_comes_from():
    b = _block("UNAUTHORIZED")
    assert 'status_code="401"' in b and '"error": "token_required"' in b
    assert "Authorization: Bearer <access token>" in b and "scripts/radar-token.py create" in b


def test_403_names_the_scopes():
    b = _block("ACCESS_DENIED")
    assert 'status_code="403"' in b and '"error": "scope_missing"' in b and "radar/read" in b and "radar/subscribe" in b


def test_the_authorizer_still_guards_every_method():
    assert '"authorizer": api_auth' in STACK and "authorizer=api_auth" in STACK
    assert "authorization_type=apigw.AuthorizationType.COGNITO" in STACK
