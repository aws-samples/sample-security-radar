"""Token access (roadmap R7.1): GET /api/data/<path> → the published document, for a caller holding a Cognito access
token with the scope radar/read. Amazon API Gateway's Cognito authorizer verifies the token and the scope before
this runs; the handler checks the scope again (fail closed if the route were ever wired without the authorizer),
serves only documents under data/ of the site bucket, and never writes.

Kept apart from radar.handlers: this Lambda needs one bucket read and nothing of the pipeline.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

SCOPE = "radar/read"
MAX_BYTES = 5_500_000      # a Lambda proxy response carries at most 6 MB
# the published layout: data/<name>.json, data/<dir>/<name>.json|atom — lower-case names, no dot segments
_PATH = re.compile(r"data(/[a-z0-9][a-z0-9_-]{0,63}){0,2}/[a-z0-9][a-z0-9_.-]{0,80}\.(json|atom)")
_TYPES = {"json": "application/json; charset=utf-8", "atom": "application/atom+xml; charset=utf-8"}
_s3: Any = None


def _answer(status: int, body: str, ctype: str = "application/json; charset=utf-8") -> dict[str, Any]:
    return {"statusCode": status, "headers": {"Content-Type": ctype, "Cache-Control": "no-store",
                                              "X-Content-Type-Options": "nosniff"}, "body": body}


def _error(status: int, code: str, message: str, actual: Any = None, limit: Any = None) -> dict[str, Any]:
    return _answer(status, json.dumps({"error": code, "message": message, "actual": actual, "limit": limit}))


def _read(key: str) -> bytes | None:
    """The object, or None when it does not exist. Any other failure raises (a 5xx, not "not found")."""
    global _s3
    if _s3 is None:
        import boto3
        _s3 = boto3.client("s3")
    try:
        return _s3.get_object(Bucket=os.environ["SITE_BUCKET"], Key=key)["Body"].read(MAX_BYTES + 1)
    except _s3.exceptions.NoSuchKey:
        return None


def handler(event: dict[str, Any], _ctx: Any = None, read: Any = None) -> dict[str, Any]:
    claims = ((event.get("requestContext") or {}).get("authorizer") or {}).get("claims") or {}
    if SCOPE not in str(claims.get("scope") or "").split():
        return _error(403, "scope_missing", "the token does not carry the read scope", claims.get("scope"), SCOPE)
    if event.get("httpMethod") != "GET":
        return _error(405, "method_not_allowed", "this API only reads", event.get("httpMethod"), "GET")
    path = (event.get("pathParameters") or {}).get("proxy") or ""
    if not _PATH.fullmatch(path) or ".." in path:
        return _error(400, "bad_path", "not a published document path", path[:120], "data/<name>.json")
    body = (read or _read)(path)
    if body is None:
        return _error(404, "not_found", "no such document", path, None)
    if len(body) > MAX_BYTES:
        return _error(413, "too_large", "the document is larger than this API returns", len(body), MAX_BYTES)
    # who read what: the client id is an identifier, not a secret
    print(json.dumps({"type": "api_read", "client_id": claims.get("client_id"), "path": path, "bytes": len(body)}))
    return _answer(200, body.decode("utf-8"), _TYPES[path.rsplit(".", 1)[1]])
