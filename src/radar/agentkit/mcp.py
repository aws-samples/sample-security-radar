"""`python -m radar.agentkit.mcp` — a Model Context Protocol server on stdio (no socket, no port): the tools of
radar.agentkit.client.TOOLS, read-only. One JSON-RPC 2.0 message per line in, one per line out; logs go to stderr.

Third-party text (titles, evidence) comes back as data inside a JSON document; the server adds no instructions to it.
"""
from __future__ import annotations

import json
import sys
from typing import IO, Any

from radar.agentkit.client import TOOLS, Radar, RadarError, call

PROTOCOL = "2024-11-05"
SERVER = {"name": "security-radar", "version": "1"}


def _tools() -> list[dict[str, Any]]:
    return [{"name": n, "description": d,
             "inputSchema": {"type": "object", "properties": p, "required": r, "additionalProperties": False},
             "annotations": {"readOnlyHint": True}} for n, (d, p, r) in TOOLS.items()]


def handle(msg: dict[str, Any], radar_factory: Any = Radar) -> dict[str, Any] | None:
    """One request → its response; a notification (no id) → None."""
    mid, method = msg.get("id"), msg.get("method")
    if mid is None:
        return None
    ok = lambda result: {"jsonrpc": "2.0", "id": mid, "result": result}
    if method == "initialize":
        return ok({"protocolVersion": (msg.get("params") or {}).get("protocolVersion") or PROTOCOL,
                   "capabilities": {"tools": {}}, "serverInfo": SERVER})
    if method == "ping":
        return ok({})
    if method == "tools/list":
        return ok({"tools": _tools()})
    if method == "tools/call":
        p = msg.get("params") or {}
        try:
            out = call(radar_factory(), p.get("name") or "", p.get("arguments") or {})
            return ok({"content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False)}], "isError": False})
        except RadarError as e:     # the caller sees why (code / actual / limit); the server keeps running
            return ok({"content": [{"type": "text", "text": json.dumps(e.detail, ensure_ascii=False)}], "isError": True})
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}


def serve(stdin: IO[str] = sys.stdin, stdout: IO[str] = sys.stdout) -> None:
    for line in stdin:
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            resp: dict[str, Any] | None = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        else:
            resp = handle(msg) if isinstance(msg, dict) else {"jsonrpc": "2.0", "id": None,
                                                              "error": {"code": -32600, "message": "invalid request"}}
        if resp is not None:
            stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            stdout.flush()


if __name__ == "__main__":
    serve()
