"""The CloudFront Function runs on cloudfront-js-2.0, a restricted ES subset: a construct it rejects is a
FunctionExecutionError ⇒ 503 for every visitor (live 2026-10-26: `for...of` took the site down ~5 min).
Guard the known-unsupported syntax statically, and exercise the handler logic in node with a stubbed runtime."""

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

SRC = (Path(__file__).resolve().parents[1] / "infra" / "basic_auth.js").read_text()


def test_no_syntax_cloudfront_js_rejects():
    code = re.sub(r"//.*", "", SRC)
    assert not re.search(r"\bfor\s*\([^)]*\b(of|in)\b", code), "for...of / for...in are not supported"
    assert "?." not in code and "??" not in code, "optional chaining / nullish coalescing are not supported"


def _hash(user: str, pw: str) -> str:
    return hashlib.sha256(("Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()).encode()).hexdigest()


# CI must never skip this silently (a skipped test let mutation M56 survive): skip only on dev machines without node
@pytest.mark.skipif(not shutil.which("node") and not os.environ.get("CI"), reason="node not installed")
@pytest.mark.parametrize("header,stored,allowed", [
    (None, "{h1}", False),
    ("Basic " + base64.b64encode(b"demo:pw").decode(), "{h1}", True),
    ("Basic " + base64.b64encode(b"aws:pw").decode(), "{h1},{h2}", True),        # alias user
    ("Basic " + base64.b64encode(b"aws:wrong").decode(), "{h1},{h2}", False),
    ("Basic " + base64.b64encode(b"demo:pw").decode(), "", False),               # missing hash ⇒ fail closed
    ("Basic " + base64.b64encode(b"demo:pw").decode(), "garbage", False),
])
def test_handler_logic(tmp_path, header, stored, allowed):
    stored = stored.format(h1=_hash("demo", "pw"), h2=_hash("aws", "pw"))
    body = SRC.replace("import cf from 'cloudfront';", "").replace("const crypto = require('crypto');", "")
    harness = f"""
const crypto = require('crypto');
const cf = {{ kvs: () => ({{ get: async () => {json.dumps(stored)} }}) }};
{body}
const ev = {{ request: {{ headers: {json.dumps({"authorization": {"value": header}} if header else {})} }} }};
handler(ev).then(r => console.log(r.statusCode === 401 ? 'DENY' : 'ALLOW'));
"""
    f = tmp_path / "h.js"
    f.write_text(harness)
    out = subprocess.run(["node", str(f)], capture_output=True, text=True, check=True).stdout.strip()
    assert out == ("ALLOW" if allowed else "DENY")
