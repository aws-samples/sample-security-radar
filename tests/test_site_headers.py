"""The site distribution sends a Content-Security-Policy (research/action/05 #2 / W2): third-party URLs reach the page
(feed links, exchange notices), and the managed SECURITY_HEADERS policy has no CSP, so one missed safeHref was stored
XSS. infra/stack.py is read with ast (importing it would need aws-cdk-lib in the test environment)."""
import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STACK = (ROOT / "infra" / "stack.py").read_text()


def _csp() -> dict[str, list[str]]:
    tree = ast.parse(STACK)
    [v] = [ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
           and getattr(n.targets[0], "id", "") == "SITE_CSP"]
    return {d.split()[0]: d.split()[1:] for d in (x.strip() for x in v.split(";")) if d}


def test_the_csp_allows_only_the_sites_own_scripts():
    csp = _csp()
    assert csp["default-src"] == ["'self'"]
    assert csp["script-src"] == ["'self'"]            # no inline script, no eval
    assert csp["object-src"] == ["'none'"] and csp["base-uri"] == ["'none'"]
    assert csp["frame-ancestors"] == ["'self'"]       # = the X-Frame-Options SAMEORIGIN the managed policy sent
    assert csp["connect-src"] == ["'self'"]           # the UI only fetches ./data/*
    # vite inlines the small Inter font subsets as data: URLs and a select arrow is a data: SVG — without these the
    # built UI renders with fallback fonts (headless check of 12 routes, 2026-11-11)
    assert csp["font-src"] == ["'self'", "data:"] and csp["img-src"] == ["'self'", "data:"]


def test_the_distribution_sends_it_instead_of_the_managed_policy():
    call = re.search(r"cf\.Distribution\((.*?)\n\n", STACK, re.DOTALL)
    assert call and "response_headers_policy=site_headers" in call.group(1)
    assert "cf.ResponseHeadersPolicy.SECURITY_HEADERS" not in STACK
    assert re.search(r"content_security_policy=SITE_CSP\b", STACK)
    for header in ("content_type_options", "frame_options", "referrer_policy", "strict_transport_security", "xss_protection"):
        assert f"{header}=" in STACK, header     # what SECURITY_HEADERS sent is still sent


def test_the_built_ui_fits_the_policy():
    """What the CSP above forbids, the UI must not need: an inline <script> in index.html, or eval / new Function."""
    html = (ROOT / "ui" / "index.html").read_text()
    assert all(re.search(r"\bsrc=", tag) for tag in re.findall(r"<script\b[^>]*>", html))
    assert not re.search(r"<script\b[^>]*>\s*[^<\s]", html)      # no body between <script …> and </script>
    src = [p for p in (ROOT / "ui" / "src").rglob("*.ts*") if "/test/" not in str(p)]
    assert not [p.name for p in src if re.search(r"\beval\(|new Function\(", p.read_text())]
