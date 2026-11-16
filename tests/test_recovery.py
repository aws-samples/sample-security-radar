"""R5.5: what an operator needs to undo a bad Publish, a wrong prune or a dropped table — read from infra/stack.py
(the synthesized template carries the same: VersioningConfiguration Enabled, NoncurrentDays, DeletionProtectionEnabled)."""
import ast
import re
from pathlib import Path

STACK = (Path(__file__).resolve().parents[1] / "infra" / "stack.py").read_text()


def _bucket_helper() -> ast.FunctionDef:
    return next(n for n in ast.walk(ast.parse(STACK)) if isinstance(n, ast.FunctionDef) and n.name == "bucket")


def test_every_bucket_is_versioned_and_its_old_versions_expire():
    src = ast.unparse(_bucket_helper())
    assert "versioned=True" in src
    assert "noncurrent_version_expiration=Duration.days(noncurrent_days)" in src
    calls = re.findall(r'= bucket\("(\w+)", (\w+)', STACK)
    assert {n for n, _ in calls} == {"RawBucket", "SiteBucket", "SecurityAgentCodeBucket"}, calls
    windows = {k: int(v) for k, v in re.findall(r"^(\w+_NONCURRENT_DAYS) = (\d+)", STACK, re.MULTILINE)}
    assert all(1 <= windows[w] <= 90 for _, w in calls), windows     # recoverable, and not kept for ever
    assert windows["SITE_NONCURRENT_DAYS"] <= 14                     # rewritten every cycle: a short window


def test_the_table_cannot_be_deleted_by_a_stack_delete_or_a_slip():
    table = re.search(r"ddb\.Table\(self, \"Table\".*?\)\)\n", STACK, re.DOTALL).group(0)
    assert "deletion_protection=not ephemeral" in table and "point_in_time_recovery_enabled=True" in table


def test_the_restore_script_knows_the_same_windows_as_the_stack():
    """scripts/restore.py refuses an --at past the window (expired history would plan a delete of a key that existed)."""
    src = (Path(__file__).resolve().parents[1] / "scripts" / "restore.py").read_text()
    script = ast.literal_eval(re.search(r"^WINDOW_DAYS = (\{.*\})", src, re.MULTILINE).group(1))
    windows = {k: int(v) for k, v in re.findall(r"^(\w+)_NONCURRENT_DAYS = (\d+)", STACK, re.MULTILINE)}
    assert script == {"site": windows["SITE"], "raw": windows["RAW"], "code": windows["RAW"]}
    assert 'get_bucket_versioning(Bucket=bucket).get("Status") != "Enabled"' in src


def test_site_access_logs_are_kept_a_month_without_cookies_and_never_public():
    """ROADMAP R3.6 veto: the phone layout waits for access data. The logs carry reader IPs: private, expired, no
    cookies (the Basic Auth header is never in a standard log)."""
    days = int(re.search(r"^ACCESS_LOG_DAYS = (\d+)", STACK, re.MULTILINE).group(1))
    assert 7 <= days <= 31                                         # a week of data at least; personal data not kept long
    b = re.search(r's3\.Bucket\(self, "AccessLogBucket",.*?\]\)', STACK, re.DOTALL).group(0)
    assert "BlockPublicAccess.BLOCK_ALL" in b and "enforce_ssl=True" in b
    assert "expiration=Duration.days(ACCESS_LOG_DAYS)" in b
    site = re.search(r'cf\.Distribution\(\s*self, "Site",.*?\n', STACK, re.DOTALL).group(0) + \
        re.search(r'enable_logging=.*\n', STACK).group(0)
    assert "enable_logging=True, log_bucket=access_logs" in site and "log_includes_cookies=False" in site
