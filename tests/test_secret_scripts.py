"""The secret-copying scripts keep values out of every child's argv (`ps` shows argv to any local user) and pass the
collector key script only the keys it needs.

Each script runs for real in a sandbox: a copy of the script next to a stub scripts/lib.sh, a fake HOME whose ~/.env
holds FAKE values, and stubs for aws / mcurl / trash (plus a jq wrapper) that log their argv. No real ~/.env is read,
nothing leaves the machine.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LIB = 'export AWS_PROFILE=${AWS_PROFILE:-stub-profile}\nout() { printf "arn:fake:%s" "$1"; }\n'

# aws: log argv + env; put-secret-value copies its file:// payload (stdin for /dev/stdin) to $CAP/secret-N
AWS = r'''#!/usr/bin/env bash
printf '%s\0' "$@" >> "$CAP/argv"; printf '\n' >> "$CAP/argv"
env > "$CAP/aws-env"
for a in "$@"; do case "$a" in file://*) n=$(ls "$CAP" | grep -c '^secret-'); cat "${a#file://}" > "$CAP/secret-$n";; esac; done
case " $* " in *" get-secret-value "*) printf '{"username":"ui-user","password":"FAKE-UI-PW-3"}\n';; esac
exit 0
'''
# mcurl: log argv; record the bodies / header files it was handed by @path; GET-for-code answers 404 (⇒ POST path)
MCURL = r'''#!/usr/bin/env bash
printf '%s\0' "$@" >> "$CAP/argv"; printf '\n' >> "$CAP/argv"
prev=""
for a in "$@"; do
  case "$prev:$a" in -d:@*|--data-binary:@*) cat "${a#@}" >> "$CAP/bodies"; echo >> "$CAP/bodies"; echo "${a#@}" >> "$CAP/paths";;
                     -H:@*) cat "${a#@}" >> "$CAP/headers"; echo "${a#@}" >> "$CAP/paths";; esac
  prev="$a"
done
case " $* " in *" -w "*) printf 404;; *) printf '{"key":"k","masked":true}';; esac
'''
JQ = '#!/usr/bin/env bash\nprintf \'%s\\0\' "$@" >> "$CAP/argv"; printf \'\\n\' >> "$CAP/argv"\nexec "$REAL_JQ" "$@"\n'
TRASH = '#!/usr/bin/env bash\nrm -f "$@"\n'

FAKES = {"SLACK_BOT_TOKEN": "FAKE-SLACK-1", "LARK_APP_SECRET": "FAKE-LARK-2", "DEMO_FLEET_GITHUB_TOKEN": "FAKE-RW-4",
         "DEMO_FLEET_GITHUB_TOKEN_RO": "FAKE-RO-5", "GITLAB_API_TOKEN": "FAKE-GL-6", "X_API_KEY": "FAKE-TW-7",
         "FIRECRAWL_API_KEY": "FAKE-FC-8", "FIRECRAWL_API_KEY_2": "FAKE-FC-9", "FOO_TOKEN": "FAKE-UNRELATED-10"}


def _exe(p: Path, body: str) -> None:
    p.write_text(body)
    p.chmod(p.stat().st_mode | stat.S_IXUSR)


def run(tmp_path: Path, script: str, env_file: str) -> Path:
    """Run scripts/<script> in the sandbox; returns the capture dir."""
    box, home, bin_, cap = tmp_path / "box", tmp_path / "home", tmp_path / "bin", tmp_path / "cap"
    for d in (box / "scripts", home, bin_, cap):
        d.mkdir(parents=True)
    shutil.copy(ROOT / "scripts" / script, box / "scripts" / script)
    (box / "scripts" / "lib.sh").write_text(LIB)
    (home / ".env").write_text(env_file)
    _exe(bin_ / "aws", AWS)
    _exe(bin_ / "mcurl", MCURL)
    _exe(bin_ / "jq", JQ)
    _exe(bin_ / "trash", TRASH)
    real_jq = shutil.which("jq")
    if not real_jq:   # GitLab's .py jobs apt-install jq (.gitlab-ci.yml); a bare image without it skips, visibly
        pytest.skip("jq not on PATH — the secret scripts build their JSON with it")
    # stubs shadow the real aws / mcurl / jq / trash; uv stays reachable (the scripts run python through it)
    env = {"PATH": f"{bin_}:{os.environ['PATH']}", "HOME": str(home), "CAP": str(cap), "REAL_JQ": real_jq,
           "UV_CACHE_DIR": os.environ.get("UV_CACHE_DIR", str(Path.home() / ".cache" / "uv"))}
    r = subprocess.run(["bash", str(box / "scripts" / script)], check=False, env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    assert not any(v in r.stdout + r.stderr for v in FAKES.values())        # never echoed either
    return cap


def argv(cap: Path) -> str:
    return (cap / "argv").read_text() if (cap / "argv").exists() else ""


def test_set_notify_puts_the_push_credentials_in_the_secret_but_never_in_argv(tmp_path):
    """Without a subscriptions file the old channel ids become the owner's subscriptions (P3 contract: the station has
    no single-channel path any more) — and the result parses with no invalid entry."""
    from radar import notify
    # plain assignments (no `export`) as well as exported ones: both must reach the secret
    cap = run(tmp_path, "set-notify.sh", "SLACK_BOT_TOKEN=FAKE-SLACK-1\nexport SLACK_CHANNEL_ID=C1\n"
                                         "LARK_APP_ID=cli_a\nLARK_APP_SECRET='FAKE-LARK-2'\nLARK_CHAT_ID=oc_1\n")
    cfg = json.loads((cap / "secret-0").read_text())
    p01 = {"severity": ["P0", "P1"]}
    assert cfg == {"rollout": "owner_only", "slack_bot_token": "FAKE-SLACK-1", "lark_app_id": "cli_a",
                   "lark_app_secret": "FAKE-LARK-2", "lark_domain": "open.larksuite.com", "subscriptions": [
                       {"id": "slack", "owner": True, "channel": "slack_channel", "target": "C1", "filters": p01},
                       {"id": "lark", "owner": True, "channel": "lark_chat", "target": "oc_1", "filters": p01}]}
    c = notify.parse_config(cfg)
    assert c.invalid == [] and [s.id for s in c.subscriptions] == ["slack", "lark"]
    seen = argv(cap)
    assert "FAKE-SLACK-1" not in seen and "FAKE-LARK-2" not in seen


def test_set_notify_leaves_an_absent_channel_out(tmp_path):
    cap = run(tmp_path, "set-notify.sh", "LARK_APP_ID=a\nLARK_APP_SECRET=s\nLARK_CHAT_ID=c\nLARK_DOMAIN=open.feishu.cn\n")
    cfg = json.loads((cap / "secret-0").read_text())
    assert [s["id"] for s in cfg["subscriptions"]] == ["lark"] and "slack_bot_token" not in cfg
    assert cfg["lark_domain"] == "open.feishu.cn"


def test_set_notify_takes_the_private_subscription_file_and_keeps_webhook_secrets_out_of_argv(tmp_path):
    subs = tmp_path / "subs.json"
    subs.write_text(json.dumps([{"id": "hook", "owner": True, "channel": "webhook", "target": "https://h.example/x",
                                 "secret": "FAKE-HOOK-11" + "k" * 30, "filters": {"domain": ["web3"]}}]))
    cap = run(tmp_path, "set-notify.sh", f"NOTIFY_SUBSCRIPTIONS_FILE={subs}\nNOTIFY_ROLLOUT=all\nSLACK_CHANNEL_ID=C1\n")
    cfg = json.loads((cap / "secret-0").read_text())
    assert cfg["rollout"] == "all" and [s["id"] for s in cfg["subscriptions"]] == ["hook"]   # the file wins
    assert "FAKE-HOOK-11" not in argv(cap)


# the public aws-samples bundle drops this script (build-sample.py DENY) but ships tests/ whole
@pytest.mark.skipif(not (ROOT / "scripts" / "set-fleet-token.sh").is_file(), reason="set-fleet-token.sh not in this tree")
def test_set_fleet_token_sends_every_token_through_files_never_argv(tmp_path):
    cap = run(tmp_path, "set-fleet-token.sh", "export DEMO_FLEET_GITHUB_TOKEN_RO=FAKE-RO-5\n"
                                              "export DEMO_FLEET_GITHUB_TOKEN=FAKE-RW-4\nexport GITLAB_API_TOKEN=FAKE-GL-6\n")
    seen = argv(cap)
    for v in ("FAKE-RO-5", "FAKE-RW-4", "FAKE-GL-6", "FAKE-UI-PW-3"):
        assert v not in seen, v
    assert (cap / "secret-0").read_text() == "FAKE-RO-5"                     # → Secrets Manager
    bodies = [json.loads(b) for b in (cap / "bodies").read_text().splitlines() if b]
    assert {b["key"]: (b["value"], b["masked"]) for b in bodies} == {
        "DEMO_FLEET_GITHUB_TOKEN": ("FAKE-RW-4", True), "RADAR_UI_USER": ("ui-user", False),
        "RADAR_UI_PASSWORD": ("FAKE-UI-PW-3", True), "RADAR_SITE_URL": ("arn:fake:SiteUrl", False)}
    assert set((cap / "headers").read_text().split("\n")) - {""} == {"PRIVATE-TOKEN: FAKE-GL-6"}
    leftovers = [p for p in set((cap / "paths").read_text().split()) if Path(p).exists()]
    assert leftovers == [], "temp files holding a token outlive the script"


def test_sync_collector_keys_reads_only_the_collector_keys(tmp_path):
    cap = run(tmp_path, "sync-collector-keys.sh",
              "export AWS_PROFILE=wrong-account\nFOO_TOKEN=FAKE-UNRELATED-10\nexport X_API_KEY=FAKE-TW-7\n"
              "FIRECRAWL_API_KEY_2=\"FAKE-FC-9\"\nexport FIRECRAWL_API_KEY=FAKE-FC-8\nFIRECRAWL_API_KEY_3=\n")
    assert json.loads((cap / "secret-0").read_text()) == {"X_API_KEY": "FAKE-TW-7",
                                                         "FIRECRAWL_API_KEYS": ["FAKE-FC-8", "FAKE-FC-9"]}
    aws_env = dict(line.split("=", 1) for line in (cap / "aws-env").read_text().splitlines() if "=" in line)
    assert aws_env["AWS_PROFILE"] == "stub-profile"                              # ~/.env cannot redirect the write
    assert not {"FOO_TOKEN", "X_API_KEY", "FIRECRAWL_API_KEY"} & set(aws_env)
    assert "FAKE-TW-7" not in argv(cap)


@pytest.mark.parametrize("script", sorted(p.name for p in (ROOT / "scripts").glob("*.sh")))
def test_no_shell_script_hands_a_secret_to_argv(script):
    # static net for scripts the sandbox above does not run: the three shapes that put a value on a command line
    import re
    src = (ROOT / "scripts" / script).read_text()
    bad = [r'--arg \w+ "\$\{?\w*(TOKEN|SECRET|KEY|PASSWORD)', r'-d "\$', r'-H "PRIVATE-TOKEN: \$']
    assert not [b for b in bad if re.search(b, src)], script
