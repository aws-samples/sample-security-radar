#!/usr/bin/env bash
# What .gitlab-ci.yml runs per commit, run before a deployment (Neo 2026-11-19: 「前置性的全部解决」 — an axe
# violation reached the site because only CI ran axe). Called by scripts/preflight.py; cheapest first, so a lint error
# does not wait for a UI build. tests/test_preflight_ci_parity.py fails when CI gains a command missing here; what
# stays CI-only is preflight.CI_ONLY with its reason.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
mkdir -p build

check() {   # check <name> <command…>: quiet on success, the last lines and exit 1 on failure
  local name=$1; shift
  local out
  if ! out=$("$@" 2>&1); then
    printf '%s\n' "$out" | tail -12
    echo "ci-parity FAIL ${name}"
    exit 1
  fi
  echo "preflight: ${name} ok"
}

gate="${CONTRACT_GATE:-$HOME/Code/touchstone/skill/tools/contract-gate.py}"   # the maintainer's budget gate (CI fetches it)

check ruff uv run ruff check src tests infra scripts integrations
check secret_scan uv run python scripts/secret_scan.py
check pyright_ratchet uv run python scripts/pyright_ratchet.py
if [ -f "$gate" ]; then check contract_gate uv run python "$gate"; else echo "preflight: contract_gate SKIPPED — ${gate} not installed"; fi
check shellcheck sh -c 'shellcheck -S warning scripts/*.sh'
# same command as the CI job (tests/test_preflight_ci_parity.py compares them verbatim)
check pip_audit sh -c 'uv export --frozen --no-hashes --no-emit-project -q > /tmp/req.txt && uvx pip-audit -r /tmp/req.txt --disable-pip --no-deps --progress-spinner off'
cd ui || exit 1
check ui_install npm ci --no-audit --no-fund -q
check ui_types_current sh -c 'npm run gen:types && git diff --exit-code -- src/types/site-data.ts'
check ui_typecheck npm run typecheck
check ui_test npm test
check ui_build npm run build
check ui_a11y npm run a11y     # axe audits the build just made
