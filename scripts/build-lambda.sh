#!/usr/bin/env bash
# Build the Lambda code asset: runtime deps (pure Python, so the macOS build runs on Lambda arm64)
# + src/radar → build/lambda. Uses `uv sync` into a throwaway env (no pip; uv only).
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf build/lambda build/venv && mkdir -p build/lambda
UV_PROJECT_ENVIRONMENT=build/venv uv sync -q --no-dev --no-install-project --python 3.12
site=build/venv/lib/python3.12/site-packages
for p in "$site"/*; do
  case "$(basename "$p")" in _virtualenv*|*.pth|__pycache__|pip|pip-*|setuptools*|_distutils_hack) ;; *) cp -R "$p" build/lambda/ ;; esac
done
cp -R src/radar build/lambda/radar
find build/lambda -name '__pycache__' -prune -exec rm -rf {} +
native=$(find build/lambda -name '*.so' | wc -l | tr -d ' ')
if [ "$native" != "0" ]; then echo "native extension found ($native) — not portable to Lambda" >&2; exit 1; fi
echo "built build/lambda ($(du -sh build/lambda | cut -f1))"
