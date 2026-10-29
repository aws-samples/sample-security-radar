#!/usr/bin/env bash
# README gallery: full-page live screenshots → vertical-strip gallery (animated SVG + static PNG) in docs/gallery/.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib.sh
arn=$(out UiSecretArn); site=$(out SiteUrl)
creds=$(aws secretsmanager get-secret-value --region ap-northeast-1 --secret-id "$arn" --query SecretString --output text)
U=$(printf '%s' "$creds" | uv run -q python -I -c 'import json,sys;print(json.load(sys.stdin)["username"])')
P=$(printf '%s' "$creds" | uv run -q python -I -c 'import json,sys;print(json.load(sys.stdin)["password"])')
unset creds
mkdir -p build/gallery docs/gallery
(cd ui && U="$U" P="$P" BASE="$site/" OUT="$(pwd)/../build/gallery" node scripts/gallery-shots.mjs)
uv run --with pillow python scripts/build_gallery.py build/gallery docs/gallery
