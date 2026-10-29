#!/usr/bin/env bash
# Zip every respond-station target (src/radar/targets.py) → build/targets/code/<id>.zip (the S3 layout both buckets use).
# Demo targets: integrations/continuum/targets/<id>/. security-radar = `git archive HEAD` (tracked files only —
# never the working tree, so local secrets or build output cannot leak into a scan).
# Consumed by the CDK BucketDeployments (infra/) — `cdk deploy` uploads them, no manual step.
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf build/targets && mkdir -p build/targets/code
read -r -a ids <<< "$(uv run -q python -I -c "import sys;sys.path.insert(0,'src');from radar.targets import TARGETS;print(' '.join(t[0] for t in TARGETS))")"
for id in "${ids[@]}"; do
    if [ "$id" = "security-radar" ]; then
    # code only: docs/screenshots/fixtures are ~30 MB of images and recorded feeds a code review cannot use
    git archive --format=zip -o "build/targets/code/$id.zip" HEAD -- . ':(exclude)docs' ':(exclude)ui/screenshots' \
      ':(exclude)tests/fixtures' ':(exclude)ui/mock-data' ':(exclude)ui/public/*.png' \
      ':(exclude)integrations/continuum/targets'  # the demo targets are scanned as themselves, not twice
  else
    # python zipfile, not the zip CLI: CI images do not all ship it; sorted + fixed mtime ⇒ reproducible bytes
    uv run -q python -I -c '
import sys, zipfile, pathlib
src, out = pathlib.Path(sys.argv[1]), sys.argv[2]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for p in sorted(x for x in src.rglob("*") if x.is_file()):
        z.writestr(zipfile.ZipInfo(str(p.relative_to(src)), (2026, 1, 1, 0, 0, 0)), p.read_bytes())
' "integrations/continuum/targets/$id" "build/targets/code/$id.zip"
  fi
done
# Continuum S3 environment reads code/ in its own bucket: only the targets whose channel is s3 (targets.CHANNEL) —
# every zip there is scanned and paid for (the radar's own repo used to be 99 % of each scan)
rm -rf build/targets-cn && mkdir -p build/targets-cn
read -r -a s3ids <<< "$(uv run -q python -I -c "import sys;sys.path.insert(0,'src');from radar import targets;print(' '.join(targets.on('s3')))")"
for id in "${s3ids[@]}"; do cp "build/targets/code/$id.zip" "build/targets-cn/$id.zip"; done
echo "built ${#ids[@]} targets: ${ids[*]} · Continuum S3 channel: ${s3ids[*]}"
