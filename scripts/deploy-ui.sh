#!/usr/bin/env bash
# Build the UI and upload it. Refuses to ship mock data (mock-data/ is dev-only by design).
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib.sh
export AWS_REGION=ap-northeast-1
# the build id the page compares with version.json to offer a reload after a deploy (roadmap R3.3)
RADAR_BUILD="$(git rev-parse --short HEAD)"   # separate from export: a failing git must stop the script (SC2155)
export RADAR_BUILD
(cd ui && rm -rf dist && npm run build >/dev/null)
if [ -e ui/dist/data ]; then echo "refusing: ui/dist/data exists (mock data would be published)" >&2; exit 1; fi
bucket=$(out SiteBucketName)
aws s3 sync ui/dist/ "s3://$bucket/" --delete --exclude "data/*" --exclude "index.html" --exclude "version.json" --cache-control "max-age=31536000,immutable" >/dev/null
aws s3 cp ui/dist/index.html "s3://$bucket/index.html" --cache-control "no-cache" --content-type "text/html; charset=utf-8" >/dev/null
aws s3 cp ui/dist/version.json "s3://$bucket/version.json" --cache-control "no-cache" --content-type "application/json" >/dev/null
aws cloudfront create-invalidation --distribution-id "$(out DistributionId)" --paths "/index.html" "/version.json" --query Invalidation.Id --output text >/dev/null
echo "ui deployed to s3://$bucket"
