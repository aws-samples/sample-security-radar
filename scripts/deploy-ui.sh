#!/usr/bin/env bash
# Build the UI and upload it. Refuses to ship mock data (mock-data/ is dev-only by design).
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib.sh
export AWS_REGION=ap-northeast-1
(cd ui && rm -rf dist && npm run build >/dev/null)
if [ -e ui/dist/data ]; then echo "refusing: ui/dist/data exists (mock data would be published)" >&2; exit 1; fi
bucket=$(out SiteBucketName)
aws s3 sync ui/dist/ "s3://$bucket/" --delete --exclude "data/*" --exclude "index.html" --cache-control "max-age=31536000,immutable" >/dev/null
aws s3 cp ui/dist/index.html "s3://$bucket/index.html" --cache-control "no-cache" --content-type "text/html; charset=utf-8" >/dev/null
aws cloudfront create-invalidation --distribution-id "$(out DistributionId)" --paths "/index.html" --query Invalidation.Id --output text >/dev/null
echo "ui deployed to s3://$bucket"
