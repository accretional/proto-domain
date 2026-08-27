#!/usr/bin/env bash
# deploy.sh — Build and deploy the DNS Resolver gRPC service to Cloud Run
# (us-central1). Scale-to-zero, IAM-only (callers need roles/run.invoker),
# gRPC over HTTP/2. Generic service: nothing project-specific beyond the
# GCP project/registry below.
#
# Knobs (env):
#   UPSTREAM   comma-separated upstream resolvers baked into the service env
#              (default: Google + Cloudflare public DNS, round-robin).
#              Inside Cloud Run /etc/resolv.conf points at the metadata
#              resolver; explicit upstreams keep full record-type fidelity.
set -euo pipefail

PROJECT="speax-498608"
REGION="us-central1"
IMAGE="us-west1-docker.pkg.dev/${PROJECT}/embedder/dns-resolver"
SA="dns-resolver@${PROJECT}.iam.gserviceaccount.com"
UPSTREAM="${UPSTREAM:-8.8.8.8:53,1.1.1.1:53}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${HERE}"

# No-role runtime service account (same pattern as webrisk-svc).
gcloud iam service-accounts describe "${SA}" --project="${PROJECT}" >/dev/null 2>&1 ||
  gcloud iam service-accounts create dns-resolver --project="${PROJECT}" \
    --display-name="dns-resolver runtime (no project roles)"

# Vendor the replace-directive deps (../gluon, ../proto-ip) into the build
# context, then build/push. vendor/ is gitignored — regenerated every deploy.
go mod vendor

SHA=$(git rev-parse --short HEAD)
DOCKER_BUILDKIT=1 docker build --platform linux/amd64 \
  -t "${IMAGE}:latest" -t "${IMAGE}:${SHA}" .
docker push "${IMAGE}:latest"
docker push "${IMAGE}:${SHA}"

# --use-http2: end-to-end HTTP/2 so gRPC (incl. server streaming) works.
gcloud run deploy dns-resolver --project="${PROJECT}" --region="${REGION}" \
  --image="${IMAGE}:${SHA}" \
  --service-account="${SA}" \
  --no-allow-unauthenticated \
  --use-http2 \
  --min-instances=0 --max-instances=2 --memory=256Mi --concurrency=80 \
  --set-env-vars="^;^UPSTREAM=${UPSTREAM}"

echo "Grant callers: gcloud run services add-iam-policy-binding dns-resolver \\"
echo "  --region=${REGION} --member=serviceAccount:<caller-sa> --role=roles/run.invoker"
