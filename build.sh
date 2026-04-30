#!/usr/bin/env bash
# build.sh — Run setup then build all binaries.
#
# IDEMPOTENCY CONTRACT:
#   Calls setup.sh first (idempotent). Always rebuilds Go binaries
#   (Go's build cache makes this fast).
#   Produces: bin/server, bin/client
set -euo pipefail

cd "$(dirname "$0")"

bash setup.sh

echo "=== build.sh ==="

mkdir -p bin

echo "  Building server..."
go build -o bin/server ./cmd/server

echo "  Building client..."
go build -o bin/client ./cmd/client

echo "  Binaries:"
ls -lh bin/
echo "=== build.sh complete ==="
