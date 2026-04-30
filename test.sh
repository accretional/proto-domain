#!/usr/bin/env bash
# test.sh — Run setup, build, then ALL tests (unit, fuzz seeds).
#
# IDEMPOTENCY CONTRACT:
#   Calls build.sh first (which calls setup.sh).
#   Tests are stateless reads of host state (except resolver tests, which
#   are skipped by default — wired up in LET_IT_RIP).
set -euo pipefail

cd "$(dirname "$0")"

bash build.sh

echo "=== test.sh ==="

echo "  Running all unit/integration tests..."
go test -v -count=1 ./...

echo "  Running short fuzz pass on each fuzz target (single worker, 2s each)..."
# -parallel=1 keeps the smoke pass to a single fuzz worker so it doesn't
# saturate the host. LET_IT_RIP runs the longer pass under the same cap.
go test -run=NONE -fuzz=FuzzDomain   -fuzztime=2s -parallel=1 ./internal/grammar
go test -run=NONE -fuzz=FuzzHostname -fuzztime=2s -parallel=1 ./internal/grammar
go test -run=NONE -fuzz=FuzzTLD      -fuzztime=2s -parallel=1 ./internal/grammar

echo "=== test.sh complete ==="
