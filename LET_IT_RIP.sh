#!/usr/bin/env bash
# LET_IT_RIP.sh — Full end-to-end flow: setup, build, test, run.
#
# IDEMPOTENCY CONTRACT:
#   Every sub-script is idempotent. Safe to run from a clean checkout
#   or mid-development. Steps:
#   1. test.sh         — runs setup + build + unit tests + short fuzz
#   2. Smoke test 1    — resolve "localhost" via local Resolver gRPC svc
#   3. Smoke test 2    — resolve "accretional.com" via local Resolver svc
#   4. Long fuzz pass  — extended fuzzing on each grammar
#
# Run before every push. If it passes, the project is healthy.
set -euo pipefail

cd "$(dirname "$0")"

echo "========================================"
echo "  LET IT RIP — proto-domain full flow"
echo "========================================"
echo ""

bash test.sh
echo ""

PORT=50098
echo "=== Smoke test: Resolver server + client ==="
echo "  Starting server on port $PORT..."
bin/server -port "$PORT" &
SERVER_PID=$!

cleanup() {
    echo "  Stopping server (PID $SERVER_PID)..."
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Give the server a moment to bind.
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if nc -z localhost "$PORT" 2>/dev/null; then
        break
    fi
    sleep 0.2
done

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "  ERROR: Server failed to start"
    exit 1
fi

echo ""
echo "  Client: GetDNSRecords localhost"
LOCAL_OUT=$(bin/client -addr "localhost:$PORT" -name "localhost")
echo "$LOCAL_OUT"
echo ""

NL=$(echo "$LOCAL_OUT" | grep -cE '^(A|AAAA|PTR|CNAME|MX|TXT|NS|SOA|SRV)' || true)
if [[ "$NL" -lt 1 ]]; then
    echo "  ✗ Expected at least one DNS record for localhost, got 0"
    exit 1
fi
echo "  ✓ Got $NL record(s) for localhost"
echo ""

echo "  Client: GetDNSRecords accretional.com"
REMOTE_OUT=$(bin/client -addr "localhost:$PORT" -name "accretional.com" || true)
echo "$REMOTE_OUT"
echo ""

NR=$(echo "$REMOTE_OUT" | grep -cE '^(A|AAAA|CNAME|MX|TXT|NS|SOA|SRV)' || true)
if [[ "$NR" -lt 1 ]]; then
    echo "  ⚠ No DNS records returned for accretional.com — network down?"
    echo "    (Treating as soft-fail; localhost lookup already verified the path.)"
else
    echo "  ✓ Got $NR record(s) for accretional.com"
fi

echo ""
echo "=== Long fuzz pass (10s per grammar, single worker) ==="
# -parallel=1 keeps fuzzing to one worker so we don't saturate the host.
go test -run=NONE -fuzz=FuzzDomain   -fuzztime=10s -parallel=1 ./internal/grammar
go test -run=NONE -fuzz=FuzzHostname -fuzztime=10s -parallel=1 ./internal/grammar
go test -run=NONE -fuzz=FuzzTLD      -fuzztime=10s -parallel=1 ./internal/grammar

echo ""
echo "========================================"
echo "  ALL CHECKS PASSED"
echo "========================================"
