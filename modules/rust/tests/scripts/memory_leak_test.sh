#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Memory Leak Detection for OpenSIPS Rust Module
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
# Strategy:
#   1. Record baseline shared memory via MI: get_statistics shmem:
#   2. Run SIPp burst: 10,000 requests from a fixed set of 10 source IPs
#   3. Wait for drain
#   4. Record final shmem stats
#   5. Compare: growth < 5% = PASS, 5-20% = WARN, >20% = FAIL
#
# Why fixed IPs:
#   The thread_local! HashMaps in rate limiters/caches grow as they see
#   new keys. Using a fixed set of IPs means the HashMaps reach steady
#   state after the first window, and any subsequent growth indicates a
#   real leak — not just cache warmup.
#
# Prerequisites:
#   - OpenSIPS running with opensips-memleak-test.cfg
#   - opensips-cli installed and configured
#   - SIPp installed
#   - mi_fifo module loaded (for memory stats)
#
# Usage:
#   ./modules/rust/tests/scripts/memory_leak_test.sh [requests] [target]
#   Default: 10000 requests to 127.0.0.1:5060
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
set -euo pipefail

TOTAL_REQUESTS="${1:-10000}"
TARGET="${2:-127.0.0.1:5060}"
FIFO="/tmp/opensips_memleak_fifo"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
SIPP_SCENARIO="$PROJECT_DIR/modules/rust/tests/sipp/rust_exec_uac.xml"

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Memory Leak Detection — Rust Module"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Target:   $TARGET"
echo "  Requests: $TOTAL_REQUESTS"
echo "  Scenario: $SIPP_SCENARIO"
echo ""

# ── Helper: query shmem stats via MI ──────────────────────────────

get_shmem_used() {
    # Query shared memory stats via MI FIFO
    if [ -S "$FIFO" ] || [ -p "$FIFO" ]; then
        local stats
        stats=$(opensips-cli -x mi get_statistics shmem: 2>/dev/null || true)
        if [ -n "$stats" ]; then
            echo "$stats" | grep -oP '"shmem:used_size"\s*:\s*\K[0-9]+' || echo "0"
            return
        fi
    fi
    # Fallback: try opensips-cli with default connection
    local stats
    stats=$(opensips-cli -x mi get_statistics shmem: 2>/dev/null || true)
    echo "$stats" | grep -oP '"shmem:used_size"\s*:\s*\K[0-9]+' || echo "0"
}

get_shmem_free() {
    local stats
    stats=$(opensips-cli -x mi get_statistics shmem: 2>/dev/null || true)
    echo "$stats" | grep -oP '"shmem:free_size"\s*:\s*\K[0-9]+' || echo "0"
}

# ── Verify prerequisites ─────────────────────────────────────────

echo "Checking prerequisites..."

if ! command -v sipp &>/dev/null; then
    echo -e "${RED}ERROR: sipp not found in PATH${NC}"
    exit 1
fi

if ! command -v opensips-cli &>/dev/null; then
    echo -e "${RED}ERROR: opensips-cli not found in PATH${NC}"
    exit 1
fi

if [ ! -f "$SIPP_SCENARIO" ]; then
    echo -e "${RED}ERROR: SIPp scenario not found: $SIPP_SCENARIO${NC}"
    exit 1
fi

# Quick connectivity check
if ! sipp -sf "$SIPP_SCENARIO" "$TARGET" -m 1 -timeout 5s -bg >/dev/null 2>&1; then
    echo -e "${YELLOW}WARNING: Could not reach $TARGET — is OpenSIPS running?${NC}"
fi

echo "Prerequisites OK."
echo ""

# ── Phase 1: Warmup ──────────────────────────────────────────────

echo "Phase 1: Warmup (500 requests to stabilize caches)..."
sipp -sf "$SIPP_SCENARIO" "$TARGET" \
    -m 500 -r 100 -l 10 \
    -timeout 30s -timeout_error \
    -trace_err -error_file /tmp/sipp_warmup_err.log \
    >/dev/null 2>&1 || true

echo "Warmup complete. Waiting 3s for drain..."
sleep 3

# ── Phase 2: Baseline measurement ────────────────────────────────

echo "Phase 2: Recording baseline memory..."
BASELINE_USED=$(get_shmem_used)
BASELINE_FREE=$(get_shmem_free)

if [ "$BASELINE_USED" = "0" ]; then
    echo -e "${YELLOW}WARNING: Could not read shmem stats. Is mi_fifo loaded?${NC}"
    echo "Continuing without memory comparison..."
    SKIP_COMPARISON=true
else
    SKIP_COMPARISON=false
    echo "  Baseline shmem used: $BASELINE_USED bytes"
    echo "  Baseline shmem free: $BASELINE_FREE bytes"
fi
echo ""

# ── Phase 3: Load test ───────────────────────────────────────────

echo "Phase 3: Running $TOTAL_REQUESTS requests..."
sipp -sf "$SIPP_SCENARIO" "$TARGET" \
    -m "$TOTAL_REQUESTS" -r 500 -l 20 \
    -timeout 120s -timeout_error \
    -trace_err -error_file /tmp/sipp_memleak_err.log \
    >/dev/null 2>&1 || true

echo "Load test complete. Waiting 5s for drain..."
sleep 5

# ── Phase 4: Final measurement ───────────────────────────────────

echo "Phase 4: Recording final memory..."
FINAL_USED=$(get_shmem_used)
FINAL_FREE=$(get_shmem_free)
echo "  Final shmem used: $FINAL_USED bytes"
echo "  Final shmem free: $FINAL_FREE bytes"
echo ""

# ── Phase 5: Analysis ────────────────────────────────────────────

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Results"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ "$SKIP_COMPARISON" = true ]; then
    echo -e "${YELLOW}SKIP: Could not read memory stats for comparison${NC}"
    echo "Check that mi_fifo is loaded and opensips-cli is configured."
    exit 2
fi

if [ "$BASELINE_USED" -eq 0 ]; then
    echo -e "${YELLOW}SKIP: Baseline was 0 — cannot compute growth${NC}"
    exit 2
fi

GROWTH=$((FINAL_USED - BASELINE_USED))
GROWTH_PCT=$((GROWTH * 100 / BASELINE_USED))

echo "  Baseline:  $BASELINE_USED bytes"
echo "  Final:     $FINAL_USED bytes"
echo "  Growth:    $GROWTH bytes ($GROWTH_PCT%)"
echo "  Requests:  $TOTAL_REQUESTS"
if [ "$TOTAL_REQUESTS" -gt 0 ]; then
    BYTES_PER_REQ=$((GROWTH / TOTAL_REQUESTS))
    echo "  Per-req:   $BYTES_PER_REQ bytes/request"
fi
echo ""

if [ "$GROWTH_PCT" -le 5 ]; then
    echo -e "${GREEN}PASS: Memory growth $GROWTH_PCT% (threshold: 5%)${NC}"
    exit 0
elif [ "$GROWTH_PCT" -le 20 ]; then
    echo -e "${YELLOW}WARN: Memory growth $GROWTH_PCT% (threshold: 5%, max: 20%)${NC}"
    echo "  This may indicate a slow leak. Investigate with a longer test."
    exit 0
else
    echo -e "${RED}FAIL: Memory growth $GROWTH_PCT% exceeds 20% threshold${NC}"
    echo "  Likely memory leak detected. Check:"
    echo "    - msg.call() allocations in call.rs"
    echo "    - String allocations in user-script handlers"
    echo "    - HashMap growth in thread_local! caches"
    exit 1
fi
