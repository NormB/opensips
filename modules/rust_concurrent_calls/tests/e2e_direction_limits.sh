#!/bin/bash
# E2e test: per-direction limits (Task 41)
#
# Verifies inbound/outbound limit parsing, asymmetric limits,
# and direction-specific check functions.

set -euo pipefail

echo "=== E2e test: per-direction limits (Task 41) ==="

source ~/.cargo/env
cd /usr/local/src/opensips
cargo test --manifest-path modules/rust_concurrent_calls/Cargo.toml -- test_direction_ test_check_inbound_ test_check_outbound_ test_parse_direction_ test_build_direction_ --test-threads=1 2>&1 | tail -25

echo "=== All direction limit tests passed ==="
