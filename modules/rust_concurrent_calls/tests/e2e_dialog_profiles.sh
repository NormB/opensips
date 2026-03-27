#!/bin/bash
# E2e test: dialog profile cross-worker accuracy (Task 40)
#
# Verifies profile-based limit checking logic: profile count vs local count,
# cross-worker totals, and fallback behavior.

set -euo pipefail

echo "=== E2e test: dialog profiles (Task 40) ==="

source ~/.cargo/env
cd /usr/local/src/opensips
cargo test --manifest-path modules/rust_concurrent_calls/Cargo.toml -- test_check_limit_with_profile test_profile_ --test-threads=1 2>&1 | tail -25

echo "=== All dialog profile tests passed ==="
