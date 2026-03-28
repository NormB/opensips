#!/bin/bash
# E2e test: per-entry counters (Task 38)

set -euo pipefail

echo "=== E2e test: per-entry counters ==="

source ~/.cargo/env
cd /usr/local/src/opensips
cargo test --manifest-path modules/rust_acl/Cargo.toml -- test_counter_ test_top_n_ test_find_matching test_counters_ --test-threads=1 2>&1 | tail -20

echo "=== All counter tests passed ==="
