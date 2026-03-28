#!/bin/bash
# E2e test: burst detection (Task 44)

set -euo pipefail

echo "=== E2e test: burst detection (Task 44) ==="

source ~/.cargo/env
cd /usr/local/src/opensips
cargo test --manifest-path modules/rust_concurrent_calls/Cargo.toml -- test_burst_ test_record_burst_ --test-threads=1 2>&1 | tail -25

echo "=== All burst detection tests passed ==="
