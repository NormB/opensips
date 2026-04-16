#!/bin/bash
# E2e test: cooldown after limit hit (Task 43)

set -euo pipefail

echo "=== E2e test: cooldown (Task 43) ==="

source ~/.cargo/env
cd /usr/local/src/opensips
cargo test --manifest-path modules/rust_concurrent_calls/Cargo.toml -- test_cooldown_ --test-threads=1 2>&1 | tail -25

echo "=== All cooldown tests passed ==="
