#!/bin/bash
# E2e test: MI status and limit override (Task 42)

set -euo pipefail

echo "=== E2e test: status and limit override (Task 42) ==="

source ~/.cargo/env
cd /usr/local/src/opensips
cargo test --manifest-path modules/rust_concurrent_calls/Cargo.toml -- test_build_status_ test_effective_limit_ test_override_ --test-threads=1 2>&1 | tail -25

echo "=== All status/override tests passed ==="
