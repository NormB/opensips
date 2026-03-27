#!/bin/bash
# E2e test: access_policy (Task 65)
#
# Verifies all 4 access policies via unit tests

set -euo pipefail

echo "=== E2e test: access_policy ==="

source ~/.cargo/env
cd /usr/local/src/opensips
cargo test --manifest-path modules/rust_acl/Cargo.toml -- test_policy_ test_access_policy --test-threads=1 2>&1 | tail -25

echo "=== All access_policy tests passed ==="
