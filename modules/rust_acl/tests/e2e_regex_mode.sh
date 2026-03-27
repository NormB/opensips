#!/bin/bash
# E2e test: regex match mode (Task 35)
#
# Verifies regex pattern matching with patterns like .*scanner.*

set -euo pipefail

echo "=== E2e test: regex match mode ==="

source ~/.cargo/env
cd /usr/local/src/opensips
cargo test --manifest-path modules/rust_acl/Cargo.toml -- test_regex_ test_build_acl_data_regex test_check_regex --test-threads=1 2>&1 | tail -20

echo "=== All regex mode tests passed ==="
