#!/bin/bash
# E2e test: dialog auto-track integration (Task 39)
#
# Verifies automatic inc/dec via dialog tracker, multiple calls, expired
# dialogs, mixed accounts, and limit enforcement with auto_track.

set -euo pipefail

echo "=== E2e test: dialog auto-track (Task 39) ==="

source ~/.cargo/env
cd /usr/local/src/opensips
cargo test --manifest-path modules/rust_concurrent_calls/Cargo.toml -- test_dialog_auto_track --test-threads=1 2>&1 | tail -25

echo "=== All dialog auto-track tests passed ==="
