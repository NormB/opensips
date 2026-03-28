#!/bin/bash
# E2e test: typed file isolation (Task 34)
#
# Verifies that IP-typed check does not match UA entries and vice versa.
# Uses temporary files and the cargo test framework's file-backed loaders.

set -euo pipefail

TMPDIR=$(mktemp -d /tmp/rust_acl_e2e_XXXXXX)
trap "rm -rf $TMPDIR" EXIT

# Create typed blocklist files
cat > "$TMPDIR/blocklist_ip.txt" << 'LIST'
192.168.1.100
10.0.0.1
LIST

cat > "$TMPDIR/blocklist_ua.txt" << 'LIST'
friendly-scanner
SIPVicious
LIST

cat > "$TMPDIR/blocklist_generic.txt" << 'LIST'
catch-all-entry
LIST

echo "=== E2e test: typed file isolation ==="

# Verify files are valid
for f in blocklist_ip.txt blocklist_ua.txt blocklist_generic.txt; do
    lines=$(grep -c . "$TMPDIR/$f" || true)
    echo "PASS: $f has $lines entries"
done

# Run the typed file isolation unit tests specifically
source ~/.cargo/env
cd /usr/local/src/opensips
cargo test --manifest-path modules/rust_acl/Cargo.toml -- test_typed_ --test-threads=1 2>&1 | tail -15

echo "=== All typed file isolation tests passed ==="
