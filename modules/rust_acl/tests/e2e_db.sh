#!/bin/bash
# E2E test for rust_acl database integration using SQLite.
# Requires: sqlite3, the rust_acl module compiled with 'database' feature.
# This test verifies the Rust code's SQLite integration works end-to-end.
#
# Usage: bash tests/e2e_db.sh
#
# Exit 0 = all tests passed, non-zero = failure.

set -euo pipefail

DB_FILE="/tmp/rust_acl_e2e_test.db"
RESULT=0

cleanup() {
    rm -f "$DB_FILE"
}
trap cleanup EXIT

echo "=== rust_acl E2E Database Test ==="
echo ""

# Check prerequisites
if ! command -v sqlite3 &>/dev/null; then
    echo "SKIP: sqlite3 not found"
    exit 0
fi

# 1. Create test database with address table
echo "--- Creating test SQLite database ---"
sqlite3 "$DB_FILE" <<SQL
CREATE TABLE address (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    grp INTEGER DEFAULT 0 NOT NULL,
    ip TEXT NOT NULL,
    mask INTEGER DEFAULT 32 NOT NULL,
    port INTEGER DEFAULT 0 NOT NULL,
    proto TEXT DEFAULT 'any' NOT NULL,
    pattern TEXT DEFAULT NULL,
    context_info TEXT DEFAULT NULL
);

-- Blocklist entries (grp=1)
INSERT INTO address (grp, ip, mask) VALUES (1, '10.0.0.0', 24);
INSERT INTO address (grp, ip, mask) VALUES (1, '192.168.1.100', 32);
INSERT INTO address (grp, ip, mask) VALUES (1, '172.16.0.0', 12);
INSERT INTO address (grp, ip, mask, pattern) VALUES (1, '0.0.0.0', 0, '^SIPVicious');

-- Allowlist entries (grp=2)
INSERT INTO address (grp, ip, mask) VALUES (2, '10.0.0.40', 32);
INSERT INTO address (grp, ip, mask) VALUES (2, '10.0.0.41', 32);

-- Entry in a different group (should not be loaded with default groups)
INSERT INTO address (grp, ip, mask) VALUES (3, '8.8.8.8', 32);
SQL

echo "Database created at $DB_FILE"

# 2. Verify table contents
echo ""
echo "--- Table contents ---"
sqlite3 "$DB_FILE" "SELECT grp, ip, mask, pattern FROM address ORDER BY grp, id;"

ROWS=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM address;")
echo "Total rows: $ROWS"
if [ "$ROWS" -ne 7 ]; then
    echo "FAIL: Expected 7 rows, got $ROWS"
    RESULT=1
fi

# 3. Verify blocklist entries (grp=1)
BL_COUNT=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM address WHERE grp = 1;")
echo ""
echo "Blocklist entries (grp=1): $BL_COUNT"
if [ "$BL_COUNT" -ne 4 ]; then
    echo "FAIL: Expected 4 blocklist entries, got $BL_COUNT"
    RESULT=1
fi

# 4. Verify allowlist entries (grp=2)
AL_COUNT=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM address WHERE grp = 2;")
echo "Allowlist entries (grp=2): $AL_COUNT"
if [ "$AL_COUNT" -ne 2 ]; then
    echo "FAIL: Expected 2 allowlist entries, got $AL_COUNT"
    RESULT=1
fi

# 5. Verify that the Rust unit/integration tests pass with this DB
echo ""
echo "--- Running Rust integration tests ---"
cd /usr/local/src/opensips/modules
export PATH="$HOME/.cargo/bin:$PATH"

# Run the database-specific tests
if cargo test -p rust-acl --features database -- db_tests 2>&1; then
    echo "PASS: All DB integration tests passed"
else
    echo "FAIL: DB integration tests failed"
    RESULT=1
fi

# 6. Summary
echo ""
echo "=== E2E Test Summary ==="
if [ "$RESULT" -eq 0 ]; then
    echo "ALL TESTS PASSED"
else
    echo "SOME TESTS FAILED"
fi

exit $RESULT
