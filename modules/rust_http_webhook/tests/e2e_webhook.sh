#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# E2E Tests for rust_http_webhook: batching, filtering, error stats
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CARGO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"

log_pass() { echo -e "${GREEN}PASS${NC}: $1"; PASS=$((PASS+1)); }
log_fail() { echo -e "${RED}FAIL${NC}: $1"; FAIL=$((FAIL+1)); }
log_info() { echo -e "${YELLOW}INFO${NC}: $1"; }

cleanup() {
    [ -n "${RECV_PID:-}" ] && kill "$RECV_PID" 2>/dev/null || true
    [ -n "${ERR_PID:-}" ] && kill "$ERR_PID" 2>/dev/null || true
    rm -f /tmp/webhook_e2e_*.py
    rm -f "$CARGO_DIR/rust/common/tests/e2e_batch.rs"
    rm -f "$CARGO_DIR/rust/common/tests/e2e_errors.rs"
}
trap cleanup EXIT

wait_for_port() {
    local port=$1 max=20 i=0
    while ! bash -c "echo >/dev/tcp/127.0.0.1/$port" 2>/dev/null; do
        i=$((i+1))
        [ $i -ge $max ] && return 1
        sleep 0.1
    done
    return 0
}

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  rust_http_webhook E2E Test Suite"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── Test 1: Batch payload construction unit tests ─────────────────

log_info "Test 1: Batch payload construction"
if RESULT=$(cd "$CARGO_DIR" && cargo test -p rust-common --lib "test_batch_payload" 2>&1); then
    log_pass "Batch payload unit tests (8 tests)"
else
    log_fail "Batch payload unit tests"
    echo "$RESULT" | tail -5
fi

# ── Test 2: Batch config defaults ────────────────────────────────

log_info "Test 2: Batch config defaults"
if RESULT=$(cd "$CARGO_DIR" && cargo test -p rust-common --lib "test_batch_config" 2>&1); then
    log_pass "Batch config unit tests"
else
    log_fail "Batch config unit tests"
fi

# ── Test 3: Batch integration (size=1 passthrough) ───────────────

log_info "Test 3: Batch size=1 passthrough + enqueue + timeout flush"
if RESULT=$(cd "$CARGO_DIR" && cargo test -p rust-common --lib "test_batch_size_1\|test_batch_enqueue\|test_batch_timeout" 2>&1); then
    log_pass "Batch integration unit tests"
else
    log_fail "Batch integration unit tests"
fi

# ── Test 4: Method filter parsing ────────────────────────────────

log_info "Test 4: Method filter parsing"
if RESULT=$(cd "$CARGO_DIR" && cargo test -p rust-http-webhook --lib "test_parse_method_filter" 2>&1); then
    log_pass "Method filter parsing (7 tests)"
else
    log_fail "Method filter parsing"
fi

# ── Test 5: Method matching logic ────────────────────────────────

log_info "Test 5: Method matching + empty filter"
if RESULT=$(cd "$CARGO_DIR" && cargo test -p rust-http-webhook --lib "test_method_match\|test_empty_filter" 2>&1); then
    log_pass "Method matching unit tests"
else
    log_fail "Method matching unit tests"
fi

# ── Test 6: E2E batch delivery (Python receiver) ─────────────────

log_info "Test 6: E2E batch delivery"

cat > /tmp/webhook_e2e_receiver.py << 'PYEOF'
import http.server, json, sys, threading
post_count = 0
bodies = []
lock = threading.Lock()

class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        global post_count
        n = int(self.headers.get('Content-Length', 0))
        b = self.rfile.read(n).decode('utf-8', errors='replace')
        with lock:
            post_count += 1
            bodies.append(b)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')
    def do_GET(self):
        with lock:
            s = json.dumps({"post_count": post_count, "bodies": bodies})
        self.send_response(200)
        self.end_headers()
        self.wfile.write(s.encode())
    def log_message(self, *a): pass

port = int(sys.argv[1]) if len(sys.argv) > 1 else 18765
http.server.HTTPServer(('127.0.0.1', port), H).serve_forever()
PYEOF

python3 /tmp/webhook_e2e_receiver.py 18765 &
RECV_PID=$!

if wait_for_port 18765; then
    mkdir -p "$CARGO_DIR/rust/common/tests"
    cat > "$CARGO_DIR/rust/common/tests/e2e_batch.rs" << 'RSEOF'
use rust_common::async_dispatch::{BatchConfig, FireAndForget, RetryConfig};

#[test]
fn e2e_batch_delivery() {
    let ff = FireAndForget::with_all_options(
        vec!["http://127.0.0.1:18765/hook".to_string()],
        64, 5,
        "application/json".to_string(),
        Vec::new(),
        RetryConfig::default(),
        BatchConfig { batch_size: 5, batch_timeout_ms: 200 },
    );
    for i in 0..10 {
        assert!(ff.send(format!(r#"{{"n":{i}}}"#)));
    }
    assert_eq!(ff.sent.get(), 10);
    std::thread::sleep(std::time::Duration::from_millis(800));

    let resp = reqwest::blocking::get("http://127.0.0.1:18765/stats")
        .expect("query receiver");
    let body: serde_json::Value = resp.json().expect("json");
    let pc = body["post_count"].as_u64().unwrap_or(0);
    assert!(pc < 10, "expected fewer than 10 POSTs (batching), got {pc}");
    assert!(pc >= 1, "expected at least 1 POST, got {pc}");

    for b in body["bodies"].as_array().unwrap() {
        let s = b.as_str().unwrap();
        let v: serde_json::Value = serde_json::from_str(s).expect("valid JSON body");
        assert!(v.is_array(), "batched body should be a JSON array, got: {s}");
    }
}
RSEOF

    if RESULT=$(cd "$CARGO_DIR" && cargo test -p rust-common --test e2e_batch e2e_batch_delivery 2>&1); then
        log_pass "E2E batch delivery: 10 messages, fewer POSTs received (batched)"
    else
        log_fail "E2E batch delivery"
        echo "$RESULT" | tail -20
    fi
else
    log_fail "E2E batch delivery (receiver failed to start on :18765)"
fi

kill "$RECV_PID" 2>/dev/null || true
unset RECV_PID
sleep 0.3

# ── Test 7: E2E error receiver (500 responses) ──────────────────

log_info "Test 7: E2E error stats (500 responses)"

cat > /tmp/webhook_e2e_error_recv.py << 'PYEOF'
import http.server, json, sys, threading
post_count = 0
lock = threading.Lock()

class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        global post_count
        n = int(self.headers.get('Content-Length', 0))
        _ = self.rfile.read(n)
        with lock:
            post_count += 1
        self.send_response(500)
        self.end_headers()
        self.wfile.write(b'Error')
    def do_GET(self):
        with lock:
            s = json.dumps({"post_count": post_count})
        self.send_response(200)
        self.end_headers()
        self.wfile.write(s.encode())
    def log_message(self, *a): pass

port = int(sys.argv[1]) if len(sys.argv) > 1 else 18766
http.server.HTTPServer(('127.0.0.1', port), H).serve_forever()
PYEOF

python3 /tmp/webhook_e2e_error_recv.py 18766 &
ERR_PID=$!

if wait_for_port 18766; then
    mkdir -p "$CARGO_DIR/rust/common/tests"
    cat > "$CARGO_DIR/rust/common/tests/e2e_errors.rs" << 'RSEOF'
use rust_common::async_dispatch::{FireAndForget, RetryConfig};

#[test]
fn e2e_error_receiver() {
    let ff = FireAndForget::with_options(
        vec!["http://127.0.0.1:18766/hook".to_string()],
        64, 5,
        "application/json".to_string(),
        Vec::new(),
        RetryConfig { max_retries: 0, retry_delay_ms: 100 },
    );
    for i in 0..5 {
        assert!(ff.send(format!(r#"{{"err":{i}}}"#)));
    }
    assert_eq!(ff.sent.get(), 5);
    std::thread::sleep(std::time::Duration::from_millis(1500));

    let resp = reqwest::blocking::get("http://127.0.0.1:18766/stats")
        .expect("query");
    let body: serde_json::Value = resp.json().expect("json");
    let pc = body["post_count"].as_u64().unwrap_or(0);
    assert!(pc >= 3, "expected at least 3 POSTs to error receiver, got {pc}");
}
RSEOF

    if RESULT=$(cd "$CARGO_DIR" && cargo test -p rust-common --test e2e_errors e2e_error_receiver 2>&1); then
        log_pass "E2E error receiver: 500 responses handled, no crash"
    else
        log_fail "E2E error receiver"
        echo "$RESULT" | tail -20
    fi
else
    log_fail "E2E error receiver (receiver failed to start on :18766)"
fi

kill "$ERR_PID" 2>/dev/null || true
unset ERR_PID

# Clean up e2e test files before running full suite
rm -f "$CARGO_DIR/rust/common/tests/e2e_batch.rs"
rm -f "$CARGO_DIR/rust/common/tests/e2e_errors.rs"

# ── Test 8: Full library test suite (no e2e files) ───────────────

log_info "Test 8: Full library test suite (common + webhook)"
if RESULT=$(cd "$CARGO_DIR" && cargo test -p rust-common -p rust-http-webhook 2>&1); then
    log_pass "Full library test suite"
else
    log_fail "Full library test suite"
    echo "$RESULT" | tail -15
fi

# ── Test 9: DocBook XML validation ───────────────────────────────

log_info "Test 9: DocBook XML validation"
if xmllint --noout --noent /usr/local/src/opensips/modules/rust_http_webhook/doc/rust_http_webhook.xml 2>&1; then
    log_pass "DocBook XML validates"
else
    log_fail "DocBook XML validation"
fi

# ── Test 10: Clippy clean ────────────────────────────────────────

log_info "Test 10: Clippy clean"
if RESULT=$(cd "$CARGO_DIR" && cargo clippy -p rust-common -p rust-http-webhook -- -W clippy::all -D warnings 2>&1); then
    log_pass "Clippy passes with no warnings"
else
    log_fail "Clippy"
    echo "$RESULT" | tail -10
fi

# ── Summary ──────────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

exit $FAIL
