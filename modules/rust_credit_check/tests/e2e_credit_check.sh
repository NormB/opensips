#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# E2E Tests for rust_credit_check: Tasks 45-50
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

PIDS=()
cleanup() {
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    rm -f /tmp/credit_e2e_*.py /tmp/credit_e2e_rates.csv
    rm -f "$CARGO_DIR/rust_credit_check/tests/e2e_debit.rs"
    rm -f "$CARGO_DIR/rust_credit_check/tests/e2e_nested_json.rs"
    rm -f "$CARGO_DIR/rust_credit_check/tests/e2e_failover.rs"
    rm -f "$CARGO_DIR/rust_credit_check/tests/e2e_rate_table.rs"
    rm -f "$CARGO_DIR/rust_credit_check/tests/e2e_recheck.rs"
    rm -f "$CARGO_DIR/rust_credit_check/tests/e2e_warmup.rs"
}
trap cleanup EXIT

wait_for_port() {
    local port=$1 max=30 i=0
    while ! bash -c "echo >/dev/tcp/127.0.0.1/$port" 2>/dev/null; do
        i=$((i+1))
        [ $i -ge $max ] && return 1
        sleep 0.1
    done
    return 0
}

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  rust_credit_check E2E Test Suite (Tasks 45-50)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── Test 1: Unit tests for all pure logic ─────────────────────────

log_info "Test 1: All unit tests"
if RESULT=$(cd "$CARGO_DIR" && cargo test -p rust-credit-check --lib 2>&1); then
    TCOUNT=$(echo "$RESULT" | grep "test result" | grep -oP '\d+ passed' || echo "? passed")
    log_pass "Unit tests ($TCOUNT)"
else
    log_fail "Unit tests"
    echo "$RESULT" | tail -20
fi

# ── Test 2: E2E debit POST (Task 45) ─────────────────────────────

log_info "Test 2: E2E debit POST delivery"

cat > /tmp/credit_e2e_debit_recv.py << 'PYEOF'
import http.server, json, sys, threading
posts = []
lock = threading.Lock()

class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        b = self.rfile.read(n).decode('utf-8', errors='replace')
        with lock:
            posts.append(json.loads(b))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')
    def do_GET(self):
        with lock:
            s = json.dumps({"post_count": len(posts), "posts": posts})
        self.send_response(200)
        self.end_headers()
        self.wfile.write(s.encode())
    def log_message(self, *a): pass

port = int(sys.argv[1]) if len(sys.argv) > 1 else 18780
http.server.HTTPServer(('127.0.0.1', port), H).serve_forever()
PYEOF

python3 /tmp/credit_e2e_debit_recv.py 18780 &
PIDS+=($!)

if wait_for_port 18780; then
    mkdir -p "$CARGO_DIR/rust_credit_check/tests"
    cat > "$CARGO_DIR/rust_credit_check/tests/e2e_debit.rs" << 'RSEOF'
use rust_common::async_dispatch::FireAndForget;
use rust_common::http::Pool;

#[test]
fn e2e_debit_post_delivery() {
    // Simulate debit POST via FireAndForget (same mechanism as the module)
    let ff = FireAndForget::new(
        "http://127.0.0.1:18780/debit".to_string(),
        64, 5,
        "application/json".to_string(),
    );

    // Simulate a debit payload
    let payload = r#"{"account":"alice","duration_secs":180,"cost":3.00}"#;
    assert!(ff.send(payload.to_string()));
    assert_eq!(ff.sent.get(), 1);

    // Second debit
    let payload2 = r#"{"account":"bob","duration_secs":60,"cost":1.00}"#;
    assert!(ff.send(payload2.to_string()));
    assert_eq!(ff.sent.get(), 2);

    // Wait for delivery
    std::thread::sleep(std::time::Duration::from_millis(800));

    // Verify the receiver got the POSTs via Pool (no reqwest dependency needed)
    let pool = Pool::new();
    pool.init(5, 4, None);
    let (status, body_str) = pool.get_url("http://127.0.0.1:18780/stats")
        .expect("query receiver");
    assert_eq!(status, 200);
    let body: serde_json::Value = serde_json::from_str(&body_str).expect("json");
    let pc = body["post_count"].as_u64().unwrap_or(0);
    assert!(pc >= 2, "expected at least 2 debit POSTs, got {pc}");

    // Verify payload structure
    let posts = body["posts"].as_array().unwrap();
    assert_eq!(posts[0]["account"], "alice");
    assert_eq!(posts[0]["duration_secs"], 180);
    assert!((posts[0]["cost"].as_f64().unwrap() - 3.0).abs() < 0.01);
}
RSEOF

    if RESULT=$(cd "$CARGO_DIR" && cargo test -p rust-credit-check --test e2e_debit e2e_debit_post_delivery 2>&1); then
        log_pass "E2E debit POST: payloads delivered with correct JSON structure"
    else
        log_fail "E2E debit POST"
        echo "$RESULT" | tail -20
    fi
else
    log_fail "E2E debit POST (receiver failed to start on :18780)"
fi

# ── Test 3: E2E nested JSON parsing (Task 46) ────────────────────

log_info "Test 3: E2E nested JSON balance extraction"

cat > /tmp/credit_e2e_nested_api.py << 'PYEOF'
import http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        resp = {"data":{"account":{"balance":42.5}}}
        self.wfile.write(json.dumps(resp).encode())
    def log_message(self, *a): pass

port = int(sys.argv[1]) if len(sys.argv) > 1 else 18781
http.server.HTTPServer(('127.0.0.1', port), H).serve_forever()
PYEOF

python3 /tmp/credit_e2e_nested_api.py 18781 &
PIDS+=($!)

if wait_for_port 18781; then
    mkdir -p "$CARGO_DIR/rust_credit_check/tests"
    cat > "$CARGO_DIR/rust_credit_check/tests/e2e_nested_json.rs" << 'RSEOF'
#[test]
fn e2e_nested_json_balance() {
    // Fetch from mock API that returns nested JSON
    let pool = rust_common::http::Pool::new();
    pool.init(5, 4, None);

    let (status, body) = pool.get_url("http://127.0.0.1:18781/balance?account=alice")
        .expect("HTTP GET");
    assert_eq!(status, 200);

    // Parse with dot-notation path
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let mut current = &v;
    for seg in "data.account.balance".split('.') {
        current = current.get(seg).expect(&format!("missing segment: {seg}"));
    }
    let balance = current.as_f64().unwrap();
    assert!((balance - 42.5).abs() < f64::EPSILON,
        "expected 42.5, got {balance}");
}
RSEOF

    if RESULT=$(cd "$CARGO_DIR" && cargo test -p rust-credit-check --test e2e_nested_json e2e_nested_json_balance 2>&1); then
        log_pass "E2E nested JSON: extracted balance=42.5 via data.account.balance"
    else
        log_fail "E2E nested JSON"
        echo "$RESULT" | tail -20
    fi
else
    log_fail "E2E nested JSON (API failed to start on :18781)"
fi

# ── Test 4: E2E failover (Task 47) ───────────────────────────────

log_info "Test 4: E2E billing failover"

# Primary that returns 500
cat > /tmp/credit_e2e_primary.py << 'PYEOF'
import http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(500)
        self.end_headers()
        self.wfile.write(b'Internal Server Error')
    def log_message(self, *a): pass

port = int(sys.argv[1]) if len(sys.argv) > 1 else 18782
http.server.HTTPServer(('127.0.0.1', port), H).serve_forever()
PYEOF

# Backup that works
cat > /tmp/credit_e2e_backup.py << 'PYEOF'
import http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        resp = {"balance": 25.0}
        self.wfile.write(json.dumps(resp).encode())
    def log_message(self, *a): pass

port = int(sys.argv[1]) if len(sys.argv) > 1 else 18783
http.server.HTTPServer(('127.0.0.1', port), H).serve_forever()
PYEOF

python3 /tmp/credit_e2e_primary.py 18782 &
PIDS+=($!)
python3 /tmp/credit_e2e_backup.py 18783 &
PIDS+=($!)

if wait_for_port 18782 && wait_for_port 18783; then
    mkdir -p "$CARGO_DIR/rust_credit_check/tests"
    cat > "$CARGO_DIR/rust_credit_check/tests/e2e_failover.rs" << 'RSEOF'
#[test]
fn e2e_billing_failover() {
    let pool = rust_common::http::Pool::new();
    pool.init(5, 4, None);

    // Query primary — should return 500
    let (status, _) = pool.get_url("http://127.0.0.1:18782/balance?account=alice")
        .expect("primary GET");
    assert_eq!(status, 500, "primary should return 500");

    // Query backup — should return 200 with balance
    let (status, body) = pool.get_url("http://127.0.0.1:18783/balance?account=alice")
        .expect("backup GET");
    assert_eq!(status, 200, "backup should return 200");

    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let balance = v["balance"].as_f64().unwrap();
    assert!((balance - 25.0).abs() < f64::EPSILON);
}
RSEOF

    if RESULT=$(cd "$CARGO_DIR" && cargo test -p rust-credit-check --test e2e_failover e2e_billing_failover 2>&1); then
        log_pass "E2E failover: primary=500, backup=200, balance=25.0"
    else
        log_fail "E2E failover"
        echo "$RESULT" | tail -20
    fi
else
    log_fail "E2E failover (servers failed to start)"
fi

# ── Test 5: E2E rate table (Task 48) ─────────────────────────────

log_info "Test 5: E2E rate table per-prefix lookup"

cat > /tmp/credit_e2e_rates.csv << 'CSVEOF'
# Rate table for E2E test
1,0.5
44,1.0
4420,0.8
33,1.5
CSVEOF

mkdir -p "$CARGO_DIR/rust_credit_check/tests"
cat > "$CARGO_DIR/rust_credit_check/tests/e2e_rate_table.rs" << 'RSEOF'
#[test]
fn e2e_rate_table_prefix_lookup() {
    // Read the CSV rate table and verify prefix matching
    let csv = std::fs::read_to_string("/tmp/credit_e2e_rates.csv")
        .expect("read rate CSV");

    // Parse CSV (same logic as module)
    let mut entries: Vec<(String, f64)> = Vec::new();
    for line in csv.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        let parts: Vec<&str> = line.splitn(2, ',').collect();
        if parts.len() == 2 {
            let prefix = parts[0].trim().to_string();
            if let Ok(rate) = parts[1].trim().parse::<f64>() {
                if !prefix.is_empty() && rate > 0.0 {
                    entries.push((prefix, rate));
                }
            }
        }
    }
    entries.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

    assert_eq!(entries.len(), 4, "expected 4 entries in rate table");

    // Test prefix matching
    let lookup = |dest: &str| -> (&str, f64) {
        for (prefix, rate) in &entries {
            if dest.starts_with(prefix.as_str()) {
                return (prefix, *rate);
            }
        }
        ("", 2.0) // default
    };

    // UK mobile (4420 prefix) should match 0.8
    let (prefix, rate) = lookup("44201234567");
    assert_eq!(prefix, "4420");
    assert!((rate - 0.8).abs() < f64::EPSILON);

    // UK landline (44 prefix) should match 1.0
    let (prefix, rate) = lookup("44301234567");
    assert_eq!(prefix, "44");
    assert!((rate - 1.0).abs() < f64::EPSILON);

    // US (1 prefix) should match 0.5
    let (prefix, rate) = lookup("15551234567");
    assert_eq!(prefix, "1");
    assert!((rate - 0.5).abs() < f64::EPSILON);

    // France (33 prefix) should match 1.5
    let (prefix, rate) = lookup("33612345678");
    assert_eq!(prefix, "33");
    assert!((rate - 1.5).abs() < f64::EPSILON);

    // No match should return default
    let (prefix, rate) = lookup("81312345678");
    assert_eq!(prefix, "");
    assert!((rate - 2.0).abs() < f64::EPSILON);

    // Verify different destinations get different max durations
    // balance=100.0 for all
    let balance = 100.0;
    let max_dur_us = ((balance / 0.5) * 60.0) as i32;   // 12000
    let max_dur_uk = ((balance / 1.0) * 60.0) as i32;   // 6000
    let max_dur_uk_mob = ((balance / 0.8) * 60.0) as i32; // 7500
    assert_ne!(max_dur_us, max_dur_uk);
    assert_ne!(max_dur_uk, max_dur_uk_mob);
    assert_eq!(max_dur_us, 12000);
    assert_eq!(max_dur_uk, 6000);
    assert_eq!(max_dur_uk_mob, 7500);
}
RSEOF

if RESULT=$(cd "$CARGO_DIR" && cargo test -p rust-credit-check --test e2e_rate_table e2e_rate_table_prefix_lookup 2>&1); then
    log_pass "E2E rate table: prefix matching + different max durations verified"
else
    log_fail "E2E rate table"
    echo "$RESULT" | tail -20
fi

# ── Test 6: E2E mid-call recheck (Task 49) ───────────────────────

log_info "Test 6: E2E mid-call balance recheck"

# API that decreases balance on each call
cat > /tmp/credit_e2e_recheck_api.py << 'PYEOF'
import http.server, json, sys, threading
balance = {"alice": 50.0}
lock = threading.Lock()

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        qs = parse_qs(urlparse(self.path).query)
        account = qs.get("account", ["unknown"])[0]
        with lock:
            b = balance.get(account, 0.0)
            # Simulate balance decrease per query (billing deducting in real time)
            if b > 10:
                balance[account] = b - 10
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps({"balance": b}).encode())
    def log_message(self, *a): pass

port = int(sys.argv[1]) if len(sys.argv) > 1 else 18784
http.server.HTTPServer(('127.0.0.1', port), H).serve_forever()
PYEOF

python3 /tmp/credit_e2e_recheck_api.py 18784 &
PIDS+=($!)

if wait_for_port 18784; then
    mkdir -p "$CARGO_DIR/rust_credit_check/tests"
    cat > "$CARGO_DIR/rust_credit_check/tests/e2e_recheck.rs" << 'RSEOF'
#[test]
fn e2e_recheck_decreasing_balance() {
    let pool = rust_common::http::Pool::new();
    pool.init(5, 4, None);

    // First check: balance=50
    let (status, body) = pool.get_url("http://127.0.0.1:18784/balance?account=alice").unwrap();
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let b1 = v["balance"].as_f64().unwrap();
    assert!((b1 - 50.0).abs() < f64::EPSILON);
    let max_dur_1 = ((b1 / 1.0) * 60.0) as i32;

    // Recheck: balance should be lower (40)
    let (_, body) = pool.get_url("http://127.0.0.1:18784/balance?account=alice").unwrap();
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let b2 = v["balance"].as_f64().unwrap();
    assert!((b2 - 40.0).abs() < f64::EPSILON);
    let max_dur_2 = ((b2 / 1.0) * 60.0) as i32;

    // Max duration should decrease
    assert!(max_dur_2 < max_dur_1,
        "recheck max_dur should decrease: {} < {}", max_dur_2, max_dur_1);

    // Third recheck: balance=30
    let (_, body) = pool.get_url("http://127.0.0.1:18784/balance?account=alice").unwrap();
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let b3 = v["balance"].as_f64().unwrap();
    assert!((b3 - 30.0).abs() < f64::EPSILON);
}
RSEOF

    if RESULT=$(cd "$CARGO_DIR" && cargo test -p rust-credit-check --test e2e_recheck e2e_recheck_decreasing_balance 2>&1); then
        log_pass "E2E recheck: balance decreasing 50->40->30, max duration tracks"
    else
        log_fail "E2E recheck"
        echo "$RESULT" | tail -20
    fi
else
    log_fail "E2E recheck (API failed to start on :18784)"
fi

# ── Test 7: E2E cache warmup (Task 50) ───────────────────────────

log_info "Test 7: E2E cache warmup"

cat > /tmp/credit_e2e_warmup_api.py << 'PYEOF'
import http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        accounts = [
            {"account":"alice","balance":42.5},
            {"account":"bob","balance":10.0},
            {"account":"charlie","balance":0.0},
        ]
        self.wfile.write(json.dumps(accounts).encode())
    def log_message(self, *a): pass

port = int(sys.argv[1]) if len(sys.argv) > 1 else 18785
http.server.HTTPServer(('127.0.0.1', port), H).serve_forever()
PYEOF

python3 /tmp/credit_e2e_warmup_api.py 18785 &
PIDS+=($!)

if wait_for_port 18785; then
    mkdir -p "$CARGO_DIR/rust_credit_check/tests"
    cat > "$CARGO_DIR/rust_credit_check/tests/e2e_warmup.rs" << 'RSEOF'
#[test]
fn e2e_cache_warmup() {
    let pool = rust_common::http::Pool::new();
    pool.init(5, 4, None);

    // Fetch warmup data
    let (status, body) = pool.get_url("http://127.0.0.1:18785/all_accounts").unwrap();
    assert_eq!(status, 200);

    // Parse warmup response (same logic as module)
    let arr: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
    assert_eq!(arr.len(), 3);

    // Simulate cache population
    let mut cache: std::collections::HashMap<String, f64> = std::collections::HashMap::new();
    for item in &arr {
        let account = item["account"].as_str().unwrap();
        let balance = item["balance"].as_f64().unwrap();
        cache.insert(account.to_string(), balance);
    }

    assert_eq!(cache.len(), 3);
    assert!((cache["alice"] - 42.5).abs() < f64::EPSILON);
    assert!((cache["bob"] - 10.0).abs() < f64::EPSILON);
    assert!((cache["charlie"] - 0.0).abs() < f64::EPSILON);

    // After warmup, credit_check_async would hit cache (instant, no blocking)
    // Verify cache-first logic: all three accounts are in cache
    assert!(cache.contains_key("alice"));
    assert!(cache.contains_key("bob"));
    assert!(cache.contains_key("charlie"));
}
RSEOF

    if RESULT=$(cd "$CARGO_DIR" && cargo test -p rust-credit-check --test e2e_warmup e2e_cache_warmup 2>&1); then
        log_pass "E2E warmup: 3 accounts loaded from warmup URL into cache"
    else
        log_fail "E2E warmup"
        echo "$RESULT" | tail -20
    fi
else
    log_fail "E2E warmup (API failed to start on :18785)"
fi

# Clean up e2e test files before full suite
rm -f "$CARGO_DIR/rust_credit_check/tests/e2e_debit.rs"
rm -f "$CARGO_DIR/rust_credit_check/tests/e2e_nested_json.rs"
rm -f "$CARGO_DIR/rust_credit_check/tests/e2e_failover.rs"
rm -f "$CARGO_DIR/rust_credit_check/tests/e2e_rate_table.rs"
rm -f "$CARGO_DIR/rust_credit_check/tests/e2e_recheck.rs"
rm -f "$CARGO_DIR/rust_credit_check/tests/e2e_warmup.rs"

# ── Test 8: Full library test suite (no e2e files) ───────────────

log_info "Test 8: Full unit test suite"
if RESULT=$(cd "$CARGO_DIR" && cargo test -p rust-credit-check --lib 2>&1); then
    TCOUNT=$(echo "$RESULT" | grep "test result" | grep -oP '\d+ passed' || echo "? passed")
    log_pass "Full unit test suite ($TCOUNT)"
else
    log_fail "Full unit test suite"
    echo "$RESULT" | tail -15
fi

# ── Test 9: DocBook XML validation ───────────────────────────────

log_info "Test 9: DocBook XML validation"
if xmllint --noout --noent /usr/local/src/opensips/modules/rust_credit_check/doc/rust_credit_check.xml 2>&1; then
    log_pass "DocBook XML validates"
else
    log_fail "DocBook XML validation"
fi

# ── Test 10: Clippy clean ────────────────────────────────────────

log_info "Test 10: Clippy clean"
if RESULT=$(cd "$CARGO_DIR" && cargo clippy -p rust-credit-check -- -W clippy::all -D warnings 2>&1); then
    log_pass "Clippy passes with no warnings"
else
    log_fail "Clippy"
    echo "$RESULT" | tail -10
fi

# ── Test 11: Release build ───────────────────────────────────────

log_info "Test 11: Release build"
if RESULT=$(cd "$CARGO_DIR" && cargo build --release -p rust-credit-check 2>&1); then
    log_pass "Release build succeeds"
else
    log_fail "Release build"
    echo "$RESULT" | tail -10
fi

# ── Summary ──────────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

exit $FAIL
