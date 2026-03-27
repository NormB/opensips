//! rust_credit_check — Prepaid credit/balance checking with per-worker cache.
//!
//! Queries an external billing API for account balance, caches results
//! per-worker with configurable TTL. Computes max call duration from balance.
//!
//! # OpenSIPS config
//!
//! ```text
//! loadmodule "rust_credit_check.so"
//! modparam("rust_credit_check", "billing_url", "http://billing:8080/balance")
//! modparam("rust_credit_check", "cache_ttl", 300)
//! modparam("rust_credit_check", "http_timeout", 2)
//! modparam("rust_credit_check", "pool_size", 4)
//! modparam("rust_credit_check", "rate_per_min", 1)
//! modparam("rust_credit_check", "on_error", "deny")
//!
//! route {
//!     if (is_method("INVITE") && !has_totag()) {
//!         if (!rust_credit_check("$fU")) {
//!             sl_send_reply(402, "Insufficient Credit");
//!             exit;
//!         }
//!         xlog("L_INFO", "balance=$var(credit_balance) max_dur=$var(credit_max_duration)s\n");
//!     }
//! }
//! ```

use opensips_rs::command::CommandFunctionParam;
use opensips_rs::param::{Integer, ModString};
use opensips_rs::sys;
use opensips_rs::{cstr_lit, opensips_log};
use rust_common::http::Pool;

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{c_int, c_void};
use std::ptr;
use std::time::Instant;

// ── Module parameters ────────────────────────────────────────────

/// Billing API endpoint (required). GET {url}?account={account}
static BILLING_URL: ModString = ModString::new();

/// Cache TTL in seconds (default 300).
static CACHE_TTL: Integer = Integer::with_default(300);

/// HTTP request timeout in seconds (default 2).
static HTTP_TIMEOUT: Integer = Integer::with_default(2);

/// HTTP connection pool size per worker (default 4).
static POOL_SIZE: Integer = Integer::with_default(4);

/// Cost units per minute for max duration calculation (default 1).
static RATE_PER_MIN: Integer = Integer::with_default(1);

/// Behavior on billing API error: "deny" (default) or "allow".
static ON_ERROR: ModString = ModString::new();

/// Optional TLS CA file path for billing API.
static TLS_CA_FILE: ModString = ModString::new();

// ── Pure logic (testable without FFI) ────────────────────────────

/// A cached credit balance entry.
struct CreditEntry {
    balance: f64,
    fetched: Instant,
}

/// Per-worker credit cache with TTL-based expiry.
struct CreditCache {
    entries: HashMap<String, CreditEntry>,
    ttl_secs: u64,
}

#[allow(dead_code)]
impl CreditCache {
    fn new(ttl_secs: u64) -> Self {
        CreditCache {
            entries: HashMap::new(),
            ttl_secs,
        }
    }

    /// Get cached balance if not expired. Returns None on miss or expiry.
    fn get(&self, account: &str) -> Option<f64> {
        let entry = self.entries.get(account)?;
        if entry.fetched.elapsed().as_secs() < self.ttl_secs {
            Some(entry.balance)
        } else {
            None
        }
    }

    /// Insert or update a cache entry.
    fn put(&mut self, account: &str, balance: f64) {
        self.entries.insert(account.to_string(), CreditEntry {
            balance,
            fetched: Instant::now(),
        });
    }

    /// Remove a single cache entry.
    fn clear(&mut self, account: &str) {
        self.entries.remove(account);
    }

    /// Remove all cache entries.
    fn clear_all(&mut self) {
        self.entries.clear();
    }

    /// Number of entries (including potentially expired ones).
    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Compute max call duration in seconds from balance and rate.
/// rate_per_min: cost units consumed per minute of call.
/// Returns seconds (integer).
fn compute_max_duration(balance: f64, rate_per_min: f64) -> i32 {
    if rate_per_min <= 0.0 || balance <= 0.0 {
        return 0;
    }
    ((balance / rate_per_min) * 60.0) as i32
}

/// Parse a JSON billing response body. Expected: {"balance": 42.50}
fn parse_balance_response(body: &str) -> Option<f64> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v.get("balance")?.as_f64()
}

/// Decide the return value when the billing API is unreachable.
/// Returns true (allow) or false (deny).
fn on_error_allows(on_error: &str) -> bool {
    on_error.eq_ignore_ascii_case("allow")
}

// ── Per-worker state ─────────────────────────────────────────────

struct WorkerState {
    cache: CreditCache,
    pool: Pool,
}

thread_local! {
    static WORKER: RefCell<Option<WorkerState>> = const { RefCell::new(None) };
}

// ── Module lifecycle ─────────────────────────────────────────────

unsafe extern "C" fn mod_init() -> c_int {
    let url = match unsafe { BILLING_URL.get_value() } {
        Some(u) if !u.is_empty() => u,
        _ => {
            opensips_log!(ERR, "rust_credit_check",
                "modparam billing_url is required but not set");
            return -1;
        }
    };

    let on_err = unsafe { ON_ERROR.get_value() }.unwrap_or("deny");

    opensips_log!(INFO, "rust_credit_check", "module initialized");
    opensips_log!(INFO, "rust_credit_check", "  billing_url={}", url);
    opensips_log!(INFO, "rust_credit_check", "  cache_ttl={}s", CACHE_TTL.get());
    opensips_log!(INFO, "rust_credit_check", "  http_timeout={}s", HTTP_TIMEOUT.get());
    opensips_log!(INFO, "rust_credit_check", "  pool_size={}", POOL_SIZE.get());
    opensips_log!(INFO, "rust_credit_check", "  rate_per_min={}", RATE_PER_MIN.get());
    opensips_log!(INFO, "rust_credit_check", "  on_error={}", on_err);

    0
}

unsafe extern "C" fn mod_child_init(rank: c_int) -> c_int {
    if rank < 1 {
        return 0;
    }

    let pool = Pool::new();
    let ca_file = unsafe { TLS_CA_FILE.get_value() };
    pool.init(HTTP_TIMEOUT.get(), POOL_SIZE.get(), ca_file);

    let ttl = CACHE_TTL.get();
    let cache = CreditCache::new(if ttl > 0 { ttl as u64 } else { 300 });

    WORKER.with(|w| {
        *w.borrow_mut() = Some(WorkerState { cache, pool });
    });

    opensips_log!(DBG, "rust_credit_check", "worker {} initialized", rank);
    0
}

unsafe extern "C" fn mod_destroy() {
    opensips_log!(INFO, "rust_credit_check", "module destroyed");
}

// ── Script function: rust_credit_check(account) ──────────────────

unsafe extern "C" fn w_rust_credit_check(
    msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_credit_check",
                    "rust_credit_check: missing or invalid parameter");
                return -1;
            }
        };

        let rate = RATE_PER_MIN.get() as f64;
        let on_err = unsafe { ON_ERROR.get_value() }.unwrap_or("deny");

        WORKER.with(|w| {
            let mut borrow = w.borrow_mut();
            let state = match borrow.as_mut() {
                Some(s) => s,
                None => {
                    opensips_log!(ERR, "rust_credit_check", "worker state not initialized");
                    return -1;
                }
            };

            // 1. Check cache
            let balance = match state.cache.get(account) {
                Some(b) => {
                    opensips_log!(DBG, "rust_credit_check",
                        "cache hit for {}: balance={}", account, b);
                    b
                }
                None => {
                    // 2. Cache miss — query billing API
                    let url = match unsafe { BILLING_URL.get_value() } {
                        Some(u) => u,
                        None => return -1,
                    };
                    let full_url = format!("{}?account={}", url, account);

                    match state.pool.get_url(&full_url) {
                        Ok((status, body)) if status == 200 => {
                            // 3. Parse response
                            match parse_balance_response(&body) {
                                Some(b) => {
                                    // 4. Cache the result
                                    state.cache.put(account, b);
                                    opensips_log!(DBG, "rust_credit_check",
                                        "fetched balance for {}: {}", account, b);
                                    b
                                }
                                None => {
                                    opensips_log!(ERR, "rust_credit_check",
                                        "failed to parse balance response: {}", body);
                                    return if on_error_allows(on_err) { 1 } else { -1 };
                                }
                            }
                        }
                        Ok((status, body)) => {
                            opensips_log!(ERR, "rust_credit_check",
                                "billing API returned status {}: {}", status, body);
                            return if on_error_allows(on_err) { 1 } else { -1 };
                        }
                        Err(e) => {
                            // 7. HTTP error
                            opensips_log!(ERR, "rust_credit_check",
                                "billing API error for {}: {}", account, e);
                            return if on_error_allows(on_err) { 1 } else { -1 };
                        }
                    }
                }
            };

            // 5. Evaluate balance
            let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };

            if balance > 0.0 {
                let max_dur = compute_max_duration(balance, rate);
                // Serialize balance as string with 2 decimal places
                let balance_str = format!("{:.2}", balance);
                let _ = sip_msg.set_pv("$var(credit_balance)", &balance_str);
                let _ = sip_msg.set_pv_int("$var(credit_max_duration)", max_dur);
                1
            } else {
                // 6. No credit
                let _ = sip_msg.set_pv("$var(credit_balance)", "0.00");
                let _ = sip_msg.set_pv_int("$var(credit_max_duration)", 0);
                -1
            }
        })
    })
}

// ── Script function: rust_credit_clear(account) ──────────────────

unsafe extern "C" fn w_rust_credit_clear(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_credit_check",
                    "rust_credit_clear: missing or invalid parameter");
                return -1;
            }
        };

        WORKER.with(|w| {
            let mut borrow = w.borrow_mut();
            match borrow.as_mut() {
                Some(state) => {
                    state.cache.clear(account);
                    opensips_log!(DBG, "rust_credit_check",
                        "cache cleared for {}", account);
                    1
                }
                None => {
                    opensips_log!(ERR, "rust_credit_check",
                        "worker state not initialized");
                    -1
                }
            }
        })
    })
}

// ── Static arrays for module registration ────────────────────────

const EMPTY_PARAMS: [sys::cmd_param; 9] = unsafe { std::mem::zeroed() };

const ONE_STR_PARAM: [sys::cmd_param; 9] = {
    let mut arr: [sys::cmd_param; 9] = unsafe { std::mem::zeroed() };
    arr[0].flags = 2; // CMD_PARAM_STR
    arr
};

#[repr(transparent)]
struct SyncArray<T, const N: usize>([T; N]);
unsafe impl<T, const N: usize> Sync for SyncArray<T, N> {}

static CMDS: SyncArray<sys::cmd_export_, 3> = SyncArray([
    sys::cmd_export_ {
        name: cstr_lit!("rust_credit_check"),
        function: Some(w_rust_credit_check),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("rust_credit_clear"),
        function: Some(w_rust_credit_clear),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    // Null terminator
    sys::cmd_export_ {
        name: ptr::null(),
        function: None,
        params: EMPTY_PARAMS,
        flags: 0,
    },
]);

static ACMDS: SyncArray<sys::acmd_export_, 1> = SyncArray([
    sys::acmd_export_ {
        name: ptr::null(),
        function: None,
        params: EMPTY_PARAMS,
    },
]);

static PARAMS: SyncArray<sys::param_export_, 8> = SyncArray([
    sys::param_export_ {
        name: cstr_lit!("billing_url"),
        type_: 1, // STR_PARAM
        param_pointer: BILLING_URL.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("cache_ttl"),
        type_: 2, // INT_PARAM
        param_pointer: CACHE_TTL.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("http_timeout"),
        type_: 2, // INT_PARAM
        param_pointer: HTTP_TIMEOUT.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("pool_size"),
        type_: 2, // INT_PARAM
        param_pointer: POOL_SIZE.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("rate_per_min"),
        type_: 2, // INT_PARAM
        param_pointer: RATE_PER_MIN.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("on_error"),
        type_: 1, // STR_PARAM
        param_pointer: ON_ERROR.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("tls_ca_file"),
        type_: 1, // STR_PARAM
        param_pointer: TLS_CA_FILE.as_ptr(),
    },
    // Null terminator
    sys::param_export_ {
        name: ptr::null(),
        type_: 0,
        param_pointer: ptr::null_mut(),
    },
]);

static DEPS: opensips_rs::ffi::DepExportConcrete<1> = opensips_rs::ffi::DepExportConcrete {
    md: unsafe { std::mem::zeroed() },
    mpd: unsafe { std::mem::zeroed() },
};

/// The module_exports struct that OpenSIPS loads via dlsym("exports").
#[no_mangle]
pub static exports: sys::module_exports = sys::module_exports {
    name: cstr_lit!("rust_credit_check"),
    type_: 1, // MOD_TYPE_DEFAULT
    ver_info: sys::module_exports__bindgen_ty_1 {
        version: cstr_lit!(env!("OPENSIPS_FULL_VERSION")),
        compile_flags: cstr_lit!(env!("OPENSIPS_COMPILE_FLAGS")),
        scm: sys::scm_version {
            type_: cstr_lit!(env!("OPENSIPS_SCM_TYPE")),
            rev: cstr_lit!(env!("OPENSIPS_SCM_REV")),
        },
    },
    dlflags: 0,
    load_f: None,
    deps: &DEPS as *const _ as *const sys::dep_export_,
    cmds: CMDS.0.as_ptr(),
    acmds: ACMDS.0.as_ptr(),
    params: PARAMS.0.as_ptr(),
    stats: ptr::null(),
    mi_cmds: ptr::null(),
    items: ptr::null(),
    trans: ptr::null(),
    procs: ptr::null(),
    preinit_f: None,
    init_f: Some(mod_init),
    response_f: None,
    destroy_f: Some(mod_destroy),
    init_child_f: Some(mod_child_init),
    reload_ack_f: None,
};

// ── Unit tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    // ── CreditCache tests ────────────────────────────────────────

    #[test]
    fn test_cache_put_get() {
        let mut cache = CreditCache::new(300);
        cache.put("alice", 42.50);
        assert_eq!(cache.get("alice"), Some(42.50));
    }

    #[test]
    fn test_cache_miss() {
        let cache = CreditCache::new(300);
        assert_eq!(cache.get("unknown"), None);
    }

    #[test]
    fn test_cache_expired() {
        let mut cache = CreditCache::new(0); // TTL of 0 seconds
        cache.put("alice", 42.50);
        thread::sleep(Duration::from_millis(10));
        assert_eq!(cache.get("alice"), None);
    }

    #[test]
    fn test_cache_clear() {
        let mut cache = CreditCache::new(300);
        cache.put("alice", 42.50);
        cache.clear("alice");
        assert_eq!(cache.get("alice"), None);
    }

    #[test]
    fn test_cache_clear_all() {
        let mut cache = CreditCache::new(300);
        cache.put("alice", 42.50);
        cache.put("bob", 10.00);
        cache.put("charlie", 100.00);
        assert_eq!(cache.len(), 3);
        cache.clear_all();
        assert_eq!(cache.len(), 0);
    }

    // ── compute_max_duration tests ───────────────────────────────

    #[test]
    fn test_compute_max_duration() {
        // balance 42.50, rate 1.0 per min -> (42.50/1.0)*60 = 2550 seconds
        assert_eq!(compute_max_duration(42.50, 1.0), 2550);
    }

    #[test]
    fn test_compute_max_duration_zero() {
        assert_eq!(compute_max_duration(0.0, 1.0), 0);
    }

    #[test]
    fn test_compute_max_duration_negative_balance() {
        assert_eq!(compute_max_duration(-5.0, 1.0), 0);
    }

    #[test]
    fn test_compute_max_duration_zero_rate() {
        // Zero rate should not divide by zero
        assert_eq!(compute_max_duration(42.50, 0.0), 0);
    }

    #[test]
    fn test_compute_max_duration_high_rate() {
        // balance 10.0, rate 2.0 per min -> (10.0/2.0)*60 = 300 seconds
        assert_eq!(compute_max_duration(10.0, 2.0), 300);
    }

    // ── parse_balance_response tests ─────────────────────────────

    #[test]
    fn test_parse_balance_valid() {
        assert_eq!(parse_balance_response(r#"{"balance": 42.50}"#), Some(42.50));
    }

    #[test]
    fn test_parse_balance_zero() {
        assert_eq!(parse_balance_response(r#"{"balance": 0}"#), Some(0.0));
    }

    #[test]
    fn test_parse_balance_negative() {
        assert_eq!(parse_balance_response(r#"{"balance": -5.0}"#), Some(-5.0));
    }

    #[test]
    fn test_parse_balance_missing() {
        assert_eq!(parse_balance_response(r#"{"name": "alice"}"#), None);
    }

    #[test]
    fn test_parse_balance_invalid_json() {
        assert_eq!(parse_balance_response("not json"), None);
    }

    #[test]
    fn test_parse_balance_integer() {
        assert_eq!(parse_balance_response(r#"{"balance": 100}"#), Some(100.0));
    }

    #[test]
    fn test_parse_balance_extra_fields() {
        // Extra fields should be ignored
        let body = r#"{"balance": 42.50, "currency": "USD", "account": "alice"}"#;
        assert_eq!(parse_balance_response(body), Some(42.50));
    }

    // ── on_error_allows tests ────────────────────────────────────

    #[test]
    fn test_on_error_deny() {
        assert!(!on_error_allows("deny"));
    }

    #[test]
    fn test_on_error_allow() {
        assert!(on_error_allows("allow"));
    }

    #[test]
    fn test_on_error_allow_case_insensitive() {
        assert!(on_error_allows("Allow"));
        assert!(on_error_allows("ALLOW"));
    }

    #[test]
    fn test_on_error_unknown_defaults_deny() {
        // Anything other than "allow" is treated as deny
        assert!(!on_error_allows(""));
        assert!(!on_error_allows("block"));
        assert!(!on_error_allows("reject"));
    }

    // ── Cache update/overwrite tests ─────────────────────────────

    #[test]
    fn test_cache_overwrite() {
        let mut cache = CreditCache::new(300);
        cache.put("alice", 42.50);
        cache.put("alice", 10.00);
        assert_eq!(cache.get("alice"), Some(10.00));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_cache_clear_nonexistent() {
        let mut cache = CreditCache::new(300);
        cache.clear("nonexistent"); // should not panic
        assert_eq!(cache.len(), 0);
    }
}
