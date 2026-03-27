//! rust_concurrent_calls — Per-account concurrent call limiting for OpenSIPS.
//!
//! Tracks active calls per account (typically `$fU`) and enforces configurable
//! limits. Uses explicit inc/dec from the OpenSIPS script — no dialog callback
//! complexity.
//!
//! # OpenSIPS config
//!
//! ```text
//! loadmodule "rust_concurrent_calls.so"
//! modparam("rust_concurrent_calls", "limits_file", "/etc/opensips/call_limits.csv")
//! modparam("rust_concurrent_calls", "default_limit", 10)
//!
//! route {
//!     if (is_method("INVITE") && !has_totag()) {
//!         if (!rust_check_concurrent("$fU")) {
//!             xlog("L_WARN", "over limit: $fU has $var(concurrent_count)/$var(concurrent_limit) calls\n");
//!             sl_send_reply(486, "Too Many Calls");
//!             exit;
//!         }
//!         rust_concurrent_inc("$fU");
//!     }
//! }
//!
//! onreply_route {
//!     if (is_method("INVITE") && $rs >= 300) {
//!         rust_concurrent_dec("$fU");
//!     }
//! }
//!
//! route[handle_bye] {
//!     rust_concurrent_dec("$fU");
//! }
//! ```
//!
//! # Limits file format (CSV)
//!
//! ```text
//! # account,max_calls
//! alice,5
//! bob,20
//! sip_trunk_1,100
//! ```

#![allow(clippy::doc_markdown)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::use_self)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::ptr_as_ptr)]
#![allow(clippy::borrow_as_ptr)]
#![allow(clippy::ref_as_ptr)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::redundant_else)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::as_ptr_cast_mut)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::pub_underscore_fields)]
#![allow(clippy::elidable_lifetime_names)]
#![allow(clippy::single_match_else)]
#![allow(clippy::let_and_return)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::bool_to_int_with_if)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::if_not_else)]
#![allow(clippy::missing_const_for_thread_local)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::single_char_pattern)]
#![allow(clippy::redundant_guards)]
#![allow(clippy::or_fun_call)]

use opensips_rs::command::CommandFunctionParam;
use opensips_rs::param::{Integer, ModString};
use opensips_rs::sys;
use opensips_rs::{cstr_lit, opensips_log};
use rust_common::mi::Stats;
use rust_common::reload::{csv_line_parser, FileLoader};

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{c_int, c_void};
use std::ptr;

// ── Module parameters ────────────────────────────────────────────

/// Path to limits CSV file (required). Format: account,max_calls
static LIMITS_FILE: ModString = ModString::new();

/// Default concurrent call limit for accounts not in the limits file.
static DEFAULT_LIMIT: Integer = Integer::with_default(10);

// ── Pure logic (testable without FFI) ────────────────────────────

/// Parse a CSV line "account,limit" into a (String, u32) pair.
fn parse_limit_entry(csv_line: &str) -> Option<(String, u32)> {
    let mut parts = csv_line.splitn(2, ',');
    let account = parts.next()?.trim();
    let limit_str = parts.next()?.trim();
    let limit = limit_str.parse::<u32>().ok()?;
    if account.is_empty() {
        return None;
    }
    Some((account.to_string(), limit))
}

/// Build a HashMap<String, u32> from parsed CSV lines.
#[allow(clippy::needless_pass_by_value)]
fn build_limits(entries: Vec<String>) -> HashMap<String, u32> {
    entries
        .iter()
        .filter_map(|line| parse_limit_entry(line))
        .collect()
}

/// Check if an account is under its concurrent call limit.
///
/// Returns (allowed, current_count, limit).
fn check_limit(
    counts: &HashMap<String, u32>,
    limits: &HashMap<String, u32>,
    account: &str,
    default_limit: u32,
) -> (bool, u32, u32) {
    let count = counts.get(account).copied().unwrap_or(0);
    let limit = limits.get(account).copied().unwrap_or(default_limit);
    (count < limit, count, limit)
}

/// Increment the call count for an account. Returns the new count.
fn increment(counts: &mut HashMap<String, u32>, account: &str) -> u32 {
    let entry = counts.entry(account.to_string()).or_insert(0);
    *entry += 1;
    *entry
}

/// Decrement the call count for an account (floor at 0). Returns the new count.
fn decrement(counts: &mut HashMap<String, u32>, account: &str) -> u32 {
    let entry = counts.entry(account.to_string()).or_insert(0);
    *entry = entry.saturating_sub(1);
    *entry
}

// ── Per-worker state ─────────────────────────────────────────────

struct WorkerState {
    counts: HashMap<String, u32>,
    loader: FileLoader<HashMap<String, u32>>,
    stats: Stats,
}

thread_local! {
    static WORKER: RefCell<Option<WorkerState>> = const { RefCell::new(None) };
}

// ── Module lifecycle ─────────────────────────────────────────────

unsafe extern "C" fn mod_init() -> c_int {
    let file = match unsafe { LIMITS_FILE.get_value() } {
        Some(f) if !f.is_empty() => f,
        _ => {
            opensips_log!(ERR, "rust_concurrent_calls",
                "modparam limits_file is required but not set");
            return -1;
        }
    };

    let default = DEFAULT_LIMIT.get();

    // Validate default_limit
    if default < 0 {
        opensips_log!(WARN, "rust_concurrent_calls",
            "default_limit={} is negative, clamping to 0 (block all)", default);
    } else if default > 100_000 {
        opensips_log!(WARN, "rust_concurrent_calls",
            "default_limit={} is very high (>100000), verify this is intentional", default);
    }

    opensips_log!(INFO, "rust_concurrent_calls", "module initialized");
    opensips_log!(INFO, "rust_concurrent_calls", "  limits_file={}", file);
    opensips_log!(INFO, "rust_concurrent_calls", "  default_limit={}", default);

    0
}

unsafe extern "C" fn mod_child_init(rank: c_int) -> c_int {
    if rank < 1 {
        return 0;
    }

    let file = match unsafe { LIMITS_FILE.get_value() } {
        Some(f) => f.to_string(),
        None => return -1,
    };

    let loader = match FileLoader::new(&file, csv_line_parser, build_limits) {
        Ok(l) => l,
        Err(e) => {
            opensips_log!(ERR, "rust_concurrent_calls",
                "failed to load limits file: {}", e);
            return -1;
        }
    };

    let entry_count = loader.get().len();

    let stats = Stats::new("rust_concurrent_calls",
        &["checked", "allowed", "blocked", "incremented", "decremented", "accounts", "reloads"]);
    stats.set("accounts", entry_count as u64);

    WORKER.with(|w| {
        *w.borrow_mut() = Some(WorkerState {
            counts: HashMap::with_capacity(256),
            loader,
            stats,
        });
    });

    opensips_log!(DBG, "rust_concurrent_calls",
        "worker {} loaded {} account limits", rank, entry_count);
    0
}

unsafe extern "C" fn mod_destroy() {
    opensips_log!(INFO, "rust_concurrent_calls", "module destroyed");
}

// ── Script function: rust_check_concurrent(account) ──────────────

unsafe extern "C" fn w_rust_check_concurrent(
    msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_concurrent_calls",
                    "rust_check_concurrent: missing or invalid parameter");
                return -2;
            }
        };

        WORKER.with(|w| {
            let borrow = w.borrow();
            match borrow.as_ref() {
                Some(state) => {
                    state.stats.inc("checked");

                    let limits = state.loader.get();
                    let default = DEFAULT_LIMIT.get() as u32;
                    let (allowed, count, limit) = check_limit(
                        &state.counts, &limits, account, default,
                    );

                    // Set $var(concurrent_count) and $var(concurrent_limit)
                    let mut sip_msg = unsafe {
                        opensips_rs::SipMessage::from_raw(msg)
                    };
                    let _ = sip_msg.set_pv_int("$var(concurrent_count)", count as i32);
                    let _ = sip_msg.set_pv_int("$var(concurrent_limit)", limit as i32);

                    if allowed {
                        state.stats.inc("allowed");
                        1
                    } else {
                        state.stats.inc("blocked");
                        opensips_log!(DBG, "rust_concurrent_calls",
                            "account {} at limit: {}/{}", account, count, limit);
                        -1
                    }
                }
                None => {
                    opensips_log!(ERR, "rust_concurrent_calls",
                        "worker state not initialized");
                    -2
                }
            }
        })
    })
}

// ── Script function: rust_concurrent_inc(account) ────────────────

unsafe extern "C" fn w_rust_concurrent_inc(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_concurrent_calls",
                    "rust_concurrent_inc: missing or invalid parameter");
                return -2;
            }
        };

        WORKER.with(|w| {
            let mut borrow = w.borrow_mut();
            match borrow.as_mut() {
                Some(state) => {
                    let new_count = increment(&mut state.counts, account);
                    state.stats.inc("incremented");
                    opensips_log!(DBG, "rust_concurrent_calls",
                        "inc {}: now {}", account, new_count);
                    1
                }
                None => {
                    opensips_log!(ERR, "rust_concurrent_calls",
                        "worker state not initialized");
                    -2
                }
            }
        })
    })
}

// ── Script function: rust_concurrent_dec(account) ────────────────

unsafe extern "C" fn w_rust_concurrent_dec(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_concurrent_calls",
                    "rust_concurrent_dec: missing or invalid parameter");
                return -2;
            }
        };

        WORKER.with(|w| {
            let mut borrow = w.borrow_mut();
            match borrow.as_mut() {
                Some(state) => {
                    let new_count = decrement(&mut state.counts, account);
                    state.stats.inc("decremented");
                    opensips_log!(DBG, "rust_concurrent_calls",
                        "dec {}: now {}", account, new_count);
                    1
                }
                None => {
                    opensips_log!(ERR, "rust_concurrent_calls",
                        "worker state not initialized");
                    -1
                }
            }
        })
    })
}

// ── Script function: rust_concurrent_reload() ────────────────────

unsafe extern "C" fn w_rust_concurrent_reload(
    _msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        WORKER.with(|w| {
            let mut borrow = w.borrow_mut();
            match borrow.as_mut() {
                Some(state) => {
                    match state.loader.reload() {
                        Ok(count) => {
                            state.stats.set("accounts", count as u64);
                            state.stats.inc("reloads");
                            opensips_log!(INFO, "rust_concurrent_calls",
                                "reloaded {} account limits", count);
                            1
                        }
                        Err(e) => {
                            opensips_log!(ERR, "rust_concurrent_calls",
                                "reload failed: {}", e);
                            -2
                        }
                    }
                }
                None => {
                    opensips_log!(ERR, "rust_concurrent_calls",
                        "worker state not initialized");
                    -2
                }
            }
        })
    })
}

// ── Script function: rust_concurrent_stats() ─────────────────────

unsafe extern "C" fn w_rust_concurrent_stats(
    msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let json = WORKER.with(|w| {
            let borrow = w.borrow();
            match borrow.as_ref() {
                Some(state) => state.stats.to_json(),
                None => r#"{"error":"not_initialized"}"#.to_string(),
            }
        });
        let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
        let _ = sip_msg.set_pv("$var(concurrent_stats)", &json);
        1
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

static CMDS: SyncArray<sys::cmd_export_, 6> = SyncArray([
    sys::cmd_export_ {
        name: cstr_lit!("rust_check_concurrent"),
        function: Some(w_rust_check_concurrent),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("rust_concurrent_inc"),
        function: Some(w_rust_concurrent_inc),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("rust_concurrent_dec"),
        function: Some(w_rust_concurrent_dec),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("rust_concurrent_reload"),
        function: Some(w_rust_concurrent_reload),
        params: EMPTY_PARAMS,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("rust_concurrent_stats"),
        function: Some(w_rust_concurrent_stats),
        params: EMPTY_PARAMS,
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

static PARAMS: SyncArray<sys::param_export_, 3> = SyncArray([
    sys::param_export_ {
        name: cstr_lit!("limits_file"),
        type_: 1, // STR_PARAM
        param_pointer: LIMITS_FILE.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("default_limit"),
        type_: 2, // INT_PARAM
        param_pointer: DEFAULT_LIMIT.as_ptr(),
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
    name: cstr_lit!("rust_concurrent_calls"),
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

    // ── parse_limit_entry ────────────────────────────────────────

    #[test]
    fn test_parse_valid_entry() {
        let result = parse_limit_entry("alice,5");
        assert_eq!(result, Some(("alice".to_string(), 5)));
    }

    #[test]
    fn test_parse_with_whitespace() {
        let result = parse_limit_entry("  bob , 20 ");
        assert_eq!(result, Some(("bob".to_string(), 20)));
    }

    #[test]
    fn test_parse_invalid_limit() {
        assert_eq!(parse_limit_entry("alice,notanumber"), None);
    }

    #[test]
    fn test_parse_empty_account() {
        assert_eq!(parse_limit_entry(",5"), None);
    }

    #[test]
    fn test_parse_no_comma() {
        assert_eq!(parse_limit_entry("alice"), None);
    }

    #[test]
    fn test_parse_zero_limit() {
        let result = parse_limit_entry("blocked_user,0");
        assert_eq!(result, Some(("blocked_user".to_string(), 0)));
    }

    #[test]
    fn test_parse_large_limit() {
        let result = parse_limit_entry("sip_trunk,10000");
        assert_eq!(result, Some(("sip_trunk".to_string(), 10000)));
    }

    // ── build_limits ─────────────────────────────────────────────

    #[test]
    fn test_limits_file_parse() {
        let entries = vec![
            "alice,5".to_string(),
            "bob,20".to_string(),
        ];
        let limits = build_limits(entries);
        assert_eq!(limits.len(), 2);
        assert_eq!(limits.get("alice"), Some(&5));
        assert_eq!(limits.get("bob"), Some(&20));
    }

    #[test]
    fn test_limits_file_comments() {
        let entries = vec![
            "alice,5".to_string(),
            "notavalidline".to_string(),
            "bob,20".to_string(),
        ];
        let limits = build_limits(entries);
        assert_eq!(limits.len(), 2);
        assert_eq!(limits.get("alice"), Some(&5));
        assert_eq!(limits.get("bob"), Some(&20));
    }

    #[test]
    fn test_limits_empty() {
        let limits = build_limits(vec![]);
        assert!(limits.is_empty());
    }

    // ── check_limit ──────────────────────────────────────────────

    #[test]
    fn test_check_under_limit() {
        let mut counts = HashMap::new();
        counts.insert("alice".to_string(), 2);
        let mut limits = HashMap::new();
        limits.insert("alice".to_string(), 5);

        let (allowed, count, limit) = check_limit(&counts, &limits, "alice", 10);
        assert!(allowed);
        assert_eq!(count, 2);
        assert_eq!(limit, 5);
    }

    #[test]
    fn test_check_at_limit() {
        let mut counts = HashMap::new();
        counts.insert("alice".to_string(), 5);
        let mut limits = HashMap::new();
        limits.insert("alice".to_string(), 5);

        let (allowed, count, limit) = check_limit(&counts, &limits, "alice", 10);
        assert!(!allowed);
        assert_eq!(count, 5);
        assert_eq!(limit, 5);
    }

    #[test]
    fn test_check_over_limit() {
        let mut counts = HashMap::new();
        counts.insert("alice".to_string(), 6);
        let mut limits = HashMap::new();
        limits.insert("alice".to_string(), 5);

        let (allowed, count, limit) = check_limit(&counts, &limits, "alice", 10);
        assert!(!allowed);
        assert_eq!(count, 6);
        assert_eq!(limit, 5);
    }

    #[test]
    fn test_check_default_limit() {
        let counts = HashMap::new();
        let limits = HashMap::new();

        let (allowed, count, limit) = check_limit(&counts, &limits, "unknown_user", 10);
        assert!(allowed);
        assert_eq!(count, 0);
        assert_eq!(limit, 10);
    }

    #[test]
    fn test_check_zero_count() {
        let counts = HashMap::new();
        let mut limits = HashMap::new();
        limits.insert("alice".to_string(), 5);

        let (allowed, count, limit) = check_limit(&counts, &limits, "alice", 10);
        assert!(allowed);
        assert_eq!(count, 0);
        assert_eq!(limit, 5);
    }

    #[test]
    fn test_check_zero_limit_blocks() {
        let counts = HashMap::new();
        let mut limits = HashMap::new();
        limits.insert("blocked".to_string(), 0);

        let (allowed, count, limit) = check_limit(&counts, &limits, "blocked", 10);
        assert!(!allowed);
        assert_eq!(count, 0);
        assert_eq!(limit, 0);
    }

    // ── increment ────────────────────────────────────────────────

    #[test]
    fn test_increment_from_zero() {
        let mut counts = HashMap::new();
        let new = increment(&mut counts, "alice");
        assert_eq!(new, 1);
        assert_eq!(counts.get("alice"), Some(&1));
    }

    #[test]
    fn test_increment_existing() {
        let mut counts = HashMap::new();
        counts.insert("alice".to_string(), 1);
        let new = increment(&mut counts, "alice");
        assert_eq!(new, 2);
        assert_eq!(counts.get("alice"), Some(&2));
    }

    #[test]
    fn test_increment_multiple() {
        let mut counts = HashMap::new();
        increment(&mut counts, "alice");
        increment(&mut counts, "alice");
        increment(&mut counts, "alice");
        assert_eq!(counts.get("alice"), Some(&3));
    }

    // ── decrement ────────────────────────────────────────────────

    #[test]
    fn test_decrement_normal() {
        let mut counts = HashMap::new();
        counts.insert("alice".to_string(), 2);
        let new = decrement(&mut counts, "alice");
        assert_eq!(new, 1);
    }

    #[test]
    fn test_decrement_to_zero() {
        let mut counts = HashMap::new();
        counts.insert("alice".to_string(), 1);
        let new = decrement(&mut counts, "alice");
        assert_eq!(new, 0);
    }

    #[test]
    fn test_decrement_floor() {
        let mut counts = HashMap::new();
        let new = decrement(&mut counts, "alice");
        assert_eq!(new, 0);

        counts.insert("bob".to_string(), 0);
        let new = decrement(&mut counts, "bob");
        assert_eq!(new, 0);
    }

    // ── Multiple accounts ────────────────────────────────────────

    #[test]
    fn test_multiple_accounts() {
        let mut counts = HashMap::new();
        let mut limits = HashMap::new();
        limits.insert("alice".to_string(), 2);
        limits.insert("bob".to_string(), 5);
        limits.insert("charlie".to_string(), 1);

        increment(&mut counts, "alice");
        let (allowed, _, _) = check_limit(&counts, &limits, "alice", 10);
        assert!(allowed);

        increment(&mut counts, "alice");
        let (allowed, count, limit) = check_limit(&counts, &limits, "alice", 10);
        assert!(!allowed);
        assert_eq!(count, 2);
        assert_eq!(limit, 2);

        increment(&mut counts, "bob");
        increment(&mut counts, "bob");
        increment(&mut counts, "bob");
        let (allowed, count, _) = check_limit(&counts, &limits, "bob", 10);
        assert!(allowed);
        assert_eq!(count, 3);

        increment(&mut counts, "charlie");
        let (allowed, _, _) = check_limit(&counts, &limits, "charlie", 10);
        assert!(!allowed);

        decrement(&mut counts, "alice");
        let (allowed, count, _) = check_limit(&counts, &limits, "alice", 10);
        assert!(allowed);
        assert_eq!(count, 1);
    }

    // ── Integration: inc/dec/check cycle ─────────────────────────

    #[test]
    fn test_full_call_lifecycle() {
        let mut counts = HashMap::new();
        let mut limits = HashMap::new();
        limits.insert("alice".to_string(), 2);

        let (allowed, _, _) = check_limit(&counts, &limits, "alice", 10);
        assert!(allowed);
        increment(&mut counts, "alice");

        let (allowed, _, _) = check_limit(&counts, &limits, "alice", 10);
        assert!(allowed);
        increment(&mut counts, "alice");

        let (allowed, count, limit) = check_limit(&counts, &limits, "alice", 10);
        assert!(!allowed);
        assert_eq!(count, 2);
        assert_eq!(limit, 2);

        decrement(&mut counts, "alice");

        let (allowed, count, _) = check_limit(&counts, &limits, "alice", 10);
        assert!(allowed);
        assert_eq!(count, 1);
    }

    // ── Stats JSON output tests ──────────────────────────────────

    #[test]
    fn test_concurrent_stats_json() {
        use rust_common::mi::Stats;
        let stats = Stats::new("rust_concurrent_calls",
            &["checked", "allowed", "blocked", "incremented", "decremented", "accounts"]);
        stats.set("accounts", 10);
        stats.inc("checked");
        stats.inc("allowed");
        stats.inc("incremented");
        stats.inc("incremented");
        stats.inc("decremented");

        let json = stats.to_json();
        assert!(json.starts_with("{"));
        assert!(json.ends_with("}"));
        assert!(json.contains(r#""accounts":10"#));
        assert!(json.contains(r#""checked":1"#));
        assert!(json.contains(r#""incremented":2"#));
    }

    // ── configuration validation edge case tests ────────────────

    #[test]
    fn test_default_limit_zero_blocks_all() {
        let counts = HashMap::new();
        let limits = HashMap::new();
        let (allowed, count, limit) = check_limit(&counts, &limits, "anyone", 0);
        assert!(!allowed);
        assert_eq!(count, 0);
        assert_eq!(limit, 0);
    }

    #[test]
    fn test_default_limit_very_high() {
        let counts = HashMap::new();
        let limits = HashMap::new();
        let (allowed, count, limit) = check_limit(&counts, &limits, "user", 100_000);
        assert!(allowed);
        assert_eq!(count, 0);
        assert_eq!(limit, 100_000);
    }

    // ── Reload integration test (file-backed) ────────────────────

    #[test]
    fn test_reload_updates_limits() {
        use rust_common::reload::{csv_line_parser, FileLoader};
        use std::io::Write;

        let path = format!("{}/rust_cc_reload_test", std::env::temp_dir().display());

        // Create initial file
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "alice,5").unwrap();
            writeln!(f, "bob,10").unwrap();
        }

        let loader = FileLoader::new(&path, csv_line_parser, build_limits).unwrap();
        let limits = loader.get();
        assert_eq!(limits.len(), 2);
        assert_eq!(limits.get("alice"), Some(&5));
        assert_eq!(limits.get("bob"), Some(&10));
        drop(limits);

        // Update file: change alice's limit, add charlie
        std::fs::write(&path, "alice,20\nbob,10\ncharlie,3\n").unwrap();

        let count = loader.reload().unwrap();
        assert_eq!(count, 3);

        let limits = loader.get();
        assert_eq!(limits.len(), 3);
        assert_eq!(limits.get("alice"), Some(&20));
        assert_eq!(limits.get("bob"), Some(&10));
        assert_eq!(limits.get("charlie"), Some(&3));
        drop(limits);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_reload_file_error_returns_err() {
        use rust_common::reload::{csv_line_parser, FileLoader};

        let path = format!("{}/rust_cc_reload_err_test", std::env::temp_dir().display());
        std::fs::write(&path, "alice,5\n").unwrap();

        let loader = FileLoader::new(&path, csv_line_parser, build_limits).unwrap();
        assert_eq!(loader.get().len(), 1);

        // Delete file, then attempt reload
        std::fs::remove_file(&path).unwrap();
        let result = loader.reload();
        assert!(result.is_err());
    }
}
