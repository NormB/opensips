//! rust_refer_handler — REFER/NOTIFY state machine tracker for OpenSIPS.
//!
//! Tracks REFER transactions per dialog via explicit script function calls.
//! The script parses Refer-To and sipfrag status codes and passes them as
//! parameters, keeping this module simple and testable.
//!
//! # OpenSIPS config
//!
//! ```text
//! loadmodule "rust_refer_handler.so"
//! modparam("rust_refer_handler", "max_pending", 1000)
//! modparam("rust_refer_handler", "expire_secs", 300)
//!
//! route {
//!     if (is_method("REFER")) {
//!         if (rust_handle_refer("$hdr(Refer-To)")) {
//!             sl_send_reply(202, "Accepted");
//!         }
//!     }
//!     if (is_method("NOTIFY")) {
//!         # Parse sipfrag body for status code
//!         rust_handle_notify("$ci", "$var(sipfrag_code)");
//!     }
//! }
//!
//! route[check_transfer] {
//!     if (rust_refer_status("$ci")) {
//!         xlog("L_INFO", "transfer status: $var(refer_status)\n");
//!     }
//! }
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
use opensips_rs::param::Integer;
use opensips_rs::sys;
use opensips_rs::{cstr_lit, opensips_log};
use rust_common::mi::Stats;

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{c_int, c_void};
use std::ptr;
use std::time::Instant;

// ── Module parameters ────────────────────────────────────────────

/// Max tracked REFER transactions per worker (default 1000).
static MAX_PENDING: Integer = Integer::with_default(1000);

/// Auto-expire stale REFER state after this many seconds (default 300).
static EXPIRE_SECS: Integer = Integer::with_default(300);

// ── Pure logic (testable without FFI) ────────────────────────────

/// Status of a REFER transfer.
#[derive(Clone, Debug, Default, PartialEq)]
enum ReferStatus {
    #[default]
    Pending,
    Trying,
    Success,
    Failed,
}



impl ReferStatus {
    /// Convert to the string representation exposed to the script.
    fn as_str(&self) -> &'static str {
        match self {
            ReferStatus::Pending => "pending",
            ReferStatus::Trying => "trying",
            ReferStatus::Success => "success",
            ReferStatus::Failed => "failed",
        }
    }
}

/// Per-REFER transaction state.
struct ReferState {
    #[allow(dead_code)]
    refer_to: String,
    status: ReferStatus,
    created: Instant,
    notify_count: u32,
}

/// Testable REFER tracker with expiry and capacity management.
struct ReferTracker {
    states: HashMap<String, ReferState>,
    max_pending: usize,
    expire_secs: u64,
}

impl ReferTracker {
    fn new(max_pending: usize, expire_secs: u64) -> Self {
        ReferTracker {
            states: HashMap::with_capacity(max_pending.min(256)),
            max_pending,
            expire_secs,
        }
    }

    /// Record a new REFER. Overwrites any existing state for this call_id.
    /// Returns true on success.
    fn handle_refer(&mut self, call_id: &str, refer_to: &str) -> bool {
        self.maybe_sweep();
        self.states.insert(
            call_id.to_string(),
            ReferState {
                refer_to: refer_to.to_string(),
                status: ReferStatus::Pending,
                created: Instant::now(),
                notify_count: 0,
            },
        );
        true
    }

    /// Process a NOTIFY for a tracked REFER. Updates the state machine.
    /// Returns true if a matching REFER was found, false otherwise.
    fn handle_notify(&mut self, call_id: &str, status_code: u16) -> bool {
        self.maybe_sweep();
        let state = match self.states.get_mut(call_id) {
            Some(s) => s,
            None => return false,
        };

        state.notify_count += 1;

        // Terminal states are sticky — once success or failed, don't change.
        if state.status == ReferStatus::Success || state.status == ReferStatus::Failed {
            return true;
        }

        match status_code {
            100 => state.status = ReferStatus::Trying,
            200..=299 => state.status = ReferStatus::Success,
            300..=699 => state.status = ReferStatus::Failed,
            _ => {} // Ignore unexpected codes, keep current status
        }

        true
    }

    /// Get the string status for a call_id. Returns None if not tracked.
    fn get_status(&self, call_id: &str) -> Option<&str> {
        self.states.get(call_id).map(|s| s.status.as_str())
    }

    /// Number of currently tracked REFER transactions.
    fn active_count(&self) -> usize {
        self.states.len()
    }

    /// Sweep all entries older than expire_secs. Returns count of removed entries.
    fn sweep_expired(&mut self) -> usize {
        let max_age = std::time::Duration::from_secs(self.expire_secs);
        let now = Instant::now();
        let before = self.states.len();
        self.states
            .retain(|_, entry| now.duration_since(entry.created) < max_age);
        before - self.states.len()
    }

    /// Lazy cleanup: sweep if we exceed max_pending.
    fn maybe_sweep(&mut self) {
        if self.states.len() >= self.max_pending {
            self.sweep_expired();
        }
    }
}

// ── Per-worker state ─────────────────────────────────────────────

struct WorkerState {
    tracker: ReferTracker,
    stats: Stats,
}

thread_local! {
    static WORKER: RefCell<Option<WorkerState>> = const { RefCell::new(None) };
}

// ── Module lifecycle ─────────────────────────────────────────────

unsafe extern "C" fn mod_init() -> c_int {
    let max_p = MAX_PENDING.get();
    let exp = EXPIRE_SECS.get();

    opensips_log!(INFO, "rust_refer_handler", "module initialized");
    opensips_log!(INFO, "rust_refer_handler", "  max_pending={}", max_p);
    opensips_log!(INFO, "rust_refer_handler", "  expire_secs={}s", exp);

    0
}

unsafe extern "C" fn mod_child_init(rank: c_int) -> c_int {
    if rank < 1 {
        return 0;
    }

    let max_p = MAX_PENDING.get() as usize;
    let exp = if EXPIRE_SECS.get() > 0 {
        EXPIRE_SECS.get() as u64
    } else {
        300
    };

    let tracker = ReferTracker::new(max_p, exp);
    let stats = Stats::new(
        "rust_refer_handler",
        &[
            "active_transfers",
            "completed",
            "failed",
            "expired",
            "unknown_notify",
        ],
    );

    WORKER.with(|w| {
        *w.borrow_mut() = Some(WorkerState { tracker, stats });
    });

    opensips_log!(DBG, "rust_refer_handler", "worker {} initialized", rank);
    0
}

unsafe extern "C" fn mod_destroy() {
    opensips_log!(INFO, "rust_refer_handler", "module destroyed");
}

// ── Script function: rust_handle_refer(refer_to) ─────────────────

unsafe extern "C" fn w_rust_handle_refer(
    msg: *mut sys::sip_msg,
    p0: *mut c_void,
    _p1: *mut c_void,
    _p2: *mut c_void,
    _p3: *mut c_void,
    _p4: *mut c_void,
    _p5: *mut c_void,
    _p6: *mut c_void,
    _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let refer_to = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
            Some(s) => s,
            None => {
                opensips_log!(
                    ERR,
                    "rust_refer_handler",
                    "rust_handle_refer: missing or invalid refer_to parameter"
                );
                return -2;
            }
        };

        // Extract Call-ID from the SIP message
        let sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
        let call_id = match sip_msg.header("Call-ID") {
            Some(cid) => cid,
            None => {
                opensips_log!(
                    ERR,
                    "rust_refer_handler",
                    "rust_handle_refer: no Call-ID header"
                );
                return -2;
            }
        };

        WORKER.with(|w| {
            let mut borrow = w.borrow_mut();
            match borrow.as_mut() {
                Some(state) => {
                    let expired = state.tracker.sweep_expired();
                    if expired > 0 {
                        state.stats.set(
                            "expired",
                            state.stats.get("expired") + expired as u64,
                        );
                    }

                    state.tracker.handle_refer(call_id, refer_to);
                    state
                        .stats
                        .set("active_transfers", state.tracker.active_count() as u64);

                    opensips_log!(
                        DBG,
                        "rust_refer_handler",
                        "REFER tracked: call_id={} refer_to={}",
                        call_id,
                        refer_to
                    );
                    1
                }
                None => {
                    opensips_log!(
                        ERR,
                        "rust_refer_handler",
                        "worker state not initialized"
                    );
                    -2
                }
            }
        })
    })
}

// ── Script function: rust_handle_notify(call_id, status_code) ────

unsafe extern "C" fn w_rust_handle_notify(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void,
    p1: *mut c_void,
    _p2: *mut c_void,
    _p3: *mut c_void,
    _p4: *mut c_void,
    _p5: *mut c_void,
    _p6: *mut c_void,
    _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let call_id = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
            Some(s) => s,
            None => {
                opensips_log!(
                    ERR,
                    "rust_refer_handler",
                    "rust_handle_notify: missing or invalid call_id parameter"
                );
                return -2;
            }
        };

        let status_code_str = match unsafe { <&str as CommandFunctionParam>::from_raw(p1) } {
            Some(s) => s,
            None => {
                opensips_log!(
                    ERR,
                    "rust_refer_handler",
                    "rust_handle_notify: missing or invalid status_code parameter"
                );
                return -2;
            }
        };

        let status_code: u16 = match status_code_str.trim().parse() {
            Ok(c) => c,
            Err(_) => {
                opensips_log!(
                    ERR,
                    "rust_refer_handler",
                    "rust_handle_notify: status_code is not a valid integer: {}",
                    status_code_str
                );
                return -2;
            }
        };

        WORKER.with(|w| {
            let mut borrow = w.borrow_mut();
            match borrow.as_mut() {
                Some(state) => {
                    if state.tracker.handle_notify(call_id, status_code) {
                        // Update stats based on new status
                        if let Some(status_str) = state.tracker.get_status(call_id) {
                            match status_str {
                                "success" => {
                                    state.stats.inc("completed");
                                }
                                "failed" => {
                                    state.stats.inc("failed");
                                }
                                _ => {}
                            }
                        }
                        state
                            .stats
                            .set("active_transfers", state.tracker.active_count() as u64);

                        opensips_log!(
                            DBG,
                            "rust_refer_handler",
                            "NOTIFY processed: call_id={} code={}",
                            call_id,
                            status_code
                        );
                        1
                    } else {
                        state.stats.inc("unknown_notify");
                        opensips_log!(
                            DBG,
                            "rust_refer_handler",
                            "NOTIFY for unknown REFER: call_id={}",
                            call_id
                        );
                        -1
                    }
                }
                None => {
                    opensips_log!(
                        ERR,
                        "rust_refer_handler",
                        "worker state not initialized"
                    );
                    -2
                }
            }
        })
    })
}

// ── Script function: rust_refer_status(call_id) ──────────────────

unsafe extern "C" fn w_rust_refer_status(
    msg: *mut sys::sip_msg,
    p0: *mut c_void,
    _p1: *mut c_void,
    _p2: *mut c_void,
    _p3: *mut c_void,
    _p4: *mut c_void,
    _p5: *mut c_void,
    _p6: *mut c_void,
    _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let call_id = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
            Some(s) => s,
            None => {
                opensips_log!(
                    ERR,
                    "rust_refer_handler",
                    "rust_refer_status: missing or invalid call_id parameter"
                );
                return -2;
            }
        };

        WORKER.with(|w| {
            let borrow = w.borrow();
            match borrow.as_ref() {
                Some(state) => match state.tracker.get_status(call_id) {
                    Some(status) => {
                        let mut sip_msg =
                            unsafe { opensips_rs::SipMessage::from_raw(msg) };
                        let _ = sip_msg.set_pv("$var(refer_status)", status);
                        1
                    }
                    None => {
                        let mut sip_msg =
                            unsafe { opensips_rs::SipMessage::from_raw(msg) };
                        let _ = sip_msg.set_pv("$var(refer_status)", "unknown");
                        -1
                    }
                },
                None => {
                    opensips_log!(
                        ERR,
                        "rust_refer_handler",
                        "worker state not initialized"
                    );
                    -2
                }
            }
        })
    })
}


// ── Script function: rust_refer_stats() ──────────────────────────

unsafe extern "C" fn w_rust_refer_stats(
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
        let _ = sip_msg.set_pv("$var(refer_stats)", &json);
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

const TWO_PARAMS_STR_STR: [sys::cmd_param; 9] = {
    let mut arr: [sys::cmd_param; 9] = unsafe { std::mem::zeroed() };
    arr[0].flags = 2; // CMD_PARAM_STR
    arr[1].flags = 2; // CMD_PARAM_STR (parsed to int internally)
    arr
};

#[repr(transparent)]
struct SyncArray<T, const N: usize>([T; N]);
unsafe impl<T, const N: usize> Sync for SyncArray<T, N> {}

static CMDS: SyncArray<sys::cmd_export_, 5> = SyncArray([
    sys::cmd_export_ {
        name: cstr_lit!("rust_handle_refer"),
        function: Some(w_rust_handle_refer),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("rust_handle_notify"),
        function: Some(w_rust_handle_notify),
        params: TWO_PARAMS_STR_STR,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("rust_refer_status"),
        function: Some(w_rust_refer_status),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("rust_refer_stats"),
        function: Some(w_rust_refer_stats),
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
        name: cstr_lit!("max_pending"),
        type_: 2, // INT_PARAM
        param_pointer: MAX_PENDING.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("expire_secs"),
        type_: 2, // INT_PARAM
        param_pointer: EXPIRE_SECS.as_ptr(),
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
    name: cstr_lit!("rust_refer_handler"),
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

    // ── test_handle_refer ────────────────────────────────────────

    #[test]
    fn test_handle_refer() {
        let mut tracker = ReferTracker::new(1000, 300);
        assert!(tracker.handle_refer("call-1", "sip:bob@example.com"));
        assert_eq!(tracker.get_status("call-1"), Some("pending"));
        assert_eq!(tracker.active_count(), 1);
    }

    // ── test_handle_refer_duplicate ──────────────────────────────

    #[test]
    fn test_handle_refer_duplicate() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_refer("call-1", "sip:bob@example.com");
        tracker.handle_refer("call-1", "sip:charlie@example.com");
        assert_eq!(tracker.active_count(), 1);
        // Verify it was overwritten — status should be pending (fresh)
        assert_eq!(tracker.get_status("call-1"), Some("pending"));
        // Verify refer_to was updated
        assert_eq!(
            tracker.states.get("call-1").unwrap().refer_to,
            "sip:charlie@example.com"
        );
    }

    // ── test_handle_notify_trying ────────────────────────────────

    #[test]
    fn test_handle_notify_trying() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_refer("call-1", "sip:bob@example.com");
        assert!(tracker.handle_notify("call-1", 100));
        assert_eq!(tracker.get_status("call-1"), Some("trying"));
    }

    // ── test_handle_notify_success ───────────────────────────────

    #[test]
    fn test_handle_notify_success() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_refer("call-1", "sip:bob@example.com");
        assert!(tracker.handle_notify("call-1", 200));
        assert_eq!(tracker.get_status("call-1"), Some("success"));
    }

    // ── test_handle_notify_failed_4xx ────────────────────────────

    #[test]
    fn test_handle_notify_failed_4xx() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_refer("call-1", "sip:bob@example.com");
        assert!(tracker.handle_notify("call-1", 486));
        assert_eq!(tracker.get_status("call-1"), Some("failed"));
    }

    // ── test_handle_notify_failed_5xx ────────────────────────────

    #[test]
    fn test_handle_notify_failed_5xx() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_refer("call-1", "sip:bob@example.com");
        assert!(tracker.handle_notify("call-1", 503));
        assert_eq!(tracker.get_status("call-1"), Some("failed"));
    }

    // ── test_handle_notify_failed_6xx ────────────────────────────

    #[test]
    fn test_handle_notify_failed_6xx() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_refer("call-1", "sip:bob@example.com");
        assert!(tracker.handle_notify("call-1", 600));
        assert_eq!(tracker.get_status("call-1"), Some("failed"));
    }

    // ── test_handle_notify_unknown ───────────────────────────────

    #[test]
    fn test_handle_notify_unknown() {
        let mut tracker = ReferTracker::new(1000, 300);
        assert!(!tracker.handle_notify("nonexistent", 200));
    }

    // ── test_refer_status_unknown ────────────────────────────────

    #[test]
    fn test_refer_status_unknown() {
        let tracker = ReferTracker::new(1000, 300);
        assert_eq!(tracker.get_status("nonexistent"), None);
    }

    // ── test_refer_status_string ─────────────────────────────────

    #[test]
    fn test_refer_status_string() {
        assert_eq!(ReferStatus::Pending.as_str(), "pending");
        assert_eq!(ReferStatus::Trying.as_str(), "trying");
        assert_eq!(ReferStatus::Success.as_str(), "success");
        assert_eq!(ReferStatus::Failed.as_str(), "failed");
    }

    // ── test_multiple_refers ─────────────────────────────────────

    #[test]
    fn test_multiple_refers() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_refer("call-1", "sip:alice@example.com");
        tracker.handle_refer("call-2", "sip:bob@example.com");
        tracker.handle_refer("call-3", "sip:charlie@example.com");
        assert_eq!(tracker.active_count(), 3);

        // Advance call-1 to trying
        tracker.handle_notify("call-1", 100);
        assert_eq!(tracker.get_status("call-1"), Some("trying"));

        // Advance call-2 to success
        tracker.handle_notify("call-2", 200);
        assert_eq!(tracker.get_status("call-2"), Some("success"));

        // call-3 still pending
        assert_eq!(tracker.get_status("call-3"), Some("pending"));
    }

    // ── test_full_lifecycle ──────────────────────────────────────

    #[test]
    fn test_full_lifecycle() {
        let mut tracker = ReferTracker::new(1000, 300);

        // REFER arrives
        tracker.handle_refer("call-1", "sip:bob@example.com");
        assert_eq!(tracker.get_status("call-1"), Some("pending"));

        // NOTIFY 100 Trying
        tracker.handle_notify("call-1", 100);
        assert_eq!(tracker.get_status("call-1"), Some("trying"));

        // NOTIFY 200 OK — transfer succeeded
        tracker.handle_notify("call-1", 200);
        assert_eq!(tracker.get_status("call-1"), Some("success"));

        // Verify notify_count
        assert_eq!(tracker.states.get("call-1").unwrap().notify_count, 2);
    }

    // ── test_sweep_expired ───────────────────────────────────────

    #[test]
    fn test_sweep_expired() {
        let mut tracker = ReferTracker::new(1000, 0); // expire_secs=0
        tracker.handle_refer("call-1", "sip:bob@example.com");
        tracker.handle_refer("call-2", "sip:alice@example.com");
        thread::sleep(Duration::from_millis(10));
        let swept = tracker.sweep_expired();
        assert_eq!(swept, 2);
        assert_eq!(tracker.active_count(), 0);
    }

    // ── test_max_pending ─────────────────────────────────────────

    #[test]
    fn test_max_pending() {
        // max_pending=2, expire_secs=0 so all entries are immediately sweepable
        let mut tracker = ReferTracker::new(2, 0);

        tracker.handle_refer("call-1", "sip:a@example.com");
        tracker.handle_refer("call-2", "sip:b@example.com");
        thread::sleep(Duration::from_millis(10));

        // Inserting a third triggers maybe_sweep, which removes the expired ones
        tracker.handle_refer("call-3", "sip:c@example.com");

        // Only call-3 should remain (call-1 and call-2 were swept)
        assert_eq!(tracker.active_count(), 1);
        assert_eq!(tracker.get_status("call-3"), Some("pending"));
        assert_eq!(tracker.get_status("call-1"), None);
        assert_eq!(tracker.get_status("call-2"), None);
    }

    // ── test_notify_after_success ────────────────────────────────

    #[test]
    fn test_notify_after_success() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_refer("call-1", "sip:bob@example.com");
        tracker.handle_notify("call-1", 200);
        assert_eq!(tracker.get_status("call-1"), Some("success"));

        // Additional NOTIFY after success is a no-op — status stays success
        assert!(tracker.handle_notify("call-1", 100));
        assert_eq!(tracker.get_status("call-1"), Some("success"));

        assert!(tracker.handle_notify("call-1", 486));
        assert_eq!(tracker.get_status("call-1"), Some("success"));

        // notify_count still increments
        assert_eq!(tracker.states.get("call-1").unwrap().notify_count, 3);
    }

    // ── Additional edge case: notify after failed ────────────────

    #[test]
    fn test_notify_after_failed() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_refer("call-1", "sip:bob@example.com");
        tracker.handle_notify("call-1", 486);
        assert_eq!(tracker.get_status("call-1"), Some("failed"));

        // Additional NOTIFY after failure is also a no-op
        assert!(tracker.handle_notify("call-1", 200));
        assert_eq!(tracker.get_status("call-1"), Some("failed"));
    }

    // ── Additional edge case: 3xx also maps to failed ────────────

    #[test]
    fn test_handle_notify_failed_3xx() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_refer("call-1", "sip:bob@example.com");
        assert!(tracker.handle_notify("call-1", 302));
        assert_eq!(tracker.get_status("call-1"), Some("failed"));
    }

    // ── Sweep preserves non-expired entries ──────────────────────

    #[test]
    fn test_sweep_preserves_fresh() {
        let mut tracker = ReferTracker::new(1000, 3600);
        tracker.handle_refer("call-1", "sip:bob@example.com");
        let swept = tracker.sweep_expired();
        assert_eq!(swept, 0);
        assert_eq!(tracker.active_count(), 1);
    }

    // ── Stats JSON output tests ──────────────────────────────────

    #[test]
    fn test_refer_stats_json() {
        use rust_common::mi::Stats;
        let stats = Stats::new("rust_refer_handler",
            &["active_transfers", "completed", "failed", "expired", "unknown_notify"]);
        stats.set("active_transfers", 5);
        stats.inc("completed");
        stats.inc("completed");
        stats.inc("failed");
        stats.inc("unknown_notify");

        let json = stats.to_json();
        assert!(json.starts_with("{"));
        assert!(json.ends_with("}"));
        assert!(json.contains(r#""active_transfers":5"#));
        assert!(json.contains(r#""completed":2"#));
        assert!(json.contains(r#""failed":1"#));
        assert!(json.contains(r#""unknown_notify":1"#));
    }

}
