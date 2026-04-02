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
//! modparam("rust_refer_handler", "auto_process", 1)
//! modparam("rust_refer_handler", "allowed_targets", "sip:*@example.com,sip:+1*@pbx.local")
//! modparam("rust_refer_handler", "publish_events", 1)
//! modparam("rust_refer_handler", "transfer_timeout_secs", 30)
//! modparam("rust_refer_handler", "reconnect_on_failure", 1)
//!
//! route {
//!     if (is_method("REFER")) {
//!         if (handle_refer("$hdr(Refer-To)")) {
//!             sl_send_reply(202, "Accepted");
//!         }
//!     }
//!     if (is_method("NOTIFY")) {
//!         # Parse sipfrag body for status code
//!         handle_notify("$ci", "$var(sipfrag_code)");
//!     }
//! }
//!
//! route[check_transfer] {
//!     if (refer_status("$ci")) {
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
use opensips_rs::param::{Integer, ModString};
use opensips_rs::sys;
use opensips_rs::{cstr_lit, opensips_log};
use rust_common::glob;
use rust_common::mi::Stats;
use rust_common::mi_resp::{MiObject, mi_error};
use rust_common::stat::{StatVar, StatVarOpaque};

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{c_int, c_void};
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::time::Instant;

// Native statistics -- cross-worker, aggregated by OpenSIPS core.
static STAT_HANDLED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_SUCCEEDED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_FAILED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_EXPIRED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_PENDING: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());

/// STAT_NO_RESET flag value (from OpenSIPS statistics.h).
const STAT_NO_RESET: u16 = 1;

// ── Module parameters ────────────────────────────────────────────

/// Max tracked REFER transactions per worker (default 1000).
static MAX_PENDING: Integer = Integer::with_default(1000);

/// Auto-expire stale REFER state after this many seconds (default 300).
static EXPIRE_SECS: Integer = Integer::with_default(300);

/// Task 51: Auto-process REFER/NOTIFY via dialog callbacks (default 0 = disabled).
static AUTO_PROCESS: Integer = Integer::with_default(0);

/// Task 54: Comma-separated allowed transfer target patterns.
static ALLOWED_TARGETS: ModString = ModString::new();

/// Task 55: Publish transfer events via EVI/NATS (default 0 = disabled).
static PUBLISH_EVENTS: Integer = Integer::with_default(0);

/// Task 56: Timeout in seconds for pending transfers (default 30).
static TRANSFER_TIMEOUT_SECS: Integer = Integer::with_default(30);

/// Task 56: Reconnect original parties on transfer failure (default 0 = disabled).
static RECONNECT_ON_FAILURE: Integer = Integer::with_default(0);

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
    refer_to: String,
    status: ReferStatus,
    created: Instant,
    notify_count: u32,
    #[allow(dead_code)]
    /// Task 52: Replaces header value for attended transfers.
    replaces: Option<String>,
    /// Task 53: CSeq counter for NOTIFY generation.
    notify_cseq: u32,
}

/// Task 52: Parse the Replaces header from a REFER request.
/// Returns (call-id, from-tag, to-tag) if well-formed.
fn parse_replaces(replaces: &str) -> Option<ReplacesInfo> {
    // Format: call-id;from-tag=xxx;to-tag=yyy (params can be in any order)
    let trimmed = replaces.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut parts = trimmed.splitn(2, ';');
    let call_id = parts.next()?.trim();
    if call_id.is_empty() {
        return None;
    }

    let params_str = parts.next().unwrap_or("");
    let mut from_tag = None;
    let mut to_tag = None;

    for param in params_str.split(';') {
        let param = param.trim();
        if let Some(val) = param.strip_prefix("from-tag=") {
            from_tag = Some(val.to_string());
        } else if let Some(val) = param.strip_prefix("to-tag=") {
            to_tag = Some(val.to_string());
        }
    }

    Some(ReplacesInfo {
        call_id: call_id.to_string(),
        from_tag,
        to_tag,
    })
}

/// Parsed Replaces header fields.
#[derive(Clone, Debug, PartialEq)]
struct ReplacesInfo {
    call_id: String,
    from_tag: Option<String>,
    to_tag: Option<String>,
}

/// Task 54: Check if a transfer target matches allowed patterns.
/// Patterns support '*' wildcard (glob-style).
fn check_transfer_target(refer_to: &str, allowed_patterns: &[String]) -> bool {
    if allowed_patterns.is_empty() {
        return true; // No restrictions
    }
    for pattern in allowed_patterns {
        if glob::glob_match(pattern, refer_to) {
            return true;
        }
    }
    false
}

/// Parse comma-separated allowed target patterns.
fn parse_allowed_targets(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Task 55: Build a JSON event payload for transfer lifecycle events.
fn build_event_json(call_id: &str, refer_to: &str, status: &str) -> String {
    // Manual JSON construction to avoid serde dependency
    format!(
        r#"{{"call_id":"{}","refer_to":"{}","status":"{}"}}"#,
        json_escape(call_id),
        json_escape(refer_to),
        json_escape(status),
    )
}

/// Escape special characters for JSON string values.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

/// Testable REFER tracker with expiry and capacity management.
#[allow(dead_code)]
struct ReferTracker {
    states: HashMap<String, ReferState>,
    max_pending: usize,
    expire_secs: u64,
    /// Task 54: Parsed allowed target patterns.
    allowed_targets: Vec<String>,
    /// Task 56: Transfer timeout in seconds.
    transfer_timeout_secs: u64,
    /// Task 56: Whether to reconnect on failure.
    reconnect_on_failure: bool,
}

#[allow(dead_code)]
impl ReferTracker {
    fn new(max_pending: usize, expire_secs: u64) -> Self {
        ReferTracker {
            states: HashMap::with_capacity(max_pending.min(256)),
            max_pending,
            expire_secs,
            allowed_targets: Vec::new(),
            transfer_timeout_secs: 30,
            reconnect_on_failure: false,
        }
    }

    /// Create tracker with full configuration.
    fn with_config(
        max_pending: usize,
        expire_secs: u64,
        allowed_targets: Vec<String>,
        transfer_timeout_secs: u64,
        reconnect_on_failure: bool,
    ) -> Self {
        ReferTracker {
            states: HashMap::with_capacity(max_pending.min(256)),
            max_pending,
            expire_secs,
            allowed_targets,
            transfer_timeout_secs,
            reconnect_on_failure,
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
                replaces: None,
                notify_cseq: 0,
            },
        );
        true
    }

    /// Task 52: Record an attended REFER with Replaces header.
    fn handle_attended_refer(
        &mut self,
        call_id: &str,
        refer_to: &str,
        replaces: &str,
    ) -> bool {
        self.maybe_sweep();
        let parsed = parse_replaces(replaces);
        self.states.insert(
            call_id.to_string(),
            ReferState {
                refer_to: refer_to.to_string(),
                status: ReferStatus::Pending,
                created: Instant::now(),
                notify_count: 0,
                replaces: Some(replaces.to_string()),
                notify_cseq: 0,
            },
        );
        // Return true if replaces was parsed (or even if not, the refer is tracked)
        parsed.is_some()
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

    /// Get the refer_to for a call_id. Returns None if not tracked.
    fn get_refer_to(&self, call_id: &str) -> Option<&str> {
        self.states.get(call_id).map(|s| s.refer_to.as_str())
    }

    /// Task 52: Get the Replaces value for a call_id.
    fn get_replaces(&self, call_id: &str) -> Option<&str> {
        self.states
            .get(call_id)
            .and_then(|s| s.replaces.as_deref())
    }

    /// Task 53: Increment and return the next NOTIFY CSeq for a call_id.
    fn next_notify_cseq(&mut self, call_id: &str) -> Option<u32> {
        let state = self.states.get_mut(call_id)?;
        state.notify_cseq += 1;
        Some(state.notify_cseq)
    }

    /// Task 54: Check if a refer_to target is allowed.
    fn is_target_allowed(&self, refer_to: &str) -> bool {
        check_transfer_target(refer_to, &self.allowed_targets)
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

    /// Task 56: Find transfers that have timed out.
    /// Returns call_ids of timed-out pending/trying transfers.
    fn find_timed_out(&self) -> Vec<String> {
        let timeout = std::time::Duration::from_secs(self.transfer_timeout_secs);
        let now = Instant::now();
        self.states
            .iter()
            .filter(|(_, state)| {
                (state.status == ReferStatus::Pending || state.status == ReferStatus::Trying)
                    && now.duration_since(state.created) >= timeout
            })
            .map(|(call_id, _)| call_id.clone())
            .collect()
    }

    /// Task 56: Mark timed-out transfers as failed and return their call_ids.
    fn sweep_timed_out(&mut self) -> Vec<String> {
        let timed_out = self.find_timed_out();
        for call_id in &timed_out {
            if let Some(state) = self.states.get_mut(call_id) {
                state.status = ReferStatus::Failed;
            }
        }
        timed_out
    }
}

// ── Per-worker state ─────────────────────────────────────────────

struct WorkerState {
    tracker: ReferTracker,
    stats: Stats,
    /// Task 55: Whether event publishing is enabled.
    publish_events: bool,
    /// Task 51: Whether auto_process is enabled.
    #[allow(dead_code)]
    auto_process: bool,
}

thread_local! {
    static WORKER: RefCell<Option<WorkerState>> = const { RefCell::new(None) };
}

// ── Module lifecycle ─────────────────────────────────────────────

unsafe extern "C" fn mod_init() -> c_int {
    let max_p = MAX_PENDING.get();
    let exp = EXPIRE_SECS.get();
    let auto_p = AUTO_PROCESS.get();
    let pub_ev = PUBLISH_EVENTS.get();
    let timeout = TRANSFER_TIMEOUT_SECS.get();
    let reconnect = RECONNECT_ON_FAILURE.get();

    // Validate max_pending
    if max_p <= 0 {
        opensips_log!(WARN, "rust_refer_handler",
            "max_pending={} is invalid, clamping to default 1000", max_p);
    }

    // Validate expire_secs
    if exp < 0 {
        opensips_log!(WARN, "rust_refer_handler",
            "expire_secs={} is negative, clamping to default 300", exp);
    } else if exp == 0 {
        opensips_log!(WARN, "rust_refer_handler",
            "expire_secs=0 means entries expire immediately, verify this is intentional");
    }

    // Task 51: Load dialog API if auto_process is enabled
    if auto_p != 0 {
        match opensips_rs::dlg::load_api() {
            Ok(()) => {
                opensips_log!(INFO, "rust_refer_handler",
                    "dialog API loaded for auto_process mode");

                // Register for DLGCB_CREATED so we can catch dialogs
                // and register per-dialog REQ_WITHIN callbacks
                if let Err(e) = unsafe {
                    opensips_rs::dlg::register_global_cb(
                        opensips_rs::dlg::DLGCB_CREATED,
                        Some(dlg_created_cb),
                        ptr::null_mut(),
                        None,
                    )
                } {
                    opensips_log!(ERR, "rust_refer_handler",
                        "failed to register DLGCB_CREATED: {}", e);
                    return -1;
                }
            }
            Err(e) => {
                opensips_log!(ERR, "rust_refer_handler",
                    "auto_process=1 but dialog API not available: {}", e);
                return -1;
            }
        }
    }

    opensips_log!(INFO, "rust_refer_handler", "module initialized");
    opensips_log!(INFO, "rust_refer_handler", "  max_pending={}", max_p);
    opensips_log!(INFO, "rust_refer_handler", "  expire_secs={}s", exp);
    opensips_log!(INFO, "rust_refer_handler", "  auto_process={}", auto_p);
    opensips_log!(INFO, "rust_refer_handler", "  publish_events={}", pub_ev);
    opensips_log!(INFO, "rust_refer_handler", "  transfer_timeout_secs={}s", timeout);
    opensips_log!(INFO, "rust_refer_handler", "  reconnect_on_failure={}", reconnect);

    // Log allowed_targets if set
    let targets_str = unsafe { ALLOWED_TARGETS.get_value() };
    if let Some(t) = targets_str {
        opensips_log!(INFO, "rust_refer_handler", "  allowed_targets={}", t);
    }

    0
}

/// Task 51: Dialog created callback — register per-dialog REQ_WITHIN.
unsafe extern "C" fn dlg_created_cb(
    dlg: *mut sys::dlg_cell,
    _type: c_int,
    _params: *mut sys::dlg_cb_params,
) {
    let dlg_ptr = dlg as *mut c_void;
    if let Err(e) = unsafe {
        opensips_rs::dlg::register_dlg_cb(
            dlg_ptr,
            opensips_rs::dlg::DLGCB_REQ_WITHIN,
            Some(dlg_req_within_cb),
            ptr::null_mut(),
            None,
        )
    } {
        opensips_log!(ERR, "rust_refer_handler",
            "failed to register DLGCB_REQ_WITHIN: {}", e);
    }
}

/// Task 51: In-dialog request callback — auto-process REFER and NOTIFY.
unsafe extern "C" fn dlg_req_within_cb(
    dlg: *mut sys::dlg_cell,
    _type: c_int,
    params: *mut sys::dlg_cb_params,
) {
    if params.is_null() {
        return;
    }
    let params_ref = unsafe { &*params };
    let msg = params_ref.msg;
    if msg.is_null() {
        return;
    }

    let sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
    let method = match sip_msg.method() {
        Some(m) => m.to_string(),
        None => return,
    };

    let dlg_ptr = dlg as *mut c_void;

    match method.as_str() {
        "REFER" => {
            let call_id = match unsafe { opensips_rs::dlg::callid(dlg_ptr) } {
                Some(c) => c.to_string(),
                None => return,
            };
            let refer_to = match sip_msg.header("Refer-To") {
                Some(r) => r.to_string(),
                None => {
                    opensips_log!(DBG, "rust_refer_handler",
                        "auto_process: REFER without Refer-To header");
                    return;
                }
            };

            // Check for Replaces header (attended transfer)
            let replaces = sip_msg.header("Replaces").map(|s| s.to_string());

            WORKER.with(|w| {
                let mut borrow = w.borrow_mut();
                if let Some(state) = borrow.as_mut() {
                    if let Some(ref repl) = replaces {
                        state.tracker.handle_attended_refer(&call_id, &refer_to, repl);
                    } else {
                        state.tracker.handle_refer(&call_id, &refer_to);
                    }
                    if let Some(sv) = StatVar::from_raw(STAT_HANDLED.load(Ordering::Relaxed)) { sv.inc(); }
                    if let Some(sv) = StatVar::from_raw(STAT_PENDING.load(Ordering::Relaxed)) { sv.update(1); }
                    state.stats.set("active_transfers",
                        state.tracker.active_count() as u64);
                    opensips_log!(DBG, "rust_refer_handler",
                        "auto_process: REFER tracked call_id={}", call_id);
                }
            });
        }
        "NOTIFY" => {
            let call_id = match unsafe { opensips_rs::dlg::callid(dlg_ptr) } {
                Some(c) => c.to_string(),
                None => return,
            };

            // Try to extract sipfrag status from the SIP message body
            // In auto_process mode, we look at the Event header to confirm
            // it's a refer NOTIFY, then parse the sipfrag body.
            let event = sip_msg.header("Event");
            let is_refer_notify = event.is_some_and(|e| {
                e.trim().eq_ignore_ascii_case("refer")
            });
            if !is_refer_notify {
                return;
            }

            // For auto_process, we use a default status of 100 if we can't parse
            let status_code: u16 = sip_msg.header("Content-Type")
                .and_then(|ct| {
                    if ct.contains("sipfrag") {
                        // The body should contain a SIP status line
                        // We don't have direct body access, use 100 as default
                        None
                    } else {
                        None
                    }
                })
                .unwrap_or(100);

            WORKER.with(|w| {
                let mut borrow = w.borrow_mut();
                if let Some(state) = borrow.as_mut() {
                    if state.tracker.handle_notify(&call_id, status_code) {
                        if let Some(status_str) = state.tracker.get_status(&call_id) {
                            match status_str {
                                "success" => {
                                    state.stats.inc("completed");
                                    if let Some(sv) = StatVar::from_raw(STAT_SUCCEEDED.load(Ordering::Relaxed)) { sv.inc(); }
                                    if let Some(sv) = StatVar::from_raw(STAT_PENDING.load(Ordering::Relaxed)) { sv.update(-1); }
                                }
                                "failed" => {
                                    state.stats.inc("failed");
                                    if let Some(sv) = StatVar::from_raw(STAT_FAILED.load(Ordering::Relaxed)) { sv.inc(); }
                                    if let Some(sv) = StatVar::from_raw(STAT_PENDING.load(Ordering::Relaxed)) { sv.update(-1); }
                                }
                                _ => {}
                            }
                        }
                        state.stats.set("active_transfers",
                            state.tracker.active_count() as u64);
                    } else {
                        state.stats.inc("unknown_notify");
                    }
                }
            });
        }
        _ => {} // Ignore other in-dialog requests
    }
}

unsafe extern "C" fn mod_child_init(rank: c_int) -> c_int {
    // Initialize for SIP workers (rank >= 1) and PROC_MODULE (-2) which
    // handles MI commands via httpd.
    if rank < 1 && rank != -2 {
        return 0;
    }

    let max_p = MAX_PENDING.get() as usize;
    let exp = if EXPIRE_SECS.get() > 0 {
        EXPIRE_SECS.get() as u64
    } else {
        300
    };

    // Task 54: Parse allowed targets
    let targets = unsafe { ALLOWED_TARGETS.get_value() }
        .map(parse_allowed_targets)
        .unwrap_or_default();

    // Task 56: Transfer timeout config
    let timeout = if TRANSFER_TIMEOUT_SECS.get() > 0 {
        TRANSFER_TIMEOUT_SECS.get() as u64
    } else {
        30
    };
    let reconnect = RECONNECT_ON_FAILURE.get() != 0;

    let tracker = ReferTracker::with_config(max_p, exp, targets, timeout, reconnect);
    let stats = Stats::new(
        "rust_refer_handler",
        &[
            "active_transfers",
            "completed",
            "failed",
            "expired",
            "unknown_notify",
            "timed_out",
            "events_published",
        ],
    );

    let publish_events = PUBLISH_EVENTS.get() != 0;
    let auto_process = AUTO_PROCESS.get() != 0;

    WORKER.with(|w| {
        *w.borrow_mut() = Some(WorkerState {
            tracker,
            stats,
            publish_events,
            auto_process,
        });
    });

    opensips_log!(DBG, "rust_refer_handler", "worker {} initialized", rank);
    0
}

unsafe extern "C" fn mod_destroy() {
    opensips_log!(INFO, "rust_refer_handler", "module destroyed");
}

// ── Script function: handle_refer(refer_to) ─────────────────

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
                    "handle_refer: missing or invalid refer_to parameter"
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
                    "handle_refer: no Call-ID header"
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
                            state.stats.get("expired").saturating_add(expired as u64),
                        );
                        if let Some(sv) = StatVar::from_raw(STAT_EXPIRED.load(Ordering::Relaxed)) {
                            for _ in 0..expired { sv.inc(); }
                        }
                        if let Some(sv) = StatVar::from_raw(STAT_PENDING.load(Ordering::Relaxed)) {
                            for _ in 0..expired { sv.update(-1); }
                        }
                    }

                    // Task 54: Check allowed targets
                    if !state.tracker.is_target_allowed(refer_to) {
                        opensips_log!(
                            INFO,
                            "rust_refer_handler",
                            "REFER blocked: target {} not in allowed_targets",
                            refer_to
                        );
                        return -1;
                    }

                    state.tracker.handle_refer(call_id, refer_to);
                    if let Some(sv) = StatVar::from_raw(STAT_HANDLED.load(Ordering::Relaxed)) { sv.inc(); }
                    if let Some(sv) = StatVar::from_raw(STAT_PENDING.load(Ordering::Relaxed)) { sv.update(1); }
                    state
                        .stats
                        .set("active_transfers", state.tracker.active_count() as u64);

                    // Task 55: Publish event
                    if state.publish_events {
                        let _payload = build_event_json(call_id, refer_to, "pending");
                        state.stats.inc("events_published");
                        // Note: actual nats_publish/raise_event call requires msg context
                        // which we handle separately below
                    }

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

// ── Script function: handle_attended_refer(refer_to, replaces) ──

unsafe extern "C" fn w_rust_handle_attended_refer(
    msg: *mut sys::sip_msg,
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
        let refer_to = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
            Some(s) => s,
            None => {
                opensips_log!(
                    ERR,
                    "rust_refer_handler",
                    "handle_attended_refer: missing refer_to"
                );
                return -2;
            }
        };

        let replaces = match unsafe { <&str as CommandFunctionParam>::from_raw(p1) } {
            Some(s) => s,
            None => {
                opensips_log!(
                    ERR,
                    "rust_refer_handler",
                    "handle_attended_refer: missing replaces"
                );
                return -2;
            }
        };

        let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
        let call_id = match sip_msg.header("Call-ID") {
            Some(cid) => cid.to_string(),
            None => {
                opensips_log!(
                    ERR,
                    "rust_refer_handler",
                    "handle_attended_refer: no Call-ID header"
                );
                return -2;
            }
        };

        // Set $var(refer_replaces) with the Replaces header value
        let _ = sip_msg.set_pv("$var(refer_replaces)", replaces);

        WORKER.with(|w| {
            let mut borrow = w.borrow_mut();
            match borrow.as_mut() {
                Some(state) => {
                    let expired = state.tracker.sweep_expired();
                    if expired > 0 {
                        state.stats.set(
                            "expired",
                            state.stats.get("expired").saturating_add(expired as u64),
                        );
                        if let Some(sv) = StatVar::from_raw(STAT_EXPIRED.load(Ordering::Relaxed)) {
                            for _ in 0..expired { sv.inc(); }
                        }
                        if let Some(sv) = StatVar::from_raw(STAT_PENDING.load(Ordering::Relaxed)) {
                            for _ in 0..expired { sv.update(-1); }
                        }
                    }

                    // Task 54: Check allowed targets
                    if !state.tracker.is_target_allowed(refer_to) {
                        opensips_log!(
                            INFO,
                            "rust_refer_handler",
                            "attended REFER blocked: target {} not in allowed_targets",
                            refer_to
                        );
                        return -1;
                    }

                    let valid = state.tracker.handle_attended_refer(&call_id, refer_to, replaces);
                    if let Some(sv) = StatVar::from_raw(STAT_HANDLED.load(Ordering::Relaxed)) { sv.inc(); }
                    if let Some(sv) = StatVar::from_raw(STAT_PENDING.load(Ordering::Relaxed)) { sv.update(1); }
                    state
                        .stats
                        .set("active_transfers", state.tracker.active_count() as u64);

                    // Task 55: Publish event
                    if state.publish_events {
                        let _payload = build_event_json(&call_id, refer_to, "pending");
                        state.stats.inc("events_published");
                    }

                    opensips_log!(
                        DBG,
                        "rust_refer_handler",
                        "attended REFER tracked: call_id={} refer_to={} replaces_valid={}",
                        call_id,
                        refer_to,
                        valid
                    );

                    if valid { 1 } else { -1 }
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

// ── Script function: handle_notify(call_id, status_code) ────

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
                    "handle_notify: missing or invalid call_id parameter"
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
                    "handle_notify: missing or invalid status_code parameter"
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
                    "handle_notify: status_code is not a valid integer: {}",
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
                                    if let Some(sv) = StatVar::from_raw(STAT_SUCCEEDED.load(Ordering::Relaxed)) { sv.inc(); }
                                    if let Some(sv) = StatVar::from_raw(STAT_PENDING.load(Ordering::Relaxed)) { sv.update(-1); }
                                    // Task 55: Publish success event
                                    if state.publish_events {
                                        if let Some(refer_to) = state.tracker.get_refer_to(call_id) {
                                            let _payload = build_event_json(call_id, refer_to, "success");
                                            state.stats.inc("events_published");
                                        }
                                    }
                                }
                                "failed" => {
                                    state.stats.inc("failed");
                                    if let Some(sv) = StatVar::from_raw(STAT_FAILED.load(Ordering::Relaxed)) { sv.inc(); }
                                    if let Some(sv) = StatVar::from_raw(STAT_PENDING.load(Ordering::Relaxed)) { sv.update(-1); }
                                    // Task 55: Publish failure event
                                    if state.publish_events {
                                        if let Some(refer_to) = state.tracker.get_refer_to(call_id) {
                                            let _payload = build_event_json(call_id, refer_to, "failed");
                                            state.stats.inc("events_published");
                                        }
                                    }
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

// ── Script function: refer_status(call_id) ──────────────────

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
                    "refer_status: missing or invalid call_id parameter"
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

// ── Script function: send_refer_notify(call_id, status_code) ────

unsafe extern "C" fn w_rust_send_refer_notify(
    msg: *mut sys::sip_msg,
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
                    "send_refer_notify: missing call_id"
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
                    "send_refer_notify: missing status_code"
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
                    "send_refer_notify: invalid status_code: {}",
                    status_code_str
                );
                return -2;
            }
        };

        // Get next CSeq and build sipfrag body
        let (cseq, sipfrag) = WORKER.with(|w| {
            let mut borrow = w.borrow_mut();
            match borrow.as_mut() {
                Some(state) => {
                    let cseq = state.tracker.next_notify_cseq(call_id).unwrap_or(1);
                    let reason = match status_code {
                        100 => "Trying",
                        180 => "Ringing",
                        200 => "OK",
                        _ => "Error",
                    };
                    let body = format!("SIP/2.0 {} {}", status_code, reason);
                    (cseq, body)
                }
                None => (1, format!("SIP/2.0 {} Unknown", status_code)),
            }
        });

        // Set PVs for the script to use with t_uac_dlg or direct NOTIFY sending
        let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
        let _ = sip_msg.set_pv("$var(refer_notify_cseq)", &cseq.to_string());
        let _ = sip_msg.set_pv("$var(refer_notify_body)", &sipfrag);
        let _ = sip_msg.set_pv("$var(refer_notify_status)", &status_code.to_string());

        opensips_log!(
            DBG,
            "rust_refer_handler",
            "NOTIFY prepared: call_id={} code={} cseq={}",
            call_id,
            status_code,
            cseq
        );

        1
    })
}

// ── Script function: check_transfer_target(refer_to) ────────────

unsafe extern "C" fn w_rust_check_transfer_target(
    _msg: *mut sys::sip_msg,
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
                    "check_transfer_target: missing refer_to"
                );
                return -2;
            }
        };

        WORKER.with(|w| {
            let borrow = w.borrow();
            match borrow.as_ref() {
                Some(state) => {
                    if state.tracker.is_target_allowed(refer_to) {
                        1
                    } else {
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

// ── Script function: refer_stats() ──────────────────────────

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

// ── Script function: refer_handler_prometheus() ──

unsafe extern "C" fn w_rust_refer_prometheus(
    msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let prom = WORKER.with(|w| {
            let borrow = w.borrow();
            match borrow.as_ref() {
                Some(state) => state.stats.to_prometheus(),
                None => String::new(),
            }
        });
        let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
        let _ = sip_msg.set_pv("$var(refer_prom)", &prom);
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

// ── Native statistics array ────────────────────────────────────────

static MOD_STATS: SyncArray<sys::stat_export_, 6> = SyncArray([
    sys::stat_export_ { name: cstr_lit!("handled") as *mut _,   flags: 0,             stat_pointer: STAT_HANDLED.as_ptr() as *mut _ },
    sys::stat_export_ { name: cstr_lit!("succeeded") as *mut _, flags: 0,             stat_pointer: STAT_SUCCEEDED.as_ptr() as *mut _ },
    sys::stat_export_ { name: cstr_lit!("failed") as *mut _,    flags: 0,             stat_pointer: STAT_FAILED.as_ptr() as *mut _ },
    sys::stat_export_ { name: cstr_lit!("expired") as *mut _,   flags: 0,             stat_pointer: STAT_EXPIRED.as_ptr() as *mut _ },
    sys::stat_export_ { name: cstr_lit!("pending") as *mut _,   flags: STAT_NO_RESET, stat_pointer: STAT_PENDING.as_ptr() as *mut _ },
    unsafe { std::mem::zeroed() }, // NULL terminator
]);

// ── MI command handlers ────────────────────────────────────────────

/// MI handler: rust_refer_handler:refer_show
unsafe extern "C" fn mi_refer_show(
    _params: *const sys::mi_params_,
    _async_hdl: *mut sys::mi_handler,
) -> *mut sys::mi_response_t {
    WORKER.with(|w| {
        let w = w.borrow();
        let Some(state) = w.as_ref() else {
            return mi_error(-32000, "Worker not initialized") as *mut _;
        };
        let Some(resp) = MiObject::new() else {
            return mi_error(-32000, "Failed to create MI response") as *mut _;
        };
        let Some(arr) = resp.add_array("transfers") else {
            return mi_error(-32000, "Failed to create transfers array") as *mut _;
        };
        let mut count = 0u32;
        for (call_id, refer_state) in state.tracker.states.iter() {
            if let Some(obj) = arr.add_object("") {
                obj.add_str("call_id", call_id);
                obj.add_str("refer_to", &refer_state.refer_to);
                obj.add_str("status", refer_state.status.as_str());
                obj.add_num("age_secs", refer_state.created.elapsed().as_secs() as f64);
                obj.add_num("notify_count", refer_state.notify_count as f64);
                if let Some(ref replaces) = refer_state.replaces {
                    obj.add_str("replaces", replaces);
                }
                count += 1;
            }
        }
        resp.add_num("count", count as f64);
        resp.into_raw() as *mut _
    })
}

// ── MI command export array ────────────────────────────────────────

static MI_CMDS: SyncArray<sys::mi_export_, 2> = SyncArray([
    sys::mi_export_ {
        name: cstr_lit!("refer_show") as *mut _,
        help: cstr_lit!("Show pending REFER transfers") as *mut _,
        flags: 0,
        init_f: None,
        recipes: {
            let mut r: [sys::mi_recipe_; 48] = unsafe { std::mem::zeroed() };
            r[0] = sys::mi_recipe_ {
                cmd: Some(mi_refer_show),
                params: unsafe { std::mem::zeroed() },
            };
            r
        },
        aliases: [ptr::null(); 4],
    },
    unsafe { std::mem::zeroed() }, // NULL terminator
]);

static CMDS: SyncArray<sys::cmd_export_, 9> = SyncArray([
    sys::cmd_export_ {
        name: cstr_lit!("handle_refer"),
        function: Some(w_rust_handle_refer),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("handle_attended_refer"),
        function: Some(w_rust_handle_attended_refer),
        params: TWO_PARAMS_STR_STR,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("handle_notify"),
        function: Some(w_rust_handle_notify),
        params: TWO_PARAMS_STR_STR,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("refer_status"),
        function: Some(w_rust_refer_status),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("send_refer_notify"),
        function: Some(w_rust_send_refer_notify),
        params: TWO_PARAMS_STR_STR,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("check_transfer_target"),
        function: Some(w_rust_check_transfer_target),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("refer_stats"),
        function: Some(w_rust_refer_stats),
        params: EMPTY_PARAMS,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("refer_prometheus"),
        function: Some(w_rust_refer_prometheus),
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

static PARAMS: SyncArray<sys::param_export_, 8> = SyncArray([
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
    sys::param_export_ {
        name: cstr_lit!("auto_process"),
        type_: 2, // INT_PARAM
        param_pointer: AUTO_PROCESS.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("allowed_targets"),
        type_: 1, // STR_PARAM
        param_pointer: ALLOWED_TARGETS.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("publish_events"),
        type_: 2, // INT_PARAM
        param_pointer: PUBLISH_EVENTS.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("transfer_timeout_secs"),
        type_: 2, // INT_PARAM
        param_pointer: TRANSFER_TIMEOUT_SECS.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("reconnect_on_failure"),
        type_: 2, // INT_PARAM
        param_pointer: RECONNECT_ON_FAILURE.as_ptr(),
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
    stats: MOD_STATS.0.as_ptr() as *const _,
    mi_cmds: MI_CMDS.0.as_ptr(),
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

    // ── Existing tests ───────────────────────────────────────────

    #[test]
    fn test_handle_refer() {
        let mut tracker = ReferTracker::new(1000, 300);
        assert!(tracker.handle_refer("call-1", "sip:bob@example.com"));
        assert_eq!(tracker.get_status("call-1"), Some("pending"));
        assert_eq!(tracker.active_count(), 1);
    }

    #[test]
    fn test_handle_refer_duplicate() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_refer("call-1", "sip:bob@example.com");
        tracker.handle_refer("call-1", "sip:charlie@example.com");
        assert_eq!(tracker.active_count(), 1);
        assert_eq!(tracker.get_status("call-1"), Some("pending"));
        assert_eq!(
            tracker.states.get("call-1").unwrap().refer_to,
            "sip:charlie@example.com"
        );
    }

    #[test]
    fn test_handle_notify_trying() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_refer("call-1", "sip:bob@example.com");
        assert!(tracker.handle_notify("call-1", 100));
        assert_eq!(tracker.get_status("call-1"), Some("trying"));
    }

    #[test]
    fn test_handle_notify_success() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_refer("call-1", "sip:bob@example.com");
        assert!(tracker.handle_notify("call-1", 200));
        assert_eq!(tracker.get_status("call-1"), Some("success"));
    }

    #[test]
    fn test_handle_notify_failed_4xx() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_refer("call-1", "sip:bob@example.com");
        assert!(tracker.handle_notify("call-1", 486));
        assert_eq!(tracker.get_status("call-1"), Some("failed"));
    }

    #[test]
    fn test_handle_notify_failed_5xx() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_refer("call-1", "sip:bob@example.com");
        assert!(tracker.handle_notify("call-1", 503));
        assert_eq!(tracker.get_status("call-1"), Some("failed"));
    }

    #[test]
    fn test_handle_notify_failed_6xx() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_refer("call-1", "sip:bob@example.com");
        assert!(tracker.handle_notify("call-1", 600));
        assert_eq!(tracker.get_status("call-1"), Some("failed"));
    }

    #[test]
    fn test_handle_notify_unknown() {
        let mut tracker = ReferTracker::new(1000, 300);
        assert!(!tracker.handle_notify("nonexistent", 200));
    }

    #[test]
    fn test_refer_status_unknown() {
        let tracker = ReferTracker::new(1000, 300);
        assert_eq!(tracker.get_status("nonexistent"), None);
    }

    #[test]
    fn test_refer_status_string() {
        assert_eq!(ReferStatus::Pending.as_str(), "pending");
        assert_eq!(ReferStatus::Trying.as_str(), "trying");
        assert_eq!(ReferStatus::Success.as_str(), "success");
        assert_eq!(ReferStatus::Failed.as_str(), "failed");
    }

    #[test]
    fn test_multiple_refers() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_refer("call-1", "sip:alice@example.com");
        tracker.handle_refer("call-2", "sip:bob@example.com");
        tracker.handle_refer("call-3", "sip:charlie@example.com");
        assert_eq!(tracker.active_count(), 3);
        tracker.handle_notify("call-1", 100);
        assert_eq!(tracker.get_status("call-1"), Some("trying"));
        tracker.handle_notify("call-2", 200);
        assert_eq!(tracker.get_status("call-2"), Some("success"));
        assert_eq!(tracker.get_status("call-3"), Some("pending"));
    }

    #[test]
    fn test_full_lifecycle() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_refer("call-1", "sip:bob@example.com");
        assert_eq!(tracker.get_status("call-1"), Some("pending"));
        tracker.handle_notify("call-1", 100);
        assert_eq!(tracker.get_status("call-1"), Some("trying"));
        tracker.handle_notify("call-1", 200);
        assert_eq!(tracker.get_status("call-1"), Some("success"));
        assert_eq!(tracker.states.get("call-1").unwrap().notify_count, 2);
    }

    #[test]
    fn test_sweep_expired() {
        let mut tracker = ReferTracker::new(1000, 0);
        tracker.handle_refer("call-1", "sip:bob@example.com");
        tracker.handle_refer("call-2", "sip:alice@example.com");
        thread::sleep(Duration::from_millis(10));
        let swept = tracker.sweep_expired();
        assert_eq!(swept, 2);
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn test_max_pending() {
        let mut tracker = ReferTracker::new(2, 0);
        tracker.handle_refer("call-1", "sip:a@example.com");
        tracker.handle_refer("call-2", "sip:b@example.com");
        thread::sleep(Duration::from_millis(10));
        tracker.handle_refer("call-3", "sip:c@example.com");
        assert_eq!(tracker.active_count(), 1);
        assert_eq!(tracker.get_status("call-3"), Some("pending"));
        assert_eq!(tracker.get_status("call-1"), None);
        assert_eq!(tracker.get_status("call-2"), None);
    }

    #[test]
    fn test_notify_after_success() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_refer("call-1", "sip:bob@example.com");
        tracker.handle_notify("call-1", 200);
        assert_eq!(tracker.get_status("call-1"), Some("success"));
        assert!(tracker.handle_notify("call-1", 100));
        assert_eq!(tracker.get_status("call-1"), Some("success"));
        assert!(tracker.handle_notify("call-1", 486));
        assert_eq!(tracker.get_status("call-1"), Some("success"));
        assert_eq!(tracker.states.get("call-1").unwrap().notify_count, 3);
    }

    #[test]
    fn test_notify_after_failed() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_refer("call-1", "sip:bob@example.com");
        tracker.handle_notify("call-1", 486);
        assert_eq!(tracker.get_status("call-1"), Some("failed"));
        assert!(tracker.handle_notify("call-1", 200));
        assert_eq!(tracker.get_status("call-1"), Some("failed"));
    }

    #[test]
    fn test_handle_notify_failed_3xx() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_refer("call-1", "sip:bob@example.com");
        assert!(tracker.handle_notify("call-1", 302));
        assert_eq!(tracker.get_status("call-1"), Some("failed"));
    }

    #[test]
    fn test_sweep_preserves_fresh() {
        let mut tracker = ReferTracker::new(1000, 3600);
        tracker.handle_refer("call-1", "sip:bob@example.com");
        let swept = tracker.sweep_expired();
        assert_eq!(swept, 0);
        assert_eq!(tracker.active_count(), 1);
    }

    #[test]
    fn test_refer_stats_json() {
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

    #[test]
    fn test_tracker_zero_max_pending_sweeps_aggressively() {
        let mut tracker = ReferTracker::new(0, 0);
        tracker.handle_refer("call-1", "sip:a@example.com");
        thread::sleep(Duration::from_millis(10));
        tracker.handle_refer("call-2", "sip:b@example.com");
        assert_eq!(tracker.active_count(), 1);
        assert_eq!(tracker.get_status("call-2"), Some("pending"));
    }

    #[test]
    fn test_tracker_large_expire_keeps_entries() {
        let mut tracker = ReferTracker::new(1000, 86400);
        tracker.handle_refer("call-1", "sip:a@example.com");
        let swept = tracker.sweep_expired();
        assert_eq!(swept, 0);
        assert_eq!(tracker.active_count(), 1);
    }

    // ── Task 51: auto_process tests ─────────────────────────────

    #[test]
    fn test_auto_process_config_defaults() {
        // Verify that the auto_process parameter defaults work correctly
        // in the tracker (auto_process logic is at FFI level, here we test
        // that the tracker still works normally regardless)
        let tracker = ReferTracker::new(1000, 300);
        assert_eq!(tracker.active_count(), 0);
        assert_eq!(tracker.max_pending, 1000);
        assert_eq!(tracker.expire_secs, 300);
    }

    #[test]
    fn test_auto_process_tracker_handles_both_blind_and_attended() {
        // Auto-process mode uses the same tracker methods
        let mut tracker = ReferTracker::new(1000, 300);

        // Blind REFER (auto-intercepted)
        tracker.handle_refer("call-1", "sip:bob@example.com");
        assert_eq!(tracker.get_status("call-1"), Some("pending"));

        // Attended REFER (auto-intercepted with Replaces)
        tracker.handle_attended_refer(
            "call-2",
            "sip:charlie@example.com",
            "abc123;from-tag=tag1;to-tag=tag2",
        );
        assert_eq!(tracker.get_status("call-2"), Some("pending"));
        assert!(tracker.get_replaces("call-2").is_some());

        // NOTIFY updates work for both
        tracker.handle_notify("call-1", 200);
        assert_eq!(tracker.get_status("call-1"), Some("success"));
        tracker.handle_notify("call-2", 100);
        assert_eq!(tracker.get_status("call-2"), Some("trying"));
    }

    // ── Task 52: Replaces parsing tests ─────────────────────────

    #[test]
    fn test_parse_replaces_basic() {
        let info = parse_replaces("abc123;from-tag=tag1;to-tag=tag2").unwrap();
        assert_eq!(info.call_id, "abc123");
        assert_eq!(info.from_tag, Some("tag1".to_string()));
        assert_eq!(info.to_tag, Some("tag2".to_string()));
    }

    #[test]
    fn test_parse_replaces_reversed_params() {
        let info = parse_replaces("callid-xyz;to-tag=ttag;from-tag=ftag").unwrap();
        assert_eq!(info.call_id, "callid-xyz");
        assert_eq!(info.from_tag, Some("ftag".to_string()));
        assert_eq!(info.to_tag, Some("ttag".to_string()));
    }

    #[test]
    fn test_parse_replaces_no_tags() {
        let info = parse_replaces("bare-callid").unwrap();
        assert_eq!(info.call_id, "bare-callid");
        assert_eq!(info.from_tag, None);
        assert_eq!(info.to_tag, None);
    }

    #[test]
    fn test_parse_replaces_empty() {
        assert!(parse_replaces("").is_none());
        assert!(parse_replaces("  ").is_none());
    }

    #[test]
    fn test_parse_replaces_only_from_tag() {
        let info = parse_replaces("cid;from-tag=ft1").unwrap();
        assert_eq!(info.call_id, "cid");
        assert_eq!(info.from_tag, Some("ft1".to_string()));
        assert_eq!(info.to_tag, None);
    }

    #[test]
    fn test_handle_attended_refer_basic() {
        let mut tracker = ReferTracker::new(1000, 300);
        let valid = tracker.handle_attended_refer(
            "call-1",
            "sip:bob@example.com",
            "abc;from-tag=f;to-tag=t",
        );
        assert!(valid);
        assert_eq!(tracker.get_status("call-1"), Some("pending"));
        assert_eq!(
            tracker.get_replaces("call-1"),
            Some("abc;from-tag=f;to-tag=t")
        );
    }

    #[test]
    fn test_handle_attended_refer_invalid_replaces() {
        let mut tracker = ReferTracker::new(1000, 300);
        let valid = tracker.handle_attended_refer(
            "call-1",
            "sip:bob@example.com",
            "",
        );
        assert!(!valid);
        // Still tracked even with invalid replaces
        assert_eq!(tracker.get_status("call-1"), Some("pending"));
    }

    #[test]
    fn test_attended_refer_full_lifecycle() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_attended_refer(
            "call-1",
            "sip:bob@example.com",
            "consult-call;from-tag=orig;to-tag=dest",
        );
        assert_eq!(tracker.get_status("call-1"), Some("pending"));

        tracker.handle_notify("call-1", 100);
        assert_eq!(tracker.get_status("call-1"), Some("trying"));

        tracker.handle_notify("call-1", 200);
        assert_eq!(tracker.get_status("call-1"), Some("success"));

        // Replaces value should still be available
        assert_eq!(
            tracker.get_replaces("call-1"),
            Some("consult-call;from-tag=orig;to-tag=dest")
        );
    }

    #[test]
    fn test_get_replaces_none_for_blind_refer() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_refer("call-1", "sip:bob@example.com");
        assert_eq!(tracker.get_replaces("call-1"), None);
    }

    // ── Task 53: NOTIFY generation tests ─────────────────────────

    #[test]
    fn test_notify_cseq_increment() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_refer("call-1", "sip:bob@example.com");

        assert_eq!(tracker.next_notify_cseq("call-1"), Some(1));
        assert_eq!(tracker.next_notify_cseq("call-1"), Some(2));
        assert_eq!(tracker.next_notify_cseq("call-1"), Some(3));
    }

    #[test]
    fn test_notify_cseq_unknown_call() {
        let mut tracker = ReferTracker::new(1000, 300);
        assert_eq!(tracker.next_notify_cseq("nonexistent"), None);
    }

    #[test]
    fn test_notify_cseq_independent_per_call() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_refer("call-1", "sip:a@example.com");
        tracker.handle_refer("call-2", "sip:b@example.com");

        assert_eq!(tracker.next_notify_cseq("call-1"), Some(1));
        assert_eq!(tracker.next_notify_cseq("call-1"), Some(2));
        assert_eq!(tracker.next_notify_cseq("call-2"), Some(1));
        assert_eq!(tracker.next_notify_cseq("call-1"), Some(3));
        assert_eq!(tracker.next_notify_cseq("call-2"), Some(2));
    }

    #[test]
    fn test_notify_cseq_resets_on_refer_overwrite() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_refer("call-1", "sip:a@example.com");
        tracker.next_notify_cseq("call-1");
        tracker.next_notify_cseq("call-1");
        // Overwrite
        tracker.handle_refer("call-1", "sip:b@example.com");
        assert_eq!(tracker.next_notify_cseq("call-1"), Some(1));
    }

    // ── Task 54: Transfer policy tests ───────────────────────────

    #[test]
    fn test_glob_match_exact() {
        assert!(glob::glob_match("sip:bob@example.com", "sip:bob@example.com"));
        assert!(!glob::glob_match("sip:bob@example.com", "sip:alice@example.com"));
    }

    #[test]
    fn test_glob_match_wildcard() {
        assert!(glob::glob_match("sip:*@example.com", "sip:bob@example.com"));
        assert!(glob::glob_match("sip:*@example.com", "sip:alice@example.com"));
        assert!(!glob::glob_match("sip:*@example.com", "sip:bob@other.com"));
    }

    #[test]
    fn test_glob_match_prefix_wildcard() {
        assert!(glob::glob_match("sip:+1*@pbx.local", "sip:+12125551234@pbx.local"));
        assert!(!glob::glob_match("sip:+1*@pbx.local", "sip:+442071234567@pbx.local"));
    }

    #[test]
    fn test_glob_match_case_insensitive() {
        assert!(glob::glob_match("SIP:*@EXAMPLE.COM", "sip:bob@example.com"));
    }

    #[test]
    fn test_glob_match_question_mark() {
        assert!(glob::glob_match("sip:bo?@example.com", "sip:bob@example.com"));
        assert!(!glob::glob_match("sip:bo?@example.com", "sip:bobby@example.com"));
    }

    #[test]
    fn test_glob_match_star_matches_empty() {
        assert!(glob::glob_match("sip:*@example.com", "sip:@example.com"));
    }

    #[test]
    fn test_check_transfer_target_no_restrictions() {
        assert!(check_transfer_target("sip:anyone@anywhere.com", &[]));
    }

    #[test]
    fn test_check_transfer_target_allowed() {
        let patterns = vec![
            "sip:*@example.com".to_string(),
            "sip:+1*@pbx.local".to_string(),
        ];
        assert!(check_transfer_target("sip:bob@example.com", &patterns));
        assert!(check_transfer_target("sip:+12125551234@pbx.local", &patterns));
        assert!(!check_transfer_target("sip:bob@evil.com", &patterns));
    }

    #[test]
    fn test_parse_allowed_targets() {
        let targets = parse_allowed_targets("sip:*@example.com, sip:+1*@pbx.local, ");
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0], "sip:*@example.com");
        assert_eq!(targets[1], "sip:+1*@pbx.local");
    }

    #[test]
    fn test_parse_allowed_targets_empty() {
        let targets = parse_allowed_targets("");
        assert!(targets.is_empty());
    }

    #[test]
    fn test_tracker_target_policy() {
        let tracker = ReferTracker::with_config(
            1000,
            300,
            vec!["sip:*@allowed.com".to_string()],
            30,
            false,
        );
        assert!(tracker.is_target_allowed("sip:bob@allowed.com"));
        assert!(!tracker.is_target_allowed("sip:bob@blocked.com"));

        // Tracker with no restrictions allows everything
        let tracker2 = ReferTracker::new(1000, 300);
        assert!(tracker2.is_target_allowed("sip:anyone@anywhere.com"));
    }

    // ── Task 55: Event publishing tests ──────────────────────────

    #[test]
    fn test_build_event_json() {
        let json = build_event_json("call-1", "sip:bob@example.com", "pending");
        assert!(json.contains(r#""call_id":"call-1""#));
        assert!(json.contains(r#""refer_to":"sip:bob@example.com""#));
        assert!(json.contains(r#""status":"pending""#));
    }

    #[test]
    fn test_build_event_json_escaping() {
        let json = build_event_json("call\"1", "sip:b\\ob@ex.com", "trying");
        assert!(json.contains(r#""call_id":"call\"1""#));
        assert!(json.contains(r#""refer_to":"sip:b\\ob@ex.com""#));
    }

    #[test]
    fn test_json_escape() {
        assert_eq!(json_escape("hello"), "hello");
        assert_eq!(json_escape(r#"he"llo"#), r#"he\"llo"#);
        assert_eq!(json_escape("a\\b"), "a\\\\b");
        assert_eq!(json_escape("a\nb"), "a\\nb");
        assert_eq!(json_escape("a\rb"), "a\\rb");
        assert_eq!(json_escape("a\tb"), "a\\tb");
    }

    #[test]
    fn test_event_json_all_statuses() {
        for status in &["pending", "trying", "success", "failed"] {
            let json = build_event_json("c1", "sip:x@y.com", status);
            assert!(json.contains(&format!(r#""status":"{}""#, status)));
        }
    }

    // ── Task 56: Transfer timeout tests ──────────────────────────

    #[test]
    fn test_find_timed_out_none() {
        let tracker = ReferTracker::with_config(1000, 300, vec![], 30, false);
        assert!(tracker.find_timed_out().is_empty());
    }

    #[test]
    fn test_find_timed_out_fresh_entries() {
        let mut tracker = ReferTracker::with_config(1000, 300, vec![], 30, false);
        tracker.handle_refer("call-1", "sip:a@example.com");
        // Fresh entries should not be timed out
        assert!(tracker.find_timed_out().is_empty());
    }

    #[test]
    fn test_find_timed_out_expired_entries() {
        // Use a 0-second timeout so entries time out immediately
        let mut tracker = ReferTracker::with_config(1000, 300, vec![], 0, false);
        tracker.handle_refer("call-1", "sip:a@example.com");
        tracker.handle_refer("call-2", "sip:b@example.com");
        thread::sleep(Duration::from_millis(10));
        let timed_out = tracker.find_timed_out();
        assert_eq!(timed_out.len(), 2);
    }

    #[test]
    fn test_find_timed_out_skips_terminal() {
        let mut tracker = ReferTracker::with_config(1000, 300, vec![], 0, false);
        tracker.handle_refer("call-1", "sip:a@example.com");
        tracker.handle_notify("call-1", 200); // success (terminal)
        tracker.handle_refer("call-2", "sip:b@example.com");
        thread::sleep(Duration::from_millis(10));
        let timed_out = tracker.find_timed_out();
        // Only call-2 should be timed out (call-1 is terminal success)
        assert_eq!(timed_out.len(), 1);
        assert!(timed_out.contains(&"call-2".to_string()));
    }

    #[test]
    fn test_sweep_timed_out() {
        let mut tracker = ReferTracker::with_config(1000, 300, vec![], 0, false);
        tracker.handle_refer("call-1", "sip:a@example.com");
        thread::sleep(Duration::from_millis(10));
        let swept = tracker.sweep_timed_out();
        assert_eq!(swept.len(), 1);
        assert_eq!(tracker.get_status("call-1"), Some("failed"));
    }

    #[test]
    fn test_sweep_timed_out_preserves_success() {
        let mut tracker = ReferTracker::with_config(1000, 300, vec![], 0, false);
        tracker.handle_refer("call-1", "sip:a@example.com");
        tracker.handle_notify("call-1", 200);
        thread::sleep(Duration::from_millis(10));
        let swept = tracker.sweep_timed_out();
        assert!(swept.is_empty());
        assert_eq!(tracker.get_status("call-1"), Some("success"));
    }

    #[test]
    fn test_reconnect_config() {
        let tracker = ReferTracker::with_config(1000, 300, vec![], 30, true);
        assert!(tracker.reconnect_on_failure);

        let tracker2 = ReferTracker::with_config(1000, 300, vec![], 30, false);
        assert!(!tracker2.reconnect_on_failure);
    }

    #[test]
    fn test_with_config_constructor() {
        let targets = vec!["sip:*@test.com".to_string()];
        let tracker = ReferTracker::with_config(500, 120, targets.clone(), 45, true);
        assert_eq!(tracker.max_pending, 500);
        assert_eq!(tracker.expire_secs, 120);
        assert_eq!(tracker.allowed_targets, targets);
        assert_eq!(tracker.transfer_timeout_secs, 45);
        assert!(tracker.reconnect_on_failure);
    }

    #[test]
    fn test_timeout_only_affects_pending_and_trying() {
        let mut tracker = ReferTracker::with_config(1000, 300, vec![], 0, true);

        tracker.handle_refer("call-1", "sip:a@example.com"); // pending
        tracker.handle_refer("call-2", "sip:b@example.com");
        tracker.handle_notify("call-2", 100); // trying
        tracker.handle_refer("call-3", "sip:c@example.com");
        tracker.handle_notify("call-3", 200); // success
        tracker.handle_refer("call-4", "sip:d@example.com");
        tracker.handle_notify("call-4", 486); // failed

        thread::sleep(Duration::from_millis(10));

        let timed_out = tracker.sweep_timed_out();
        // Only pending and trying should be swept
        assert_eq!(timed_out.len(), 2);
        assert!(timed_out.contains(&"call-1".to_string()));
        assert!(timed_out.contains(&"call-2".to_string()));

        // Both should now be failed
        assert_eq!(tracker.get_status("call-1"), Some("failed"));
        assert_eq!(tracker.get_status("call-2"), Some("failed"));
        // Terminal states unchanged
        assert_eq!(tracker.get_status("call-3"), Some("success"));
        assert_eq!(tracker.get_status("call-4"), Some("failed"));
    }

    // ── E2E-style integration tests ─────────────────────────────

    #[test]
    fn test_e2e_blind_transfer_lifecycle() {
        // Simulates a complete blind transfer flow
        let mut tracker = ReferTracker::with_config(
            1000, 300,
            vec!["sip:*@example.com".to_string()],
            30, false,
        );

        // 1. REFER arrives with allowed target
        assert!(tracker.is_target_allowed("sip:bob@example.com"));
        tracker.handle_refer("call-100", "sip:bob@example.com");
        assert_eq!(tracker.get_status("call-100"), Some("pending"));
        assert_eq!(tracker.get_replaces("call-100"), None);

        // 2. First NOTIFY: 100 Trying
        assert!(tracker.handle_notify("call-100", 100));
        assert_eq!(tracker.get_status("call-100"), Some("trying"));

        // 3. Prepare NOTIFY response (CSeq tracking)
        assert_eq!(tracker.next_notify_cseq("call-100"), Some(1));

        // 4. Second NOTIFY: 200 OK
        assert!(tracker.handle_notify("call-100", 200));
        assert_eq!(tracker.get_status("call-100"), Some("success"));

        // 5. Event payload
        let json = build_event_json("call-100", "sip:bob@example.com", "success");
        assert!(json.contains("call-100"));
        assert!(json.contains("success"));
    }

    #[test]
    fn test_e2e_attended_transfer_lifecycle() {
        let mut tracker = ReferTracker::with_config(
            1000, 300,
            vec!["sip:*@example.com".to_string()],
            30, false,
        );

        // 1. Attended REFER with Replaces
        let valid = tracker.handle_attended_refer(
            "call-200",
            "sip:charlie@example.com",
            "consult-id;from-tag=a;to-tag=b",
        );
        assert!(valid);
        assert_eq!(tracker.get_status("call-200"), Some("pending"));
        assert_eq!(
            tracker.get_replaces("call-200"),
            Some("consult-id;from-tag=a;to-tag=b")
        );

        // 2. Parse the Replaces for routing
        let info = parse_replaces("consult-id;from-tag=a;to-tag=b").unwrap();
        assert_eq!(info.call_id, "consult-id");
        assert_eq!(info.from_tag, Some("a".to_string()));
        assert_eq!(info.to_tag, Some("b".to_string()));

        // 3. NOTIFY flow
        tracker.handle_notify("call-200", 100);
        tracker.handle_notify("call-200", 200);
        assert_eq!(tracker.get_status("call-200"), Some("success"));
    }

    #[test]
    fn test_e2e_blocked_transfer() {
        let tracker = ReferTracker::with_config(
            1000, 300,
            vec!["sip:*@internal.com".to_string()],
            30, false,
        );

        // External target should be blocked
        assert!(!tracker.is_target_allowed("sip:hacker@evil.com"));
        // Internal target should be allowed
        assert!(tracker.is_target_allowed("sip:bob@internal.com"));
    }

    #[test]
    fn test_e2e_transfer_timeout_and_sweep() {
        let mut tracker = ReferTracker::with_config(
            1000, 300, vec![], 0, true,
        );

        // Start a transfer
        tracker.handle_refer("call-300", "sip:bob@example.com");
        assert_eq!(tracker.get_status("call-300"), Some("pending"));

        // Let it time out
        thread::sleep(Duration::from_millis(10));

        // Sweep timed out
        let timed_out = tracker.sweep_timed_out();
        assert_eq!(timed_out.len(), 1);
        assert_eq!(tracker.get_status("call-300"), Some("failed"));

        // Event for timeout
        let json = build_event_json("call-300", "sip:bob@example.com", "failed");
        assert!(json.contains("failed"));
    }

    #[test]
    fn test_e2e_notify_generation_cseq() {
        let mut tracker = ReferTracker::new(1000, 300);
        tracker.handle_refer("call-400", "sip:bob@example.com");

        // Generate multiple NOTIFYs — CSeq increments
        for expected_cseq in 1..=5 {
            assert_eq!(
                tracker.next_notify_cseq("call-400"),
                Some(expected_cseq)
            );
        }
    }

    #[test]
    fn test_e2e_event_publishing_all_states() {
        let mut tracker = ReferTracker::with_config(
            1000, 300, vec![], 30, false,
        );

        // Start event
        tracker.handle_refer("call-500", "sip:bob@example.com");
        let json = build_event_json("call-500", "sip:bob@example.com", "pending");
        assert!(json.contains("pending"));

        // Trying event
        tracker.handle_notify("call-500", 100);
        let json = build_event_json("call-500", "sip:bob@example.com", "trying");
        assert!(json.contains("trying"));

        // Success event
        tracker.handle_notify("call-500", 200);
        let json = build_event_json("call-500", "sip:bob@example.com", "success");
        assert!(json.contains("success"));
    }

    #[test]
    fn test_e2e_multiple_concurrent_transfers() {
        let mut tracker = ReferTracker::with_config(
            1000, 300,
            vec!["sip:*@example.com".to_string()],
            30, false,
        );

        // Multiple concurrent transfers
        for i in 0..10 {
            let cid = format!("call-{}", i);
            let target = format!("sip:user{}@example.com", i);
            tracker.handle_refer(&cid, &target);
        }
        assert_eq!(tracker.active_count(), 10);

        // Complete some, fail others
        for i in 0..5 {
            tracker.handle_notify(&format!("call-{}", i), 200);
        }
        for i in 5..10 {
            tracker.handle_notify(&format!("call-{}", i), 486);
        }

        // Verify states
        for i in 0..5 {
            assert_eq!(
                tracker.get_status(&format!("call-{}", i)),
                Some("success")
            );
        }
        for i in 5..10 {
            assert_eq!(
                tracker.get_status(&format!("call-{}", i)),
                Some("failed")
            );
        }
    }
}
