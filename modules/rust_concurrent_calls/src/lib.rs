//! rust_concurrent_calls — Per-account concurrent call limiting for OpenSIPS.
//!
//! Tracks active calls per account (typically `$fU`) and enforces configurable
//! limits. Supports both automatic dialog callback tracking (when dialog.so is
//! loaded) and explicit inc/dec from the OpenSIPS script.
//!
//! # OpenSIPS config (automatic mode — with dialog.so)
//!
//! ```text
//! loadmodule "dialog.so"
//! loadmodule "rust_concurrent_calls.so"
//! modparam("rust_concurrent_calls", "limits_file", "/etc/opensips/call_limits.csv")
//! modparam("rust_concurrent_calls", "default_limit", 10)
//! modparam("rust_concurrent_calls", "auto_track", 1)
//! modparam("rust_concurrent_calls", "account_var", "$fU")
//!
//! route {
//!     if (is_method("INVITE") && !has_totag()) {
//!         if (!check_concurrent("$fU")) {
//!             sl_send_reply(486, "Too Many Calls");
//!             exit;
//!         }
//!         # No need for concurrent_inc() — auto_track handles it
//!     }
//! }
//! # No need for concurrent_dec() on BYE — auto_track handles it
//! ```
//!
//! # OpenSIPS config (manual mode — without dialog.so)
//!
//! ```text
//! loadmodule "rust_concurrent_calls.so"
//! modparam("rust_concurrent_calls", "limits_file", "/etc/opensips/call_limits.csv")
//! modparam("rust_concurrent_calls", "default_limit", 10)
//! modparam("rust_concurrent_calls", "auto_track", 0)
//!
//! route {
//!     if (is_method("INVITE") && !has_totag()) {
//!         if (!check_concurrent("$fU")) {
//!             sl_send_reply(486, "Too Many Calls");
//!             exit;
//!         }
//!         concurrent_inc("$fU");
//!     }
//! }
//!
//! onreply_route {
//!     if (is_method("INVITE") && $rs >= 300) {
//!         concurrent_dec("$fU");
//!     }
//! }
//!
//! route[handle_bye] {
//!     concurrent_dec("$fU");
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
use rust_common::dialog;
use rust_common::event;
use rust_common::mi::Stats;
use rust_common::mi_resp::{MiObject, mi_ok, mi_error, mi_param_error, mi_try_get_string_param, mi_params_t};
use rust_common::stat::{StatVar, StatVarOpaque};
use rust_common::reload::{csv_line_parser, FileLoader};

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::ffi::{c_int, c_void};
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::time::Instant;

// Native statistics -- cross-worker, aggregated by OpenSIPS core.
static STAT_CHECKED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_ALLOWED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_BLOCKED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_ACTIVE_CALLS: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_ACCOUNTS: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());

const STAT_NO_RESET: u16 = 1;

// ── Module parameters ────────────────────────────────────────────

/// Path to limits CSV file (required). Format: account,max_calls
static LIMITS_FILE: ModString = ModString::new();

/// Default concurrent call limit for accounts not in the limits file.
static DEFAULT_LIMIT: Integer = Integer::with_default(10);

/// Enable automatic dialog tracking (1 = enabled, 0 = manual only).
static AUTO_TRACK: Integer = Integer::with_default(1);

/// PV expression to extract account from SIP message (default: "$fU").
static ACCOUNT_VAR: ModString = ModString::new();

/// Enable dialog profiles for cross-worker accurate counts (0 = local HashMap, 1 = dialog profiles).
static USE_DIALOG_PROFILES: Integer = Integer::with_default(0);

/// Dialog profile name for cross-worker counting (default: "concurrent_calls").
static PROFILE_NAME: ModString = ModString::new();

/// Enable per-direction (inbound/outbound) limits (0 = single limit, 1 = direction-aware).
static DIRECTION_AWARE: Integer = Integer::with_default(0);

/// Cooldown period in seconds after a limit rejection (0 = disabled).
static COOLDOWN_SECS: Integer = Integer::with_default(0);

/// Burst threshold: flag if concurrent count increases by this many within burst_window_secs (0 = disabled).
static BURST_THRESHOLD: Integer = Integer::with_default(0);

/// Enable event publishing (0=off, 1=on, default 0).
static PUBLISH_EVENTS: Integer = Integer::with_default(0);

/// Time window in seconds for burst detection.
static BURST_WINDOW_SECS: Integer = Integer::with_default(10);


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

/// Per-direction limits for an account.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectionLimits {
    inbound: u32,
    outbound: u32,
}

/// Parse a direction-aware CSV line "account,max_inbound,max_outbound".
fn parse_direction_limit_entry(csv_line: &str) -> Option<(String, DirectionLimits)> {
    let mut parts = csv_line.splitn(3, ',');
    let account = parts.next()?.trim();
    let inbound_str = parts.next()?.trim();
    let outbound_str = parts.next()?.trim();
    let inbound = inbound_str.parse::<u32>().ok()?;
    let outbound = outbound_str.parse::<u32>().ok()?;
    if account.is_empty() {
        return None;
    }
    Some((account.to_string(), DirectionLimits { inbound, outbound }))
}

/// Build a HashMap of direction-aware limits from parsed CSV lines.
#[allow(clippy::needless_pass_by_value)]
fn build_direction_limits(entries: Vec<String>) -> HashMap<String, DirectionLimits> {
    entries
        .iter()
        .filter_map(|line| parse_direction_limit_entry(line))
        .collect()
}

/// Check if an account is under its inbound concurrent call limit.
///
/// Returns (allowed, current_count, limit).
fn check_inbound_limit(
    counts: &HashMap<String, u32>,
    limits: &HashMap<String, DirectionLimits>,
    account: &str,
    default_limit: u32,
) -> (bool, u32, u32) {
    let count = counts.get(account).copied().unwrap_or(0);
    let limit = limits.get(account)
        .map(|dl| dl.inbound)
        .unwrap_or(default_limit);
    (count < limit, count, limit)
}

/// Check if an account is under its outbound concurrent call limit.
///
/// Returns (allowed, current_count, limit).
fn check_outbound_limit(
    counts: &HashMap<String, u32>,
    limits: &HashMap<String, DirectionLimits>,
    account: &str,
    default_limit: u32,
) -> (bool, u32, u32) {
    let count = counts.get(account).copied().unwrap_or(0);
    let limit = limits.get(account)
        .map(|dl| dl.outbound)
        .unwrap_or(default_limit);
    (count < limit, count, limit)
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

/// Check if an account is in cooldown. Returns true if still cooling down.
fn is_in_cooldown(cooldowns: &HashMap<String, Instant>, account: &str, cooldown_secs: u64) -> bool {
    if cooldown_secs == 0 {
        return false;
    }
    match cooldowns.get(account) {
        Some(expiry) => {
            let duration = std::time::Duration::from_secs(cooldown_secs);
            expiry.elapsed() < duration
        }
        None => false,
    }
}

/// Record a count snapshot for burst detection.
fn record_burst_snapshot(
    history: &mut HashMap<String, VecDeque<(Instant, u32)>>,
    account: &str,
    count: u32,
) {
    let deque = history.entry(account.to_string()).or_default();
    deque.push_back((Instant::now(), count));
}

/// Check for burst: returns (is_burst, delta) comparing current count
/// to the count at the start of the time window.
fn check_burst_from_history(
    history: &mut HashMap<String, VecDeque<(Instant, u32)>>,
    account: &str,
    current_count: u32,
    threshold: u32,
    window_secs: u64,
) -> (bool, i32) {
    let window = std::time::Duration::from_secs(window_secs);
    let now = Instant::now();

    let deque = match history.get_mut(account) {
        Some(d) => d,
        None => return (false, 0),
    };

    // Prune entries older than the window
    while let Some(&(ts, _)) = deque.front() {
        if now.duration_since(ts) > window {
            deque.pop_front();
        } else {
            break;
        }
    }

    // Get the oldest count in the window
    let oldest_count = match deque.front() {
        Some(&(_, c)) => c,
        None => return (false, 0),
    };

    // gui_dCquvqE1csI3: use saturating arithmetic to prevent overflow
    let delta = (current_count as i32).saturating_sub(oldest_count as i32);
    let is_burst = delta >= (threshold as i32);
    (is_burst, delta)
}

/// Record a cooldown for an account (called when a limit rejection happens).
fn set_cooldown(cooldowns: &mut HashMap<String, Instant>, account: &str) {
    cooldowns.insert(account.to_string(), Instant::now());
}

/// Resolve the effective limit for an account, considering live overrides.
fn effective_limit(
    limits: &HashMap<String, u32>,
    overrides: &HashMap<String, u32>,
    account: &str,
    default_limit: u32,
) -> u32 {
    overrides.get(account).copied()
        .or_else(|| limits.get(account).copied())
        .unwrap_or(default_limit)
}

/// Build a JSON status string for an account.
fn build_status_json(
    account: &str,
    count: u32,
    limit: u32,
    inbound: u32,
    outbound: u32,
) -> String {
    format!(
        r#"{{"account":"{}","count":{},"limit":{},"direction":{{"inbound":{},"outbound":{}}}}}"#,
        account, count, limit, inbound, outbound
    )
}

/// Check limit using an external (profile-based) count instead of the local HashMap.
///
/// When dialog profiles are enabled, the profile count comes from
/// get_profile_size() which is accurate across all workers.
/// Returns (allowed, profile_count, limit).
fn check_limit_with_profile_count(
    profile_count: u32,
    limits: &HashMap<String, u32>,
    account: &str,
    default_limit: u32,
) -> (bool, u32, u32) {
    let limit = limits.get(account).copied().unwrap_or(default_limit);
    (profile_count < limit, profile_count, limit)
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

// ── Dialog tracker state ─────────────────────────────────────────

/// Per-dialog state stored in the DialogTracker.
#[derive(Default)]
struct CallDialogState {
    /// The account identifier associated with this dialog.
    account: String,
}

// ── Per-worker state ─────────────────────────────────────────────

struct WorkerState {
    counts: HashMap<String, u32>,
    loader: FileLoader<HashMap<String, u32>>,
    stats: Stats,
    dialog_tracker: dialog::DialogTracker<CallDialogState>,
    // Direction-aware state (only used when direction_aware=1)
    inbound_counts: HashMap<String, u32>,
    outbound_counts: HashMap<String, u32>,
    direction_loader: Option<FileLoader<HashMap<String, DirectionLimits>>>,
    // Live limit overrides (Task 42) — persist until reload or restart
    limit_overrides: HashMap<String, u32>,
    // Cooldown tracking (Task 43) — per-account cooldown expiry
    cooldowns: HashMap<String, Instant>,
    // Burst detection (Task 44) — per-account count snapshots
    burst_history: HashMap<String, VecDeque<(Instant, u32)>>,
}

thread_local! {
    static WORKER: RefCell<Option<WorkerState>> = const { RefCell::new(None) };
}

// ── Dialog callback trampolines ──────────────────────────────────

/// DLGCB_CREATED callback: auto-increment account counter and register
/// per-dialog TERMINATED/EXPIRED callbacks.
///
/// # Safety
/// Called by OpenSIPS dialog module with valid pointers.
unsafe extern "C" fn dlg_on_created(
    dlg: *mut dialog::dlg_cell,
    _cb_type: c_int,
    params: *mut dialog::dlg_cb_params,
) {
    // Extract account from the SIP message
    let msg_ptr = if !params.is_null() {
        unsafe { (*params).msg }
    } else {
        ptr::null_mut()
    };

    if msg_ptr.is_null() {
        return;
    }

    // Get the account variable expression
    let account_var_expr = unsafe { ACCOUNT_VAR.get_value() }
        .unwrap_or("$fU");

    // Read the account from the SIP message PV
    let sip_msg = unsafe {
        opensips_rs::SipMessage::from_raw(msg_ptr.cast())
    };
    let account = match sip_msg.pv(account_var_expr) {
        Some(a) if !a.is_empty() => a,
        _ => return,
    };

    // Get dialog ID (Call-ID)
    let call_id = match unsafe { dialog::callid_from_dlg(dlg as *mut c_void) } {
        Some(id) => id,
        None => return,
    };

    // Increment SHM counter (cross-worker visible)
    // Increment counter and track dialog
    WORKER.with(|w| {
        let mut borrow = w.borrow_mut();
        if let Some(state) = borrow.as_mut() {
            let new_count = increment(&mut state.counts, &account);
            state.stats.inc("incremented");
            state.stats.inc("auto_tracked");
            if let Some(s) = StatVar::from_raw(STAT_ACTIVE_CALLS.load(Ordering::Relaxed)) { s.inc(); }

            // Store account in dialog tracker
            state.dialog_tracker.on_created(&call_id);
            state.dialog_tracker.with_state(&call_id, |s| {
                s.account = account.clone();
            });

            opensips_log!(DBG, "rust_concurrent_calls",
                "auto_track inc {}: now {} (dialog {})", account, new_count, call_id);
        }
    });

    // Register per-dialog TERMINATED|EXPIRED callback
    let _ = unsafe {
        dialog::dlg::register_dlg_cb(
            dlg as *mut c_void,
            dialog::DLGCB_TERMINATED | dialog::DLGCB_EXPIRED,
            Some(dlg_on_terminated),
            ptr::null_mut(),
            None,
        )
    };
}

/// DLGCB_TERMINATED/EXPIRED callback: auto-decrement account counter.
///
/// # Safety
/// Called by OpenSIPS dialog module with valid pointers.
unsafe extern "C" fn dlg_on_terminated(
    dlg: *mut dialog::dlg_cell,
    _cb_type: c_int,
    _params: *mut dialog::dlg_cb_params,
) {
    let call_id = match unsafe { dialog::callid_from_dlg(dlg as *mut c_void) } {
        Some(id) => id,
        None => return,
    };

    WORKER.with(|w| {
        let mut borrow = w.borrow_mut();
        if let Some(state) = borrow.as_mut() {
            // Look up the account from our tracker
            let account = state.dialog_tracker.on_terminated(&call_id)
                .map(|s| s.account);

            if let Some(acct) = account {
                if !acct.is_empty() {
                    let new_count = decrement(&mut state.counts, &acct);
                    state.stats.inc("decremented");
                    if let Some(s) = StatVar::from_raw(STAT_ACTIVE_CALLS.load(Ordering::Relaxed)) { s.dec(); }
                    opensips_log!(DBG, "rust_concurrent_calls",
                        "auto_track dec {}: now {} (dialog {})", acct, new_count, call_id);
                }
            }
        }
    });
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
    let auto_track = AUTO_TRACK.get();
    let account_var = unsafe { ACCOUNT_VAR.get_value() }
        .unwrap_or("$fU");

    // Validate default_limit
    if default < 0 {
        opensips_log!(WARN, "rust_concurrent_calls",
            "default_limit={} is negative, clamping to 0 (block all)", default);
    } else if default > 100_000 {
        opensips_log!(WARN, "rust_concurrent_calls",
            "default_limit={} is very high (>100000), verify this is intentional", default);
    }

    // Try to load dialog API if auto_track is enabled
    if auto_track != 0 {
        match dialog::load_api() {
            Ok(()) => {
                // Register DLGCB_CREATED global callback
                match unsafe {
                    dialog::dlg::register_global_cb(
                        dialog::DLGCB_CREATED,
                        Some(dlg_on_created),
                        ptr::null_mut(),
                        None,
                    )
                } {
                    Ok(()) => {
                        opensips_log!(INFO, "rust_concurrent_calls",
                            "auto_track enabled: dialog callbacks registered (account_var={})",
                            account_var);
                    }
                    Err(e) => {
                        opensips_log!(ERR, "rust_concurrent_calls",
                            "auto_track: failed to register DLGCB_CREATED: {}", e);
                        return -1;
                    }
                }
            }
            Err(e) => {
                opensips_log!(WARN, "rust_concurrent_calls",
                    "auto_track enabled but dialog API unavailable ({}). \
                     Falling back to manual mode. Load dialog.so before this module.", e);
            }
        }
    }

    opensips_log!(INFO, "rust_concurrent_calls", "module initialized");
    opensips_log!(INFO, "rust_concurrent_calls", "  limits_file={}", file);
    opensips_log!(INFO, "rust_concurrent_calls", "  default_limit={}", default);
    opensips_log!(INFO, "rust_concurrent_calls", "  auto_track={}", auto_track);
    opensips_log!(INFO, "rust_concurrent_calls", "  account_var={}", account_var);

    let direction_aware = DIRECTION_AWARE.get();
    let cooldown = COOLDOWN_SECS.get();
    opensips_log!(INFO, "rust_concurrent_calls", "  direction_aware={}", direction_aware);
    opensips_log!(INFO, "rust_concurrent_calls", "  cooldown_secs={}", cooldown);

    let burst_threshold = BURST_THRESHOLD.get();
    let burst_window = BURST_WINDOW_SECS.get();
    opensips_log!(INFO, "rust_concurrent_calls", "  burst_threshold={}", burst_threshold);
    opensips_log!(INFO, "rust_concurrent_calls", "  burst_window_secs={}", burst_window);

    let use_profiles = USE_DIALOG_PROFILES.get();
    let profile_name = unsafe { PROFILE_NAME.get_value() }
        .unwrap_or("concurrent_calls");
    opensips_log!(INFO, "rust_concurrent_calls", "  use_dialog_profiles={}", use_profiles);
    opensips_log!(INFO, "rust_concurrent_calls", "  profile_name={}", profile_name);

    0
}

unsafe extern "C" fn mod_child_init(rank: c_int) -> c_int {
    // Initialize for SIP workers (rank >= 1) and PROC_MODULE (-2) which
    // handles MI commands via httpd.  Skip all other non-worker processes
    // (PROC_MAIN=0, TCP=-1, etc.).
    if rank < 1 && rank != -2 {
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
        &["checked", "allowed", "blocked", "incremented", "decremented",
          "accounts", "reloads", "auto_tracked", "cooldown_blocked", "burst_detected"]);
    stats.set("accounts", entry_count as u64);

    // Load direction-aware limits if enabled
    let direction_aware = DIRECTION_AWARE.get() != 0;
    let direction_loader = if direction_aware {
        match FileLoader::new(&file, csv_line_parser, build_direction_limits) {
            Ok(l) => Some(l),
            Err(e) => {
                opensips_log!(WARN, "rust_concurrent_calls",
                    "direction_aware enabled but failed to load direction limits: {}", e);
                None
            }
        }
    } else {
        None
    };

    WORKER.with(|w| {
        *w.borrow_mut() = Some(WorkerState {
            counts: HashMap::with_capacity(256),
            loader,
            stats,
            dialog_tracker: dialog::DialogTracker::new(3600),
            inbound_counts: HashMap::with_capacity(256),
            outbound_counts: HashMap::with_capacity(256),
            direction_loader,
            limit_overrides: HashMap::new(),
            cooldowns: HashMap::new(),
            burst_history: HashMap::new(),
        });
    });

    opensips_log!(DBG, "rust_concurrent_calls",
        "worker {} loaded {} account limits", rank, entry_count);
    0
}

unsafe extern "C" fn mod_destroy() {
    opensips_log!(INFO, "rust_concurrent_calls", "module destroyed");
}

// ── Script function: check_concurrent(account) ──────────────

unsafe extern "C" fn w_check_concurrent(
    msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_concurrent_calls",
                    "check_concurrent: missing or invalid parameter");
                return -2;
            }
        };

        let use_profiles = USE_DIALOG_PROFILES.get() != 0;
        let profile = if use_profiles {
            unsafe { PROFILE_NAME.get_value() }.unwrap_or("concurrent_calls")
        } else {
            ""
        };

        WORKER.with(|w| {
            let mut borrow = w.borrow_mut();
            match borrow.as_mut() {
                Some(state) => {
                    state.stats.inc("checked");
                    if let Some(s) = StatVar::from_raw(STAT_CHECKED.load(Ordering::Relaxed)) { s.inc(); }

                    // Check cooldown first (Task 43)
                    let cooldown_secs = COOLDOWN_SECS.get();
                    if cooldown_secs > 0 && is_in_cooldown(&state.cooldowns, account, cooldown_secs as u64) {
                        state.stats.inc("blocked");
                        if let Some(s) = StatVar::from_raw(STAT_BLOCKED.load(Ordering::Relaxed)) { s.inc(); }
                        state.stats.inc("cooldown_blocked");
                        opensips_log!(DBG, "rust_concurrent_calls",
                            "account {} in cooldown period", account);
                        let mut sip_msg = unsafe {
                            opensips_rs::SipMessage::from_raw(msg)
                        };
                        let _ = sip_msg.set_pv_int("$var(concurrent_count)", -1);
                        let _ = sip_msg.set_pv_int("$var(concurrent_limit)", 0);
                        return -1;
                    }

                    let limits = state.loader.get();
                    let default = DEFAULT_LIMIT.get().max(0) as u32;

                    // When dialog profiles are enabled, use get_profile_size
                    // for cross-worker accurate counts
                    // Check overrides first
                    let eff_limit = effective_limit(
                        &limits, &state.limit_overrides, account, default,
                    );

                    // Note: use_profiles only affects concurrent_inc (set_dlg_profile).
                    // get_profile_size requires a CMD_PARAM_VAR output param that
                    // sip_msg.call() cannot provide, so always use local counts.
                    let (allowed, count, limit) = {
                        let count = state.counts.get(account).copied().unwrap_or(0);
                        (count < eff_limit, count, eff_limit)
                    };

                    // Set $var(concurrent_count) and $var(concurrent_limit)
                    let mut sip_msg = unsafe {
                        opensips_rs::SipMessage::from_raw(msg)
                    };
                    let _ = sip_msg.set_pv_int("$var(concurrent_count)", count.min(i32::MAX as u32) as i32);
                    let _ = sip_msg.set_pv_int("$var(concurrent_limit)", limit.min(i32::MAX as u32) as i32);

                    if allowed {
                        state.stats.inc("allowed");
                        if let Some(s) = StatVar::from_raw(STAT_ALLOWED.load(Ordering::Relaxed)) { s.inc(); }
                        1
                    } else {
                        state.stats.inc("blocked");
                        if let Some(s) = StatVar::from_raw(STAT_BLOCKED.load(Ordering::Relaxed)) { s.inc(); }
                        // Set cooldown on rejection (Task 43)
                        let cooldown_secs = COOLDOWN_SECS.get();
                        if cooldown_secs > 0 {
                            set_cooldown(&mut state.cooldowns, account);
                        }
                        opensips_log!(DBG, "rust_concurrent_calls",
                            "account {} at limit: {}/{}", account, count, limit);
                        // Publish E_CONCURRENT_LIMIT event
                        if event::is_enabled() {
                            let payload = event::format_payload(&[
                                ("account", &event::json_str(account)),
                                ("count", &count.to_string()),
                                ("limit", &limit.to_string()),
                            ]);
                            opensips_log!(NOTICE, "rust_concurrent_calls", "EVENT E_CONCURRENT_LIMIT {}", payload);
                        }
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

// ── Script function: concurrent_inc(account) ────────────────

unsafe extern "C" fn w_concurrent_inc(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_concurrent_calls",
                    "concurrent_inc: missing or invalid parameter");
                return -2;
            }
        };

        // When dialog profiles are enabled, also set the profile
        if USE_DIALOG_PROFILES.get() != 0 {
            let profile = unsafe { PROFILE_NAME.get_value() }
                .unwrap_or("concurrent_calls");
            let mut sip_msg = unsafe {
                opensips_rs::SipMessage::from_raw(_msg)
            };
            let _ = sip_msg.call_str("set_dlg_profile", &[profile, account]);
        }

        WORKER.with(|w| {
            let mut borrow = w.borrow_mut();
            match borrow.as_mut() {
                Some(state) => {
                    let new_count = increment(&mut state.counts, account);
                    state.stats.inc("incremented");
                    if let Some(s) = StatVar::from_raw(STAT_ACTIVE_CALLS.load(Ordering::Relaxed)) { s.inc(); }
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

// ── Script function: concurrent_dec(account) ────────────────

unsafe extern "C" fn w_concurrent_dec(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_concurrent_calls",
                    "concurrent_dec: missing or invalid parameter");
                return -2;
            }
        };

        WORKER.with(|w| {
            let mut borrow = w.borrow_mut();
            match borrow.as_mut() {
                Some(state) => {
                    let new_count = decrement(&mut state.counts, account);
                    state.stats.inc("decremented");
                    if let Some(s) = StatVar::from_raw(STAT_ACTIVE_CALLS.load(Ordering::Relaxed)) { s.dec(); }
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

// ── Script function: check_concurrent_inbound(account) ───────

unsafe extern "C" fn w_check_concurrent_inbound(
    msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_concurrent_calls",
                    "check_concurrent_inbound: missing or invalid parameter");
                return -2;
            }
        };

        WORKER.with(|w| {
            let borrow = w.borrow();
            match borrow.as_ref() {
                Some(state) => {
                    state.stats.inc("checked");
                    if let Some(s) = StatVar::from_raw(STAT_CHECKED.load(Ordering::Relaxed)) { s.inc(); }

                    let default = DEFAULT_LIMIT.get().max(0) as u32;
                    let (allowed, count, limit) = match &state.direction_loader {
                        Some(dl) => {
                            let limits = dl.get();
                            check_inbound_limit(&state.inbound_counts, &limits, account, default)
                        }
                        None => {
                            opensips_log!(WARN, "rust_concurrent_calls",
                                "check_concurrent_inbound called but direction_aware=0");
                            let limits = state.loader.get();
                            check_limit(&state.counts, &limits, account, default)
                        }
                    };

                    let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
                    let _ = sip_msg.set_pv_int("$var(concurrent_count)", count.min(i32::MAX as u32) as i32);
                    let _ = sip_msg.set_pv_int("$var(concurrent_limit)", limit.min(i32::MAX as u32) as i32);

                    if allowed {
                        state.stats.inc("allowed");
                        if let Some(s) = StatVar::from_raw(STAT_ALLOWED.load(Ordering::Relaxed)) { s.inc(); }
                        1
                    } else {
                        state.stats.inc("blocked");
                        if let Some(s) = StatVar::from_raw(STAT_BLOCKED.load(Ordering::Relaxed)) { s.inc(); }
                        -1
                    }
                }
                None => -2,
            }
        })
    })
}

// ── Script function: check_concurrent_outbound(account) ──────

unsafe extern "C" fn w_check_concurrent_outbound(
    msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_concurrent_calls",
                    "check_concurrent_outbound: missing or invalid parameter");
                return -2;
            }
        };

        WORKER.with(|w| {
            let borrow = w.borrow();
            match borrow.as_ref() {
                Some(state) => {
                    state.stats.inc("checked");
                    if let Some(s) = StatVar::from_raw(STAT_CHECKED.load(Ordering::Relaxed)) { s.inc(); }

                    let default = DEFAULT_LIMIT.get().max(0) as u32;
                    let (allowed, count, limit) = match &state.direction_loader {
                        Some(dl) => {
                            let limits = dl.get();
                            check_outbound_limit(&state.outbound_counts, &limits, account, default)
                        }
                        None => {
                            opensips_log!(WARN, "rust_concurrent_calls",
                                "check_concurrent_outbound called but direction_aware=0");
                            let limits = state.loader.get();
                            check_limit(&state.counts, &limits, account, default)
                        }
                    };

                    let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
                    let _ = sip_msg.set_pv_int("$var(concurrent_count)", count.min(i32::MAX as u32) as i32);
                    let _ = sip_msg.set_pv_int("$var(concurrent_limit)", limit.min(i32::MAX as u32) as i32);

                    if allowed {
                        state.stats.inc("allowed");
                        if let Some(s) = StatVar::from_raw(STAT_ALLOWED.load(Ordering::Relaxed)) { s.inc(); }
                        1
                    } else {
                        state.stats.inc("blocked");
                        if let Some(s) = StatVar::from_raw(STAT_BLOCKED.load(Ordering::Relaxed)) { s.inc(); }
                        -1
                    }
                }
                None => -2,
            }
        })
    })
}

// ── Script function: concurrent_status(account) ─────────────

unsafe extern "C" fn w_concurrent_status(
    msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_concurrent_calls",
                    "concurrent_status: missing or invalid parameter");
                return -2;
            }
        };

        let json = WORKER.with(|w| {
            let borrow = w.borrow();
            match borrow.as_ref() {
                Some(state) => {
                    let count = state.counts.get(account).copied().unwrap_or(0);
                    let limits = state.loader.get();
                    let default = DEFAULT_LIMIT.get().max(0) as u32;
                    let limit = effective_limit(&limits, &state.limit_overrides, account, default);
                    let inbound = state.inbound_counts.get(account).copied().unwrap_or(0);
                    let outbound = state.outbound_counts.get(account).copied().unwrap_or(0);
                    build_status_json(account, count, limit, inbound, outbound)
                }
                None => r#"{"error":"not_initialized"}"#.to_string(),
            }
        });

        let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
        let _ = sip_msg.set_pv("$var(concurrent_status)", &json);
        1
    })
}

// ── Script function: concurrent_set_limit(account, limit) ───

const TWO_STR_PARAMS: [sys::cmd_param; 9] = {
    let mut arr: [sys::cmd_param; 9] = unsafe { std::mem::zeroed() };
    arr[0].flags = 2; // CMD_PARAM_STR
    arr[1].flags = 2; // CMD_PARAM_STR
    arr
};

unsafe extern "C" fn w_concurrent_set_limit(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_concurrent_calls",
                    "concurrent_set_limit: missing account parameter");
                return -2;
            }
        };
        let limit_str = match unsafe { <&str as CommandFunctionParam>::from_raw(p1) } {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_concurrent_calls",
                    "concurrent_set_limit: missing limit parameter");
                return -2;
            }
        };

        let new_limit = match limit_str.parse::<u32>() {
            Ok(v) => v,
            Err(_) => {
                opensips_log!(ERR, "rust_concurrent_calls",
                    "concurrent_set_limit: invalid limit value: {}", limit_str);
                return -2;
            }
        };

        WORKER.with(|w| {
            let mut borrow = w.borrow_mut();
            match borrow.as_mut() {
                Some(state) => {
                    state.limit_overrides.insert(account.to_string(), new_limit);
                    opensips_log!(INFO, "rust_concurrent_calls",
                        "live override: {} limit set to {}", account, new_limit);
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

// ── Script function: check_burst(account) ────────────────────

unsafe extern "C" fn w_check_burst(
    msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_concurrent_calls",
                    "check_burst: missing or invalid parameter");
                return -2;
            }
        };

        let threshold = BURST_THRESHOLD.get();
        if threshold <= 0 {
            // Burst detection disabled
            let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
            let _ = sip_msg.set_pv_int("$var(burst_delta)", 0);
            return -1;
        }

        let window_secs = BURST_WINDOW_SECS.get().max(1);

        WORKER.with(|w| {
            let mut borrow = w.borrow_mut();
            match borrow.as_mut() {
                Some(state) => {
                    let current_count = state.counts.get(account).copied().unwrap_or(0);

                    // Record snapshot
                    record_burst_snapshot(&mut state.burst_history, account, current_count);

                    // Check burst
                    let (is_burst, delta) = check_burst_from_history(
                        &mut state.burst_history,
                        account,
                        current_count,
                        threshold as u32,
                        window_secs as u64,
                    );

                    let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
                    let _ = sip_msg.set_pv_int("$var(burst_delta)", delta);

                    if is_burst {
                        state.stats.inc("burst_detected");
                        opensips_log!(DBG, "rust_concurrent_calls",
                            "burst detected for {}: delta={} threshold={}", account, delta, threshold);
                        1
                    } else {
                        -1
                    }
                }
                None => -2,
            }
        })
    })
}

// ── Script function: concurrent_reload() ────────────────────

unsafe extern "C" fn w_concurrent_reload(
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
                            // Clear live overrides on reload
                            state.limit_overrides.clear();
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

// ── Script function: concurrent_stats() ─────────────────────

unsafe extern "C" fn w_concurrent_stats(
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

// ── Script function: concurrent_calls_prometheus() ──

unsafe extern "C" fn w_concurrent_prometheus(
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
        let _ = sip_msg.set_pv("$var(concurrent_prom)", &prom);
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

// ── Native statistics array ────────────────────────────────────────

static MOD_STATS: SyncArray<sys::stat_export_, 6> = SyncArray([
    sys::stat_export_ { name: cstr_lit!("checked") as *mut _,      flags: 0,             stat_pointer: STAT_CHECKED.as_ptr() as *mut _ },
    sys::stat_export_ { name: cstr_lit!("allowed") as *mut _,      flags: 0,             stat_pointer: STAT_ALLOWED.as_ptr() as *mut _ },
    sys::stat_export_ { name: cstr_lit!("blocked") as *mut _,      flags: 0,             stat_pointer: STAT_BLOCKED.as_ptr() as *mut _ },
    sys::stat_export_ { name: cstr_lit!("active_calls") as *mut _, flags: STAT_NO_RESET, stat_pointer: STAT_ACTIVE_CALLS.as_ptr() as *mut _ },
    sys::stat_export_ { name: cstr_lit!("accounts") as *mut _,     flags: STAT_NO_RESET, stat_pointer: STAT_ACCOUNTS.as_ptr() as *mut _ },
    unsafe { std::mem::zeroed() }, // NULL terminator
]);

// ── MI command handlers ────────────────────────────────────────────

/// MI handler: rust_concurrent_calls:concurrent_show
/// Without `account` param: all accounts summary.
/// With `account` param: single account detail.
unsafe extern "C" fn mi_concurrent_show(
    params: *const sys::mi_params_,
    _async_hdl: *mut sys::mi_handler,
) -> *mut sys::mi_response_t {
    let filter = mi_try_get_string_param(params as *const mi_params_t, "account\0");

    // Active call counts come from STAT_ACTIVE_CALLS (SHM StatVar,
    // cross-worker aggregate). Per-account breakdown uses worker-local
    // data (accurate within the MI process's view) plus global stat.
    let default = DEFAULT_LIMIT.get().max(0) as u32;

    WORKER.with(|w| {
        let w = w.borrow();
        let limits_map = w.as_ref().map(|s| s.loader.get());
        let overrides = w.as_ref().map(|s| &s.limit_overrides);
        let empty_limits: HashMap<String, u32> = HashMap::new();
        let empty_overrides: HashMap<String, u32> = HashMap::new();
        let limits = limits_map.as_deref().unwrap_or(&empty_limits);
        let ovr = overrides.unwrap_or(&empty_overrides);

        if let Some(account) = filter {
            let limit = effective_limit(limits, ovr, &account, default);
            let Some(resp) = MiObject::new() else {
                return mi_error(-32000, "Failed to create MI response") as *mut _;
            };
            resp.add_str("account", &account);
            resp.add_num("limit", limit as f64);
            resp.into_raw() as *mut _
        } else {
            let Some(resp) = MiObject::new() else {
                return mi_error(-32000, "Failed to create MI response") as *mut _;
            };
            // List configured accounts with their limits
            let Some(arr) = resp.add_array("accounts") else {
                return mi_error(-32000, "Failed to create accounts array") as *mut _;
            };
            for (account, _) in limits.iter() {
                let eff = effective_limit(limits, ovr, account, default);
                if let Some(obj) = arr.add_object("") {
                    obj.add_str("account", account);
                    obj.add_num("limit", eff as f64);
                }
            }
            // Global active calls from cross-worker SHM stat
            if let Some(sv) = StatVar::from_raw(STAT_ACTIVE_CALLS.load(Ordering::Relaxed)) {
                resp.add_num("active_calls", sv.get() as f64);
            }
            resp.into_raw() as *mut _
        }
    })
}

/// MI handler: rust_concurrent_calls:concurrent_override
unsafe extern "C" fn mi_concurrent_override(
    params: *const sys::mi_params_,
    _async_hdl: *mut sys::mi_handler,
) -> *mut sys::mi_response_t {
    let Some(account) = mi_try_get_string_param(params as *const mi_params_t, "account\0") else {
        return mi_param_error() as *mut _;
    };
    let Some(limit_str) = mi_try_get_string_param(params as *const mi_params_t, "limit\0") else {
        return mi_param_error() as *mut _;
    };
    let Ok(limit) = limit_str.parse::<u32>() else {
        return mi_error(-32000, "Invalid limit value") as *mut _;
    };
    WORKER.with(|w| {
        let mut w = w.borrow_mut();
        let Some(state) = w.as_mut() else {
            return mi_error(-32000, "Worker not initialized") as *mut _;
        };
        state.limit_overrides.insert(account.clone(), limit);
        mi_ok() as *mut _
    })
}

/// MI handler: rust_concurrent_calls:concurrent_reset
unsafe extern "C" fn mi_concurrent_reset(
    params: *const sys::mi_params_,
    _async_hdl: *mut sys::mi_handler,
) -> *mut sys::mi_response_t {
    let filter = mi_try_get_string_param(params as *const mi_params_t, "account\0");
    WORKER.with(|w| {
        let mut w = w.borrow_mut();
        let Some(state) = w.as_mut() else {
            return mi_error(-32000, "Worker not initialized") as *mut _;
        };
        if let Some(ref account) = filter {
            state.counts.remove(account.as_str());
            state.inbound_counts.remove(account.as_str());
            state.outbound_counts.remove(account.as_str());
        } else {
            state.counts.clear();
            state.inbound_counts.clear();
            state.outbound_counts.clear();
        }
        mi_ok() as *mut _
    })
}

// ── MI command export array ────────────────────────────────────────

static MI_CMDS: SyncArray<sys::mi_export_, 4> = SyncArray([
    sys::mi_export_ {
        name: cstr_lit!("concurrent_show") as *mut _,
        help: cstr_lit!("Show concurrent call accounts and counts") as *mut _,
        flags: 0,
        init_f: None,
        recipes: {
            let mut r: [sys::mi_recipe_; 48] = unsafe { std::mem::zeroed() };
            r[0] = sys::mi_recipe_ {
                cmd: Some(mi_concurrent_show),
                params: unsafe { std::mem::zeroed() }, // no params (all accounts)
            };
            r[1] = sys::mi_recipe_ {
                cmd: Some(mi_concurrent_show),
                params: {
                    let mut p: [*mut u8; 20] = unsafe { std::mem::zeroed() };
                    p[0] = cstr_lit!("account") as *mut _;
                    p
                },
            };
            r
        },
        aliases: [ptr::null(); 4],
    },
    sys::mi_export_ {
        name: cstr_lit!("concurrent_override") as *mut _,
        help: cstr_lit!("Set temporary limit override for an account") as *mut _,
        flags: 0,
        init_f: None,
        recipes: {
            let mut r: [sys::mi_recipe_; 48] = unsafe { std::mem::zeroed() };
            r[0] = sys::mi_recipe_ {
                cmd: Some(mi_concurrent_override),
                params: {
                    let mut p: [*mut u8; 20] = unsafe { std::mem::zeroed() };
                    p[0] = cstr_lit!("account") as *mut _;
                    p[1] = cstr_lit!("limit") as *mut _;
                    p
                },
            };
            r
        },
        aliases: [ptr::null(); 4],
    },
    sys::mi_export_ {
        name: cstr_lit!("concurrent_reset") as *mut _,
        help: cstr_lit!("Reset call counts (all or single account)") as *mut _,
        flags: 0,
        init_f: None,
        recipes: {
            let mut r: [sys::mi_recipe_; 48] = unsafe { std::mem::zeroed() };
            r[0] = sys::mi_recipe_ {
                cmd: Some(mi_concurrent_reset),
                params: unsafe { std::mem::zeroed() }, // no params (all accounts)
            };
            r[1] = sys::mi_recipe_ {
                cmd: Some(mi_concurrent_reset),
                params: {
                    let mut p: [*mut u8; 20] = unsafe { std::mem::zeroed() };
                    p[0] = cstr_lit!("account") as *mut _;
                    p
                },
            };
            r
        },
        aliases: [ptr::null(); 4],
    },
    unsafe { std::mem::zeroed() }, // NULL terminator
]);

static CMDS: SyncArray<sys::cmd_export_, 12> = SyncArray([
    sys::cmd_export_ {
        name: cstr_lit!("check_concurrent"),
        function: Some(w_check_concurrent),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("concurrent_inc"),
        function: Some(w_concurrent_inc),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("concurrent_dec"),
        function: Some(w_concurrent_dec),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("concurrent_reload"),
        function: Some(w_concurrent_reload),
        params: EMPTY_PARAMS,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("concurrent_stats"),
        function: Some(w_concurrent_stats),
        params: EMPTY_PARAMS,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("check_burst"),
        function: Some(w_check_burst),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("concurrent_status"),
        function: Some(w_concurrent_status),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("concurrent_set_limit"),
        function: Some(w_concurrent_set_limit),
        params: TWO_STR_PARAMS,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("check_concurrent_inbound"),
        function: Some(w_check_concurrent_inbound),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("check_concurrent_outbound"),
        function: Some(w_check_concurrent_outbound),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("concurrent_prometheus"),
        function: Some(w_concurrent_prometheus),
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

static PARAMS: SyncArray<sys::param_export_, 12> = SyncArray([
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
    sys::param_export_ {
        name: cstr_lit!("auto_track"),
        type_: 2, // INT_PARAM
        param_pointer: AUTO_TRACK.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("account_var"),
        type_: 1, // STR_PARAM
        param_pointer: ACCOUNT_VAR.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("use_dialog_profiles"),
        type_: 2, // INT_PARAM
        param_pointer: USE_DIALOG_PROFILES.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("profile_name"),
        type_: 1, // STR_PARAM
        param_pointer: PROFILE_NAME.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("direction_aware"),
        type_: 2, // INT_PARAM
        param_pointer: DIRECTION_AWARE.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("cooldown_secs"),
        type_: 2, // INT_PARAM
        param_pointer: COOLDOWN_SECS.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("burst_threshold"),
        type_: 2, // INT_PARAM
        param_pointer: BURST_THRESHOLD.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("burst_window_secs"),
        type_: 2, // INT_PARAM
        param_pointer: BURST_WINDOW_SECS.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("publish_events"),
        type_: 2, // INT_PARAM
        param_pointer: PUBLISH_EVENTS.as_ptr(),
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

    // ── Dialog tracker integration tests (Task 39) ───────────────

    #[test]
    fn test_dialog_auto_track_inc_dec() {
        // Simulate automatic dialog tracking: created increments, terminated decrements.
        let mut counts = HashMap::new();
        let tracker: dialog::DialogTracker<CallDialogState> = dialog::DialogTracker::new(3600);

        // Simulate DLGCB_CREATED: increment and track
        let account = "alice";
        let call_id = "call-abc-123";
        increment(&mut counts, account);
        tracker.on_created(call_id);
        tracker.with_state(call_id, |s| {
            s.account = account.to_string();
        });

        assert_eq!(counts.get("alice"), Some(&1));
        assert!(tracker.contains(call_id));

        // Simulate DLGCB_TERMINATED: look up account, decrement
        let terminated_state = tracker.on_terminated(call_id);
        assert!(terminated_state.is_some());
        let acct = terminated_state.unwrap().account;
        assert_eq!(acct, "alice");
        decrement(&mut counts, &acct);

        assert_eq!(counts.get("alice"), Some(&0));
        assert!(!tracker.contains(call_id));
    }

    #[test]
    fn test_dialog_auto_track_multiple_calls() {
        let mut counts = HashMap::new();
        let tracker: dialog::DialogTracker<CallDialogState> = dialog::DialogTracker::new(3600);

        // Alice makes 3 calls
        for i in 0..3 {
            let call_id = format!("call-alice-{}", i);
            increment(&mut counts, "alice");
            tracker.on_created(&call_id);
            tracker.with_state(&call_id, |s| {
                s.account = "alice".to_string();
            });
        }
        assert_eq!(counts.get("alice"), Some(&3));
        assert_eq!(tracker.active_count(), 3);

        // Terminate first 2 calls
        for i in 0..2 {
            let call_id = format!("call-alice-{}", i);
            let state = tracker.on_terminated(&call_id).unwrap();
            decrement(&mut counts, &state.account);
        }
        assert_eq!(counts.get("alice"), Some(&1));
        assert_eq!(tracker.active_count(), 1);
    }

    #[test]
    fn test_dialog_auto_track_expired() {
        let mut counts = HashMap::new();
        let tracker: dialog::DialogTracker<CallDialogState> = dialog::DialogTracker::new(3600);

        increment(&mut counts, "bob");
        tracker.on_created("call-expired");
        tracker.with_state("call-expired", |s| {
            s.account = "bob".to_string();
        });

        // Dialog expires (not terminated)
        let state = tracker.on_expired("call-expired").unwrap();
        decrement(&mut counts, &state.account);
        assert_eq!(counts.get("bob"), Some(&0));
    }

    #[test]
    fn test_dialog_auto_track_unknown_terminated() {
        // TERMINATED for a dialog we never tracked should be a no-op
        let tracker: dialog::DialogTracker<CallDialogState> = dialog::DialogTracker::new(3600);
        let result = tracker.on_terminated("never-seen");
        assert!(result.is_none());
    }

    #[test]
    fn test_dialog_auto_track_with_limits() {
        let mut counts = HashMap::new();
        let mut limits = HashMap::new();
        limits.insert("alice".to_string(), 2);
        let tracker: dialog::DialogTracker<CallDialogState> = dialog::DialogTracker::new(3600);

        // Simulate: check, then auto-inc on CREATED
        let (allowed, _, _) = check_limit(&counts, &limits, "alice", 10);
        assert!(allowed);
        increment(&mut counts, "alice");
        tracker.on_created("c1");
        tracker.with_state("c1", |s| s.account = "alice".to_string());

        let (allowed, _, _) = check_limit(&counts, &limits, "alice", 10);
        assert!(allowed);
        increment(&mut counts, "alice");
        tracker.on_created("c2");
        tracker.with_state("c2", |s| s.account = "alice".to_string());

        // Third call should be blocked
        let (allowed, count, limit) = check_limit(&counts, &limits, "alice", 10);
        assert!(!allowed);
        assert_eq!(count, 2);
        assert_eq!(limit, 2);

        // First call ends
        let state = tracker.on_terminated("c1").unwrap();
        decrement(&mut counts, &state.account);

        // Now allowed again
        let (allowed, count, _) = check_limit(&counts, &limits, "alice", 10);
        assert!(allowed);
        assert_eq!(count, 1);
    }

    // ── Dialog profile check tests (Task 40) ────────────────────

    #[test]
    fn test_check_limit_with_profile_count_under() {
        let mut limits = HashMap::new();
        limits.insert("alice".to_string(), 5);
        let (allowed, count, limit) = check_limit_with_profile_count(2, &limits, "alice", 10);
        assert!(allowed);
        assert_eq!(count, 2);
        assert_eq!(limit, 5);
    }

    #[test]
    fn test_check_limit_with_profile_count_at_limit() {
        let mut limits = HashMap::new();
        limits.insert("alice".to_string(), 5);
        let (allowed, count, limit) = check_limit_with_profile_count(5, &limits, "alice", 10);
        assert!(!allowed);
        assert_eq!(count, 5);
        assert_eq!(limit, 5);
    }

    #[test]
    fn test_check_limit_with_profile_count_over() {
        let mut limits = HashMap::new();
        limits.insert("alice".to_string(), 5);
        let (allowed, count, limit) = check_limit_with_profile_count(7, &limits, "alice", 10);
        assert!(!allowed);
        assert_eq!(count, 7);
        assert_eq!(limit, 5);
    }

    #[test]
    fn test_check_limit_with_profile_count_default_limit() {
        let limits = HashMap::new();
        let (allowed, count, limit) = check_limit_with_profile_count(0, &limits, "unknown", 10);
        assert!(allowed);
        assert_eq!(count, 0);
        assert_eq!(limit, 10);
    }

    #[test]
    fn test_check_limit_with_profile_count_zero_limit() {
        let mut limits = HashMap::new();
        limits.insert("blocked".to_string(), 0);
        let (allowed, count, limit) = check_limit_with_profile_count(0, &limits, "blocked", 10);
        assert!(!allowed);
        assert_eq!(count, 0);
        assert_eq!(limit, 0);
    }

    #[test]
    fn test_profile_vs_local_different_counts() {
        // Simulate: local count is 1 (this worker), profile count is 5 (all workers)
        let mut counts = HashMap::new();
        counts.insert("alice".to_string(), 1);
        let mut limits = HashMap::new();
        limits.insert("alice".to_string(), 5);

        // Local check says allowed (1 < 5)
        let (local_allowed, _, _) = check_limit(&counts, &limits, "alice", 10);
        assert!(local_allowed);

        // Profile check says blocked (5 >= 5)
        let (profile_allowed, _, _) = check_limit_with_profile_count(5, &limits, "alice", 10);
        assert!(!profile_allowed);
    }

    // ── Burst detection tests (Task 44) ──────────────────────────

    #[test]
    fn test_burst_empty_history() {
        let mut history: HashMap<String, VecDeque<(Instant, u32)>> = HashMap::new();
        let (is_burst, delta) = check_burst_from_history(&mut history, "alice", 5, 3, 10);
        assert!(!is_burst);
        assert_eq!(delta, 0);
    }

    #[test]
    fn test_burst_single_snapshot() {
        let mut history: HashMap<String, VecDeque<(Instant, u32)>> = HashMap::new();
        record_burst_snapshot(&mut history, "alice", 2);
        let (is_burst, delta) = check_burst_from_history(&mut history, "alice", 2, 3, 10);
        assert!(!is_burst);
        assert_eq!(delta, 0);
    }

    #[test]
    fn test_burst_detected() {
        let mut history: HashMap<String, VecDeque<(Instant, u32)>> = HashMap::new();
        record_burst_snapshot(&mut history, "alice", 1);
        // Current count jumped to 5 (delta = 4, threshold = 3)
        let (is_burst, delta) = check_burst_from_history(&mut history, "alice", 5, 3, 10);
        assert!(is_burst);
        assert_eq!(delta, 4);
    }

    #[test]
    fn test_burst_not_detected_below_threshold() {
        let mut history: HashMap<String, VecDeque<(Instant, u32)>> = HashMap::new();
        record_burst_snapshot(&mut history, "alice", 3);
        // Current count is 5 (delta = 2, threshold = 3)
        let (is_burst, delta) = check_burst_from_history(&mut history, "alice", 5, 3, 10);
        assert!(!is_burst);
        assert_eq!(delta, 2);
    }

    #[test]
    fn test_burst_at_threshold() {
        let mut history: HashMap<String, VecDeque<(Instant, u32)>> = HashMap::new();
        record_burst_snapshot(&mut history, "alice", 2);
        // Current count is 5 (delta = 3, threshold = 3)
        let (is_burst, delta) = check_burst_from_history(&mut history, "alice", 5, 3, 10);
        assert!(is_burst);
        assert_eq!(delta, 3);
    }

    #[test]
    fn test_burst_window_expiry() {
        let mut history: HashMap<String, VecDeque<(Instant, u32)>> = HashMap::new();
        // Insert old snapshot (2 seconds ago)
        let old_time = Instant::now() - std::time::Duration::from_secs(2);
        history.entry("alice".to_string())
            .or_default()
            .push_back((old_time, 1));
        // With 1-second window, the old snapshot should be pruned
        let (is_burst, delta) = check_burst_from_history(&mut history, "alice", 5, 3, 1);
        // After pruning, no snapshots remain, so no burst
        assert!(!is_burst);
        assert_eq!(delta, 0);
    }

    #[test]
    fn test_burst_per_account() {
        let mut history: HashMap<String, VecDeque<(Instant, u32)>> = HashMap::new();
        record_burst_snapshot(&mut history, "alice", 1);
        record_burst_snapshot(&mut history, "bob", 10);

        let (alice_burst, _) = check_burst_from_history(&mut history, "alice", 5, 3, 10);
        assert!(alice_burst); // delta = 4 >= 3

        let (bob_burst, _) = check_burst_from_history(&mut history, "bob", 11, 3, 10);
        assert!(!bob_burst); // delta = 1 < 3
    }

    #[test]
    fn test_burst_negative_delta() {
        let mut history: HashMap<String, VecDeque<(Instant, u32)>> = HashMap::new();
        record_burst_snapshot(&mut history, "alice", 10);
        // Count went down (calls ended)
        let (is_burst, delta) = check_burst_from_history(&mut history, "alice", 5, 3, 10);
        assert!(!is_burst);
        assert_eq!(delta, -5);
    }

    #[test]
    fn test_record_burst_snapshot() {
        let mut history: HashMap<String, VecDeque<(Instant, u32)>> = HashMap::new();
        record_burst_snapshot(&mut history, "alice", 1);
        record_burst_snapshot(&mut history, "alice", 2);
        record_burst_snapshot(&mut history, "alice", 3);
        assert_eq!(history.get("alice").unwrap().len(), 3);
    }

    // ── Cooldown tests (Task 43) ─────────────────────────────────

    #[test]
    fn test_cooldown_disabled() {
        let cooldowns = HashMap::new();
        assert!(!is_in_cooldown(&cooldowns, "alice", 0));
    }

    #[test]
    fn test_cooldown_not_set() {
        let cooldowns = HashMap::new();
        assert!(!is_in_cooldown(&cooldowns, "alice", 30));
    }

    #[test]
    fn test_cooldown_active() {
        let mut cooldowns = HashMap::new();
        set_cooldown(&mut cooldowns, "alice");
        // Just set, should still be in cooldown
        assert!(is_in_cooldown(&cooldowns, "alice", 30));
    }

    #[test]
    fn test_cooldown_expired() {
        let mut cooldowns: HashMap<String, Instant> = HashMap::new();
        // Insert a cooldown that started 2 seconds ago
        cooldowns.insert("alice".to_string(), Instant::now() - std::time::Duration::from_secs(2));
        // With 1-second cooldown, it should be expired
        assert!(!is_in_cooldown(&cooldowns, "alice", 1));
    }

    #[test]
    fn test_cooldown_per_account() {
        let mut cooldowns = HashMap::new();
        set_cooldown(&mut cooldowns, "alice");
        assert!(is_in_cooldown(&cooldowns, "alice", 30));
        assert!(!is_in_cooldown(&cooldowns, "bob", 30));
    }

    #[test]
    fn test_cooldown_set_overwrites() {
        let mut cooldowns = HashMap::new();
        set_cooldown(&mut cooldowns, "alice");
        std::thread::sleep(std::time::Duration::from_millis(10));
        set_cooldown(&mut cooldowns, "alice"); // reset
        // Should still be in cooldown
        assert!(is_in_cooldown(&cooldowns, "alice", 30));
    }

    #[test]
    fn test_cooldown_integration_with_limits() {
        let mut counts = HashMap::new();
        let mut limits = HashMap::new();
        limits.insert("alice".to_string(), 2);
        let mut cooldowns: HashMap<String, Instant> = HashMap::new();

        // First two calls allowed
        increment(&mut counts, "alice");
        increment(&mut counts, "alice");

        // Third blocked (at limit)
        let (allowed, _, _) = check_limit(&counts, &limits, "alice", 10);
        assert!(!allowed);

        // Set cooldown
        set_cooldown(&mut cooldowns, "alice");

        // Even after decrement, cooldown blocks
        decrement(&mut counts, "alice");
        assert!(is_in_cooldown(&cooldowns, "alice", 30));
    }

    // ── MI status and limit override tests (Task 42) ────────────

    #[test]
    fn test_build_status_json() {
        let json = build_status_json("alice", 3, 5, 2, 1);
        assert_eq!(json, r#"{"account":"alice","count":3,"limit":5,"direction":{"inbound":2,"outbound":1}}"#);
    }

    #[test]
    fn test_build_status_json_zeros() {
        let json = build_status_json("bob", 0, 10, 0, 0);
        assert_eq!(json, r#"{"account":"bob","count":0,"limit":10,"direction":{"inbound":0,"outbound":0}}"#);
    }

    #[test]
    fn test_effective_limit_override() {
        let mut limits = HashMap::new();
        limits.insert("alice".to_string(), 5);
        let mut overrides = HashMap::new();
        overrides.insert("alice".to_string(), 20);

        // Override takes precedence
        let limit = effective_limit(&limits, &overrides, "alice", 10);
        assert_eq!(limit, 20);
    }

    #[test]
    fn test_effective_limit_no_override() {
        let mut limits = HashMap::new();
        limits.insert("alice".to_string(), 5);
        let overrides = HashMap::new();

        // No override, use file limit
        let limit = effective_limit(&limits, &overrides, "alice", 10);
        assert_eq!(limit, 5);
    }

    #[test]
    fn test_effective_limit_default() {
        let limits = HashMap::new();
        let overrides = HashMap::new();

        // No file limit, no override, use default
        let limit = effective_limit(&limits, &overrides, "unknown", 10);
        assert_eq!(limit, 10);
    }

    #[test]
    fn test_effective_limit_override_zero_blocks() {
        let mut limits = HashMap::new();
        limits.insert("alice".to_string(), 5);
        let mut overrides = HashMap::new();
        overrides.insert("alice".to_string(), 0);

        let limit = effective_limit(&limits, &overrides, "alice", 10);
        assert_eq!(limit, 0);
    }

    #[test]
    fn test_override_cleared_on_reload() {
        // Simulate: set override, then clear (as reload would do)
        let mut overrides = HashMap::new();
        overrides.insert("alice".to_string(), 99);
        assert_eq!(overrides.get("alice"), Some(&99));

        overrides.clear();
        assert!(overrides.is_empty());
    }

    #[test]
    fn test_override_with_check_limit() {
        let mut counts = HashMap::new();
        counts.insert("alice".to_string(), 3);
        let mut limits = HashMap::new();
        limits.insert("alice".to_string(), 5);
        let mut overrides = HashMap::new();

        // Without override: 3 < 5, allowed
        let eff = effective_limit(&limits, &overrides, "alice", 10);
        assert!(counts.get("alice").copied().unwrap_or(0) < eff);

        // With override to 2: 3 >= 2, blocked
        overrides.insert("alice".to_string(), 2);
        let eff = effective_limit(&limits, &overrides, "alice", 10);
        assert!(counts.get("alice").copied().unwrap_or(0) >= eff);
    }

    // ── Direction-aware limit tests (Task 41) ────────────────────

    #[test]
    fn test_parse_direction_limit_entry() {
        let result = parse_direction_limit_entry("alice,5,3");
        assert_eq!(result, Some(("alice".to_string(), DirectionLimits { inbound: 5, outbound: 3 })));
    }

    #[test]
    fn test_parse_direction_limit_whitespace() {
        let result = parse_direction_limit_entry("  bob , 10 , 5 ");
        assert_eq!(result, Some(("bob".to_string(), DirectionLimits { inbound: 10, outbound: 5 })));
    }

    #[test]
    fn test_parse_direction_limit_invalid() {
        assert_eq!(parse_direction_limit_entry("alice,5"), None);
        assert_eq!(parse_direction_limit_entry("alice,abc,3"), None);
        assert_eq!(parse_direction_limit_entry(",5,3"), None);
    }

    #[test]
    fn test_build_direction_limits() {
        let entries = vec![
            "alice,5,3".to_string(),
            "trunk-1,100,50".to_string(),
        ];
        let limits = build_direction_limits(entries);
        assert_eq!(limits.len(), 2);
        assert_eq!(limits.get("alice"), Some(&DirectionLimits { inbound: 5, outbound: 3 }));
        assert_eq!(limits.get("trunk-1"), Some(&DirectionLimits { inbound: 100, outbound: 50 }));
    }

    #[test]
    fn test_check_inbound_limit_under() {
        let mut counts = HashMap::new();
        counts.insert("alice".to_string(), 2);
        let mut limits = HashMap::new();
        limits.insert("alice".to_string(), DirectionLimits { inbound: 5, outbound: 3 });

        let (allowed, count, limit) = check_inbound_limit(&counts, &limits, "alice", 10);
        assert!(allowed);
        assert_eq!(count, 2);
        assert_eq!(limit, 5);
    }

    #[test]
    fn test_check_inbound_limit_at() {
        let mut counts = HashMap::new();
        counts.insert("alice".to_string(), 5);
        let mut limits = HashMap::new();
        limits.insert("alice".to_string(), DirectionLimits { inbound: 5, outbound: 3 });

        let (allowed, _, _) = check_inbound_limit(&counts, &limits, "alice", 10);
        assert!(!allowed);
    }

    #[test]
    fn test_check_outbound_limit_under() {
        let mut counts = HashMap::new();
        counts.insert("alice".to_string(), 1);
        let mut limits = HashMap::new();
        limits.insert("alice".to_string(), DirectionLimits { inbound: 5, outbound: 3 });

        let (allowed, count, limit) = check_outbound_limit(&counts, &limits, "alice", 10);
        assert!(allowed);
        assert_eq!(count, 1);
        assert_eq!(limit, 3);
    }

    #[test]
    fn test_check_outbound_limit_at() {
        let mut counts = HashMap::new();
        counts.insert("alice".to_string(), 3);
        let mut limits = HashMap::new();
        limits.insert("alice".to_string(), DirectionLimits { inbound: 5, outbound: 3 });

        let (allowed, _, _) = check_outbound_limit(&counts, &limits, "alice", 10);
        assert!(!allowed);
    }

    #[test]
    fn test_direction_default_limit() {
        let counts = HashMap::new();
        let limits: HashMap<String, DirectionLimits> = HashMap::new();

        let (allowed, _, limit) = check_inbound_limit(&counts, &limits, "unknown", 10);
        assert!(allowed);
        assert_eq!(limit, 10);

        let (allowed, _, limit) = check_outbound_limit(&counts, &limits, "unknown", 10);
        assert!(allowed);
        assert_eq!(limit, 10);
    }

    #[test]
    fn test_direction_asymmetric_limits() {
        // Inbound limit 100, outbound limit 5
        let mut limits = HashMap::new();
        limits.insert("trunk".to_string(), DirectionLimits { inbound: 100, outbound: 5 });

        let mut in_counts = HashMap::new();
        in_counts.insert("trunk".to_string(), 50);

        let mut out_counts = HashMap::new();
        out_counts.insert("trunk".to_string(), 5);

        // Inbound: 50 < 100, allowed
        let (allowed, _, _) = check_inbound_limit(&in_counts, &limits, "trunk", 10);
        assert!(allowed);

        // Outbound: 5 >= 5, blocked
        let (allowed, _, _) = check_outbound_limit(&out_counts, &limits, "trunk", 10);
        assert!(!allowed);
    }

    #[test]
    fn test_profile_count_matches_cross_worker_total() {
        // Simulate 3 workers each with 2 calls = 6 total
        let mut limits = HashMap::new();
        limits.insert("alice".to_string(), 10);

        // Each worker sees only its own 2 calls
        let mut w1_counts = HashMap::new();
        w1_counts.insert("alice".to_string(), 2);
        let (w1_allowed, w1_count, _) = check_limit(&w1_counts, &limits, "alice", 10);
        assert!(w1_allowed);
        assert_eq!(w1_count, 2);

        // Profile-based check sees all 6
        let (profile_allowed, profile_count, _) = check_limit_with_profile_count(6, &limits, "alice", 10);
        assert!(profile_allowed);
        assert_eq!(profile_count, 6);
    }

    #[test]
    fn test_dialog_auto_track_mixed_accounts() {
        let mut counts = HashMap::new();
        let tracker: dialog::DialogTracker<CallDialogState> = dialog::DialogTracker::new(3600);

        // Alice and Bob both make calls
        increment(&mut counts, "alice");
        tracker.on_created("call-a1");
        tracker.with_state("call-a1", |s| s.account = "alice".to_string());

        increment(&mut counts, "bob");
        tracker.on_created("call-b1");
        tracker.with_state("call-b1", |s| s.account = "bob".to_string());

        assert_eq!(counts.get("alice"), Some(&1));
        assert_eq!(counts.get("bob"), Some(&1));

        // Bob's call ends
        let state = tracker.on_terminated("call-b1").unwrap();
        assert_eq!(state.account, "bob");
        decrement(&mut counts, &state.account);

        assert_eq!(counts.get("alice"), Some(&1));
        assert_eq!(counts.get("bob"), Some(&0));
    }

    // ── event publishing tests ──────────────────────────────────

    #[test]
    fn test_event_payload_concurrent_limit() {
        let payload = event::format_payload(&[
            ("account", &event::json_str("alice")),
            ("count", "10"),
            ("limit", "10"),
        ]);
        assert!(payload.contains(r#""account":"alice""#));
        assert!(payload.contains(r#""count":10"#));
        assert!(payload.contains(r#""limit":10"#));
    }

    #[test]
    fn test_event_payload_concurrent_burst() {
        let payload = event::format_payload(&[
            ("account", &event::json_str("bob")),
            ("recent_count", "5"),
            ("threshold", "3"),
        ]);
        assert!(payload.contains(r#""account":"bob""#));
        assert!(payload.contains(r#""recent_count":5"#));
    }
}
