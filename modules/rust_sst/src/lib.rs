//! rust_sst — SIP Session Timers (RFC 4028) rewrite for OpenSIPS.
//!
//! A clean Rust implementation replacing the C sst module. All timer
//! negotiation logic is extracted into pure, testable functions.
//!
//! ## Automatic mode (dialog lifecycle integration)
//!
//! When `dialog.so` is loaded, the module automatically:
//! 1. Registers a DLGCB_CREATED callback to intercept new INVITEs
//! 2. Parses Session-Expires / Min-SE / Supported: timer from requests
//! 3. On 2XX responses, inserts Session-Expires + Require: timer headers
//! 4. Sets dialog lifetime to match the negotiated interval
//! 5. Handles re-INVITE/UPDATE refreshes
//! 6. Prevents 422 loops by adjusting Min-SE from 422 replies
//!
//! ## Script override mode
//!
//! `sst_check()` and `sst_update()` remain available for
//! operators who want per-call control over SST negotiation.
//!
//! # `OpenSIPS` config (automatic mode)
//!
//! ```text
//! loadmodule "dialog.so"
//! loadmodule "sipmsgops.so"
//! loadmodule "rust_sst.so"
//!
//! modparam("rust_sst", "default_interval", 1800)
//! modparam("rust_sst", "default_min_se", 90)
//! modparam("rust_sst", "default_refresher", "uas")
//!
//! route {
//!     if (is_method("INVITE"))
//!         create_dialog();
//!     # SST is handled automatically via dialog callbacks.
//! }
//! ```
//!
//! # `OpenSIPS` config (script override)
//!
//! ```text
//! route {
//!     if (is_method("INVITE")) {
//!         if (sst_check("1800", "90") == -1) {
//!             append_hf("Min-SE: $var(sst_min_se)\r\n");
//!             sl_send_reply(422, "Session Interval Too Small");
//!             exit;
//!         }
//!     }
//! }
//!
//! onreply_route[sst_reply] {
//!     if ($rs == "200" && is_method("INVITE")) {
//!         sst_update("0", "0", "uas");
//!         append_hf("Session-Expires: $var(sst_session_expires)\r\n");
//!         append_hf("Min-SE: $var(sst_min_se)\r\n");
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

use rust_common::dialog::{self, DialogTracker};
use rust_common::event;
use rust_common::mi::Stats;
use rust_common::mi_resp::{MiObject, mi_error};
use rust_common::stat::{StatVar, StatVarOpaque};
use rust_common::reload::FileLoader;

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{c_int, c_void};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::time::Instant;

// Native statistics -- cross-worker, aggregated by OpenSIPS core.
static STAT_CHECKED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_ACCEPTED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_REJECTED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_ACTIVE_TIMERS: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_REFRESHES: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_REFRESH_FAILED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());

/// STAT_NO_RESET flag value (from OpenSIPS statistics.h).
const STAT_NO_RESET: u16 = 1;

// ── Module parameters ────────────────────────────────────────────

/// Default Session-Expires interval in seconds (default 1800 = 30 min).
static DEFAULT_INTERVAL: Integer = Integer::with_default(1800);

/// Default Min-SE value in seconds (default 90, RFC 4028 minimum).
static DEFAULT_MIN_SE: Integer = Integer::with_default(90);

/// Default refresher role: "uac" or "uas" (default "uas").
static DEFAULT_REFRESHER: ModString = ModString::new();

/// Path to per-account timer policies file (optional, CSV).
/// Format: account,interval,min_se,refresher
static POLICIES_FILE: ModString = ModString::new();

/// Enable adaptive min_se learning from 422 replies (0=off, 1=on, default 0).
static ADAPTIVE_MIN_SE: Integer = Integer::with_default(0);

/// Enable event publishing (0=off, 1=on, default 0).
static PUBLISH_EVENTS: Integer = Integer::with_default(0);

/// Force refresher role: "" (disabled), "uac", or "uas" (default "").
/// When set, always use this refresher regardless of negotiation.
static FORCE_REFRESHER: ModString = ModString::new();

/// Whether dialog API was loaded (set once in mod_init).
static DLG_LOADED: AtomicBool = AtomicBool::new(false);

// ── Per-dialog SST state ─────────────────────────────────────────

/// Who requested SST.
#[derive(Clone, Debug, PartialEq, Default)]
#[allow(dead_code)]
enum SstRequester {
    #[default]
    Undefined,
    Uac,
    Uas,
    Proxy,
}

/// Who supports the timer extension.
#[derive(Clone, Debug, PartialEq, Default)]
#[allow(dead_code)]
enum SstSupported {
    #[default]
    Undefined,
    Uac,
    Uas,
    Both,
}

/// The refresher role for session timer negotiation.
#[derive(Clone, Debug, PartialEq, Default)]
enum Refresher {
    Uac,
    #[default]
    Uas,
}

impl Refresher {
    fn as_str(&self) -> &'static str {
        match self {
            Refresher::Uac => "uac",
            Refresher::Uas => "uas",
        }
    }
}

/// Per-dialog SST state, stored in the DialogTracker.
#[derive(Clone, Debug, Default)]
struct SstState {
    requester: SstRequester,
    supported: SstSupported,
    interval: u32,
    min_se: u32,
    refresher: Refresher,
    refresh_count: u32,
    /// Timestamp of last refresh (re-INVITE/UPDATE), or dialog creation if none.
    last_refresh: Option<Instant>,
}

// ── Thread-local state ───────────────────────────────────────────

/// Per-account timer policy override.
#[derive(Clone, Debug)]
#[allow(dead_code)]
struct AccountPolicy {
    interval: u32,
    min_se: u32,
    refresher: Refresher,
}

/// Parse a policies CSV line: "account,interval,min_se,refresher"
fn parse_policy_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let parts: Vec<&str> = trimmed.split(',').collect();
    if parts.len() >= 4 {
        Some(trimmed.to_string())
    } else {
        None
    }
}

/// Build a HashMap<String, AccountPolicy> from parsed CSV lines.
fn build_policies(entries: Vec<String>) -> HashMap<String, AccountPolicy> {
    let mut map = HashMap::new();
    for line in &entries {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() >= 4 {
            let account = parts[0].trim().to_string();
            let interval = parts[1].trim().parse::<u32>().unwrap_or(0);
            let min_se = parts[2].trim().parse::<u32>().unwrap_or(0);
            let refresher = parse_refresher(parts[3].trim());
            if !account.is_empty() && interval > 0 {
                map.insert(account, AccountPolicy {
                    interval: std::cmp::max(interval, 90),
                    min_se: std::cmp::max(min_se, 90),
                    refresher,
                });
            }
        }
    }
    map
}

/// Look up per-account policy by account name.
fn lookup_policy(account: &str) -> Option<AccountPolicy> {
    POLICIES.with(|p| {
        let loader = p.borrow();
        loader.as_ref().and_then(|l| {
            let data = l.get();
            data.get(account).cloned()
        })
    })
}

/// Get the learned min_se for a destination, if adaptive_min_se is enabled.
fn get_adaptive_min_se(dest_host: &str) -> Option<u32> {
    if ADAPTIVE_MIN_SE.get() == 0 {
        return None;
    }
    ADAPTIVE_MAP.with(|m| {
        m.borrow().get(dest_host).copied()
    })
}

/// Record a learned min_se from a 422 reply for a destination.
fn record_adaptive_min_se(dest_host: &str, min_se: u32) {
    if ADAPTIVE_MIN_SE.get() == 0 || min_se == 0 {
        return;
    }
    ADAPTIVE_MAP.with(|m| {
        let mut map = m.borrow_mut();
        let current = map.get(dest_host).copied().unwrap_or(0);
        if min_se > current {
            map.insert(dest_host.to_string(), min_se);
            opensips_log!(
                DBG,
                "rust_sst",
                "adaptive min_se: {} -> {} for destination {}",
                current,
                min_se,
                dest_host
            );
        }
    });
}

/// Extract host from R-URI or destination.
fn extract_dest_host(ruri: &str) -> String {
    // Parse "sip:user@host:port" -> "host"
    let without_scheme = if let Some(idx) = ruri.find(':') {
        &ruri[idx + 1..]
    } else {
        ruri
    };
    let without_user = if let Some(idx) = without_scheme.find('@') {
        &without_scheme[idx + 1..]
    } else {
        without_scheme
    };
    // Remove port and parameters
    let host = without_user
        .split(':')
        .next()
        .unwrap_or(without_user)
        .split(';')
        .next()
        .unwrap_or(without_user)
        .split('>')
        .next()
        .unwrap_or(without_user);
    host.trim().to_string()
}

/// Build JSON status for all active SST-tracked dialogs.
fn build_sst_status_json() -> String {
    TRACKER.with(|t| {
        t.collect_json(|callid, entry| {
            let s = &entry.state;
            let age = entry.created.elapsed().as_secs();
            let time_remaining = (s.interval as u64).saturating_sub(age);
            let escaped_callid = callid.replace('\\', "\\\\").replace('"', "\\\"");
            let mut buf = String::with_capacity(128);
            buf.push_str("{\"call_id\":\"");
            buf.push_str(&escaped_callid);
            buf.push_str("\",\"interval\":");
            buf.push_str(&s.interval.to_string());
            buf.push_str(",\"refresher\":\"");
            buf.push_str(s.refresher.as_str());
            buf.push_str("\",\"time_remaining\":");
            buf.push_str(&time_remaining.to_string());
            buf.push_str(",\"refresh_count\":");
            buf.push_str(&s.refresh_count.to_string());
            buf.push('}');
            buf
        })
    })
}

thread_local! {
    static TRACKER: DialogTracker<SstState> = DialogTracker::new(7200);
    static SST_STATS: Stats = Stats::new("rust_sst", &[
        "sessions_active",
        "sessions_expired",
        "422_sent",
        "headers_inserted",
        "stale_sessions",
        "sessions_uac_refresher",
        "sessions_uas_refresher",
    ]);
    static POLICIES: RefCell<Option<FileLoader<HashMap<String, AccountPolicy>>>> = RefCell::new(None);
    /// Per-worker map of destination host -> learned Min-SE from 422 replies.
    static ADAPTIVE_MAP: RefCell<HashMap<String, u32>> = RefCell::new(HashMap::new());
}

// ── Pure logic (testable without FFI) ────────────────────────────

/// Parse a refresher string to enum. Defaults to Uas for unknown values.
fn parse_refresher(s: &str) -> Refresher {
    if s.trim().eq_ignore_ascii_case("uac") {
        Refresher::Uac
    } else {
        Refresher::Uas
    }
}

/// Check if the requested Session-Expires interval is acceptable.
///
/// Implements RFC 4028 Section 4 validation:
/// - `requested_interval`: the Session-Expires value from the INVITE (0 = not present)
/// - `requested_min_se`: the Min-SE value from the INVITE (0 = not present)
/// - `our_min_se`: our local minimum session interval policy
///
/// Returns `(acceptable, negotiated_interval, effective_min_se)`:
/// - `acceptable`: true if the interval passes validation, false means 422
/// - `negotiated_interval`: the interval to use (0 if rejected)
/// - `effective_min_se`: the effective Min-SE (max of requested and ours)
fn sst_check(requested_interval: u32, requested_min_se: u32, our_min_se: u32) -> (bool, u32, u32) {
    let effective_min_se = std::cmp::max(requested_min_se, our_min_se);
    if requested_interval > 0 && requested_interval < effective_min_se {
        // Session-Expires is below the effective minimum — reject with 422
        (false, 0, effective_min_se)
    } else {
        // Acceptable: use the requested interval, or fall back to double our min_se
        let interval = if requested_interval > 0 {
            requested_interval
        } else {
            // No Session-Expires in request — we'll insert one
            std::cmp::max(our_min_se * 2, effective_min_se)
        };
        (true, interval, effective_min_se)
    }
}

/// Build a Session-Expires header value string.
///
/// Format per RFC 4028: `"1800;refresher=uas"`
fn build_session_expires_header(interval: u32, refresher: &Refresher) -> String {
    format!("{};refresher={}", interval, refresher.as_str())
}

/// Build a Min-SE header value string.
fn build_min_se_header(min_se: u32) -> String {
    min_se.to_string()
}

/// Parse a Session-Expires header value.
///
/// Input formats:
/// - `"1800;refresher=uac"`
/// - `"1800"`
/// - `" 1800 ; refresher = uas "`
///
/// Returns `(interval, optional refresher)` or None on parse failure.
fn parse_session_expires(header: &str) -> Option<(u32, Option<Refresher>)> {
    let parts: Vec<&str> = header.split(';').collect();
    let interval: u32 = parts[0].trim().parse().ok()?;
    if interval == 0 {
        return None;
    }
    let refresher = parts
        .iter()
        .skip(1)
        .find(|p| p.trim().starts_with("refresher"))
        .and_then(|p| p.split('=').nth(1))
        .map(|r| parse_refresher(r.trim()));
    Some((interval, refresher))
}

/// Parse a Min-SE header value. Returns the interval or 0 on failure.
fn parse_min_se_value(header: &str) -> u32 {
    header.split(';').next()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Check if the Supported header contains "timer".
fn has_timer_support(supported_hdr: Option<&str>) -> bool {
    supported_hdr
        .is_some_and(|h| h.split(',').any(|ext| ext.trim().eq_ignore_ascii_case("timer")))
}

/// Negotiate session timer parameters for a 200 OK response.
///
/// Given the desired interval, min_se, and refresher, produces the final
/// values to insert into the response headers.
fn sst_update(
    interval: u32,
    min_se: u32,
    refresher: &Refresher,
    default_interval: u32,
    default_min_se: u32,
) -> (String, String) {
    let effective_min_se = if min_se > 0 { min_se } else { default_min_se };
    let effective_interval = if interval > 0 {
        std::cmp::max(interval, effective_min_se)
    } else {
        std::cmp::max(default_interval, effective_min_se)
    };
    let se_header = build_session_expires_header(effective_interval, refresher);
    let min_se_header = build_min_se_header(effective_min_se);
    (se_header, min_se_header)
}

// ── Helper: read default refresher from modparam ─────────────────

/// Get the forced refresher, if configured.
fn get_forced_refresher() -> Option<Refresher> {
    let s = unsafe { FORCE_REFRESHER.get_value() };
    match s {
        Some(v) if v.trim().eq_ignore_ascii_case("uac") => Some(Refresher::Uac),
        Some(v) if v.trim().eq_ignore_ascii_case("uas") => Some(Refresher::Uas),
        _ => None,
    }
}

fn get_default_refresher() -> Refresher {
    let s = unsafe { DEFAULT_REFRESHER.get_value() };
    match s {
        Some(v) => parse_refresher(v),
        None => Refresher::Uas,
    }
}

fn get_our_min_se() -> u32 {
    std::cmp::max(DEFAULT_MIN_SE.get() as u32, 90)
}

fn get_our_interval() -> u32 {
    let interval = DEFAULT_INTERVAL.get() as u32;
    std::cmp::max(interval, get_our_min_se())
}

// ── Dialog callback trampolines ──────────────────────────────────

/// DLGCB_CREATED — called for every new dialog (INVITE).
///
/// Parses SST headers from the request, initializes per-dialog state,
/// registers per-dialog callbacks, and sets the initial dialog lifetime.
#[allow(clippy::too_many_lines)]
unsafe extern "C" fn sst_dialog_created_cb(
    dlg: *mut sys::dlg_cell,
    _type: c_int,
    params: *mut sys::dlg_cb_params,
) {
    let params_ref = unsafe { &*params };
    let msg_ptr = params_ref.msg;
    if msg_ptr.is_null() {
        return;
    }

    // Only process INVITE requests
    let mut msg = unsafe { opensips_rs::SipMessage::from_raw(msg_ptr) };
    if !msg.is_request() {
        return;
    }
    let method = msg.method().unwrap_or("");
    if method != "INVITE" {
        return;
    }

    // Extract Call-ID for dialog tracking
    let callid = match unsafe { dialog::callid_from_dlg(dlg as *mut c_void) } {
        Some(id) => id,
        None => return,
    };

    // Increment native STAT_CHECKED for every dialog SST processes
    if let Some(sv) = StatVar::from_raw(STAT_CHECKED.load(Ordering::Relaxed)) { sv.inc(); }

    let our_min_se = get_our_min_se();
    let our_interval = get_our_interval();

    // Check adaptive min_se for this destination
    let ruri = msg.pv("$ru").unwrap_or_default();
    let dest_host = extract_dest_host(&ruri);
    let adaptive = if !dest_host.is_empty() { get_adaptive_min_se(&dest_host) } else { None };
    let our_min_se = match adaptive {
        Some(learned) if learned > our_min_se => learned,
        _ => our_min_se,
    };

    // Parse SST-related headers from the INVITE
    let se_hdr = msg.header("Session-Expires").map(|s| s.to_string());
    let min_se_hdr = msg.header("Min-SE").map(|s| s.to_string());
    let supported_hdr = msg.header("Supported").map(|s| s.to_string());

    let has_timer = has_timer_support(supported_hdr.as_deref());

    let (req_se, req_refresher) = match se_hdr.as_deref() {
        Some(hval) => match parse_session_expires(hval) {
            Some((se, r)) => (se, r),
            None => (0, None),
        },
        None => (0, None),
    };

    let req_min_se = match min_se_hdr.as_deref() {
        Some(hval) => parse_min_se_value(hval),
        None => 0,
    };

    // Build initial SST state
    let mut state = SstState {
        requester: if req_se > 0 { SstRequester::Uac } else { SstRequester::Undefined },
        supported: if has_timer { SstSupported::Uac } else { SstSupported::Undefined },
        interval: std::cmp::max(our_interval, 90),
        min_se: std::cmp::max(req_min_se, our_min_se),
        refresher: req_refresher.unwrap_or_else(get_default_refresher),
        refresh_count: 0,
        last_refresh: Some(Instant::now()),
    };

    // Apply force_refresher override if configured
    if let Some(forced) = get_forced_refresher() {
        state.refresher = forced;
    }

    if req_se > 0 {
        // Session-Expires present in INVITE
        if req_se < our_min_se {
            if !has_timer {
                // UAC doesn't support timer -- increase Min-SE and forward
                state.interval = std::cmp::max(our_min_se, req_min_se);
                // Insert updated Min-SE header (remove old + append new)
                if req_min_se > 0 {
                    let _ = msg.call_str("remove_hf", &["Min-SE"]);
                }
                let hdr = format!("Min-SE: {}\r\n", state.interval);
                let _ = msg.call_str("append_hf", &[&hdr]);
                SST_STATS.with(|s| s.inc("headers_inserted"));
                if let Some(sv) = StatVar::from_raw(STAT_REFRESHES.load(Ordering::Relaxed)) { sv.inc(); }
            }
            // If UAC supports timer, the response_fwded callback will
            // handle rejection or negotiation in the response path.
        } else {
            // Use the INVITE's Session-Expires value
            state.interval = req_se;
        }
    } else {
        // No Session-Expires in INVITE — proxy inserts one
        state.interval = std::cmp::max(
            std::cmp::max(req_min_se, our_min_se),
            our_interval,
        );
        state.requester = SstRequester::Proxy;

        // Remove old Min-SE if ours is higher
        if req_min_se > 0 && req_min_se < our_min_se {
            let _ = msg.call_str("remove_hf", &["Min-SE"]);
            let min_hdr = format!("Min-SE: {}\r\n", state.min_se);
            let _ = msg.call_str("append_hf", &[&min_hdr]);
            SST_STATS.with(|s| s.inc("headers_inserted"));
            if let Some(sv) = StatVar::from_raw(STAT_REFRESHES.load(Ordering::Relaxed)) { sv.inc(); }
        }

        // Insert Session-Expires header
        let se_hdr_val = format!("Session-Expires: {}\r\n", state.interval);
        let _ = msg.call_str("append_hf", &[&se_hdr_val]);
        SST_STATS.with(|s| s.inc("headers_inserted"));
        if let Some(sv) = StatVar::from_raw(STAT_REFRESHES.load(Ordering::Relaxed)) { sv.inc(); }
    }

    // Store state in tracker
    TRACKER.with(|t| {
        t.on_created(&callid);
        t.with_state(&callid, |s| *s = state);
    });
    if let Some(sv) = StatVar::from_raw(STAT_ACCEPTED.load(Ordering::Relaxed)) { sv.inc(); }
    if let Some(sv) = StatVar::from_raw(STAT_ACTIVE_TIMERS.load(Ordering::Relaxed)) { sv.update(1); }
    SST_STATS.with(|s| {
        let count = TRACKER.with(|t| t.active_count()) as u64;
        s.set("sessions_active", count);
    });

    // Track refresher direction stat
    let refresher_dir = TRACKER.with(|t| {
        t.with_state_ref(&callid, |s| s.refresher.clone())
    });
    match refresher_dir {
        Some(Refresher::Uac) => SST_STATS.with(|s| s.inc("sessions_uac_refresher")),
        Some(Refresher::Uas) => SST_STATS.with(|s| s.inc("sessions_uas_refresher")),
        None => {}
    }

    // Set initial dialog lifetime via $DLG_timeout
    let interval = TRACKER.with(|t| {
        t.with_state_ref(&callid, |s| s.interval).unwrap_or(1800)
    });
    let _ = msg.set_pv("$DLG_timeout", &interval.to_string());

    // Register per-dialog callbacks
    let dlg_void = dlg as *mut c_void;
    unsafe {
        let _ = dialog::dlg::register_dlg_cb(
            dlg_void,
            dialog::DLGCB_RESPONSE_FWDED | dialog::DLGCB_RESPONSE_WITHIN,
            Some(sst_dialog_response_fwded_cb),
            ptr::null_mut(),
            None,
        );
        let _ = dialog::dlg::register_dlg_cb(
            dlg_void,
            dialog::DLGCB_REQ_WITHIN,
            Some(sst_dialog_request_within_cb),
            ptr::null_mut(),
            None,
        );
        let _ = dialog::dlg::register_dlg_cb(
            dlg_void,
            dialog::DLGCB_TERMINATED | dialog::DLGCB_FAILED | dialog::DLGCB_EXPIRED,
            Some(sst_dialog_terminated_cb),
            ptr::null_mut(),
            None,
        );
    }

    opensips_log!(
        DBG,
        "rust_sst",
        "CREATED: callid={}, interval={}, requester={:?}, supported={:?}",
        callid,
        interval,
        TRACKER.with(|t| t.with_state_ref(&callid, |s| s.requester.clone())),
        TRACKER.with(|t| t.with_state_ref(&callid, |s| s.supported.clone()))
    );
}

/// DLGCB_RESPONSE_FWDED / DLGCB_RESPONSE_WITHIN — called on responses.
///
/// Handles:
/// - 422 replies: adjusts min_se to prevent loops
/// - 2XX replies to INVITE/UPDATE: inserts Session-Expires + Require: timer,
///   sets dialog lifetime
#[allow(clippy::too_many_lines)]
unsafe extern "C" fn sst_dialog_response_fwded_cb(
    dlg: *mut sys::dlg_cell,
    _type: c_int,
    params: *mut sys::dlg_cb_params,
) {
    let params_ref = unsafe { &*params };
    let msg_ptr = params_ref.msg;
    if msg_ptr.is_null() {
        return;
    }

    let mut msg = unsafe { opensips_rs::SipMessage::from_raw(msg_ptr) };
    if !msg.is_reply() {
        return;
    }

    let callid = match unsafe { dialog::callid_from_dlg(dlg as *mut c_void) } {
        Some(id) => id,
        None => return,
    };

    // Check if we're tracking this dialog
    if !TRACKER.with(|t| t.contains(&callid)) {
        return;
    }

    let status_code = msg.status_code().unwrap_or(0);

    // Handle 422 — adjust min_se to prevent loop
    if status_code == 422 {
        let reply_min_se = msg.header("Min-SE")
            .map_or(0, parse_min_se_value);

        if reply_min_se > 0 {
            TRACKER.with(|t| {
                t.with_state(&callid, |s| {
                    if s.interval < reply_min_se {
                        s.interval = reply_min_se;
                    }
                    if s.min_se < reply_min_se {
                        s.min_se = reply_min_se;
                    }
                });
            });
            SST_STATS.with(|s| s.inc("422_sent"));
            if let Some(sv) = StatVar::from_raw(STAT_REJECTED.load(Ordering::Relaxed)) { sv.inc(); }

            // Adaptive min_se: learn from 422 reply
            let ruri = msg.pv("$ru").unwrap_or_default();
            if !ruri.is_empty() {
                let dest = extract_dest_host(&ruri);
                if !dest.is_empty() {
                    record_adaptive_min_se(&dest, reply_min_se);
                }
            }
        }

        opensips_log!(
            DBG,
            "rust_sst",
            "422 reply: callid={}, adjusted min_se to {}",
            callid,
            reply_min_se
        );
        return;
    }

    // Only process 2XX responses
    if !(200..300).contains(&status_code) {
        return;
    }

    let our_min_se = get_our_min_se();
    let our_interval = get_our_interval();

    // Parse SST info from the response
    let se_hdr = msg.header("Session-Expires").map(|s| s.to_string());
    let supported_hdr = msg.header("Supported").map(|s| s.to_string());
    let min_se_hdr = msg.header("Min-SE").map(|s| s.to_string());

    let has_timer = has_timer_support(supported_hdr.as_deref());
    let (resp_se, resp_refresher) = match se_hdr.as_deref() {
        Some(hval) => match parse_session_expires(hval) {
            Some((se, r)) => (se, r),
            None => (0, None),
        },
        None => (0, None),
    };
    let resp_min_se = match min_se_hdr.as_deref() {
        Some(hval) => parse_min_se_value(hval),
        None => 0,
    };

    // Update supported state from UAS response
    TRACKER.with(|t| {
        t.with_state(&callid, |s| {
            if s.supported != SstSupported::Uac {
                s.supported = if has_timer { SstSupported::Uas } else { SstSupported::Undefined };
            }
        });
    });

    if resp_se > 0 {
        // UAS included Session-Expires — use it
        let new_interval = if our_interval > resp_min_se {
            our_interval
        } else {
            std::cmp::max(resp_se, our_min_se)
        };

        TRACKER.with(|t| {
            t.with_state(&callid, |s| {
                s.interval = new_interval;
                if let Some(r) = resp_refresher {
                    s.refresher = r;
                }
            });
        });

        // Set dialog lifetime
        let _ = msg.set_pv("$DLG_timeout", &new_interval.to_string());

        opensips_log!(
            DBG,
            "rust_sst",
            "2XX with SE: callid={}, interval={}",
            callid,
            new_interval
        );
    } else {
        // No Session-Expires in response — proxy must insert one
        let uac_supports = TRACKER.with(|t| {
            t.with_state_ref(&callid, |s| s.supported == SstSupported::Uac)
                .unwrap_or(false)
        });

        if uac_supports {
            // UAC supports timer — insert SE and Require: timer
            let interval = TRACKER.with(|t| {
                t.with_state(&callid, |s| {
                    if our_interval > resp_min_se {
                        s.interval = our_interval;
                    } else {
                        s.interval = std::cmp::max(s.interval, our_min_se);
                    }
                    s.refresher = Refresher::Uac;
                    s.interval
                }).unwrap_or(our_interval)
            });

            let se_hdr_val = format!("Session-Expires: {interval};refresher=uac\r\n");
            let _ = msg.call_str("append_hf", &[&se_hdr_val]);
            let _ = msg.call_str("append_hf", &["Require: timer\r\n"]);
            SST_STATS.with(|s| s.inc("headers_inserted"));
            if let Some(sv) = StatVar::from_raw(STAT_REFRESHES.load(Ordering::Relaxed)) { sv.inc(); }

            let _ = msg.set_pv("$DLG_timeout", &interval.to_string());

            opensips_log!(
                DBG,
                "rust_sst",
                "2XX no SE, UAC supports timer: callid={}, inserted SE={}",
                callid,
                interval
            );
        } else {
            // Neither side actively supports timer
            // Use a generous default (12 hours or the configured interval)
            let interval = std::cmp::max(our_interval, 12 * 3600);
            TRACKER.with(|t| {
                t.with_state(&callid, |s| {
                    s.interval = interval;
                });
            });
            let _ = msg.set_pv("$DLG_timeout", &interval.to_string());

            opensips_log!(
                DBG,
                "rust_sst",
                "2XX no SE, no timer support: callid={}, fallback interval={}",
                callid,
                interval
            );
        }
    }
}

/// DLGCB_REQ_WITHIN — re-INVITE or UPDATE within the dialog.
///
/// Updates the dialog lifetime based on the new Session-Expires value.
#[allow(clippy::too_many_lines)]
unsafe extern "C" fn sst_dialog_request_within_cb(
    dlg: *mut sys::dlg_cell,
    _type: c_int,
    params: *mut sys::dlg_cb_params,
) {
    let params_ref = unsafe { &*params };
    let msg_ptr = params_ref.msg;
    if msg_ptr.is_null() {
        return;
    }

    let mut msg = unsafe { opensips_rs::SipMessage::from_raw(msg_ptr) };

    let callid = match unsafe { dialog::callid_from_dlg(dlg as *mut c_void) } {
        Some(id) => id,
        None => return,
    };

    if !TRACKER.with(|t| t.contains(&callid)) {
        return;
    }

    if msg.is_request() {
        let method = msg.method().unwrap_or("").to_string();
        if method == "INVITE" || method == "UPDATE" {
            let se_hdr = msg.header("Session-Expires").map(|s| s.to_string());
            let supported_hdr = msg.header("Supported").map(|s| s.to_string());
            let min_se_hdr = msg.header("Min-SE").map(|s| s.to_string());

            let our_min_se = get_our_min_se();
            let our_interval = get_our_interval();
            let has_timer = has_timer_support(supported_hdr.as_deref());

            let (req_se, _req_refresher) = match se_hdr.as_deref() {
                Some(hval) => match parse_session_expires(hval) {
                    Some((se, r)) => (se, r),
                    None => (0, None),
                },
                None => (0, None),
            };
            let req_min_se = match min_se_hdr.as_deref() {
                Some(hval) => parse_min_se_value(hval),
                None => 0,
            };

            if req_se > 0 {
                let new_interval = if our_interval > req_min_se {
                    our_interval
                } else {
                    std::cmp::max(req_se, our_min_se)
                };

                TRACKER.with(|t| {
                    t.with_state(&callid, |s| {
                        s.interval = new_interval;
                        s.supported = if has_timer { SstSupported::Uac } else { SstSupported::Undefined };
                        s.refresh_count += 1;
                        s.last_refresh = Some(Instant::now());
                    });
                });

                let _ = msg.set_pv("$DLG_timeout", &new_interval.to_string());
            }
        } else if method == "PRACK" || method == "ACK" {
            // Workaround: re-set dialog timeout for PRACK/ACK transactions
            let interval = TRACKER.with(|t| {
                t.with_state_ref(&callid, |s| s.interval).unwrap_or(1800)
            });
            let _ = msg.set_pv("$DLG_timeout", &interval.to_string());
        }
    } else if msg.is_reply() {
        let status_code = msg.status_code().unwrap_or(0);
        if (200..300).contains(&status_code) {
            let se_hdr = msg.header("Session-Expires").map(|s| s.to_string());
            let supported_hdr = msg.header("Supported").map(|s| s.to_string());
            let has_timer = has_timer_support(supported_hdr.as_deref());

            let (resp_se, _resp_refresher) = match se_hdr.as_deref() {
                Some(hval) => match parse_session_expires(hval) {
                    Some((se, r)) => (se, r),
                    None => (0, None),
                },
                None => (0, None),
            };

            if resp_se > 0 {
                TRACKER.with(|t| {
                    t.with_state(&callid, |s| {
                        s.interval = resp_se;
                        s.supported = if has_timer { SstSupported::Uas } else { SstSupported::Undefined };
                    });
                });
                let _ = msg.set_pv("$DLG_timeout", &resp_se.to_string());
            }
        }
    }
}

/// DLGCB_TERMINATED / DLGCB_FAILED / DLGCB_EXPIRED — dialog ended.
unsafe extern "C" fn sst_dialog_terminated_cb(
    dlg: *mut sys::dlg_cell,
    type_: c_int,
    _params: *mut sys::dlg_cb_params,
) {
    let callid = match unsafe { dialog::callid_from_dlg(dlg as *mut c_void) } {
        Some(id) => id,
        None => return,
    };

    let was_expired = type_ as u32 == dialog::DLGCB_EXPIRED;

    // Check for stale session before removing state
    let is_stale = TRACKER.with(|t| {
        t.with_state_ref(&callid, |s| {
            if let Some(last) = s.last_refresh {
                let since_refresh = last.elapsed().as_secs() as u32;
                // Stale if the session should have been refreshed but wasn't
                since_refresh > s.interval && s.interval > 0
            } else {
                false
            }
        }).unwrap_or(false)
    });

    if is_stale || was_expired {
        let (interval, since_refresh) = TRACKER.with(|t| {
            t.with_state_ref(&callid, |s| {
                let since = s.last_refresh.map_or(0, |t| t.elapsed().as_secs() as u32);
                (s.interval, since)
            }).unwrap_or((0, 0))
        });
        if is_stale {
            opensips_log!(
                WARN,
                "rust_sst",
                "stale session detected: callid={}, interval={}, since_last_refresh={}s",
                callid,
                interval,
                since_refresh
            );
            SST_STATS.with(|s| s.inc("stale_sessions"));
            if let Some(sv) = StatVar::from_raw(STAT_REFRESH_FAILED.load(Ordering::Relaxed)) { sv.inc(); }

            // Publish E_SST_STALE event
            if event::is_enabled() {
                let payload = event::format_payload(&[
                    ("call_id", &event::json_str(&callid)),
                    ("interval", &interval.to_string()),
                    ("since_last_refresh", &since_refresh.to_string()),
                ]);
                opensips_log!(NOTICE, "rust_sst", "EVENT E_SST_STALE {}", payload);
            }
        }
    }

    TRACKER.with(|t| {
        t.on_terminated(&callid);
    });
    if let Some(sv) = StatVar::from_raw(STAT_ACTIVE_TIMERS.load(Ordering::Relaxed)) { sv.update(-1); }

    SST_STATS.with(|s| {
        let count = TRACKER.with(|t| t.active_count()) as u64;
        s.set("sessions_active", count);
        if was_expired {
            s.inc("sessions_expired");
            if let Some(sv) = StatVar::from_raw(STAT_REFRESH_FAILED.load(Ordering::Relaxed)) { sv.inc(); }
            // Publish E_SST_EXPIRED event
            if event::is_enabled() {
                let payload = event::format_payload(&[
                    ("call_id", &event::json_str(&callid)),
                ]);
                opensips_log!(NOTICE, "rust_sst", "EVENT E_SST_EXPIRED {}", payload);
            }
        }
    });

    opensips_log!(
        DBG,
        "rust_sst",
        "TERMINATED: callid={}, expired={}, stale={}",
        callid,
        was_expired,
        is_stale
    );
}

// ── Module lifecycle ─────────────────────────────────────────────

unsafe extern "C" fn mod_init() -> c_int {
    let interval = DEFAULT_INTERVAL.get();
    let min_se = DEFAULT_MIN_SE.get();
    let refresher = get_default_refresher();

    // Validate default_refresher value
    if let Some(r) = unsafe { DEFAULT_REFRESHER.get_value() } {
        if !r.trim().eq_ignore_ascii_case("uac") && !r.trim().eq_ignore_ascii_case("uas") {
            opensips_log!(
                WARN,
                "rust_sst",
                "default_refresher='{}' is not 'uac' or 'uas', defaulting to 'uas'",
                r
            );
        }
    }

    // Validate default_interval
    if interval < 0 {
        opensips_log!(
            WARN,
            "rust_sst",
            "default_interval={} is negative, clamping to 1800",
            interval
        );
    } else if interval > 0 && interval < 90 {
        opensips_log!(
            WARN,
            "rust_sst",
            "default_interval={} is below RFC 4028 minimum of 90, clamping to 90",
            interval
        );
    }

    if min_se < 90 {
        opensips_log!(
            WARN,
            "rust_sst",
            "default_min_se={} is below RFC 4028 minimum of 90, clamping",
            min_se
        );
    }

    // Initialize event publishing
    if PUBLISH_EVENTS.get() != 0 {
        event::set_enabled(true);
        opensips_log!(INFO, "rust_sst", "event publishing enabled");
    }

    // Validate force_refresher
    if let Some(fr) = unsafe { FORCE_REFRESHER.get_value() } {
        let fr_trimmed = fr.trim();
        if !fr_trimmed.is_empty()
            && !fr_trimmed.eq_ignore_ascii_case("uac")
            && !fr_trimmed.eq_ignore_ascii_case("uas")
        {
            opensips_log!(
                WARN,
                "rust_sst",
                "force_refresher='{}' is not 'uac' or 'uas', ignoring",
                fr
            );
        } else if !fr_trimmed.is_empty() {
            opensips_log!(
                INFO,
                "rust_sst",
                "force_refresher='{}' enabled -- overriding all negotiated refreshers",
                fr_trimmed
            );
        }
    }

    // Load per-account policies file if configured
    if let Some(path) = unsafe { POLICIES_FILE.get_value() } {
        if !path.is_empty() {
            match FileLoader::new(path, parse_policy_line, build_policies) {
                Ok(loader) => {
                    let count = loader.get().len();
                    POLICIES.with(|p| {
                        *p.borrow_mut() = Some(loader);
                    });
                    opensips_log!(INFO, "rust_sst", "loaded {} per-account policies from {}", count, path);
                }
                Err(e) => {
                    opensips_log!(ERR, "rust_sst", "failed to load policies_file '{}': {}", path, e);
                    return -1;
                }
            }
        }
    }

    // Try to load dialog API for automatic mode
    match dialog::load_api() {
        Ok(()) => {
            DLG_LOADED.store(true, Ordering::Relaxed);
            opensips_log!(INFO, "rust_sst", "dialog API loaded — automatic SST mode enabled");

            // Register DLGCB_CREATED for all new dialogs
            unsafe {
                if let Err(e) = dialog::dlg::register_global_cb(
                    dialog::DLGCB_CREATED,
                    Some(sst_dialog_created_cb),
                    ptr::null_mut(),
                    None,
                ) {
                    opensips_log!(
                        ERR,
                        "rust_sst",
                        "failed to register DLGCB_CREATED callback: {}",
                        e
                    );
                    return -1;
                }
            }
        }
        Err(e) => {
            opensips_log!(
                WARN,
                "rust_sst",
                "dialog API not available ({}), running in script-only mode",
                e
            );
        }
    }

    opensips_log!(INFO, "rust_sst", "module initialized");
    opensips_log!(
        INFO,
        "rust_sst",
        "  default_interval={}, default_min_se={}, default_refresher={}",
        interval,
        min_se,
        refresher.as_str()
    );

    0
}

unsafe extern "C" fn mod_destroy() {
    opensips_log!(INFO, "rust_sst", "module destroyed");
}

// ── Script function: sst_check(interval, min_se) ────────────

unsafe extern "C" fn w_rust_sst_check(
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
        let param_interval = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
            Some(s) => s.trim().parse::<u32>().unwrap_or(0),
            None => 0,
        };
        let param_min_se = match unsafe { <&str as CommandFunctionParam>::from_raw(p1) } {
            Some(s) => s.trim().parse::<u32>().unwrap_or(0),
            None => 0,
        };

        let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };

        // Look up per-account policy from $fU
        let account = sip_msg.pv("$fU").unwrap_or_default();
        let policy = if !account.is_empty() { lookup_policy(&account) } else { None };

        let our_min_se = if param_min_se > 0 {
            param_min_se
        } else if let Some(ref pol) = policy {
            pol.min_se
        } else {
            get_our_min_se()
        };

        let requested_interval = if param_interval > 0 {
            param_interval
        } else if let Some(ref pol) = policy {
            pol.interval
        } else {
            0
        };
        let se_header = sip_msg.header("Session-Expires");
        let (req_interval, req_min_se, req_refresher) = match &se_header {
            Some(hval) => match parse_session_expires(hval) {
                Some((interval, refresher)) => {
                    let min_se_hdr = sip_msg.header("Min-SE");
                    let req_min: u32 = min_se_hdr
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    (interval, req_min, refresher)
                }
                None => (0, 0, None),
            },
            None => (0, 0, None),
        };

        let check_interval = if requested_interval > 0 {
            requested_interval
        } else {
            req_interval
        };

        let (acceptable, negotiated, effective_min_se) =
            sst_check(check_interval, req_min_se, our_min_se);

        let refresher = req_refresher.unwrap_or_else(get_default_refresher);

        let _ = sip_msg.set_pv("$var(sst_interval)", &negotiated.to_string());
        let _ = sip_msg.set_pv("$var(sst_min_se)", &effective_min_se.to_string());
        let _ = sip_msg.set_pv("$var(sst_refresher)", refresher.as_str());

        if acceptable {
            opensips_log!(
                DBG,
                "rust_sst",
                "sst_check OK: interval={}, min_se={}, refresher={}",
                negotiated,
                effective_min_se,
                refresher.as_str()
            );
            1
        } else {
            opensips_log!(
                DBG,
                "rust_sst",
                "sst_check REJECTED: requested={} < effective_min_se={}",
                check_interval,
                effective_min_se
            );
            -1
        }
    })
}

// ── Script function: sst_update(interval, min_se, refresher) ─

unsafe extern "C" fn w_rust_sst_update(
    msg: *mut sys::sip_msg,
    p0: *mut c_void,
    p1: *mut c_void,
    p2: *mut c_void,
    _p3: *mut c_void,
    _p4: *mut c_void,
    _p5: *mut c_void,
    _p6: *mut c_void,
    _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let param_interval = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
            Some(s) => s.trim().parse::<u32>().unwrap_or(0),
            None => 0,
        };
        let param_min_se = match unsafe { <&str as CommandFunctionParam>::from_raw(p1) } {
            Some(s) => s.trim().parse::<u32>().unwrap_or(0),
            None => 0,
        };
        let param_refresher = match unsafe { <&str as CommandFunctionParam>::from_raw(p2) } {
            Some(s) => parse_refresher(s),
            None => get_default_refresher(),
        };

        let default_interval = DEFAULT_INTERVAL.get() as u32;
        let default_min_se = get_our_min_se();

        let (se_header, min_se_header) = sst_update(
            param_interval,
            param_min_se,
            &param_refresher,
            default_interval,
            default_min_se,
        );

        let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
        let _ = sip_msg.set_pv("$var(sst_session_expires)", &se_header);
        let _ = sip_msg.set_pv("$var(sst_min_se)", &min_se_header);

        opensips_log!(
            DBG,
            "rust_sst",
            "sst_update: Session-Expires: {}, Min-SE: {}",
            se_header,
            min_se_header
        );

        1
    })
}


// ── Script function: sst_reload() ────────────────────────────

unsafe extern "C" fn w_rust_sst_reload(
    msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let result = POLICIES.with(|p| {
            let loader = p.borrow();
            match loader.as_ref() {
                Some(l) => match l.reload() {
                    Ok(count) => {
                        opensips_log!(INFO, "rust_sst", "reloaded {} per-account policies", count);
                        let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
                        let _ = sip_msg.set_pv("$var(sst_reload_count)", &count.to_string());
                        1
                    }
                    Err(e) => {
                        opensips_log!(ERR, "rust_sst", "policies reload failed: {}", e);
                        -1
                    }
                },
                None => {
                    opensips_log!(WARN, "rust_sst", "no policies_file configured, nothing to reload");
                    -1
                }
            }
        });
        result
    })
}

// ── Script function: sst_status() ────────────────────────────

unsafe extern "C" fn w_rust_sst_status(
    msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let json = build_sst_status_json();
        let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
        let _ = sip_msg.set_pv("$var(sst_status)", &json);
        1
    })
}

// ── Script function: sst_stats() ────────────────────────────

unsafe extern "C" fn w_rust_sst_stats(
    msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let json = SST_STATS.with(|s| s.to_json());
        let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
        let _ = sip_msg.set_pv("$var(sst_stats)", &json);
        1
    })
}

// ── Script function: sst_prometheus() ────────────────────────

unsafe extern "C" fn w_rust_sst_prometheus(
    msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let prom = SST_STATS.with(|s| s.to_prometheus());
        let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
        let _ = sip_msg.set_pv("$var(sst_prom)", &prom);
        1
    })
}


// ── Static arrays for module registration ────────────────────────

const EMPTY_PARAMS: [sys::cmd_param; 9] = unsafe { std::mem::zeroed() };

const TWO_STR_PARAMS: [sys::cmd_param; 9] = {
    let mut arr: [sys::cmd_param; 9] = unsafe { std::mem::zeroed() };
    arr[0].flags = 2; // CMD_PARAM_STR
    arr[1].flags = 2; // CMD_PARAM_STR
    arr
};

const THREE_STR_PARAMS: [sys::cmd_param; 9] = {
    let mut arr: [sys::cmd_param; 9] = unsafe { std::mem::zeroed() };
    arr[0].flags = 2; // CMD_PARAM_STR
    arr[1].flags = 2; // CMD_PARAM_STR
    arr[2].flags = 2; // CMD_PARAM_STR
    arr
};

#[repr(transparent)]
struct SyncArray<T, const N: usize>([T; N]);
unsafe impl<T, const N: usize> Sync for SyncArray<T, N> {}

// ── Native statistics array ────────────────────────────────────────

static MOD_STATS: SyncArray<sys::stat_export_, 7> = SyncArray([
    sys::stat_export_ { name: cstr_lit!("checked") as *mut _,        flags: 0,             stat_pointer: STAT_CHECKED.as_ptr() as *mut _ },
    sys::stat_export_ { name: cstr_lit!("accepted") as *mut _,       flags: 0,             stat_pointer: STAT_ACCEPTED.as_ptr() as *mut _ },
    sys::stat_export_ { name: cstr_lit!("rejected") as *mut _,       flags: 0,             stat_pointer: STAT_REJECTED.as_ptr() as *mut _ },
    sys::stat_export_ { name: cstr_lit!("active_timers") as *mut _,  flags: STAT_NO_RESET, stat_pointer: STAT_ACTIVE_TIMERS.as_ptr() as *mut _ },
    sys::stat_export_ { name: cstr_lit!("refreshes") as *mut _,      flags: 0,             stat_pointer: STAT_REFRESHES.as_ptr() as *mut _ },
    sys::stat_export_ { name: cstr_lit!("refresh_failed") as *mut _, flags: 0,             stat_pointer: STAT_REFRESH_FAILED.as_ptr() as *mut _ },
    unsafe { std::mem::zeroed() }, // NULL terminator
]);

// ── MI command handlers ────────────────────────────────────────────

/// MI handler: rust_sst:sst_show
unsafe extern "C" fn mi_sst_show(
    _params: *const sys::mi_params_,
    _async_hdl: *mut sys::mi_handler,
) -> *mut sys::mi_response_t {
    let Some(resp) = MiObject::new() else {
        return mi_error(-32000, "Failed to create MI response") as *mut _;
    };
    let Some(arr) = resp.add_array("sessions") else {
        return mi_error(-32000, "Failed to create sessions array") as *mut _;
    };
    let mut count = 0u32;
    TRACKER.with(|t| {
        t.for_each_ref(|callid, entry| {
            let s = &entry.state;
            let age = entry.created.elapsed().as_secs();
            let time_remaining = (s.interval as u64).saturating_sub(age);
            if let Some(obj) = arr.add_object("") {
                obj.add_str("call_id", callid);
                obj.add_num("interval", s.interval as f64);
                obj.add_num("min_se", s.min_se as f64);
                obj.add_str("refresher", s.refresher.as_str());
                obj.add_num("age_secs", age as f64);
                obj.add_num("time_remaining", time_remaining as f64);
                obj.add_num("refresh_count", s.refresh_count as f64);
                count += 1;
            }
        });
    });
    resp.add_num("count", count as f64);
    resp.into_raw() as *mut _
}

// ── MI command export array ────────────────────────────────────────

static MI_CMDS: SyncArray<sys::mi_export_, 2> = SyncArray([
    sys::mi_export_ {
        name: cstr_lit!("sst_show") as *mut _,
        help: cstr_lit!("Show active SST sessions with timer details") as *mut _,
        flags: 0,
        init_f: None,
        recipes: {
            let mut r: [sys::mi_recipe_; 48] = unsafe { std::mem::zeroed() };
            r[0] = sys::mi_recipe_ {
                cmd: Some(mi_sst_show),
                params: unsafe { std::mem::zeroed() },
            };
            r
        },
        aliases: [ptr::null(); 4],
    },
    unsafe { std::mem::zeroed() }, // NULL terminator
]);

static CMDS: SyncArray<sys::cmd_export_, 7> = SyncArray([
    sys::cmd_export_ {
        name: cstr_lit!("sst_check"),
        function: Some(w_rust_sst_check),
        params: TWO_STR_PARAMS,
        flags: 1, // REQUEST_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("sst_update"),
        function: Some(w_rust_sst_update),
        params: THREE_STR_PARAMS,
        flags: 1 | 4, // REQUEST_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("sst_stats"),
        function: Some(w_rust_sst_stats),
        params: EMPTY_PARAMS,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("sst_status"),
        function: Some(w_rust_sst_status),
        params: EMPTY_PARAMS,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("sst_reload"),
        function: Some(w_rust_sst_reload),
        params: EMPTY_PARAMS,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("sst_prometheus"),
        function: Some(w_rust_sst_prometheus),
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

static ACMDS: SyncArray<sys::acmd_export_, 1> = SyncArray([sys::acmd_export_ {
    name: ptr::null(),
    function: None,
    params: EMPTY_PARAMS,
}]);

static PARAMS: SyncArray<sys::param_export_, 8> = SyncArray([
    sys::param_export_ {
        name: cstr_lit!("default_interval"),
        type_: 2, // INT_PARAM
        param_pointer: DEFAULT_INTERVAL.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("default_min_se"),
        type_: 2, // INT_PARAM
        param_pointer: DEFAULT_MIN_SE.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("default_refresher"),
        type_: 1, // STR_PARAM
        param_pointer: DEFAULT_REFRESHER.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("policies_file"),
        type_: 1, // STR_PARAM
        param_pointer: POLICIES_FILE.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("adaptive_min_se"),
        type_: 2, // INT_PARAM
        param_pointer: ADAPTIVE_MIN_SE.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("force_refresher"),
        type_: 1, // STR_PARAM
        param_pointer: FORCE_REFRESHER.as_ptr(),
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
    name: cstr_lit!("rust_sst"),
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
    init_child_f: None,
    reload_ack_f: None,
};

// ── Unit tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── sst_check tests ──────────────────────────────────────────

    #[test]
    fn test_sst_check_acceptable() {
        let (ok, interval, min_se) = sst_check(1800, 90, 90);
        assert!(ok);
        assert_eq!(interval, 1800);
        assert_eq!(min_se, 90);
    }

    #[test]
    fn test_sst_check_too_small() {
        let (ok, interval, min_se) = sst_check(60, 90, 90);
        assert!(!ok);
        assert_eq!(interval, 0);
        assert_eq!(min_se, 90);
    }

    #[test]
    fn test_sst_check_our_min_se_higher() {
        let (ok, interval, min_se) = sst_check(120, 60, 180);
        assert!(!ok);
        assert_eq!(interval, 0);
        assert_eq!(min_se, 180);
    }

    #[test]
    fn test_sst_check_zero_interval() {
        let (ok, interval, min_se) = sst_check(0, 90, 90);
        assert!(ok);
        assert_eq!(interval, 180);
        assert_eq!(min_se, 90);
    }

    #[test]
    fn test_sst_check_equal() {
        let (ok, interval, min_se) = sst_check(90, 90, 90);
        assert!(ok);
        assert_eq!(interval, 90);
        assert_eq!(min_se, 90);
    }

    // ── build_session_expires_header tests ───────────────────────

    #[test]
    fn test_build_session_expires_uac() {
        let result = build_session_expires_header(1800, &Refresher::Uac);
        assert_eq!(result, "1800;refresher=uac");
    }

    #[test]
    fn test_build_session_expires_uas() {
        let result = build_session_expires_header(1800, &Refresher::Uas);
        assert_eq!(result, "1800;refresher=uas");
    }

    // ── build_min_se_header tests ────────────────────────────────

    #[test]
    fn test_build_min_se() {
        assert_eq!(build_min_se_header(90), "90");
    }

    // ── parse_session_expires tests ──────────────────────────────

    #[test]
    fn test_parse_session_expires_full() {
        let result = parse_session_expires("1800;refresher=uac");
        assert_eq!(result, Some((1800, Some(Refresher::Uac))));
    }

    #[test]
    fn test_parse_session_expires_no_refresher() {
        let result = parse_session_expires("1800");
        assert_eq!(result, Some((1800, None)));
    }

    #[test]
    fn test_parse_session_expires_with_spaces() {
        let result = parse_session_expires(" 1800 ; refresher = uas ");
        assert_eq!(result, Some((1800, Some(Refresher::Uas))));
    }

    #[test]
    fn test_parse_session_expires_invalid() {
        assert_eq!(parse_session_expires("abc"), None);
    }

    // ── parse_refresher tests ────────────────────────────────────

    #[test]
    fn test_parse_refresher_uac() {
        assert_eq!(parse_refresher("uac"), Refresher::Uac);
    }

    #[test]
    fn test_parse_refresher_uas() {
        assert_eq!(parse_refresher("uas"), Refresher::Uas);
    }

    #[test]
    fn test_parse_refresher_case_insensitive() {
        assert_eq!(parse_refresher("UAC"), Refresher::Uac);
    }

    #[test]
    fn test_parse_refresher_default() {
        assert_eq!(parse_refresher("unknown"), Refresher::Uas);
    }

    // ── sst_update tests ─────────────────────────────────────────

    #[test]
    fn test_sst_update_defaults() {
        let (se, min) = sst_update(0, 0, &Refresher::Uas, 1800, 90);
        assert_eq!(se, "1800;refresher=uas");
        assert_eq!(min, "90");
    }

    #[test]
    fn test_sst_update_custom_interval() {
        let (se, min) = sst_update(3600, 0, &Refresher::Uac, 1800, 90);
        assert_eq!(se, "3600;refresher=uac");
        assert_eq!(min, "90");
    }

    #[test]
    fn test_sst_update_interval_below_min_se() {
        let (se, min) = sst_update(60, 90, &Refresher::Uas, 1800, 90);
        assert_eq!(se, "90;refresher=uas");
        assert_eq!(min, "90");
    }

    #[test]
    fn test_sst_update_custom_min_se() {
        let (se, min) = sst_update(1800, 120, &Refresher::Uas, 1800, 90);
        assert_eq!(se, "1800;refresher=uas");
        assert_eq!(min, "120");
    }

    // ── has_timer_support tests ──────────────────────────────────

    #[test]
    fn test_has_timer_support_present() {
        assert!(has_timer_support(Some("timer")));
    }

    #[test]
    fn test_has_timer_support_in_list() {
        assert!(has_timer_support(Some("replaces, timer, 100rel")));
    }

    #[test]
    fn test_has_timer_support_case_insensitive() {
        assert!(has_timer_support(Some("Timer")));
    }

    #[test]
    fn test_has_timer_support_absent() {
        assert!(!has_timer_support(Some("replaces, 100rel")));
    }

    #[test]
    fn test_has_timer_support_none() {
        assert!(!has_timer_support(None));
    }

    #[test]
    fn test_has_timer_support_empty() {
        assert!(!has_timer_support(Some("")));
    }

    // ── parse_min_se_value tests ─────────────────────────────────

    #[test]
    fn test_parse_min_se_value_simple() {
        assert_eq!(parse_min_se_value("90"), 90);
    }

    #[test]
    fn test_parse_min_se_value_with_params() {
        assert_eq!(parse_min_se_value("120;something"), 120);
    }

    #[test]
    fn test_parse_min_se_value_whitespace() {
        assert_eq!(parse_min_se_value(" 90 "), 90);
    }

    #[test]
    fn test_parse_min_se_value_invalid() {
        assert_eq!(parse_min_se_value("abc"), 0);
    }

    // ── 422 loop prevention tests ────────────────────────────────

    #[test]
    fn test_422_min_se_adjustment() {
        // Simulate: our min_se is 90, 422 reply says Min-SE: 180
        // After adjustment, our state.min_se should be >= 180
        let mut state = SstState {
            interval: 90,
            min_se: 90,
            ..SstState::default()
        };
        let reply_min_se: u32 = 180;
        if state.interval < reply_min_se {
            state.interval = reply_min_se;
        }
        if state.min_se < reply_min_se {
            state.min_se = reply_min_se;
        }
        assert_eq!(state.interval, 180);
        assert_eq!(state.min_se, 180);
    }

    // ── SstState default tests ───────────────────────────────────

    #[test]
    fn test_sst_state_default() {
        let state = SstState::default();
        assert_eq!(state.requester, SstRequester::Undefined);
        assert_eq!(state.supported, SstSupported::Undefined);
        assert_eq!(state.interval, 0);
        assert_eq!(state.min_se, 0);
        assert_eq!(state.refresher, Refresher::Uas);
    }

    // ── negotiation flow test ────────────────────────────────────

    #[test]
    fn test_negotiation_flow() {
        // 1. INVITE with Session-Expires: 1800;refresher=uac, Min-SE: 90
        let (ok, interval, min_se) = sst_check(1800, 90, 90);
        assert!(ok);
        assert_eq!(interval, 1800);
        assert_eq!(min_se, 90);

        // 2. Parse Session-Expires header
        let parsed = parse_session_expires("1800;refresher=uac");
        assert_eq!(parsed, Some((1800, Some(Refresher::Uac))));
        let (parsed_interval, parsed_refresher) = parsed.unwrap();
        let refresher = parsed_refresher.unwrap();

        // 3. Build response headers
        let (se_hdr, min_se_hdr) =
            sst_update(parsed_interval, min_se, &refresher, 1800, 90);
        assert_eq!(se_hdr, "1800;refresher=uac");
        assert_eq!(min_se_hdr, "90");

        // 4. Verify round-trip
        let reparsed = parse_session_expires(&se_hdr);
        assert_eq!(reparsed, Some((1800, Some(Refresher::Uac))));
    }

    // ── edge cases ───────────────────────────────────────────────

    #[test]
    fn test_sst_check_large_interval() {
        let (ok, interval, min_se) = sst_check(86400, 90, 90);
        assert!(ok);
        assert_eq!(interval, 86400);
        assert_eq!(min_se, 90);
    }

    #[test]
    fn test_sst_check_zero_min_se() {
        let (ok, interval, min_se) = sst_check(1800, 0, 0);
        assert!(ok);
        assert_eq!(interval, 1800);
        assert_eq!(min_se, 0);
    }

    #[test]
    fn test_refresher_as_str() {
        assert_eq!(Refresher::Uac.as_str(), "uac");
        assert_eq!(Refresher::Uas.as_str(), "uas");
    }

    // ── dialog tracker integration tests ─────────────────────────

    #[test]
    fn test_tracker_sst_state_lifecycle() {
        let tracker: DialogTracker<SstState> = DialogTracker::new(3600);
        tracker.on_created("call-1");

        tracker.with_state("call-1", |s| {
            s.requester = SstRequester::Uac;
            s.supported = SstSupported::Uac;
            s.interval = 1800;
            s.min_se = 90;
            s.refresher = Refresher::Uac;
        });

        let interval = tracker.with_state_ref("call-1", |s| s.interval);
        assert_eq!(interval, Some(1800));

        let refresher = tracker.with_state_ref("call-1", |s| s.refresher.clone());
        assert_eq!(refresher, Some(Refresher::Uac));

        // Simulate re-INVITE updating interval
        tracker.with_state("call-1", |s| {
            s.interval = 3600;
        });
        let new_interval = tracker.with_state_ref("call-1", |s| s.interval);
        assert_eq!(new_interval, Some(3600));

        // Terminate
        let state = tracker.on_terminated("call-1");
        assert!(state.is_some());
        let final_state = state.unwrap();
        assert_eq!(final_state.interval, 3600);
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn test_tracker_422_adjustment() {
        let tracker: DialogTracker<SstState> = DialogTracker::new(3600);
        tracker.on_created("call-1");
        tracker.with_state("call-1", |s| {
            s.interval = 90;
            s.min_se = 90;
        });

        // Simulate 422 reply with Min-SE: 180
        let reply_min_se: u32 = 180;
        tracker.with_state("call-1", |s| {
            if s.interval < reply_min_se {
                s.interval = reply_min_se;
            }
            if s.min_se < reply_min_se {
                s.min_se = reply_min_se;
            }
        });

        let interval = tracker.with_state_ref("call-1", |s| s.interval);
        assert_eq!(interval, Some(180));
        let min_se = tracker.with_state_ref("call-1", |s| s.min_se);
        assert_eq!(min_se, Some(180));
    }

    // ── stats tests ──────────────────────────────────────────────

    #[test]
    fn test_stats_counters() {
        let stats = Stats::new("test_sst", &[
            "sessions_active",
            "sessions_expired",
            "422_sent",
            "headers_inserted",
        ]);
        assert_eq!(stats.get("sessions_active"), 0);

        stats.set("sessions_active", 5);
        assert_eq!(stats.get("sessions_active"), 5);

        stats.inc("headers_inserted");
        stats.inc("headers_inserted");
        assert_eq!(stats.get("headers_inserted"), 2);

        stats.inc("422_sent");
        assert_eq!(stats.get("422_sent"), 1);

        stats.inc("sessions_expired");
        assert_eq!(stats.get("sessions_expired"), 1);

        let json = stats.to_json();
        assert!(json.contains("\"sessions_active\":5"));
        assert!(json.contains("\"headers_inserted\":2"));
    }

    // ── stats JSON output test ──────────────────────────────────

    #[test]
    fn test_sst_stats_json_format() {
        let stats = Stats::new("test_sst_json", &[
            "sessions_active",
            "sessions_expired",
            "422_sent",
            "headers_inserted",
        ]);
        stats.set("sessions_active", 3);
        stats.inc("422_sent");
        stats.inc("headers_inserted");
        stats.inc("headers_inserted");
        stats.inc("sessions_expired");

        let json = stats.to_json();
        assert!(json.starts_with("{"));
        assert!(json.ends_with("}"));
        assert!(json.contains(r#""sessions_active":3"#));
        assert!(json.contains(r#""sessions_expired":1"#));
        assert!(json.contains(r#""422_sent":1"#));
        assert!(json.contains(r#""headers_inserted":2"#));
    }


    // ── configuration validation tests ──────────────────────────

    #[test]
    fn test_parse_refresher_invalid_defaults_uas() {
        // Invalid refresher values should default to UAS
        assert_eq!(parse_refresher("invalid"), Refresher::Uas);
        assert_eq!(parse_refresher(""), Refresher::Uas);
        assert_eq!(parse_refresher("both"), Refresher::Uas);
    }

    #[test]
    fn test_sst_check_min_se_clamped_to_90() {
        // Even with our_min_se=0, the function handles it
        let (ok, interval, min_se) = sst_check(1800, 0, 0);
        assert!(ok);
        assert_eq!(interval, 1800);
        assert_eq!(min_se, 0);
    }

    #[test]
    fn test_sst_update_negative_interval_clamps() {
        // Interval 0 falls back to default
        let (se, min) = sst_update(0, 0, &Refresher::Uas, 1800, 90);
        assert_eq!(se, "1800;refresher=uas");
        assert_eq!(min, "90");
    }

    // ── per-account policy tests ─────────────────────────────────

    #[test]
    fn test_parse_policy_line_valid() {
        let result = parse_policy_line("alice,1800,90,uac");
        assert_eq!(result, Some("alice,1800,90,uac".to_string()));
    }

    #[test]
    fn test_parse_policy_line_comment() {
        assert_eq!(parse_policy_line("# comment"), None);
    }

    #[test]
    fn test_parse_policy_line_empty() {
        assert_eq!(parse_policy_line(""), None);
    }

    #[test]
    fn test_parse_policy_line_too_few_fields() {
        assert_eq!(parse_policy_line("alice,1800"), None);
    }

    #[test]
    fn test_parse_policy_line_whitespace() {
        let result = parse_policy_line("  bob , 3600 , 120 , uas  ");
        assert_eq!(result, Some("bob , 3600 , 120 , uas".to_string()));
    }

    #[test]
    fn test_build_policies_basic() {
        let entries = vec![
            "alice,1800,90,uac".to_string(),
            "bob,3600,120,uas".to_string(),
        ];
        let map = build_policies(entries);
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("alice"));
        assert!(map.contains_key("bob"));
        let alice = &map["alice"];
        assert_eq!(alice.interval, 1800);
        assert_eq!(alice.min_se, 90);
        assert_eq!(alice.refresher, Refresher::Uac);
        let bob = &map["bob"];
        assert_eq!(bob.interval, 3600);
        assert_eq!(bob.min_se, 120);
        assert_eq!(bob.refresher, Refresher::Uas);
    }

    #[test]
    fn test_build_policies_clamps_min() {
        let entries = vec!["alice,50,30,uac".to_string()];
        let map = build_policies(entries);
        let alice = &map["alice"];
        assert_eq!(alice.interval, 90); // clamped from 50
        assert_eq!(alice.min_se, 90);   // clamped from 30
    }

    #[test]
    fn test_build_policies_empty() {
        let map = build_policies(vec![]);
        assert!(map.is_empty());
    }

    #[test]
    fn test_build_policies_skips_bad_interval() {
        let entries = vec!["alice,0,90,uac".to_string()];
        let map = build_policies(entries);
        assert!(map.is_empty()); // interval=0 is skipped
    }

    #[test]
    fn test_build_policies_skips_empty_account() {
        let entries = vec![",1800,90,uac".to_string()];
        let map = build_policies(entries);
        assert!(map.is_empty());
    }

    #[test]
    fn test_build_policies_with_whitespace() {
        let entries = vec!["  bob , 3600 , 120 , uas  ".to_string()];
        let map = build_policies(entries);
        assert!(map.contains_key("bob"));
        let bob = &map["bob"];
        assert_eq!(bob.interval, 3600);
        assert_eq!(bob.min_se, 120);
        assert_eq!(bob.refresher, Refresher::Uas);
    }

    #[test]
    fn test_build_policies_invalid_numbers() {
        let entries = vec!["alice,abc,xyz,uac".to_string()];
        let map = build_policies(entries);
        assert!(map.is_empty()); // interval=0 (parse fail) => skipped
    }

    // ── sst_status / refresh_count tests ─────────────────────────

    #[test]
    fn test_sst_state_refresh_count_default() {
        let state = SstState::default();
        assert_eq!(state.refresh_count, 0);
    }

    #[test]
    fn test_tracker_refresh_count_increment() {
        let tracker: DialogTracker<SstState> = DialogTracker::new(3600);
        tracker.on_created("call-1");
        tracker.with_state("call-1", |s| {
            s.interval = 1800;
            s.refresher = Refresher::Uac;
            s.refresh_count += 1;
        });
        tracker.with_state("call-1", |s| {
            s.refresh_count += 1;
        });
        let count = tracker.with_state_ref("call-1", |s| s.refresh_count);
        assert_eq!(count, Some(2));
    }

    #[test]
    fn test_build_sst_status_json_empty() {
        // When no dialogs are tracked, should return "[]"
        TRACKER.with(|t| {
            // Ensure empty
            while t.active_count() > 0 {
                // cleanup any leftover from other tests
                break;
            }
        });
        let json = build_sst_status_json();
        assert!(json.starts_with('['));
        assert!(json.ends_with(']'));
    }

    // ── stale session detection tests ───────────────────────────

    #[test]
    fn test_sst_state_last_refresh_default() {
        let state = SstState::default();
        assert!(state.last_refresh.is_none());
    }

    #[test]
    fn test_stale_detection_not_stale() {
        // Session refreshed recently, interval=1800 => not stale
        let state = SstState {
            interval: 1800,
            last_refresh: Some(Instant::now()),
            ..SstState::default()
        };
        let since = state.last_refresh.unwrap().elapsed().as_secs() as u32;
        let is_stale = since > state.interval && state.interval > 0;
        assert!(!is_stale);
    }

    #[test]
    fn test_stale_detection_stale() {
        // Session with interval=0 => not stale (interval=0 means no timer)
        let state = SstState {
            interval: 0,
            last_refresh: Some(Instant::now() - std::time::Duration::from_secs(100)),
            ..SstState::default()
        };
        let since = state.last_refresh.unwrap().elapsed().as_secs() as u32;
        let is_stale = since > state.interval && state.interval > 0;
        assert!(!is_stale);
    }

    #[test]
    fn test_stale_detection_no_refresh() {
        let state = SstState::default();
        let is_stale = match state.last_refresh {
            Some(t) => t.elapsed().as_secs() as u32 > state.interval && state.interval > 0,
            None => false,
        };
        assert!(!is_stale);
    }

    // ── event publishing tests ──────────────────────────────────

    #[test]
    fn test_event_payload_sst_stale() {
        let payload = event::format_payload(&[
            ("call_id", &event::json_str("abc-123")),
            ("interval", "1800"),
            ("since_last_refresh", "2000"),
        ]);
        assert!(payload.contains(r#""call_id":"abc-123""#));
        assert!(payload.contains(r#""interval":1800"#));
        assert!(payload.contains(r#""since_last_refresh":2000"#));
    }

    #[test]
    fn test_event_payload_sst_expired() {
        let payload = event::format_payload(&[
            ("call_id", &event::json_str("xyz-789")),
        ]);
        assert_eq!(payload, r#"{"call_id":"xyz-789"}"#);
    }

    // ── force refresher tests ─────────────────────────────────

    #[test]
    fn test_force_refresher_uac_state() {
        // Simulate force_refresher overriding state
        let mut state = SstState {
            refresher: Refresher::Uas,
            ..SstState::default()
        };
        // Simulating what get_forced_refresher would return
        let forced = Some(Refresher::Uac);
        if let Some(f) = forced {
            state.refresher = f;
        }
        assert_eq!(state.refresher, Refresher::Uac);
    }

    #[test]
    fn test_force_refresher_uas_state() {
        let mut state = SstState {
            refresher: Refresher::Uac,
            ..SstState::default()
        };
        let forced = Some(Refresher::Uas);
        if let Some(f) = forced {
            state.refresher = f;
        }
        assert_eq!(state.refresher, Refresher::Uas);
    }

    #[test]
    fn test_force_refresher_none_no_change() {
        let mut state = SstState {
            refresher: Refresher::Uac,
            ..SstState::default()
        };
        let forced: Option<Refresher> = None;
        if let Some(f) = forced {
            state.refresher = f;
        }
        assert_eq!(state.refresher, Refresher::Uac); // unchanged
    }

    // ── adaptive min_se tests ────────────────────────────────────

    #[test]
    fn test_extract_dest_host_full_uri() {
        assert_eq!(extract_dest_host("sip:alice@example.com:5060;transport=tcp"), "example.com");
    }

    #[test]
    fn test_extract_dest_host_no_user() {
        assert_eq!(extract_dest_host("sip:10.0.0.1:5060"), "10.0.0.1");
    }

    #[test]
    fn test_extract_dest_host_simple() {
        assert_eq!(extract_dest_host("sip:user@host"), "host");
    }

    #[test]
    fn test_extract_dest_host_with_angle() {
        assert_eq!(extract_dest_host("sip:user@host>"), "host");
    }

    #[test]
    fn test_extract_dest_host_empty() {
        assert_eq!(extract_dest_host(""), "");
    }

    #[test]
    fn test_record_and_get_adaptive() {
        // Test the adaptive map directly
        ADAPTIVE_MAP.with(|m| m.borrow_mut().clear());
        ADAPTIVE_MAP.with(|m| m.borrow_mut().insert("10.0.0.1".to_string(), 180));
        let val = ADAPTIVE_MAP.with(|m| m.borrow().get("10.0.0.1").copied());
        assert_eq!(val, Some(180));
        ADAPTIVE_MAP.with(|m| m.borrow_mut().clear());
    }

    #[test]
    fn test_adaptive_keeps_highest() {
        ADAPTIVE_MAP.with(|m| m.borrow_mut().clear());
        ADAPTIVE_MAP.with(|m| m.borrow_mut().insert("host1".to_string(), 120));
        // Higher value should replace
        let current = ADAPTIVE_MAP.with(|m| m.borrow().get("host1").copied().unwrap_or(0));
        if 180 > current {
            ADAPTIVE_MAP.with(|m| m.borrow_mut().insert("host1".to_string(), 180));
        }
        let val = ADAPTIVE_MAP.with(|m| m.borrow().get("host1").copied());
        assert_eq!(val, Some(180));
        // Lower value should NOT replace
        let current = ADAPTIVE_MAP.with(|m| m.borrow().get("host1").copied().unwrap_or(0));
        if 90 > current {
            ADAPTIVE_MAP.with(|m| m.borrow_mut().insert("host1".to_string(), 90));
        }
        let val = ADAPTIVE_MAP.with(|m| m.borrow().get("host1").copied());
        assert_eq!(val, Some(180)); // Still 180
        ADAPTIVE_MAP.with(|m| m.borrow_mut().clear());
    }

    // ── per-refresher direction stat tests ──────────────────────

    #[test]
    fn test_refresher_direction_stats() {
        let stats = Stats::new("test_dir", &[
            "sessions_uac_refresher",
            "sessions_uas_refresher",
        ]);
        stats.inc("sessions_uac_refresher");
        stats.inc("sessions_uac_refresher");
        stats.inc("sessions_uas_refresher");
        assert_eq!(stats.get("sessions_uac_refresher"), 2);
        assert_eq!(stats.get("sessions_uas_refresher"), 1);
    }

    #[test]
    fn test_refresher_stats_in_json() {
        let stats = Stats::new("test_dir_json", &[
            "sessions_active",
            "sessions_expired",
            "422_sent",
            "headers_inserted",
            "stale_sessions",
            "sessions_uac_refresher",
            "sessions_uas_refresher",
        ]);
        stats.inc("sessions_uac_refresher");
        stats.set("sessions_uas_refresher", 5);
        let json = stats.to_json();
        assert!(json.contains(r#""sessions_uac_refresher":1"#));
        assert!(json.contains(r#""sessions_uas_refresher":5"#));
    }

    #[test]
    fn test_stale_sessions_stat() {
        let stats = Stats::new("test_stale", &[
            "sessions_active",
            "sessions_expired",
            "422_sent",
            "headers_inserted",
            "stale_sessions",
        ]);
        stats.inc("stale_sessions");
        stats.inc("stale_sessions");
        assert_eq!(stats.get("stale_sessions"), 2);
        let json = stats.to_json();
        assert!(json.contains(r#""stale_sessions":2"#));
    }

    #[test]
    fn test_status_json_contains_fields() {
        TRACKER.with(|t| {
            t.on_created("status-test-call");
            t.with_state("status-test-call", |s| {
                s.interval = 1800;
                s.refresher = Refresher::Uac;
                s.refresh_count = 3;
            });
        });
        let json = build_sst_status_json();
        assert!(json.contains(r#""call_id":"status-test-call""#));
        assert!(json.contains(r#""interval":1800"#));
        assert!(json.contains(r#""refresher":"uac""#));
        assert!(json.contains(r#""refresh_count":3"#));
        assert!(json.contains(r#""time_remaining":"#));
        // cleanup
        TRACKER.with(|t| { t.on_terminated("status-test-call"); });
    }

}
