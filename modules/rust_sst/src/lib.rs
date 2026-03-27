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
//! `rust_sst_check()` and `rust_sst_update()` remain available for
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
//!         if (rust_sst_check("1800", "90") == -1) {
//!             append_hf("Min-SE: $var(sst_min_se)\r\n");
//!             sl_send_reply(422, "Session Interval Too Small");
//!             exit;
//!         }
//!     }
//! }
//!
//! onreply_route[sst_reply] {
//!     if ($rs == "200" && is_method("INVITE")) {
//!         rust_sst_update("0", "0", "uas");
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
use rust_common::mi::Stats;


use std::ffi::{c_int, c_void};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

// ── Module parameters ────────────────────────────────────────────

/// Default Session-Expires interval in seconds (default 1800 = 30 min).
static DEFAULT_INTERVAL: Integer = Integer::with_default(1800);

/// Default Min-SE value in seconds (default 90, RFC 4028 minimum).
static DEFAULT_MIN_SE: Integer = Integer::with_default(90);

/// Default refresher role: "uac" or "uas" (default "uas").
static DEFAULT_REFRESHER: ModString = ModString::new();

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
}

// ── Thread-local state ───────────────────────────────────────────

thread_local! {
    static TRACKER: DialogTracker<SstState> = DialogTracker::new(7200);
    static SST_STATS: Stats = Stats::new("rust_sst", &[
        "sessions_active",
        "sessions_expired",
        "422_sent",
        "headers_inserted",
    ]);
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

    let our_min_se = get_our_min_se();
    let our_interval = get_our_interval();

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
    };

    if req_se > 0 {
        // Session-Expires present in INVITE
        if req_se < our_min_se {
            if !has_timer {
                // UAC doesn't support timer -- increase Min-SE and forward
                state.interval = std::cmp::max(our_min_se, req_min_se);
                // Insert updated Min-SE header (remove old + append new)
                if req_min_se > 0 {
                    let _ = msg.call("remove_hf", &["Min-SE"]);
                }
                let hdr = format!("Min-SE: {}\r\n", state.interval);
                let _ = msg.call("append_hf", &[&hdr]);
                SST_STATS.with(|s| s.inc("headers_inserted"));
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
            let _ = msg.call("remove_hf", &["Min-SE"]);
            let min_hdr = format!("Min-SE: {}\r\n", state.min_se);
            let _ = msg.call("append_hf", &[&min_hdr]);
            SST_STATS.with(|s| s.inc("headers_inserted"));
        }

        // Insert Session-Expires header
        let se_hdr_val = format!("Session-Expires: {}\r\n", state.interval);
        let _ = msg.call("append_hf", &[&se_hdr_val]);
        SST_STATS.with(|s| s.inc("headers_inserted"));
    }

    // Store state in tracker
    TRACKER.with(|t| {
        t.on_created(&callid);
        t.with_state(&callid, |s| *s = state);
    });
    SST_STATS.with(|s| {
        let count = TRACKER.with(|t| t.active_count()) as u64;
        s.set("sessions_active", count);
    });

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
            let _ = msg.call("append_hf", &[&se_hdr_val]);
            let _ = msg.call("append_hf", &["Require: timer\r\n"]);
            SST_STATS.with(|s| s.inc("headers_inserted"));

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

    TRACKER.with(|t| {
        t.on_terminated(&callid);
    });

    SST_STATS.with(|s| {
        let count = TRACKER.with(|t| t.active_count()) as u64;
        s.set("sessions_active", count);
        if was_expired {
            s.inc("sessions_expired");
        }
    });

    opensips_log!(
        DBG,
        "rust_sst",
        "TERMINATED: callid={}, expired={}",
        callid,
        was_expired
    );
}

// ── Module lifecycle ─────────────────────────────────────────────

unsafe extern "C" fn mod_init() -> c_int {
    let interval = DEFAULT_INTERVAL.get();
    let min_se = DEFAULT_MIN_SE.get();
    let refresher = get_default_refresher();

    if min_se < 90 {
        opensips_log!(
            WARN,
            "rust_sst",
            "default_min_se={} is below RFC 4028 minimum of 90, clamping",
            min_se
        );
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

// ── Script function: rust_sst_check(interval, min_se) ────────────

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

        let our_min_se = if param_min_se > 0 {
            param_min_se
        } else {
            get_our_min_se()
        };

        let requested_interval = if param_interval > 0 {
            param_interval
        } else {
            0
        };

        let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
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

// ── Script function: rust_sst_update(interval, min_se, refresher) ─

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


// ── Script function: rust_sst_stats() ────────────────────────────

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

static CMDS: SyncArray<sys::cmd_export_, 4> = SyncArray([
    sys::cmd_export_ {
        name: cstr_lit!("rust_sst_check"),
        function: Some(w_rust_sst_check),
        params: TWO_STR_PARAMS,
        flags: 1, // REQUEST_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("rust_sst_update"),
        function: Some(w_rust_sst_update),
        params: THREE_STR_PARAMS,
        flags: 1 | 4, // REQUEST_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("rust_sst_stats"),
        function: Some(w_rust_sst_stats),
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

static PARAMS: SyncArray<sys::param_export_, 4> = SyncArray([
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
    stats: ptr::null(),
    mi_cmds: ptr::null(),
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

}
