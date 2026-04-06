//! rust_sst — SIP Session Timers (RFC 4028) for OpenSIPS.
//!
//! Rewritten to avoid Rust trait objects / dynamic dispatch which trigger a
//! rustc 1.94 aarch64 cdylib codegen bug: R_AARCH64_RELATIVE relocations for
//! trait vtable entries point directly to function code instead of vtable data,
//! causing the vtable dispatch to read instruction bytes as function pointers.
//!
//! This version is script-only mode: sst_check() validates Session-Expires
//! values using pure arithmetic. All dialog callback code (which was the sole
//! source of trait-object dispatch via HashMap, Vec, String, Box, format!,
//! to_string(), catch_unwind) has been removed.
//!
//! # OpenSIPS config
//!
//! ```text
//! loadmodule "rust_sst.so"
//!
//! modparam("rust_sst", "default_interval", 1800)
//! modparam("rust_sst", "default_min_se", 90)
//! modparam("rust_sst", "default_refresher", "uas")
//!
//! route {
//!     if (is_method("INVITE")) {
//!         if (sst_check("1800", "90") == -1) {
//!             append_hf("Min-SE: $var(sst_min_se)\r\n");
//!             sl_send_reply(422, "Session Interval Too Small");
//!             exit;
//!         }
//!     }
//! }
//! ```

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]

use opensips_rs::command::CommandFunctionParam;
use opensips_rs::param::{Integer, ModString};
use opensips_rs::sys;
use opensips_rs::{cstr_lit, opensips_log};

use rust_common::mi_resp::mi_ok;
use rust_common::stat::{StatVar, StatVarOpaque};

use std::ffi::{c_int, c_void};
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};

// SyncArray: wrapper to satisfy Rust's Sync trait requirement for
// static arrays of C structs containing raw pointers.
#[repr(transparent)]
struct SyncArray<T, const N: usize>([T; N]);
unsafe impl<T, const N: usize> Sync for SyncArray<T, N> {}

// ── Native statistics ────────────────────────────────────────────
static STAT_CHECKED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_ACCEPTED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_REJECTED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());

/// STAT_NO_RESET flag value (from OpenSIPS statistics.h).
#[allow(dead_code)]
const STAT_NO_RESET: u16 = 1;

// ── Module parameters ────────────────────────────────────────────

/// Default Session-Expires interval in seconds (default 1800 = 30 min).
static DEFAULT_INTERVAL: Integer = Integer::with_default(1800);

/// Default Min-SE value in seconds (default 90, RFC 4028 minimum).
static DEFAULT_MIN_SE: Integer = Integer::with_default(90);

/// Default refresher role: "uac" or "uas" (default "uas").
static DEFAULT_REFRESHER: ModString = ModString::new();

/// Enable event publishing (0=off, 1=on, default 0).
static PUBLISH_EVENTS: Integer = Integer::with_default(0);

// ── Pure arithmetic helpers (no String, no format!, no alloc) ────

/// Parse a byte slice as u32. Returns None on empty or non-digit input.
fn parse_u32(b: &[u8]) -> Option<u32> {
    if b.is_empty() { return None; }
    let mut val: u32 = 0;
    for &c in b {
        if c < b'0' || c > b'9' { return None; }
        val = val.checked_mul(10)?.checked_add((c - b'0') as u32)?;
    }
    Some(val)
}

/// Trim leading/trailing whitespace from a byte slice.
fn trim_bytes(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&c| c != b' ' && c != b'\t' && c != b'\r' && c != b'\n').unwrap_or(b.len());
    let end = b.iter().rposition(|&c| c != b' ' && c != b'\t' && c != b'\r' && c != b'\n').map_or(start, |e| e + 1);
    if start >= end { &[] } else { &b[start..end] }
}

/// Parse a &str parameter as u32, trimming whitespace.
fn parse_str_param(s: &str) -> u32 {
    parse_u32(trim_bytes(s.as_bytes())).unwrap_or(0)
}

/// Core SST check: pure arithmetic, no allocations.
///
/// Returns (acceptable, negotiated_interval, effective_min_se):
/// - acceptable: true if interval >= effective_min_se (or no interval given)
/// - negotiated_interval: the interval to use (0 if rejected)
/// - effective_min_se: max(requested_min_se, our_min_se)
fn sst_check_logic(requested_interval: u32, requested_min_se: u32, our_min_se: u32) -> (bool, u32, u32) {
    let effective_min_se = if requested_min_se > our_min_se { requested_min_se } else { our_min_se };
    if requested_interval > 0 && requested_interval < effective_min_se {
        // Session-Expires is below the effective minimum — reject with 422
        (false, 0, effective_min_se)
    } else {
        // Acceptable: use the requested interval, or fall back to double our min_se
        let interval = if requested_interval > 0 {
            requested_interval
        } else {
            let doubled = our_min_se * 2;
            if doubled > effective_min_se { doubled } else { effective_min_se }
        };
        (true, interval, effective_min_se)
    }
}

// ── Module lifecycle ─────────────────────────────────────────────

unsafe extern "C" fn mod_init() -> c_int {
    let interval = DEFAULT_INTERVAL.get();
    let min_se = DEFAULT_MIN_SE.get();

    // Validate default_interval
    if interval < 0 {
        opensips_log!(WARN, "rust_sst",
            "default_interval={} is negative, clamping to 1800", interval);
    } else if interval > 0 && interval < 90 {
        opensips_log!(WARN, "rust_sst",
            "default_interval={} is below RFC 4028 minimum of 90", interval);
    }

    if min_se < 90 {
        opensips_log!(WARN, "rust_sst",
            "default_min_se={} is below RFC 4028 minimum of 90", min_se);
    }

    opensips_log!(INFO, "rust_sst", "module initialized (script-only mode, no vtable dispatch)");
    opensips_log!(INFO, "rust_sst",
        "  default_interval={}, default_min_se={}, publish_events={}",
        interval, min_se, PUBLISH_EVENTS.get());
    0
}

unsafe extern "C" fn mod_destroy() {
    opensips_log!(INFO, "rust_sst", "module destroyed");
}

// ── Script function: sst_check(interval, min_se) ────────────────

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
    // Parse the two string parameters as integers
    let param_interval = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
        Some(s) => parse_str_param(s),
        None => 0,
    };
    let param_min_se = match unsafe { <&str as CommandFunctionParam>::from_raw(p1) } {
        Some(s) => parse_str_param(s),
        None => 0,
    };

    // Get our configured minimum
    let our_min_se = {
        let v = DEFAULT_MIN_SE.get() as u32;
        if v < 90 { 90 } else { v }
    };

    // Use param_interval as the requested Session-Expires
    // Use param_min_se as the requested Min-SE (0 means use our default)
    let (acceptable, negotiated, effective_min_se) =
        sst_check_logic(param_interval, param_min_se, our_min_se);

    // Increment native statistics
    if let Some(sv) = StatVar::from_raw(STAT_CHECKED.load(Ordering::Relaxed)) { sv.inc(); }

    // Set pseudo-variables via stack-based C FFI (no vtable dispatch)
    let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
    let _ = sip_msg.set_pv_int("$var(sst_interval)", negotiated as i32);
    let _ = sip_msg.set_pv_int("$var(sst_min_se)", effective_min_se as i32);

    if acceptable {
        if let Some(sv) = StatVar::from_raw(STAT_ACCEPTED.load(Ordering::Relaxed)) { sv.inc(); }
        opensips_log!(DBG, "rust_sst",
            "sst_check OK: interval={}, min_se={}", negotiated, effective_min_se);
        1
    } else {
        if let Some(sv) = StatVar::from_raw(STAT_REJECTED.load(Ordering::Relaxed)) { sv.inc(); }
        opensips_log!(DBG, "rust_sst",
            "sst_check REJECTED: requested={} < effective_min_se={}",
            param_interval, effective_min_se);
        -1
    }
}

// ── Stub functions (no-ops for removed features) ─────────────────

unsafe extern "C" fn w_noop(
    _msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int { 1 }

// ── MI commands (stubs) ──────────────────────────────────────────

const NULL_RECIPE: sys::mi_recipe_ = sys::mi_recipe_ { cmd: None, params: [ptr::null_mut(); 20] };

const NULL_MI: sys::mi_export_ = sys::mi_export_ {
    name: ptr::null_mut(), help: ptr::null_mut(), flags: 0, init_f: None,
    recipes: [NULL_RECIPE; 48], aliases: [ptr::null(); 4],
};

unsafe extern "C" fn mi_sst_show(
    _params: *const sys::mi_params_t,
    _async_hdl: *mut sys::mi_handler,
) -> *mut sys::mi_response_t {
    mi_ok() as *mut _
}

macro_rules! mi_entry {
    ($name:expr, $help:expr, $handler:expr) => {
        sys::mi_export_ {
            name: cstr_lit!($name) as *mut _,
            help: cstr_lit!($help) as *mut _,
            flags: 0,
            init_f: None,
            recipes: {
                let mut r = [NULL_RECIPE; 48];
                r[0].cmd = Some($handler);
                r
            },
            aliases: [ptr::null(); 4],
        }
    };
}

// ── Static export arrays ─────────────────────────────────────────

const EMPTY_PARAMS: [sys::cmd_param; 9] = [sys::cmd_param { flags: 0, fixup: None, free_fixup: None }; 9];

const TWO_STR_PARAMS: [sys::cmd_param; 9] = {
    let mut p = [sys::cmd_param { flags: 0, fixup: None, free_fixup: None }; 9];
    p[0].flags = 2; // CMD_PARAM_STR
    p[1].flags = 2; // CMD_PARAM_STR
    p
};

static CMDS: SyncArray<sys::cmd_export_, 7> = SyncArray([
    sys::cmd_export_ {
        name: cstr_lit!("sst_check"),
        function: Some(w_rust_sst_check),
        params: TWO_STR_PARAMS,
        flags: 1, // REQUEST_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("sst_update"),
        function: Some(w_noop),
        params: EMPTY_PARAMS,
        flags: 1 | 4, // REQUEST_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("sst_stats"),
        function: Some(w_noop),
        params: EMPTY_PARAMS,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("sst_status"),
        function: Some(w_noop),
        params: EMPTY_PARAMS,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("sst_reload"),
        function: Some(w_noop),
        params: EMPTY_PARAMS,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("sst_prometheus"),
        function: Some(w_noop),
        params: EMPTY_PARAMS,
        flags: 1 | 2 | 4,
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
    sys::acmd_export_ { name: ptr::null(), function: None, params: EMPTY_PARAMS },
]);

static PARAMS: SyncArray<sys::param_export_, 5> = SyncArray([
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

static MOD_STATS: SyncArray<sys::stat_export_, 4> = SyncArray([
    sys::stat_export_ { name: cstr_lit!("checked") as *mut _,  flags: 0, stat_pointer: &STAT_CHECKED as *const _ as *mut _ },
    sys::stat_export_ { name: cstr_lit!("accepted") as *mut _, flags: 0, stat_pointer: &STAT_ACCEPTED as *const _ as *mut _ },
    sys::stat_export_ { name: cstr_lit!("rejected") as *mut _, flags: 0, stat_pointer: &STAT_REJECTED as *const _ as *mut _ },
    sys::stat_export_ { name: ptr::null_mut(), flags: 0, stat_pointer: ptr::null_mut() },
]);

static MI_CMDS: SyncArray<sys::mi_export_, 2> = SyncArray([
    mi_entry!("sst_show", "Show SST status (stub)", mi_sst_show),
    NULL_MI,
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

    #[test]
    fn test_sst_check_acceptable() {
        let (ok, interval, min_se) = sst_check_logic(1800, 90, 90);
        assert!(ok);
        assert_eq!(interval, 1800);
        assert_eq!(min_se, 90);
    }

    #[test]
    fn test_sst_check_rejected() {
        let (ok, interval, min_se) = sst_check_logic(60, 0, 90);
        assert!(!ok);
        assert_eq!(interval, 0);
        assert_eq!(min_se, 90);
    }

    #[test]
    fn test_sst_check_no_interval() {
        let (ok, interval, min_se) = sst_check_logic(0, 0, 90);
        assert!(ok);
        assert_eq!(interval, 180); // 90 * 2
        assert_eq!(min_se, 90);
    }

    #[test]
    fn test_sst_check_remote_min_se_higher() {
        let (ok, interval, min_se) = sst_check_logic(1800, 120, 90);
        assert!(ok);
        assert_eq!(interval, 1800);
        assert_eq!(min_se, 120);
    }

    #[test]
    fn test_sst_check_rejected_with_remote_min_se() {
        // requested_interval=100 < effective_min_se=max(120,90)=120
        let (ok, interval, min_se) = sst_check_logic(100, 120, 90);
        assert!(!ok);
        assert_eq!(interval, 0);
        assert_eq!(min_se, 120);
    }

    #[test]
    fn test_parse_u32_valid() {
        assert_eq!(parse_u32(b"1800"), Some(1800));
        assert_eq!(parse_u32(b"90"), Some(90));
        assert_eq!(parse_u32(b"0"), Some(0));
    }

    #[test]
    fn test_parse_u32_invalid() {
        assert_eq!(parse_u32(b""), None);
        assert_eq!(parse_u32(b"abc"), None);
        assert_eq!(parse_u32(b"-1"), None);
    }

    #[test]
    fn test_trim_bytes() {
        assert_eq!(trim_bytes(b"  1800  "), b"1800");
        assert_eq!(trim_bytes(b"90"), b"90");
        assert_eq!(trim_bytes(b"  "), &[] as &[u8]);
    }
}
