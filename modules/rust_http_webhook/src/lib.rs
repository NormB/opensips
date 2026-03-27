//! rust_http_webhook — Fire-and-forget HTTP POST webhook for OpenSIPS.
//!
//! Enqueues SIP event payloads for non-blocking HTTP delivery.
//! The script function returns immediately; delivery happens in a
//! background tokio task. If the queue is full, the payload is dropped
//! and the drop counter incremented.
//!
//! # OpenSIPS config
//!
//! ```text
//! loadmodule "rust_http_webhook.so"
//! modparam("rust_http_webhook", "url", "https://example.com/hook")
//! modparam("rust_http_webhook", "max_queue", 2000)
//! modparam("rust_http_webhook", "http_timeout", 5)
//! modparam("rust_http_webhook", "content_type", "application/json")
//!
//! route {
//!     rust_webhook("{\"method\":\"$rm\",\"ruri\":\"$ru\"}");
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
use rust_common::async_dispatch::FireAndForget;

use std::cell::RefCell;
use std::ffi::{c_int, c_void};
use std::ptr;

// ── Module parameters ────────────────────────────────────────────

/// Webhook endpoint URL (required).
static URL: ModString = ModString::new();

/// Maximum queued payloads before dropping (default: 1000).
static MAX_QUEUE: Integer = Integer::with_default(1000);

/// HTTP request timeout in seconds (default: 5).
static HTTP_TIMEOUT: Integer = Integer::with_default(5);

/// Content-Type header for POST requests (default: "application/json").
static CONTENT_TYPE: ModString = ModString::new();

/// Path to a custom CA certificate file for TLS verification (optional).
static TLS_CA_FILE: ModString = ModString::new();

// ── Per-worker state ─────────────────────────────────────────────

thread_local! {
    static WEBHOOK: RefCell<Option<FireAndForget>> = const { RefCell::new(None) };
}

// ── Module lifecycle ─────────────────────────────────────────────

unsafe extern "C" fn mod_init() -> c_int {
    let url = match URL.get_value() {
        Some(u) if !u.is_empty() => u,
        _ => {
            opensips_log!(ERR, "rust_http_webhook",
                "modparam 'url' is required but not set");
            return -1;
        }
    };

    let content_type = CONTENT_TYPE.get_value().unwrap_or("application/json");

    opensips_log!(INFO, "rust_http_webhook", "module initialized");
    opensips_log!(INFO, "rust_http_webhook", "  url={}", url);
    opensips_log!(INFO, "rust_http_webhook", "  max_queue={}", MAX_QUEUE.get());
    opensips_log!(INFO, "rust_http_webhook", "  http_timeout={}s", HTTP_TIMEOUT.get());
    opensips_log!(INFO, "rust_http_webhook", "  content_type={}", content_type);

    if let Some(ca) = TLS_CA_FILE.get_value() {
        opensips_log!(INFO, "rust_http_webhook", "  tls_ca_file={}", ca);
    }

    0
}

unsafe extern "C" fn mod_child_init(rank: c_int) -> c_int {
    // Only initialize for worker processes (rank >= 1).
    // Rank 0 is the main/attendant process, negative ranks are special.
    if rank < 1 {
        return 0;
    }

    let url = match URL.get_value() {
        Some(u) => u.to_string(),
        None => return -1,
    };
    let content_type = CONTENT_TYPE.get_value()
        .unwrap_or("application/json")
        .to_string();

    WEBHOOK.with(|w| {
        *w.borrow_mut() = Some(FireAndForget::new(
            url,
            MAX_QUEUE.get() as usize,
            HTTP_TIMEOUT.get() as u64,
            content_type,
        ));
    });

    opensips_log!(DBG, "rust_http_webhook",
        "worker {} initialized fire-and-forget dispatcher", rank);
    0
}

unsafe extern "C" fn mod_destroy() {
    opensips_log!(INFO, "rust_http_webhook", "module destroyed");
}

// ── Script function: rust_webhook(payload) ───────────────────────

unsafe extern "C" fn w_rust_webhook(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let payload = match <&str as CommandFunctionParam>::from_raw(p0) {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_http_webhook",
                    "rust_webhook: missing or invalid payload parameter");
                return -1;
            }
        };

        WEBHOOK.with(|w| {
            let borrow = w.borrow();
            match borrow.as_ref() {
                Some(ff) => {
                    if !ff.send(payload.to_string()) {
                        opensips_log!(WARN, "rust_http_webhook",
                            "queue full, payload dropped (dropped={})",
                            ff.dropped.get());
                    }
                    1
                }
                None => {
                    opensips_log!(ERR, "rust_http_webhook",
                        "webhook dispatcher not initialized in this worker");
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

static CMDS: SyncArray<sys::cmd_export_, 2> = SyncArray([
    sys::cmd_export_ {
        name: cstr_lit!("rust_webhook"),
        function: Some(w_rust_webhook),
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

// No async commands
static ACMDS: SyncArray<sys::acmd_export_, 1> = SyncArray([
    sys::acmd_export_ {
        name: ptr::null(),
        function: None,
        params: EMPTY_PARAMS,
    },
]);

static PARAMS: SyncArray<sys::param_export_, 6> = SyncArray([
    sys::param_export_ {
        name: cstr_lit!("url"),
        type_: 1, // STR_PARAM
        param_pointer: URL.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("max_queue"),
        type_: 2, // INT_PARAM
        param_pointer: MAX_QUEUE.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("http_timeout"),
        type_: 2, // INT_PARAM
        param_pointer: HTTP_TIMEOUT.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("content_type"),
        type_: 1, // STR_PARAM
        param_pointer: CONTENT_TYPE.as_ptr(),
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

// No module dependencies
static DEPS: opensips_rs::ffi::DepExportConcrete<1> = opensips_rs::ffi::DepExportConcrete {
    md: unsafe { std::mem::zeroed() },
    mpd: unsafe { std::mem::zeroed() },
};

/// The module_exports struct that OpenSIPS loads via dlsym("exports").
#[no_mangle]
pub static exports: sys::module_exports = sys::module_exports {
    name: cstr_lit!("rust_http_webhook"),
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
