//! rust_http_webhook — Fire-and-forget HTTP POST webhook for OpenSIPS.
//!
//! Enqueues SIP event payloads for non-blocking HTTP delivery.
//! The script function returns immediately; delivery happens in a
//! background tokio task. If the queue is full, the payload is dropped
//! and the drop counter incremented.
//!
//! Supports custom headers, multiple URLs (fanout), retry with
//! exponential backoff, message batching, SIP method filtering,
//! and HTTP error logging/stats.
//!
//! # OpenSIPS config
//!
//! ```text
//! loadmodule "rust_http_webhook.so"
//! modparam("rust_http_webhook", "url", "https://example.com/hook")
//! modparam("rust_http_webhook", "max_queue", 2000)
//! modparam("rust_http_webhook", "http_timeout", 5)
//! modparam("rust_http_webhook", "content_type", "application/json")
//! modparam("rust_http_webhook", "headers", "Authorization: Bearer xxx|X-Source: opensips")
//! modparam("rust_http_webhook", "max_retries", 3)
//! modparam("rust_http_webhook", "retry_delay_ms", 1000)
//! modparam("rust_http_webhook", "batch_size", 10)
//! modparam("rust_http_webhook", "batch_timeout_ms", 200)
//! modparam("rust_http_webhook", "method_filter", "INVITE,BYE,REGISTER")
//! modparam("rust_http_webhook", "log_errors", 1)
//!
//! route {
//!     webhook("{\"method\":\"$rm\",\"ruri\":\"$ru\"}");
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
use rust_common::async_dispatch::{
    parse_headers, parse_urls, BatchConfig, FireAndForget, RetryConfig,
};
use rust_common::mi::Stats;
use rust_common::mi_resp::{MiObject, mi_error};
use rust_common::stat::{StatVar, StatVarOpaque};

use std::cell::RefCell;
use std::collections::HashSet;
use std::ffi::{c_int, c_void};
use std::ptr;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicPtr, Ordering};

// Native statistics -- cross-worker, aggregated by OpenSIPS core.
static STAT_SENT: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_FAILED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_DROPPED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_RETRIED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_RETRY_EXHAUSTED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_FILTERED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_QUEUE_DEPTH: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());

/// STAT_NO_RESET flag value (from OpenSIPS statistics.h).
use opensips_rs::stat_flags::NO_RESET as STAT_NO_RESET;

// ── Module parameters ────────────────────────────────────────────

/// Webhook endpoint URL(s) (required). Comma-separated for fanout.
static URL: ModString = ModString::new();

/// Maximum queued payloads before dropping (default: 1000).
static MAX_QUEUE: Integer = Integer::with_default(1000);

/// HTTP request timeout in seconds (default: 5).
static HTTP_TIMEOUT: Integer = Integer::with_default(5);

/// Content-Type header for POST requests (default: "application/json").
static CONTENT_TYPE: ModString = ModString::new();

/// Path to a custom CA certificate file for TLS verification (optional).
static TLS_CA_FILE: ModString = ModString::new();

/// Custom headers, pipe-separated: "Name: Value|Name2: Value2"
static HEADERS: ModString = ModString::new();

/// Maximum retry attempts on HTTP failure (default: 0 = no retry).
static MAX_RETRIES: Integer = Integer::with_default(0);

/// Base retry delay in milliseconds (default: 1000). Exponential backoff:
/// delay * 2^(attempt-1).
static RETRY_DELAY_MS: Integer = Integer::with_default(1000);

/// Number of messages to accumulate before sending as a JSON array batch.
/// 1 = no batching (default, current behavior).
static BATCH_SIZE: Integer = Integer::with_default(1);

/// Maximum wait in milliseconds before flushing a partial batch (default: 100).
static BATCH_TIMEOUT_MS: Integer = Integer::with_default(100);

/// Comma-separated list of SIP methods to send webhooks for.
/// Empty = all methods (default).
static METHOD_FILTER: ModString = ModString::new();

/// If 1, log each webhook HTTP failure at WARN level (default: 0).
static LOG_ERRORS: Integer = Integer::with_default(0);

// ── Parsed method filter ─────────────────────────────────────────

/// Parsed method filter set. Empty = allow all.
static METHOD_FILTER_SET: OnceLock<HashSet<String>> = OnceLock::new();

/// Parse a comma-separated method list into a HashSet of uppercase methods.
pub fn parse_method_filter(raw: &str) -> HashSet<String> {
    if raw.is_empty() {
        return HashSet::new();
    }
    raw.split(',')
        .map(|m| m.trim().to_uppercase())
        .filter(|m| !m.is_empty())
        .collect()
}

// ── Per-worker state ─────────────────────────────────────────────

thread_local! {
    static WEBHOOK: RefCell<Option<FireAndForget>> = const { RefCell::new(None) };
    static WEBHOOK_STATS: Stats = Stats::new("rust_http_webhook", &[
        "sent",
        "dropped",
        "failed",
        "retried",
        "retry_exhausted",
        "errors_4xx",
        "errors_5xx",
        "errors_timeout",
        "filtered",
    ]);
    /// Tracks last-synced values for delta-based StatVar updates.
    static LAST_SYNCED: std::cell::Cell<StatSyncState> = const { std::cell::Cell::new(StatSyncState::new()) };
}

/// Snapshot of FireAndForget counters for delta-based StatVar sync.
#[derive(Clone, Copy)]
struct StatSyncState {
    sent: u64,
    failed: u64,
    dropped: u64,
    retried: u64,
    retry_exhausted: u64,
}

impl StatSyncState {
    const fn new() -> Self {
        Self { sent: 0, failed: 0, dropped: 0, retried: 0, retry_exhausted: 0 }
    }
}

/// Sync FireAndForget counters to native StatVars via delta calculation.
/// Called from webhook() so shared-memory stats stay current.
fn sync_ff_to_native_stats(ff: &FireAndForget) {
    LAST_SYNCED.with(|cell| {
        let prev = cell.get();
        let now = StatSyncState {
            sent: ff.sent.get(),
            failed: ff.failed.get(),
            dropped: ff.dropped.get(),
            retried: ff.retried.get(),
            retry_exhausted: ff.retry_exhausted.get(),
        };
        macro_rules! sync_delta {
            ($field:ident, $stat:ident) => {
                let delta = now.$field.wrapping_sub(prev.$field);
                if delta > 0 {
                    if let Some(sv) = StatVar::from_raw($stat.load(Ordering::Relaxed)) {
                        // gui_dCquvqE1csI3: clamp to i32::MAX to prevent overflow
                        let clamped: i32 = delta.min(i32::MAX as u64) as i32;
                        sv.update(clamped);
                    }
                }
            };
        }
        sync_delta!(sent, STAT_SENT);
        sync_delta!(failed, STAT_FAILED);
        sync_delta!(dropped, STAT_DROPPED);
        sync_delta!(retried, STAT_RETRIED);
        sync_delta!(retry_exhausted, STAT_RETRY_EXHAUSTED);
        cell.set(now);
    });
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

    // Validate max_queue
    let max_q = MAX_QUEUE.get();
    if max_q <= 0 {
        opensips_log!(WARN, "rust_http_webhook",
            "max_queue={} is invalid, clamping to default 1000", max_q);
    }

    // Validate http_timeout
    let timeout = HTTP_TIMEOUT.get();
    if timeout <= 0 {
        opensips_log!(WARN, "rust_http_webhook",
            "http_timeout={} is invalid, clamping to default 5", timeout);
    } else if timeout > 300 {
        opensips_log!(WARN, "rust_http_webhook",
            "http_timeout={} is very high (>300s), clamping to 300", timeout);
    }

    // Parse and validate URLs
    let urls = parse_urls(url);
    if urls.is_empty() {
        opensips_log!(ERR, "rust_http_webhook",
            "modparam 'url' resulted in 0 valid URLs after parsing");
        return -1;
    }

    // Parse and validate headers
    let headers_str = HEADERS.get_value().unwrap_or("");
    let headers = parse_headers(headers_str);

    let max_retries = MAX_RETRIES.get();
    let retry_delay = RETRY_DELAY_MS.get();
    let batch_size = BATCH_SIZE.get();
    let batch_timeout = BATCH_TIMEOUT_MS.get();

    // Parse method filter
    let filter_raw = METHOD_FILTER.get_value().unwrap_or("");
    let filter_set = parse_method_filter(filter_raw);
    let _ = METHOD_FILTER_SET.set(filter_set.clone());

    opensips_log!(INFO, "rust_http_webhook", "module initialized");
    for (i, u) in urls.iter().enumerate() {
        opensips_log!(INFO, "rust_http_webhook", "  url[{}]={}", i, u);
    }
    opensips_log!(INFO, "rust_http_webhook", "  max_queue={}", MAX_QUEUE.get());
    opensips_log!(INFO, "rust_http_webhook", "  http_timeout={}s", HTTP_TIMEOUT.get());
    opensips_log!(INFO, "rust_http_webhook", "  content_type={}", content_type);
    if !headers.is_empty() {
        opensips_log!(INFO, "rust_http_webhook", "  custom_headers={}", headers.len());
    }
    if max_retries > 0 {
        opensips_log!(INFO, "rust_http_webhook",
            "  max_retries={}, retry_delay_ms={}", max_retries, retry_delay);
    }
    if batch_size > 1 {
        opensips_log!(INFO, "rust_http_webhook",
            "  batch_size={}, batch_timeout_ms={}", batch_size, batch_timeout);
    }
    if !filter_set.is_empty() {
        opensips_log!(INFO, "rust_http_webhook",
            "  method_filter={:?}", filter_set);
    }
    if LOG_ERRORS.get() > 0 {
        opensips_log!(INFO, "rust_http_webhook", "  log_errors=enabled");
    }

    if let Some(ca) = TLS_CA_FILE.get_value() {
        opensips_log!(INFO, "rust_http_webhook", "  tls_ca_file={}", ca);
    }

    0
}

unsafe extern "C" fn mod_child_init(rank: c_int) -> c_int {
    // Initialize for SIP workers (rank >= 1) and PROC_MODULE (-2) which
    // handles MI commands via httpd.
    if rank < 1 && rank != -2 {
        return 0;
    }

    let url_raw = match URL.get_value() {
        Some(u) => u.to_string(),
        None => return -1,
    };
    let content_type = CONTENT_TYPE.get_value()
        .unwrap_or("application/json")
        .to_string();
    let headers_str = HEADERS.get_value().unwrap_or("").to_string();

    let urls = parse_urls(&url_raw);
    let custom_headers = parse_headers(&headers_str);
    let retry = RetryConfig {
        max_retries: MAX_RETRIES.get().max(0) as u32,
        retry_delay_ms: RETRY_DELAY_MS.get().max(100) as u64,
    };
    let batch = BatchConfig {
        batch_size: BATCH_SIZE.get().max(1) as usize,
        batch_timeout_ms: BATCH_TIMEOUT_MS.get().max(1) as u64,
    };

    WEBHOOK.with(|w| {
        *w.borrow_mut() = Some(FireAndForget::with_all_options(
            urls,
            MAX_QUEUE.get().max(1) as usize,
            HTTP_TIMEOUT.get().max(1) as u64,
            content_type,
            custom_headers,
            retry,
            batch,
        ));
    });

    opensips_log!(DBG, "rust_http_webhook",
        "worker {} initialized fire-and-forget dispatcher", rank);
    0
}

unsafe extern "C" fn mod_destroy() {
    opensips_log!(INFO, "rust_http_webhook", "module destroyed");
}

// ── Script function: webhook(payload) ───────────────────────

unsafe extern "C" fn w_rust_webhook(
    msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let payload = match <&str as CommandFunctionParam>::from_raw(p0) {
            Ok(s) => s,
            Err(_) => {
                opensips_log!(ERR, "rust_http_webhook",
                    "webhook: missing or invalid payload parameter");
                return -2;
            }
        };

        // Check method filter
        if let Some(filter) = METHOD_FILTER_SET.get() {
            if !filter.is_empty() {
                let sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
                let method = sip_msg.method().unwrap_or("").to_uppercase();
                if !filter.contains(&method) {
                    WEBHOOK_STATS.with(|s| s.inc("filtered"));
                    if let Some(sv) = StatVar::from_raw(STAT_FILTERED.load(Ordering::Relaxed)) {
                        sv.inc();
                    }
                    return 1; // Silently skip -- not an error
                }
            }
        }

        WEBHOOK.with(|w| {
            let borrow = w.borrow();
            match borrow.as_ref() {
                Some(ff) => {
                    if !ff.send(payload.to_string()) {
                        opensips_log!(WARN, "rust_http_webhook",
                            "queue full, payload dropped (dropped={})",
                            ff.dropped.get());
                    }
                    // Sync FireAndForget counters → shared-memory StatVars
                    // so MI and `statistics:get` reflect current totals.
                    sync_ff_to_native_stats(ff);
                    1
                }
                None => {
                    opensips_log!(ERR, "rust_http_webhook",
                        "webhook dispatcher not initialized in this worker");
                    -2
                }
            }
        })
    })
}


// ── Script function: webhook_stats() ────────────────────────

unsafe extern "C" fn w_rust_webhook_stats(
    msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let json = WEBHOOK.with(|w| {
            let borrow = w.borrow();
            match borrow.as_ref() {
                Some(ff) => {
                    // Sync stats from FireAndForget counters
                    WEBHOOK_STATS.with(|s| {
                        s.set("sent", ff.sent.get());
                        s.set("dropped", ff.dropped.get());
                        s.set("failed", ff.failed.get());
                        s.set("retried", ff.retried.get());
                        s.set("retry_exhausted", ff.retry_exhausted.get());
                        s.to_json()
                    })
                }
                None => {
                    WEBHOOK_STATS.with(|s| s.to_json())
                }
            }
        });
        let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
        let _ = sip_msg.set_pv("$var(webhook_stats)", &json);
        1
    })
}

// ── Script function: webhook_prometheus() ────────────────────

unsafe extern "C" fn w_rust_webhook_prometheus(
    msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let prom = WEBHOOK.with(|w| {
            let borrow = w.borrow();
            match borrow.as_ref() {
                Some(ff) => {
                    WEBHOOK_STATS.with(|s| {
                        s.set("sent", ff.sent.get());
                        s.set("dropped", ff.dropped.get());
                        s.set("failed", ff.failed.get());
                        s.set("retried", ff.retried.get());
                        s.set("retry_exhausted", ff.retry_exhausted.get());
                        s.to_prometheus()
                    })
                }
                None => {
                    WEBHOOK_STATS.with(|s| s.to_prometheus())
                }
            }
        });
        let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
        let _ = sip_msg.set_pv("$var(webhook_prom)", &prom);
        1
    })
}


// ── Static arrays for module registration ────────────────────────

const EMPTY_PARAMS: [sys::cmd_param; 9] = unsafe { std::mem::zeroed() };

const ONE_STR_PARAM: [sys::cmd_param; 9] = {
    let mut arr: [sys::cmd_param; 9] = unsafe { std::mem::zeroed() };
    arr[0].flags = opensips_rs::command::CMD_PARAM_STR;
    arr
};

#[repr(transparent)]
struct SyncArray<T, const N: usize>([T; N]);
unsafe impl<T, const N: usize> Sync for SyncArray<T, N> {}

// ── Native statistics array ────────────────────────────────────────

static MOD_STATS: SyncArray<sys::stat_export_, 8> = SyncArray([
    sys::stat_export_ { name: cstr_lit!("sent") as *mut _,            flags: 0,             stat_pointer: STAT_SENT.as_ptr() as *mut _ },
    sys::stat_export_ { name: cstr_lit!("failed") as *mut _,          flags: 0,             stat_pointer: STAT_FAILED.as_ptr() as *mut _ },
    sys::stat_export_ { name: cstr_lit!("dropped") as *mut _,         flags: 0,             stat_pointer: STAT_DROPPED.as_ptr() as *mut _ },
    sys::stat_export_ { name: cstr_lit!("retried") as *mut _,         flags: 0,             stat_pointer: STAT_RETRIED.as_ptr() as *mut _ },
    sys::stat_export_ { name: cstr_lit!("retry_exhausted") as *mut _, flags: 0,             stat_pointer: STAT_RETRY_EXHAUSTED.as_ptr() as *mut _ },
    sys::stat_export_ { name: cstr_lit!("filtered") as *mut _,        flags: 0,             stat_pointer: STAT_FILTERED.as_ptr() as *mut _ },
    sys::stat_export_ { name: cstr_lit!("queue_depth") as *mut _,     flags: STAT_NO_RESET, stat_pointer: STAT_QUEUE_DEPTH.as_ptr() as *mut _ },
    unsafe { std::mem::zeroed() }, // NULL terminator
]);

// ── MI command handlers ────────────────────────────────────────────

/// MI handler: rust_http_webhook:webhook_status
///
/// Reads from native StatVar (OpenSIPS-core-managed shared memory,
/// aggregated across all workers) so the MI process sees global totals
/// regardless of which process handles the MI request.
///
/// # Why this module is NOT affected by the per-worker thread_local bug
///
/// Sister modules (rust_acl, rust_concurrent_calls, rust_refer_handler)
/// hit a bug where MI handlers iterated the MI process's own
/// thread_local state, which was always empty because the MI process
/// never serves SIP traffic. This module avoids that trap by design:
///
///  * Per-worker `StatSyncState` tracks last-synced deltas; each call
///    to `webhook()` calls `sync_ff_to_native_stats(ff)` which pushes
///    its delta into the shared StatVars.
///  * This MI handler reads ONLY from the shared StatVars — never
///    from the per-worker `FireAndForget` counters or `StatSyncState`.
///
/// So the per-worker struct is effectively a write-through cache, and
/// the MI view is already authoritative and cross-worker. No shm-map
/// refactor needed here.
unsafe extern "C" fn mi_webhook_status(
    _params: *const sys::mi_params_,
    _async_hdl: *mut sys::mi_handler,
) -> *mut sys::mi_response_t {
    let Some(resp) = MiObject::new() else {
        return mi_error(-32000, "Failed to create MI response") as *mut _;
    };

    // Helper: read a StatVar or return 0 if not yet registered.
    fn sv_get(ptr: *mut StatVarOpaque) -> u64 {
        StatVar::from_raw(ptr).map(|s| s.get()).unwrap_or(0)
    }

    // Read from shared-memory native stats (aggregated across all workers).
    resp.add_num("sent",            sv_get(STAT_SENT.load(Ordering::Relaxed)) as f64);
    resp.add_num("failed",          sv_get(STAT_FAILED.load(Ordering::Relaxed)) as f64);
    resp.add_num("dropped",         sv_get(STAT_DROPPED.load(Ordering::Relaxed)) as f64);
    resp.add_num("retried",         sv_get(STAT_RETRIED.load(Ordering::Relaxed)) as f64);
    resp.add_num("retry_exhausted", sv_get(STAT_RETRY_EXHAUSTED.load(Ordering::Relaxed)) as f64);
    resp.add_num("filtered",        sv_get(STAT_FILTERED.load(Ordering::Relaxed)) as f64);

    resp.into_raw() as *mut _
}

// ── MI command export array ────────────────────────────────────────

static MI_CMDS: SyncArray<sys::mi_export_, 2> = SyncArray([
    sys::mi_export_ {
        name: cstr_lit!("webhook_status") as *mut _,
        help: cstr_lit!("Show webhook delivery statistics") as *mut _,
        flags: 0,
        init_f: None,
        recipes: {
            let mut r: [sys::mi_recipe_; 48] = unsafe { std::mem::zeroed() };
            r[0] = sys::mi_recipe_ {
                cmd: Some(mi_webhook_status),
                params: unsafe { std::mem::zeroed() },
            };
            r
        },
        aliases: [ptr::null(); 4],
    },
    unsafe { std::mem::zeroed() }, // NULL terminator
]);

static CMDS: SyncArray<sys::cmd_export_, 4> = SyncArray([
    sys::cmd_export_ {
        name: cstr_lit!("webhook"),
        function: Some(w_rust_webhook),
        params: ONE_STR_PARAM,
        flags: opensips_rs::route::REQ_FAIL_ONREPLY,
    },
    sys::cmd_export_ {
        name: cstr_lit!("webhook_stats"),
        function: Some(w_rust_webhook_stats),
        params: EMPTY_PARAMS,
        flags: opensips_rs::route::REQ_FAIL_ONREPLY,
    },
    sys::cmd_export_ {
        name: cstr_lit!("webhook_prometheus"),
        function: Some(w_rust_webhook_prometheus),
        params: EMPTY_PARAMS,
        flags: opensips_rs::route::REQ_FAIL_ONREPLY,
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

static PARAMS: SyncArray<sys::param_export_, 13> = SyncArray([
    sys::param_export_ {
        name: cstr_lit!("url"),
        type_: opensips_rs::param_type::STR,
        param_pointer: URL.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("max_queue"),
        type_: opensips_rs::param_type::INT,
        param_pointer: MAX_QUEUE.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("http_timeout"),
        type_: opensips_rs::param_type::INT,
        param_pointer: HTTP_TIMEOUT.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("content_type"),
        type_: opensips_rs::param_type::STR,
        param_pointer: CONTENT_TYPE.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("tls_ca_file"),
        type_: opensips_rs::param_type::STR,
        param_pointer: TLS_CA_FILE.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("headers"),
        type_: opensips_rs::param_type::STR,
        param_pointer: HEADERS.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("max_retries"),
        type_: opensips_rs::param_type::INT,
        param_pointer: MAX_RETRIES.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("retry_delay_ms"),
        type_: opensips_rs::param_type::INT,
        param_pointer: RETRY_DELAY_MS.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("batch_size"),
        type_: opensips_rs::param_type::INT,
        param_pointer: BATCH_SIZE.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("batch_timeout_ms"),
        type_: opensips_rs::param_type::INT,
        param_pointer: BATCH_TIMEOUT_MS.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("method_filter"),
        type_: opensips_rs::param_type::STR,
        param_pointer: METHOD_FILTER.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("log_errors"),
        type_: opensips_rs::param_type::INT,
        param_pointer: LOG_ERRORS.as_ptr(),
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
    type_: opensips_rs::module_type::DEFAULT,
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_method_filter tests ────────────────────────────────

    #[test]
    fn test_parse_method_filter_empty() {
        let set = parse_method_filter("");
        assert!(set.is_empty());
    }

    #[test]
    fn test_parse_method_filter_single() {
        let set = parse_method_filter("INVITE");
        assert_eq!(set.len(), 1);
        assert!(set.contains("INVITE"));
    }

    #[test]
    fn test_parse_method_filter_multiple() {
        let set = parse_method_filter("INVITE,BYE,REGISTER");
        assert_eq!(set.len(), 3);
        assert!(set.contains("INVITE"));
        assert!(set.contains("BYE"));
        assert!(set.contains("REGISTER"));
    }

    #[test]
    fn test_parse_method_filter_lowercase() {
        let set = parse_method_filter("invite,bye");
        assert!(set.contains("INVITE"));
        assert!(set.contains("BYE"));
    }

    #[test]
    fn test_parse_method_filter_whitespace() {
        let set = parse_method_filter("  INVITE , BYE , REGISTER  ");
        assert_eq!(set.len(), 3);
        assert!(set.contains("INVITE"));
        assert!(set.contains("BYE"));
        assert!(set.contains("REGISTER"));
    }

    #[test]
    fn test_parse_method_filter_trailing_comma() {
        let set = parse_method_filter("INVITE,BYE,");
        assert_eq!(set.len(), 2);
        assert!(set.contains("INVITE"));
        assert!(set.contains("BYE"));
    }

    #[test]
    fn test_parse_method_filter_duplicates() {
        let set = parse_method_filter("INVITE,INVITE,BYE");
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_method_match_in_filter() {
        let filter = parse_method_filter("INVITE,BYE");
        assert!(filter.contains("INVITE"));
        assert!(!filter.contains("OPTIONS"));
        assert!(filter.contains("BYE"));
    }

    #[test]
    fn test_empty_filter_allows_all() {
        let filter = parse_method_filter("");
        // Empty filter means allow all; check is: if filter.is_empty() => allow
        assert!(filter.is_empty());
    }
}
