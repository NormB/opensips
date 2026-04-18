//! opensips-mod-rust — Production demo OpenSIPS module in Rust.
//!
//! Demonstrates three stateful patterns that are unsafe or impossible
//! in OpenSIPS's Python/Lua/Perl modules:
//! 1. Per-caller rate limiting (thread_local state)
//! 2. Routing cache with TTL (thread_local state)
//! 3. Persistent HTTP connection pool (OnceLock)
//!
//! # Rust Concepts Demonstrated
//!
//! - **Module registration structs (CMDS, PARAMS)**: `OpenSIPS` discovers
//!   modules via a `#[no_mangle] pub static exports: module_exports` symbol.
//!   This struct contains pointers to command and parameter arrays, lifecycle
//!   callbacks, and version info. We initialize everything as `static` (global)
//!   constants because OpenSIPS reads them before calling mod_init.
//!
//! - **`SyncArray` wrapper for FFI types**: `OpenSIPS`'s C structs contain
//!   raw pointers, which Rust considers non-Send/non-Sync by default.
//!   Our `SyncArray<T, N>` wrapper uses `unsafe impl Sync` to promise
//!   the compiler that these read-only arrays are safe to share. This is
//!   correct because they're never mutated after initialization.
//!
//! - **Const initialization of C structs**: Rust's `const` context is very
//!   limited — no heap allocation, no function calls. We use
//!   `unsafe { std::mem::zeroed() }` to create zeroed structs, then fill
//!   in fields at compile time. The compiler verifies all types match.
//!
//! - **`unsafe extern "C"` function signatures**: `OpenSIPS` calls our
//!   functions through C function pointers. `extern "C"` ensures the
//!   correct calling convention (System V ABI on Linux). `unsafe` because
//!   the raw sip_msg pointer has no Rust lifetime guarantees.
//!
//! - **`std::mem::zeroed()`**: creates a value where all bytes are zero.
//!   Used for C structs that expect NULL/0 defaults. In Rust, this is
//!   `unsafe` because not all types have valid zero representations
//!   (e.g., references can't be null). For C FFI structs it's correct.

#![allow(clippy::doc_markdown)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::use_self)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
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

mod ratelimit;
mod cache;
mod http_pool;
mod script;
mod counter;

use opensips_rs::command::CommandFunctionParam;
use opensips_rs::param::{Integer, ModString};
use opensips_rs::sys;
use opensips_rs::{cstr_lit, opensips_log};
use std::ffi::{c_int, c_void};
use std::ptr;

// ── Module parameters ────────────────────────────────────────────

static MAX_RATE: Integer = Integer::with_default(100);
static WINDOW_SECONDS: Integer = Integer::with_default(60);
static CACHE_TTL: Integer = Integer::with_default(300);
static HTTP_TIMEOUT: Integer = Integer::with_default(2);
static POOL_SIZE: Integer = Integer::with_default(4);
static SCRIPT_NAME: ModString = ModString::new();

// ── Module lifecycle ─────────────────────────────────────────────

unsafe extern "C" fn mod_init() -> c_int {
    opensips_log!(INFO, "rust", "module initialized (v{}.{})",
        opensips_rs::VERSION_MAJOR, opensips_rs::VERSION_MINOR);
    opensips_log!(INFO, "rust", "  max_rate={}, window={}s, cache_ttl={}s",
        MAX_RATE.get(), WINDOW_SECONDS.get(), CACHE_TTL.get());
    opensips_log!(INFO, "rust", "  http_timeout={}s, pool_size={}",
        HTTP_TIMEOUT.get(), POOL_SIZE.get());

    // Initialize shared atomic counter (in shm, before fork)
    counter::init();

    // Load user script if script_name is configured
    if let Some(path) = SCRIPT_NAME.get_value() {
        opensips_log!(INFO, "rust", "  script_name={}", path);
        if let Err(e) = script::load_script(path) {
            opensips_log!(ERR, "rust", "failed to load script: {}", e);
            return -1;
        }
    }

    0
}

unsafe extern "C" fn mod_child_init(rank: c_int) -> c_int {
    opensips_log!(DBG, "rust", "child_init called for rank {}", rank);
    http_pool::init_pool(HTTP_TIMEOUT.get(), POOL_SIZE.get());
    0
}

unsafe extern "C" fn mod_destroy() {
    script::unload();
    opensips_log!(INFO, "rust", "module destroyed");
}

// ── Command shims ────────────────────────────────────────────────

unsafe extern "C" fn w_check_rate(
    msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let mut sip_msg = opensips_rs::SipMessage::from_raw(msg);
        ratelimit::check_rate(&mut sip_msg, MAX_RATE.get(), WINDOW_SECONDS.get())
    })
}

unsafe extern "C" fn w_cache_lookup(
    msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let mut sip_msg = opensips_rs::SipMessage::from_raw(msg);
        cache::cache_lookup(&mut sip_msg, CACHE_TTL.get())
    })
}

unsafe extern "C" fn w_cache_store(
    msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let mut sip_msg = opensips_rs::SipMessage::from_raw(msg);
        cache::cache_store(&mut sip_msg)
    })
}

unsafe extern "C" fn w_http_query(
    msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let mut sip_msg = opensips_rs::SipMessage::from_raw(msg);
        let url = match <&str as CommandFunctionParam>::from_raw(p0) {
            Ok(s) => s,
            Err(_) => {
                opensips_log!(ERR, "rust", "http_query: missing or invalid URL");
                return -1;
            }
        };
        http_pool::http_query(&mut sip_msg, url)
    })
}

unsafe extern "C" fn w_counter_inc(
    msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let mut sip_msg = opensips_rs::SipMessage::from_raw(msg);
        counter::counter_inc(&mut sip_msg)
    })
}

unsafe extern "C" fn w_rust_exec(
    msg: *mut sys::sip_msg,
    p0: *mut c_void, p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let func_name = match <&str as CommandFunctionParam>::from_raw(p0) {
            Ok(s) if !s.is_empty() => s,
            _ => {
                opensips_log!(ERR, "rust", "rust_exec: missing or invalid function name");
                return -1;
            }
        };
        let param = match <Option<&str> as CommandFunctionParam>::from_raw(p1) {
            Ok(opt) => opt,
            Err(_) => {
                opensips_log!(ERR, "rust", "rust_exec: invalid UTF-8 in parameter");
                return -1;
            }
        };
        script::dispatch(msg as *mut c_void, func_name, param)
    })
}

unsafe extern "C" fn w_async_rust_exec(
    msg: *mut sys::sip_msg,
    ctx: *mut sys::async_ctx,
    p0: *mut c_void, p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let func_name = match <&str as CommandFunctionParam>::from_raw(p0) {
            Ok(s) if !s.is_empty() => s,
            _ => {
                opensips_log!(ERR, "rust", "async rust_exec: missing or invalid function name");
                return -1;
            }
        };
        let param = match <Option<&str> as CommandFunctionParam>::from_raw(p1) {
            Ok(opt) => opt,
            Err(_) => {
                opensips_log!(ERR, "rust", "async rust_exec: invalid UTF-8 in parameter");
                return -1;
            }
        };
        script::dispatch_async(msg as *mut c_void, ctx as *mut c_void, func_name, param)
    })
}

// ── Static arrays for module registration ────────────────────────
//
// These must be available immediately when `exports` is read by OpenSIPS.
// Raw pointers in the structs aren't Send+Sync by default, so we use
// wrapper types with unsafe impls.
//
// OpenSIPS scans the `cmds` array to register script functions, and
// the `params` array to register modparam directives. Both arrays are
// null-terminated (last entry has name = null).

/// Null-terminated cmd_param array for functions with no params.
/// `std::mem::zeroed()` fills all 9 entries with zeros — the null terminator
/// is implicit (flags=0 means "end of params").
const EMPTY_PARAMS: [sys::cmd_param; 9] = unsafe { std::mem::zeroed() };

/// cmd_param array for one string parameter.
/// Const initialization: we create a zeroed array, then set arr[0].flags
/// at compile time. The remaining 8 entries stay zeroed (null terminator).
const ONE_STR_PARAM: [sys::cmd_param; 9] = {
    let mut arr: [sys::cmd_param; 9] = unsafe { std::mem::zeroed() };
    arr[0].flags = opensips_rs::command::CMD_PARAM_STR;
    arr
};

/// cmd_param array for one required string + one optional string parameter.
/// Bitwise OR: `2 | 16` = CMD_PARAM_STR | CMD_PARAM_OPT.
const TWO_STR_PARAM: [sys::cmd_param; 9] = {
    let mut arr: [sys::cmd_param; 9] = unsafe { std::mem::zeroed() };
    arr[0].flags = opensips_rs::command::CMD_PARAM_STR;
    arr[1].flags = opensips_rs::command::CMD_PARAM_STR | opensips_rs::command::CMD_PARAM_OPT;  // CMD_PARAM_STR | CMD_PARAM_OPT
    arr
};

// SyncArray: wrapper to satisfy Rust's Sync trait requirement.
// OpenSIPS's C structs contain raw pointers (*const c_char, etc.) which
// Rust considers non-Sync. But these arrays are read-only after init,
// so sharing them is safe. #[repr(transparent)] means the wrapper has
// the same memory layout as the inner array.
#[repr(transparent)]
struct SyncArray<T, const N: usize>([T; N]);
unsafe impl<T, const N: usize> Sync for SyncArray<T, N> {}

static CMDS: SyncArray<sys::cmd_export_, 7> = SyncArray([
    sys::cmd_export_ {
        name: cstr_lit!("check_rate"),
        function: Some(w_check_rate),
        params: EMPTY_PARAMS,
        flags: opensips_rs::route::REQ_FAIL,
    },
    sys::cmd_export_ {
        name: cstr_lit!("cache_lookup"),
        function: Some(w_cache_lookup),
        params: EMPTY_PARAMS,
        flags: opensips_rs::route_flags::REQUEST,
    },
    sys::cmd_export_ {
        name: cstr_lit!("cache_store"),
        function: Some(w_cache_store),
        params: EMPTY_PARAMS,
        flags: opensips_rs::route_flags::REQUEST,
    },
    sys::cmd_export_ {
        name: cstr_lit!("http_query"),
        function: Some(w_http_query),
        params: ONE_STR_PARAM,
        flags: opensips_rs::route_flags::REQUEST,
    },
    sys::cmd_export_ {
        name: cstr_lit!("counter_inc"),
        function: Some(w_counter_inc),
        params: EMPTY_PARAMS,
        flags: opensips_rs::route_flags::REQUEST | opensips_rs::route_flags::ONREPLY,
    },
    sys::cmd_export_ {
        name: cstr_lit!("rust_exec"),
        function: Some(w_rust_exec),
        params: TWO_STR_PARAM,
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

static ACMDS: SyncArray<sys::acmd_export_, 2> = SyncArray([
    sys::acmd_export_ {
        name: cstr_lit!("rust_exec"),
        function: Some(w_async_rust_exec),
        params: TWO_STR_PARAM,
    },
    // Null terminator
    sys::acmd_export_ {
        name: ptr::null(),
        function: None,
        params: EMPTY_PARAMS,
    },
]);

static PARAMS: SyncArray<sys::param_export_, 7> = SyncArray([
    sys::param_export_ {
        name: cstr_lit!("max_rate"),
        type_: opensips_rs::param_type::INT,
        param_pointer: MAX_RATE.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("window_seconds"),
        type_: opensips_rs::param_type::INT,
        param_pointer: WINDOW_SECONDS.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("cache_ttl"),
        type_: opensips_rs::param_type::INT,
        param_pointer: CACHE_TTL.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("http_timeout"),
        type_: opensips_rs::param_type::INT,
        param_pointer: HTTP_TIMEOUT.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("pool_size"),
        type_: opensips_rs::param_type::INT,
        param_pointer: POOL_SIZE.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("script_name"),
        type_: opensips_rs::param_type::STR,
        param_pointer: SCRIPT_NAME.as_ptr(),
    },
    // Null terminator
    sys::param_export_ {
        name: ptr::null(),
        type_: 0,
        param_pointer: ptr::null_mut(),
    },
]);

// Module dependency — no deps for the demo
static DEPS: opensips_rs::ffi::DepExportConcrete<1> = opensips_rs::ffi::DepExportConcrete {
    md: unsafe { std::mem::zeroed() },
    mpd: unsafe { std::mem::zeroed() },
};

/// The module_exports struct that OpenSIPS loads via dlsym("exports").
#[no_mangle]
pub static exports: sys::module_exports = sys::module_exports {
    name: cstr_lit!("rust"),
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
