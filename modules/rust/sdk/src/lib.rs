//! opensips-rs — Rust SDK for building OpenSIPS modules.
//!
//! Provides safe wrappers around the `OpenSIPS` C API, enabling
//! module development in Rust with memory safety and panic protection.

#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::ptr_as_ptr)]
#![allow(clippy::borrow_as_ptr)]
#![allow(clippy::ref_as_ptr)]
#![allow(clippy::use_self)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::redundant_else)]
#![allow(clippy::elidable_lifetime_names)]
#![allow(clippy::pub_underscore_fields)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::as_ptr_cast_mut)]
#![allow(clippy::missing_const_for_fn)]
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

pub mod sys;
pub mod ffi;
pub mod param;
pub mod command;
pub mod msg;
pub mod log;
pub mod pv;
pub mod call;
pub mod error;
pub mod shm;
pub mod async_ctx;
pub mod dlg;

// Re-export key types at crate root
pub use call::CallArg;
pub use error::{Error, Result};
pub use msg::SipMessage;
pub use param::{Integer, ModString};
pub use ffi::catch_unwind_ffi;

/// `OpenSIPS` version detected at build time.
pub const VERSION_MAJOR: &str = env!("OPENSIPS_VERSION_MAJOR");
pub const VERSION_MINOR: &str = env!("OPENSIPS_VERSION_MINOR");

// ── User script support ──────────────────────────────────────────

/// Declare a handler function for use with `rust_exec()`.
///
/// Wraps an `extern "C"` ABI function with safe Rust types. The generated
/// function has the signature expected by the rust module's script loader:
///   `extern "C" fn(msg: *mut c_void, param: *const c_char, param_len: c_int) -> c_int`
///
/// Two forms:
///
/// ```ignore
/// // Handler with optional parameter
/// opensips_handler!(greet, |msg, param| {
///     let greeting = param.unwrap_or("hello");
///     opensips_rs::opensips_log!(INFO, "rust", "{} from {}", greeting, msg.source_ip());
///     1
/// });
///
/// // Handler with no parameter
/// opensips_handler!(hello_world, |msg| {
///     opensips_rs::opensips_log!(INFO, "rust", "hello from {}", msg.source_ip());
///     1
/// });
/// ```
///
/// Return `1` for success, `-1` for failure.
#[macro_export]
macro_rules! opensips_handler {
    // Two-arg form: fn(msg, param)
    ($name:ident, |$msg:ident, $param:ident| $body:block) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
            raw_msg: *mut ::std::ffi::c_void,
            param_ptr: *const ::std::ffi::c_char,
            param_len: ::std::ffi::c_int,
        ) -> ::std::ffi::c_int {
            $crate::ffi::catch_unwind_ffi_mut(|| {
                // SAFETY: raw_msg is a valid *mut sip_msg for the duration
                // of the route call. SipMessage borrows it mutably.
                let mut $msg = unsafe {
                    $crate::SipMessage::from_raw(raw_msg as *mut $crate::sys::sip_msg)
                };
                // SAFETY: param_ptr is either null (no param) or points to a
                // valid UTF-8 byte sequence of length param_len, owned by
                // OpenSIPS for the duration of the route call.
                let $param: Option<&str> = if param_ptr.is_null() || param_len < 0 {
                    None
                } else {
                    unsafe {
                        ::std::str::from_utf8(
                            ::std::slice::from_raw_parts(
                                param_ptr as *const u8,
                                param_len as usize,
                            )
                        ).ok()
                    }
                };
                $body
            })
        }
    };
    // One-arg form: fn(msg) — delegates to two-arg with unused param
    ($name:ident, |$msg:ident| $body:block) => {
        $crate::opensips_handler!($name, |$msg, _param| $body);
    };
}

// ── Async handler support ────────────────────────────────────────

/// Declare an async-capable handler function for use with `async(rust_exec(...))`.
///
/// Like `opensips_handler!`, but the generated function receives an additional
/// `AsyncContext` parameter that lets the handler set up non-blocking I/O:
///
/// ```ignore
/// opensips_async_handler!(async_http_query, |msg, ctx, param| {
///     let url = param.unwrap_or("");
///     if url.is_empty() {
///         ctx.no_io();  // nothing to do, continue synchronously
///         return 1;
///     }
///     // ... set up non-blocking I/O, populate ctx ...
///     ctx.set_fd(fd);
///     ctx.set_resume(my_resume_fn);
///     ctx.set_resume_param(state_ptr);
///     ctx.set_timeout(5);
///     1
/// });
/// ```
///
/// The generated function has the signature expected by `dispatch_async`:
///   `extern "C" fn(msg: *mut c_void, ctx: *mut c_void, param: *const c_char, param_len: c_int) -> c_int`
///
/// The handler name MUST be prefixed with `async_` — the dispatch logic
/// looks for `async_{handler_name}` when called inside an `async()` block.
#[macro_export]
macro_rules! opensips_async_handler {
    ($name:ident, |$msg:ident, $ctx:ident, $param:ident| $body:block) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
            raw_msg: *mut ::std::ffi::c_void,
            raw_ctx: *mut ::std::ffi::c_void,
            param_ptr: *const ::std::ffi::c_char,
            param_len: ::std::ffi::c_int,
        ) -> ::std::ffi::c_int {
            $crate::ffi::catch_unwind_ffi_mut(|| {
                let mut $msg = unsafe {
                    $crate::SipMessage::from_raw(raw_msg as *mut $crate::sys::sip_msg)
                };
                let $ctx = unsafe {
                    $crate::async_ctx::AsyncContext::from_raw(
                        raw_ctx as *mut $crate::sys::async_ctx
                    )
                };
                let $param: Option<&str> = if param_ptr.is_null() || param_len < 0 {
                    None
                } else {
                    unsafe {
                        ::std::str::from_utf8(
                            ::std::slice::from_raw_parts(
                                param_ptr as *const u8,
                                param_len as usize,
                            )
                        ).ok()
                    }
                };
                $body
            })
        }
    };
    // Two-arg form: fn(msg, ctx) — no param
    ($name:ident, |$msg:ident, $ctx:ident| $body:block) => {
        $crate::opensips_async_handler!($name, |$msg, $ctx, _param| $body);
    };
}

/// Prelude for user scripts — import everything needed for `opensips_handler!`.
///
/// ```ignore
/// use opensips_rs::prelude::*;
///
/// opensips_handler!(hello, |msg| {
///     log!(INFO, "rust", "hello from {}", msg.source_ip());
///     1
/// });
/// ```
pub mod prelude {
    pub use crate::{opensips_handler, opensips_async_handler, opensips_log, SipMessage};
    pub use crate::pv::PvValue;
    pub use crate::async_ctx::{self, AsyncContext};
}
