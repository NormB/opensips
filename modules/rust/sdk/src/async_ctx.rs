//! Safe wrapper around OpenSIPS `async_ctx` for async command support.
//!
//! When a module registers an async command (`acmd_export_`), OpenSIPS calls
//! it with an `async_ctx *` parameter. The module populates this context to
//! tell the core:
//!   - What fd to monitor for I/O readiness
//!   - What function to call when the fd is ready (resume callback)
//!   - What opaque state to pass to the resume callback
//!   - How long to wait before timing out
//!
//! The global `async_status` variable signals the outcome:
//!   - `>= 0`        → fd to monitor (async I/O launched)
//!   - `ASYNC_NO_IO` (-8) → no I/O, continue script synchronously
//!   - `ASYNC_SYNC`  (-7) → completed synchronously, run resume route
//!   - `ASYNC_NO_FD` (-6) → async launched but no fd (module triggers resume)
//!
//! # Safety
//!
//! `AsyncContext` wraps a raw pointer to the core-allocated `async_ctx`.
//! It is only valid for the duration of the acmd function call. The resume
//! callback and resume parameter must outlive the reactor loop iteration,
//! so resume_param should point to heap-allocated state (pkg_malloc or Box).
//! Since `async()` (script-level) resumes in the same worker process,
//! regular Rust heap allocation (Box) is fine.

use crate::sys;
use std::ffi::c_void;

/// Async status constants matching OpenSIPS async.h.
pub const ASYNC_NO_IO: i32 = -8;
pub const ASYNC_SYNC: i32 = -7;
pub const ASYNC_NO_FD: i32 = -6;
pub const ASYNC_CONTINUE: i32 = -5;
pub const ASYNC_CHANGE_FD: i32 = -4;
pub const ASYNC_DONE_CLOSE_FD: i32 = -2;
pub const ASYNC_DONE_NO_IO: i32 = -3;
pub const ASYNC_DONE: i32 = -1;

/// Safe wrapper around OpenSIPS `async_ctx`.
///
/// Provided to async handler functions via `opensips_async_handler!`.
/// Methods on this type set the global `async_status` variable and
/// populate the `async_ctx` struct fields that the core reads after
/// the acmd function returns.
pub struct AsyncContext {
    raw: *mut sys::async_ctx,
}

impl AsyncContext {
    /// Create an AsyncContext from a raw pointer.
    ///
    /// # Safety
    /// The pointer must be a valid `async_ctx` allocated by the OpenSIPS core.
    /// Only valid for the duration of the acmd function call.
    pub unsafe fn from_raw(raw: *mut sys::async_ctx) -> Self {
        Self { raw }
    }

    /// Set the fd for the reactor to monitor.
    ///
    /// This signals `async_status = fd`, telling the core to add this fd
    /// to the reactor and call the resume callback when it becomes readable.
    pub fn set_fd(&self, fd: i32) {
        unsafe { sys::async_status = fd; }
    }

    /// Set the resume callback.
    ///
    /// The callback is invoked when the monitored fd becomes readable.
    /// Signature: `extern "C" fn(fd: i32, msg: *mut sip_msg, param: *mut c_void) -> i32`
    ///
    /// The callback should return one of:
    ///   - `ASYNC_DONE` (-1): async complete, continue to resume route
    ///   - `ASYNC_DONE_CLOSE_FD` (-2): complete + close fd
    ///   - `ASYNC_DONE_NO_IO` (-3): complete, no more I/O
    ///   - `ASYNC_CONTINUE` (-5): not done yet, keep monitoring
    ///   - `ASYNC_CHANGE_FD` (-4): switch to a different fd
    pub fn set_resume(&self, f: unsafe extern "C" fn(i32, *mut sys::sip_msg, *mut c_void) -> i32) {
        unsafe {
            // resume_f expects `fn(...) -> async_ret_code` where async_ret_code
            // is a C enum that bindgen generates as `type async_ret_code = c_int`.
            // The transmute is safe because both are fn pointers with identical
            // calling convention and ABI-compatible return types (i32 == c_int).
            (*self.raw).resume_f = std::mem::transmute(f);
        }
    }

    /// Store opaque resume parameter.
    ///
    /// This pointer is passed to the resume callback as the `param` argument.
    /// For `async()` (script-level), the same worker process resumes, so
    /// regular heap allocation (`Box::into_raw`) works. For `async_launch()`
    /// (fire-and-forget), you would need `shm_malloc`.
    pub fn set_resume_param(&self, param: *mut c_void) {
        unsafe { (*self.raw).resume_param = param; }
    }

    /// Signal synchronous completion — run the resume route immediately.
    ///
    /// Use this when your handler completed the work synchronously
    /// (e.g., data was already cached) but you still want the resume
    /// route to execute.
    pub fn done_sync(&self) {
        unsafe { sys::async_status = ASYNC_SYNC; }
    }

    /// Signal no I/O needed — continue the current script, no resume route.
    ///
    /// Use this when the handler has nothing to do asynchronously.
    /// The script continues as if rust_exec() returned normally.
    pub fn no_io(&self) {
        unsafe { sys::async_status = ASYNC_NO_IO; }
    }

    /// Signal async launched with no fd to monitor.
    ///
    /// The module itself is responsible for triggering the resume.
    pub fn no_fd(&self) {
        unsafe { sys::async_status = ASYNC_NO_FD; }
    }

    /// Set timeout in seconds.
    ///
    /// If the fd doesn't become readable within this time, the timeout
    /// callback is invoked (if set), or the async operation is cancelled.
    pub fn set_timeout(&self, seconds: u32) {
        unsafe { (*self.raw).timeout_s = seconds; }
    }
}
