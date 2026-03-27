//! FFI safety utilities: cstr_lit!, Sync impls, catch_unwind, NULL sentinels.

use crate::sys;
use std::ffi::c_int;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Create a null-terminated C string literal at compile time.
///
/// Returns a `*const c_char` pointer to a static string.
#[macro_export]
macro_rules! cstr_lit {
    ($s:expr) => {
        concat!($s, "\0").as_ptr() as *const ::std::ffi::c_char
    };
}

/// Wrap a closure with catch_unwind for use at the FFI boundary.
///
/// If the closure panics, logs the panic (if possible) and returns -1.
/// This prevents Rust panics from unwinding into C code (undefined behavior).
pub fn catch_unwind_ffi<F>(f: F) -> c_int
where
    F: FnOnce() -> c_int + std::panic::UnwindSafe,
{
    match catch_unwind(f) {
        Ok(ret) => ret,
        Err(e) => {
            // Try to extract a message from the panic
            let msg = if let Some(s) = e.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = e.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            // Log via our shim if available, otherwise eprintln
            crate::log::log_err(&format!("Rust panic caught at FFI boundary: {}", msg));
            -1
        }
    }
}

/// Variant of catch_unwind_ffi that takes a non-UnwindSafe closure.
/// Use this for closures that capture mutable references.
pub fn catch_unwind_ffi_mut<F>(f: F) -> c_int
where
    F: FnOnce() -> c_int,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(ret) => ret,
        Err(e) => {
            let msg = if let Some(s) = e.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = e.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            crate::log::log_err(&format!("Rust panic caught at FFI boundary: {}", msg));
            -1
        }
    }
}

// ── Sync impls ──────────────────────────────────────────────────────
//
// OpenSIPS module_exports and related types are declared as statics
// and accessed from the main process. They are effectively read-only
// after module registration, so Sync is safe.

unsafe impl Sync for sys::module_exports {}
unsafe impl Sync for sys::cmd_export_ {}
unsafe impl Sync for sys::cmd_param {}
unsafe impl Sync for sys::param_export_ {}
unsafe impl Sync for sys::mi_export_ {}
unsafe impl Sync for sys::mi_recipe_ {}
unsafe impl Sync for sys::acmd_export_ {}

// ── NULL sentinels ──────────────────────────────────────────────────
//
// OpenSIPS uses null-filled structs as array terminators.

/// Zeroed cmd_export_ sentinel for terminating command arrays.
pub static CMD_EXPORT_NULL: sys::cmd_export_ = unsafe { std::mem::zeroed() };

/// Zeroed param_export_ sentinel for terminating parameter arrays.
pub static PARAM_EXPORT_NULL: sys::param_export_ = unsafe { std::mem::zeroed() };

/// Zeroed mi_export_ sentinel for terminating MI command arrays.
pub static MI_EXPORT_NULL: sys::mi_export_ = unsafe { std::mem::zeroed() };

// ── dep_export flexible array member workaround ─────────────────────
//
// dep_export_t contains a flexible array member (mpd[]).
// We cannot represent this directly in Rust, so we create a
// concrete struct with a fixed-size mpd array.

/// Concrete dep_export with N modparam_dependency entries.
/// Use dep_export_concrete::<0> for modules with no param dependencies.
#[repr(C)]
pub struct DepExportConcrete<const N: usize> {
    pub md: [sys::module_dependency; 10], // MAX_MOD_DEPS = 10
    pub mpd: [sys::modparam_dependency; N],
}

unsafe impl<const N: usize> Sync for DepExportConcrete<N> {}
