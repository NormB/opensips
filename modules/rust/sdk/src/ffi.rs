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

/// Log a panic payload without allocating.
///
/// On aarch64 the rustc 1.94 cdylib vtable bug fires when `format!`/`String`
/// allocation triggers a Debug trait dispatch — exactly the path taken by
/// `{msg}` interpolation. We therefore handle the three common payload
/// shapes (`&str`, `String`, other) with `write(STDERR_FILENO)` only,
/// reusing the SDK's pre-built static prefix.
fn log_panic(payload: &(dyn std::any::Any + Send)) {
    const STDERR_FD: std::ffi::c_int = 2;
    const PREFIX: &[u8] = b"Rust panic caught at FFI boundary: ";
    const UNKNOWN: &[u8] = b"<non-string payload>";
    const NEWLINE: &[u8] = b"\n";

    // Use raw write() to avoid the Rust formatter (and its vtable lookups).
    // SAFETY: STDERR_FD is always valid for the lifetime of the process.
    let _ = unsafe { libc_write(STDERR_FD, PREFIX) };
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        let _ = unsafe { libc_write(STDERR_FD, s.as_bytes()) };
    } else if let Some(s) = payload.downcast_ref::<String>() {
        let _ = unsafe { libc_write(STDERR_FD, s.as_bytes()) };
    } else {
        let _ = unsafe { libc_write(STDERR_FD, UNKNOWN) };
    }
    let _ = unsafe { libc_write(STDERR_FD, NEWLINE) };
}

unsafe fn libc_write(fd: std::ffi::c_int, bytes: &[u8]) -> isize {
    extern "C" {
        fn write(fd: std::ffi::c_int, buf: *const std::ffi::c_void,
                 count: usize) -> isize;
    }
    write(fd, bytes.as_ptr().cast(), bytes.len())
}

/// Wrap a closure with catch_unwind for use at the FFI boundary.
///
/// If the closure panics, logs the panic (if possible) and returns -1.
/// This prevents Rust panics from unwinding into C code (undefined behavior).
/// The panic logger avoids the Rust formatter to sidestep the aarch64
/// rustc-1.94 cdylib vtable bug.
pub fn catch_unwind_ffi<F>(f: F) -> c_int
where
    F: FnOnce() -> c_int + std::panic::UnwindSafe,
{
    match catch_unwind(f) {
        Ok(ret) => ret,
        Err(payload) => {
            log_panic(&*payload);
            -1
        }
    }
}

/// Variant of `catch_unwind_ffi` that takes a non-UnwindSafe closure.
/// Use this for closures that capture mutable references.
pub fn catch_unwind_ffi_mut<F>(f: F) -> c_int
where
    F: FnOnce() -> c_int,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(ret) => ret,
        Err(payload) => {
            log_panic(&*payload);
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
