//! Dialog module FFI — safe wrappers around the C shim functions.
//!
//! The dialog module API is loaded at runtime via `find_export("load_dlg")`.
//! Since `load_dlg_api()` is a static inline in C, we wrap it in shim.c
//! and expose thin safe Rust functions here.
//!
//! Service modules use these to register callbacks and query dialog state.
//! The pure Rust `DialogTracker<T>` lives in rust-common.

use crate::sys;
use std::ffi::{c_char, c_int, c_void};

unsafe extern "C" {
    fn opensips_rs_load_dlg_api() -> c_int;
    fn opensips_rs_dlg_api_loaded() -> c_int;
    fn opensips_rs_dlg_register_cb(
        dlg: *mut c_void,
        cb_types: c_int,
        cb: sys::dialog_cb,
        param: *mut c_void,
        param_free: sys::param_free_cb,
    ) -> c_int;
    fn opensips_rs_dlg_callid(
        dlg: *mut c_void,
        out: *mut *const c_char,
        len: *mut c_int,
    ) -> c_int;
    fn opensips_rs_dlg_get_ctx() -> *mut c_void;
    fn opensips_rs_dlg_create(msg: *mut c_void, flags: c_int) -> c_int;
}

// ── Re-export callback constants from bindgen ────────────────────────

pub use sys::DLGCB_LOADED;
pub use sys::DLGCB_CREATED;
pub use sys::DLGCB_FAILED;
pub use sys::DLGCB_CONFIRMED;
pub use sys::DLGCB_REQ_WITHIN;
pub use sys::DLGCB_TERMINATED;
pub use sys::DLGCB_EXPIRED;
pub use sys::DLGCB_EARLY;
pub use sys::DLGCB_RESPONSE_FWDED;
pub use sys::DLGCB_RESPONSE_WITHIN;
pub use sys::DLGCB_MI_CONTEXT;
pub use sys::DLGCB_DESTROY;
pub use sys::DLGCB_DB_SAVED;
pub use sys::DLGCB_WRITE_VP;
pub use sys::DLGCB_PROCESS_VARS;

// ── Safe wrappers ────────────────────────────────────────────────────

/// Load the dialog module API. Call once from mod_init.
///
/// # Safety
/// Must be called from an OpenSIPS process context (mod_init) after
/// the dialog module has been loaded.
pub fn load_api() -> Result<(), &'static str> {
    let ret = unsafe { opensips_rs_load_dlg_api() };
    if ret < 0 {
        Err("failed to load dialog API (is dialog.so loaded?)")
    } else {
        Ok(())
    }
}

/// Check if the dialog API has been loaded.
pub fn api_loaded() -> bool {
    unsafe { opensips_rs_dlg_api_loaded() != 0 }
}

/// Register a global dialog callback (dlg=NULL).
///
/// Typically used for `DLGCB_CREATED` to be notified when any dialog is created.
///
/// # Safety
/// `cb` must be a valid `extern "C"` function with the dialog_cb signature.
/// `param` will be passed to every callback invocation and must remain valid
/// for the lifetime of the process (or until the callback is unregistered).
pub unsafe fn register_global_cb(
    cb_types: u32,
    cb: sys::dialog_cb,
    param: *mut c_void,
    param_free: sys::param_free_cb,
) -> Result<(), &'static str> {
    let ret = unsafe {
        opensips_rs_dlg_register_cb(
            std::ptr::null_mut(),
            cb_types as c_int,
            cb,
            param,
            param_free,
        )
    };
    if ret < 0 {
        Err("register_dlgcb failed")
    } else {
        Ok(())
    }
}

/// Register a per-dialog callback.
///
/// # Safety
/// `dlg` must be a valid pointer to a `dlg_cell` obtained from a dialog callback.
pub unsafe fn register_dlg_cb(
    dlg: *mut c_void,
    cb_types: u32,
    cb: sys::dialog_cb,
    param: *mut c_void,
    param_free: sys::param_free_cb,
) -> Result<(), &'static str> {
    let ret = unsafe {
        opensips_rs_dlg_register_cb(dlg, cb_types as c_int, cb, param, param_free)
    };
    if ret < 0 {
        Err("register_dlgcb failed")
    } else {
        Ok(())
    }
}

/// Extract the Call-ID from an opaque dlg_cell pointer.
///
/// # Safety
/// `dlg` must be a valid pointer to a `dlg_cell`.
pub unsafe fn callid(dlg: *mut c_void) -> Option<&'static str> {
    let mut out: *const c_char = std::ptr::null();
    let mut len: c_int = 0;
    let ret = unsafe { opensips_rs_dlg_callid(dlg, &mut out, &mut len) };
    if ret < 0 || out.is_null() || len <= 0 {
        return None;
    }
    let bytes = unsafe { std::slice::from_raw_parts(out as *const u8, len as usize) };
    std::str::from_utf8(bytes).ok()
}

/// Get the current dialog from the processing context.
///
/// Returns a raw pointer (may be null if no dialog is associated).
///
/// # Safety
/// Must be called during SIP message processing.
pub unsafe fn get_ctx() -> *mut c_void {
    unsafe { opensips_rs_dlg_get_ctx() }
}

/// Create a dialog for the current INVITE.
///
/// # Safety
/// Must be called from a request route with a valid sip_msg pointer.
pub unsafe fn create(msg: *mut sys::sip_msg, flags: i32) -> Result<(), &'static str> {
    let ret = unsafe { opensips_rs_dlg_create(msg as *mut c_void, flags as c_int) };
    if ret < 0 {
        Err("create_dlg failed")
    } else {
        Ok(())
    }
}
