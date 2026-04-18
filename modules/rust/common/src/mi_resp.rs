//! Safe wrappers for OpenSIPS MI response builders.
//!
//! These wrap the C functions from mi/item.h to build JSON-RPC
//! MI responses from Rust MI command handlers.

use std::ffi::{c_char, c_double, c_int};
use std::ptr;

// FFI declarations -- these are real C functions (not macros).
#[allow(dead_code)]
extern "C" {
    fn init_mi_result_object(obj_out: *mut *mut cJSON) -> *mut cJSON;
    fn init_mi_result_array(arr_out: *mut *mut cJSON) -> *mut cJSON;
    fn init_mi_result_string(value: *const c_char, value_len: c_int) -> *mut cJSON;
    fn init_mi_error_extra(
        code: c_int, msg: *const c_char, msg_len: c_int,
        details: *const c_char, details_len: c_int,
    ) -> *mut cJSON;
    fn init_mi_param_error() -> *mut cJSON;
    fn add_mi_object(to: *mut cJSON, name: *mut c_char, name_len: c_int) -> *mut cJSON;
    fn add_mi_array(to: *mut cJSON, name: *mut c_char, name_len: c_int) -> *mut cJSON;
    fn add_mi_string(
        to: *mut cJSON, name: *mut c_char, name_len: c_int,
        value: *const c_char, value_len: c_int,
    ) -> c_int;
    fn add_mi_number(
        to: *mut cJSON, name: *mut c_char, name_len: c_int, value: c_double,
    ) -> c_int;
    fn add_mi_bool(
        to: *mut cJSON, name: *mut c_char, name_len: c_int, b: c_int,
    ) -> c_int;
    fn add_mi_null(to: *mut cJSON, name: *mut c_char, name_len: c_int) -> c_int;
    fn try_get_mi_string_param(
        params: *const mi_params_t, name: *mut c_char,
        value: *mut *mut c_char, value_len: *mut c_int,
    ) -> c_int;
    fn opensips_rs_init_mi_result_ok() -> *mut cJSON;
    fn opensips_rs_init_mi_error(
        code: c_int, msg: *const c_char, msg_len: c_int,
    ) -> *mut cJSON;
}

// Opaque C types -- we only use pointers.
#[repr(C)]
pub struct cJSON {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct mi_params_t {
    _opaque: [u8; 0],
}

/// Raw pointer to an MI response (cJSON tree).
/// The caller must return this from the MI handler -- OpenSIPS frees it.
pub type MiResponsePtr = *mut cJSON;

/// Builder for an MI response containing a top-level JSON object.
pub struct MiObject {
    resp: *mut cJSON,
    obj: *mut cJSON,
}

impl MiObject {
    /// Create a new MI response with a top-level JSON object.
    pub fn new() -> Option<Self> {
        unsafe {
            let mut obj: *mut cJSON = ptr::null_mut();
            let resp = init_mi_result_object(&mut obj);
            if resp.is_null() || obj.is_null() {
                return None;
            }
            Some(Self { resp, obj })
        }
    }

    /// Add a string field.
    pub fn add_str(&self, name: &str, value: &str) {
        unsafe {
            add_mi_string(
                self.obj,
                name.as_ptr() as *mut c_char, name.len() as c_int,
                value.as_ptr() as *const c_char, value.len() as c_int,
            );
        }
    }

    /// Add a number field.
    pub fn add_num(&self, name: &str, value: f64) {
        unsafe {
            add_mi_number(
                self.obj, name.as_ptr() as *mut c_char, name.len() as c_int, value,
            );
        }
    }

    /// Add a boolean field.
    pub fn add_bool(&self, name: &str, value: bool) {
        unsafe {
            add_mi_bool(
                self.obj, name.as_ptr() as *mut c_char, name.len() as c_int,
                if value { 1 } else { 0 },
            );
        }
    }

    /// Add a null field.
    pub fn add_null(&self, name: &str) {
        unsafe {
            add_mi_null(self.obj, name.as_ptr() as *mut c_char, name.len() as c_int);
        }
    }

    /// Add a nested object, returning a handle to populate it.
    pub fn add_object(&self, name: &str) -> Option<MiItem> {
        unsafe {
            let obj = add_mi_object(
                self.obj, name.as_ptr() as *mut c_char, name.len() as c_int,
            );
            if obj.is_null() { None } else { Some(MiItem(obj)) }
        }
    }

    /// Add a nested array, returning a handle to populate it.
    pub fn add_array(&self, name: &str) -> Option<MiItem> {
        unsafe {
            let arr = add_mi_array(
                self.obj, name.as_ptr() as *mut c_char, name.len() as c_int,
            );
            if arr.is_null() { None } else { Some(MiItem(arr)) }
        }
    }

    /// Consume the builder and return the raw response pointer.
    /// The MI framework takes ownership and frees it.
    pub fn into_raw(self) -> MiResponsePtr {
        self.resp
    }
}

/// Handle to a nested MI item (object or array) within a response.
pub struct MiItem(pub *mut cJSON);

impl MiItem {
    /// Add a string to this item.
    pub fn add_str(&self, name: &str, value: &str) {
        unsafe {
            add_mi_string(
                self.0,
                name.as_ptr() as *mut c_char, name.len() as c_int,
                value.as_ptr() as *const c_char, value.len() as c_int,
            );
        }
    }

    /// Add a number to this item.
    pub fn add_num(&self, name: &str, value: f64) {
        unsafe {
            add_mi_number(
                self.0, name.as_ptr() as *mut c_char, name.len() as c_int, value,
            );
        }
    }

    /// Add a boolean to this item.
    pub fn add_bool(&self, name: &str, value: bool) {
        unsafe {
            add_mi_bool(
                self.0, name.as_ptr() as *mut c_char, name.len() as c_int,
                if value { 1 } else { 0 },
            );
        }
    }

    /// Add a null to this item.
    pub fn add_null(&self, name: &str) {
        unsafe {
            add_mi_null(self.0, name.as_ptr() as *mut c_char, name.len() as c_int);
        }
    }

    /// Add a nested object within this item.
    pub fn add_object(&self, name: &str) -> Option<MiItem> {
        unsafe {
            let obj = add_mi_object(
                self.0, name.as_ptr() as *mut c_char, name.len() as c_int,
            );
            if obj.is_null() { None } else { Some(MiItem(obj)) }
        }
    }

    /// Add a nested array within this item.
    pub fn add_array(&self, name: &str) -> Option<MiItem> {
        unsafe {
            let arr = add_mi_array(
                self.0, name.as_ptr() as *mut c_char, name.len() as c_int,
            );
            if arr.is_null() { None } else { Some(MiItem(arr)) }
        }
    }
}

/// Return an `"OK"` MI response, or a null pointer if allocation fails.
///
/// Callers cast this as `*mut _` and return it from MI handlers.
/// OpenSIPS core tolerates NULL MI returns (logs an error and sends
/// a generic 500 response), so a NULL return under OOM is safe.
pub fn mi_ok() -> MiResponsePtr {
    let ptr = unsafe { opensips_rs_init_mi_result_ok() };
    if ptr.is_null() {
        eprintln!("ERROR: [rust] mi_ok: allocation failed (OOM)");
    }
    ptr
}

/// Return an MI error response, or a null pointer if allocation fails.
pub fn mi_error(code: i32, msg: &str) -> MiResponsePtr {
    let ptr = unsafe {
        opensips_rs_init_mi_error(code, msg.as_ptr() as *const c_char, msg.len() as c_int)
    };
    if ptr.is_null() {
        eprintln!("ERROR: [rust] mi_error: allocation failed (OOM)");
    }
    ptr
}

/// Return the standard "invalid params" MI error, or null on OOM.
pub fn mi_param_error() -> MiResponsePtr {
    let ptr = unsafe { init_mi_param_error() };
    if ptr.is_null() {
        eprintln!("ERROR: [rust] mi_param_error: allocation failed (OOM)");
    }
    ptr
}

/// Try to extract a named string parameter from MI params.
/// Returns `Some(String)` if present, `None` if missing.
pub fn mi_try_get_string_param(
    params: *const mi_params_t,
    name: &str,
) -> Option<String> {
    unsafe {
        let mut val: *mut c_char = ptr::null_mut();
        let mut val_len: c_int = 0;
        let rc = try_get_mi_string_param(
            params,
            name.as_ptr() as *mut c_char,
            &mut val,
            &mut val_len,
        );
        if rc != 0 || val.is_null() || val_len <= 0 {
            return None;
        }
        let slice = std::slice::from_raw_parts(val as *const u8, val_len as usize);
        Some(String::from_utf8_lossy(slice).into_owned())
    }
}
