//! Module parameter types: Integer and String.
//!
//! These types wrap raw C pointers/values and are used in the static
//! parameter exports array. OpenSIPS writes to them during config parsing.

use std::cell::UnsafeCell;
use std::ffi::{c_char, c_int, CStr};
use std::num::NonZeroI32;
use std::ptr;


/// An integer module parameter.
///
/// `OpenSIPS` writes to the inner value during `modparam()` processing.
/// Thread-safety: config parsing is single-threaded.
pub struct Integer(UnsafeCell<c_int>);

unsafe impl Sync for Integer {}

impl Default for Integer {
    fn default() -> Self {
        Self::new()
    }
}

impl Integer {
    /// Create a new integer parameter with default value 0.
    pub const fn new() -> Self {
        Integer(UnsafeCell::new(0))
    }

    /// Create a new integer parameter with a default value.
    pub const fn with_default(val: c_int) -> Self {
        Integer(UnsafeCell::new(val))
    }

    /// Get the current value. Returns None if 0.
    pub fn get_value(&self) -> Option<NonZeroI32> {
        NonZeroI32::new(unsafe { *self.0.get() })
    }

    /// Get the raw integer value.
    pub fn get(&self) -> c_int {
        unsafe { *self.0.get() }
    }

    /// Get a pointer suitable for param_export_t.param_pointer.
    pub const fn as_ptr(&self) -> *mut std::ffi::c_void {
        self.0.get() as *mut std::ffi::c_void
    }
}

/// A string module parameter.
///
/// `OpenSIPS` writes a `char*` pointer during `modparam()` processing.
/// The pointer refers to pkg_malloc'd memory owned by OpenSIPS.
pub struct ModString(UnsafeCell<*mut c_char>);

unsafe impl Sync for ModString {}

impl Default for ModString {
    fn default() -> Self {
        Self::new()
    }
}

impl ModString {
    /// Create a new string parameter with a null default.
    pub const fn new() -> Self {
        ModString(UnsafeCell::new(ptr::null_mut()))
    }

    /// Get the current value as a Rust &str.
    ///
    /// # Safety
    /// The returned reference borrows from `OpenSIPS` pkg memory.
    /// It is valid for the lifetime of the module.
    pub unsafe fn get_value(&self) -> Option<&str> {
        let p = *self.0.get();
        if p.is_null() {
            return None;
        }
        CStr::from_ptr(p).to_str().ok()
    }

    /// Get a pointer suitable for param_export_t.param_pointer.
    pub const fn as_ptr(&self) -> *mut std::ffi::c_void {
        self.0.get() as *mut std::ffi::c_void
    }
}

/// Trait for types that can be used as module parameters.
pub trait ModuleParameter {
    /// The `OpenSIPS` param type constant (STR_PARAM or INT_PARAM).
    const PARAM_TYPE: u32;

    /// Get a void pointer to the underlying storage.
    fn as_void_ptr(&self) -> *mut std::ffi::c_void;
}

impl ModuleParameter for Integer {
    const PARAM_TYPE: u32 = 2; // INT_PARAM
    fn as_void_ptr(&self) -> *mut std::ffi::c_void {
        self.as_ptr()
    }
}

impl ModuleParameter for ModString {
    const PARAM_TYPE: u32 = 1; // STR_PARAM
    fn as_void_ptr(&self) -> *mut std::ffi::c_void {
        self.as_ptr()
    }
}

/// Declare module parameters as a static array suitable for module_exports.
///
/// Usage:
/// ```ignore
/// static MAX_RATE: Integer = Integer::with_default(100);
/// static TIMEOUT: ModString = ModString::new();
///
/// module_parameters! {
///     PARAMS => [
///         ("max_rate", &MAX_RATE),
///         ("timeout", &TIMEOUT),
///     ]
/// }
/// ```
#[macro_export]
macro_rules! module_parameters {
    ($name:ident => [ $(($pname:expr, $param:expr)),* $(,)? ]) => {
        static $name: &[opensips_rs::sys::param_export_] = &[
            $(
                opensips_rs::sys::param_export_ {
                    name: $crate::cstr_lit!($pname),
                    type_: <_ as opensips_rs::param::ModuleParameter>::PARAM_TYPE,
                    param_pointer: unsafe {
                        // SAFETY: Parameter storage is static and lives for the program lifetime.
                        // OpenSIPS writes to it during single-threaded config parsing.
                        $param.as_void_ptr() as *mut ::std::ffi::c_void
                    },
                },
            )*
        ];
    };
}
