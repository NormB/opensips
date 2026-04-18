//! Command function traits and the commands! macro.
//!
//! Provides the mechanism for declaring script-callable functions
//! that `OpenSIPS` can invoke from opensips.cfg routes.

use std::ffi::{c_int, c_void};

// ── Command parameter type flags ─────────────────────────────────

pub const CMD_PARAM_INT: c_int = 1 << 0;
pub const CMD_PARAM_STR: c_int = 1 << 1;
pub const CMD_PARAM_VAR: c_int = 1 << 2;
pub const CMD_PARAM_REGEX: c_int = 1 << 3;
pub const CMD_PARAM_OPT: c_int = 1 << 4;
pub const CMD_PARAM_FIX_NULL: c_int = 1 << 5;
pub const CMD_PARAM_NO_EXPAND: c_int = 1 << 6;
pub const CMD_PARAM_STATIC: c_int = 1 << 7;

/// Why a parameter could not be extracted from its raw FFI pointer.
///
/// `as_str()` returns a `&'static str` so callers can log the cause
/// without triggering the `Display`/`Debug` trait vtable on aarch64
/// (see rustc 1.94 cdylib vtable bug).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ParamError {
    /// Required pointer was null.
    NullPointer,
    /// OpenSIPS `str` length was <= 0.
    EmptyOrNegativeLength,
    /// Bytes were not valid UTF-8.
    InvalidUtf8,
}

impl ParamError {
    /// Stable, non-allocating message for logging.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NullPointer => "null pointer",
            Self::EmptyOrNegativeLength => "empty or negative length",
            Self::InvalidUtf8 => "invalid UTF-8",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn param_error_as_str_is_static() {
        // `as_str` must return a reference with static lifetime so callers
        // can stash it without allocation (aarch64 safety).
        let _: &'static str = ParamError::NullPointer.as_str();
        let _: &'static str = ParamError::EmptyOrNegativeLength.as_str();
        let _: &'static str = ParamError::InvalidUtf8.as_str();
    }

    #[test]
    fn param_error_messages_distinct() {
        let msgs = [
            ParamError::NullPointer.as_str(),
            ParamError::EmptyOrNegativeLength.as_str(),
            ParamError::InvalidUtf8.as_str(),
        ];
        for i in 0..msgs.len() {
            for j in (i + 1)..msgs.len() {
                assert_ne!(msgs[i], msgs[j], "duplicate error message");
            }
        }
    }

    #[test]
    fn param_error_copy_and_eq() {
        // Copy + PartialEq are required by the trait contract;
        // callers rely on `error == ParamError::NullPointer` style matches.
        let a = ParamError::NullPointer;
        let b = a;  // Copy
        assert_eq!(a, b);
        assert_eq!(a, ParamError::NullPointer);
        assert_ne!(a, ParamError::InvalidUtf8);
    }

    #[test]
    fn cmd_param_flags_are_bits() {
        // Each flag occupies a distinct bit — verifies no overlap.
        let all = [
            CMD_PARAM_INT, CMD_PARAM_STR, CMD_PARAM_VAR, CMD_PARAM_REGEX,
            CMD_PARAM_OPT, CMD_PARAM_FIX_NULL, CMD_PARAM_NO_EXPAND, CMD_PARAM_STATIC,
        ];
        for f in &all {
            assert!(f.count_ones() == 1, "not single-bit: {}", f);
        }
    }
}

/// Trait for types that can appear as command function parameters.
pub trait CommandFunctionParam {
    /// The CMD_PARAM_* flags for this parameter type.
    const FLAGS: c_int;

    /// Extract the parameter from the raw void pointer passed by `OpenSIPS`.
    ///
    /// Returns `Err(ParamError)` when the pointer is null, the data is
    /// malformed (negative or zero length), or contents are not valid for
    /// this param type. Callers must handle the failure explicitly.
    ///
    /// # Safety
    /// The pointer must point to the correct type when non-null.
    unsafe fn from_raw(ptr: *mut c_void) -> Result<Self, ParamError>
    where
        Self: Sized;
}

impl CommandFunctionParam for &str {
    const FLAGS: c_int = CMD_PARAM_STR;

    unsafe fn from_raw(ptr: *mut c_void) -> Result<Self, ParamError> {
        if ptr.is_null() { return Err(ParamError::NullPointer); }
        let osips_str = &*(ptr as *const crate::sys::__str);
        if osips_str.s.is_null() || osips_str.len <= 0 {
            return Err(ParamError::EmptyOrNegativeLength);
        }
        let slice = std::slice::from_raw_parts(
            osips_str.s as *const u8, osips_str.len as usize);
        std::str::from_utf8(slice).map_err(|_| ParamError::InvalidUtf8)
    }
}

impl CommandFunctionParam for i32 {
    const FLAGS: c_int = CMD_PARAM_INT;

    unsafe fn from_raw(ptr: *mut c_void) -> Result<Self, ParamError> {
        if ptr.is_null() { return Err(ParamError::NullPointer); }
        Ok(*(ptr as *const c_int))
    }
}

impl CommandFunctionParam for Option<&str> {
    const FLAGS: c_int = CMD_PARAM_STR | CMD_PARAM_OPT;

    /// Optional string: a null pointer or empty `str` is `Ok(None)`;
    /// only invalid UTF-8 is an error.
    unsafe fn from_raw(ptr: *mut c_void) -> Result<Self, ParamError> {
        if ptr.is_null() { return Ok(None); }
        let osips_str = &*(ptr as *const crate::sys::__str);
        if osips_str.s.is_null() || osips_str.len <= 0 { return Ok(None); }
        let slice = std::slice::from_raw_parts(
            osips_str.s as *const u8, osips_str.len as usize);
        std::str::from_utf8(slice).map(Some).map_err(|_| ParamError::InvalidUtf8)
    }
}

/// Declare script-callable commands with automatic FFI shim generation.
///
/// This macro generates:
/// 1. An `extern "C"` function matching the OpenSIPS cmd_function signature
/// 2. A `cmd_export_t` entry with correct param flags
/// 3. catch_unwind protection at the FFI boundary
///
/// Usage:
/// ```ignore
/// commands! {
///     CMDS => [
///         // (name, rust_fn, [param_types...], route_flags)
///         ("rust_check_rate", check_rate, [], REQUEST_ROUTE | FAILURE_ROUTE),
///         ("rust_http_query", http_query, [&str], REQUEST_ROUTE),
///     ]
/// }
/// ```
#[macro_export]
macro_rules! commands {
    ($name:ident => [
        $( ($cmd_name:expr, $func:ident, [$($ptype:ty),*], $flags:expr) ),* $(,)?
    ]) => {
        // Generate extern "C" shims
        $(
            $crate::_gen_cmd_shim!($func, [$($ptype),*]);
        )*

        // Build the command export array
        // NOTE: This must be constructed at runtime because cmd_export_ contains
        // inline arrays that cannot be trivially const-initialized.
        // The module's lib.rs should build the array in a lazy_static or OnceLock.
    };
}

/// Internal macro: generate an extern "C" shim for a command function.
///
/// The shim receives (sip_msg*, void*, void*, ...) and:
/// 1. Wraps in catch_unwind
/// 2. Constructs a SipMessage
/// 3. Extracts typed parameters
/// 4. Calls the Rust function
#[macro_export]
macro_rules! _gen_cmd_shim {
    // 0 params
    ($func:ident, []) => {
        paste::paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<__shim_ $func>](
                msg: *mut opensips_rs::sys::sip_msg,
                _p0: *mut ::std::ffi::c_void,
                _p1: *mut ::std::ffi::c_void,
                _p2: *mut ::std::ffi::c_void,
                _p3: *mut ::std::ffi::c_void,
                _p4: *mut ::std::ffi::c_void,
                _p5: *mut ::std::ffi::c_void,
                _p6: *mut ::std::ffi::c_void,
                _p7: *mut ::std::ffi::c_void,
            ) -> ::std::ffi::c_int {
                opensips_rs::catch_unwind_ffi(|| {
                    let mut sip_msg = opensips_rs::SipMessage::from_raw(msg);
                    $func(&mut sip_msg)
                })
            }
        }
    };
    // 1 param
    ($func:ident, [$t0:ty]) => {
        paste::paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<__shim_ $func>](
                msg: *mut opensips_rs::sys::sip_msg,
                p0: *mut ::std::ffi::c_void,
                _p1: *mut ::std::ffi::c_void,
                _p2: *mut ::std::ffi::c_void,
                _p3: *mut ::std::ffi::c_void,
                _p4: *mut ::std::ffi::c_void,
                _p5: *mut ::std::ffi::c_void,
                _p6: *mut ::std::ffi::c_void,
                _p7: *mut ::std::ffi::c_void,
            ) -> ::std::ffi::c_int {
                opensips_rs::ffi::catch_unwind_ffi_mut(|| {
                    let mut sip_msg = opensips_rs::SipMessage::from_raw(msg);
                    let a0 = match <$t0 as opensips_rs::command::CommandFunctionParam>::from_raw(p0) {
                        Ok(v) => v,
                        Err(e) => {
                            opensips_rs::opensips_log!(ERR, "rust",
                                "{}: param 0: {}", stringify!($func), e.as_str());
                            return -1;
                        }
                    };
                    $func(&mut sip_msg, a0)
                })
            }
        }
    };
    // 2 params
    ($func:ident, [$t0:ty, $t1:ty]) => {
        paste::paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<__shim_ $func>](
                msg: *mut opensips_rs::sys::sip_msg,
                p0: *mut ::std::ffi::c_void,
                p1: *mut ::std::ffi::c_void,
                _p2: *mut ::std::ffi::c_void,
                _p3: *mut ::std::ffi::c_void,
                _p4: *mut ::std::ffi::c_void,
                _p5: *mut ::std::ffi::c_void,
                _p6: *mut ::std::ffi::c_void,
                _p7: *mut ::std::ffi::c_void,
            ) -> ::std::ffi::c_int {
                opensips_rs::ffi::catch_unwind_ffi_mut(|| {
                    let mut sip_msg = opensips_rs::SipMessage::from_raw(msg);
                    let a0 = match <$t0 as opensips_rs::command::CommandFunctionParam>::from_raw(p0) {
                        Ok(v) => v,
                        Err(e) => {
                            opensips_rs::opensips_log!(ERR, "rust",
                                "{}: param 0: {}", stringify!($func), e.as_str());
                            return -1;
                        }
                    };
                    let a1 = match <$t1 as opensips_rs::command::CommandFunctionParam>::from_raw(p1) {
                        Ok(v) => v,
                        Err(e) => {
                            opensips_rs::opensips_log!(ERR, "rust",
                                "{}: param 1: {}", stringify!($func), e.as_str());
                            return -1;
                        }
                    };
                    $func(&mut sip_msg, a0, a1)
                })
            }
        }
    };
}
