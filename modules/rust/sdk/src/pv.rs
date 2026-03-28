//! Pseudo-variable (PV) read/write access.
//!
//! Provides safe wrappers around OpenSIPS's pv_parse_format, pv_printf,
//! pv_get_spec_value, and pv_set_value.

use crate::error::{PvError, Error};
use crate::msg::SipMessage;
use crate::sys;
use std::ffi::{c_char, c_int};
use std::ptr;

extern "C" {
    fn opensips_rs_pv_is_writable(sp: *mut sys::_pv_spec) -> c_int;
}

/// PV value flag: value is null/undefined.
const PV_VAL_NULL: c_int = 1;
/// PV value flag: value contains a string.
const PV_VAL_STR: c_int = 4;
/// PV value flag: value contains an integer.
const PV_VAL_INT: c_int = 8;

/// RAII guard that calls `pv_elem_free_all` on drop.
///
/// Ensures the parsed pv_elem list is freed even if a panic occurs
/// between `pv_parse_format` and the manual `pv_elem_free_all` call
/// (e.g., if `pv_printf` triggers a panic caught by `catch_unwind`).
struct PvElemGuard {
    elem: *mut sys::_pv_elem,
}

impl Drop for PvElemGuard {
    fn drop(&mut self) {
        if !self.elem.is_null() {
            unsafe { sys::pv_elem_free_all(self.elem); }
        }
    }
}

/// The result of reading a PV value.
#[derive(Debug)]
pub enum PvValue {
    Int(i32),
    Str(String),
    Null,
}

impl SipMessage<'_> {
    /// Read a PV format string (e.g., "$ru", "$ci - $fu") and return the formatted result.
    ///
    /// This uses pv_parse_format + pv_printf for complex expressions.
    /// The parsed pv_elem is wrapped in an RAII guard so it's freed even
    /// if a panic occurs during pv_printf (caught by catch_unwind above).
    pub fn pv(&self, spec: &str) -> Option<String> {
        unsafe {
            // Build an OpenSIPS str from the spec
            let spec_bytes = spec.as_bytes();
            let osips_str = sys::__str {
                s: spec_bytes.as_ptr() as *mut c_char,
                len: spec_bytes.len() as c_int,
            };

            // Parse the format string
            let mut elem: *mut sys::_pv_elem = ptr::null_mut();
            let rc = sys::pv_parse_format(&osips_str as *const sys::__str, &mut elem);
            if rc < 0 || elem.is_null() {
                return None;
            }

            // RAII guard ensures pv_elem_free_all is called even on panic
            let _guard = PvElemGuard { elem };

            // Format into a stack buffer
            let mut buf = [0u8; 4096];
            let mut buf_len: c_int = buf.len() as c_int;

            let rc = sys::pv_printf(
                self.raw,
                elem,
                buf.as_mut_ptr() as *mut c_char,
                &mut buf_len,
            );

            if rc < 0 || buf_len <= 0 {
                return None;
            }

            let result = std::str::from_utf8(&buf[..buf_len as usize])
                .ok()?
                .to_string();
            Some(result)
        }
    }

    /// Set a PV value (e.g., "$var(result)" = "value").
    ///
    /// The spec must be a single writable PV (not a format string).
    pub fn set_pv(&mut self, spec: &str, value: &str) -> Result<(), Error> {
        unsafe {
            // Parse the PV spec
            let spec_bytes = spec.as_bytes();
            let osips_str = sys::__str {
                s: spec_bytes.as_ptr() as *mut c_char,
                len: spec_bytes.len() as c_int,
            };

            let mut pv_spec: sys::_pv_spec = std::mem::zeroed();
            let result = sys::pv_parse_spec(
                &osips_str as *const sys::__str,
                &mut pv_spec,
            );
            if result.is_null() {
                return Err(PvError::ParseFailed.into());
            }

            // Check if writable
            if opensips_rs_pv_is_writable(&mut pv_spec) == 0 {
                return Err(PvError::NotWritable.into());
            }

            // Build the PV value
            let value_bytes = value.as_bytes();
            let mut pv_val: sys::_pv_value = std::mem::zeroed();
            pv_val.flags = PV_VAL_STR;
            pv_val.rs.s = value_bytes.as_ptr() as *mut c_char;
            pv_val.rs.len = value_bytes.len() as c_int;

            let rc = sys::pv_set_value(
                self.raw,
                &mut pv_spec,
                0, // op = assign
                &mut pv_val,
            );

            if rc < 0 {
                return Err(PvError::SetFailed(rc as i32).into());
            }

            Ok(())
        }
    }

    /// Set a PV to an integer value (e.g., "$shv(counter)" = 42).
    ///
    /// Uses PV_VAL_INT internally. Needed for shared variables ($shv)
    /// declared as integer type, and for any PV where integer semantics
    /// matter (e.g., atomic operations in shared memory).
    pub fn set_pv_int(&mut self, spec: &str, value: i32) -> Result<(), Error> {
        unsafe {
            let spec_bytes = spec.as_bytes();
            let osips_str = sys::__str {
                s: spec_bytes.as_ptr() as *mut c_char,
                len: spec_bytes.len() as c_int,
            };

            let mut pv_spec: sys::_pv_spec = std::mem::zeroed();
            let result = sys::pv_parse_spec(
                &osips_str as *const sys::__str,
                &mut pv_spec,
            );
            if result.is_null() {
                return Err(PvError::ParseFailed.into());
            }

            if opensips_rs_pv_is_writable(&mut pv_spec) == 0 {
                return Err(PvError::NotWritable.into());
            }

            let mut pv_val: sys::_pv_value = std::mem::zeroed();
            pv_val.flags = PV_VAL_INT;
            pv_val.ri = value;

            let rc = sys::pv_set_value(
                self.raw,
                &mut pv_spec,
                0, // op = assign
                &mut pv_val,
            );

            if rc < 0 {
                return Err(PvError::SetFailed(rc as i32).into());
            }

            Ok(())
        }
    }

    /// Get the raw value of a single PV spec (returns Int or Str).
    pub fn pv_get(&self, spec: &str) -> Option<PvValue> {
        unsafe {
            let spec_bytes = spec.as_bytes();
            let osips_str = sys::__str {
                s: spec_bytes.as_ptr() as *mut c_char,
                len: spec_bytes.len() as c_int,
            };

            let mut pv_spec: sys::_pv_spec = std::mem::zeroed();
            let result = sys::pv_parse_spec(
                &osips_str as *const sys::__str,
                &mut pv_spec,
            );
            if result.is_null() {
                return None;
            }

            let mut pv_val: sys::_pv_value = std::mem::zeroed();
            let rc = sys::pv_get_spec_value(
                self.raw,
                &mut pv_spec as *mut sys::_pv_spec,
                &mut pv_val,
            );
            if rc < 0 {
                return None;
            }

            // Check flags
            let flags = pv_val.flags;
            if flags & PV_VAL_NULL != 0 {
                return Some(PvValue::Null);
            }

            if flags & PV_VAL_INT != 0 {
                return Some(PvValue::Int(pv_val.ri));
            }

            if flags & PV_VAL_STR != 0 {
                if !pv_val.rs.s.is_null() && pv_val.rs.len > 0 {
                    let slice = std::slice::from_raw_parts(
                        pv_val.rs.s as *const u8,
                        pv_val.rs.len as usize,
                    );
                    if let Ok(s) = std::str::from_utf8(slice) {
                        return Some(PvValue::Str(s.to_string()));
                    }
                }
                return Some(PvValue::Str(String::new()));
            }

            Some(PvValue::Null)
        }
    }
}
