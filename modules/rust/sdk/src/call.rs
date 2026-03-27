//! Module function call-through.
//!
//! Enables calling other OpenSIPS module functions from Rust, e.g.,
//! `msg.call("sl_send_reply", &["429", "Rate Limited"])`.
//!
//! Reference: Python module's python_msgobj.c lines 232-366.

use crate::error::{CallError, Error};
use crate::msg::SipMessage;
use crate::sys;
use std::ffi::{c_char, c_int, c_void, CString};
use std::ptr;

extern "C" {
    fn opensips_rs_pkg_malloc(size: std::ffi::c_ulong) -> *mut c_void;
    fn opensips_rs_pkg_free(p: *mut c_void);
}

impl SipMessage<'_> {
    /// Call an OpenSIPS module function by name with string arguments.
    ///
    /// This mirrors the Python module's `call_function()` implementation:
    /// 1. Find the cmd_export_t by name
    /// 2. Build action_elem_t array with string arguments
    /// 3. Run fixups via fix_cmd / get_cmd_fixups
    /// 4. Call the function
    /// 5. Clean up
    ///
    /// Returns the function's return code (typically 1 for success, -1 for failure).
    pub fn call(&mut self, func: &str, args: &[&str]) -> Result<i32, Error> {
        unsafe {
            let func_cstr = CString::new(func).map_err(|_| CallError::NotFound(func.to_string()))?;

            // Find the exported command
            let cmd = sys::find_cmd_export_t(func_cstr.as_ptr(), 0);
            if cmd.is_null() {
                return Err(CallError::NotFound(func.to_string()).into());
            }

            let cmd_ref = &*cmd;

            // Build action_elem_t array (9 elements = MAX_ACTION_ELEMS)
            let mut elems: [sys::action_elem_; 9] = std::mem::zeroed();

            // Track allocations for cleanup (2 pkg_malloc calls per arg)
            let mut to_free: Vec<*mut c_void> = Vec::with_capacity(args.len() * 2);

            // Set string arguments in elem[1..n] (elem[0] reserved for cmd)
            for (i, arg) in args.iter().enumerate() {
                if i >= 8 {
                    break; // MAX_CMD_PARAMS = 8
                }

                let arg_len = arg.len();

                // Allocate OpenSIPS str in pkg memory
                let pkg_str = opensips_rs_pkg_malloc(
                    std::mem::size_of::<sys::__str>() as std::ffi::c_ulong
                ) as *mut sys::__str;

                if pkg_str.is_null() {
                    for p in &to_free { opensips_rs_pkg_free(*p); }
                    return Err(CallError::AllocFailed.into());
                }
                to_free.push(pkg_str as *mut c_void);

                // Allocate string content in pkg memory
                let pkg_buf = opensips_rs_pkg_malloc((arg_len + 1) as std::ffi::c_ulong) as *mut c_char;
                if pkg_buf.is_null() {
                    for p in &to_free { opensips_rs_pkg_free(*p); }
                    return Err(CallError::AllocFailed.into());
                }
                to_free.push(pkg_buf as *mut c_void);

                // Copy string content
                ptr::copy_nonoverlapping(arg.as_ptr(), pkg_buf as *mut u8, arg_len);
                *pkg_buf.add(arg_len) = 0; // null terminate

                (*pkg_str).s = pkg_buf;
                (*pkg_str).len = arg_len as c_int;

                // Store in elem's union via the data pointer
                elems[i + 1].type_ = 2; // STR_ST from route_struct.h
                elems[i + 1].u.__bindgen_anon_1.data = pkg_str as *mut c_void;
            }

            // Run fixups
            let rc = sys::fix_cmd(cmd_ref.params.as_ptr(), elems.as_mut_ptr());
            if rc < 0 {
                for p in &to_free { opensips_rs_pkg_free(*p); }
                return Err(CallError::FixupFailed(rc as i32).into());
            }

            // Get fixups and call
            let mut cmd_params: [*mut c_void; 8] = [ptr::null_mut(); 8];
            let mut tmp_val: sys::_pv_value = std::mem::zeroed();

            let rc = sys::get_cmd_fixups(
                self.raw,
                cmd_ref.params.as_ptr(),
                elems.as_mut_ptr(),
                cmd_params.as_mut_ptr(),
                &mut tmp_val,
            );

            if rc < 0 {
                for p in &to_free { opensips_rs_pkg_free(*p); }
                return Err(CallError::FixupFailed(rc as i32).into());
            }

            // Call the actual function
            let func_ptr = cmd_ref.function
                .ok_or_else(|| CallError::NotFound(func.to_string()))?;
            let result = func_ptr(
                self.raw,
                cmd_params[0],
                cmd_params[1],
                cmd_params[2],
                cmd_params[3],
                cmd_params[4],
                cmd_params[5],
                cmd_params[6],
                cmd_params[7],
            );

            // Free fixups
            sys::free_cmd_fixups(
                cmd_ref.params.as_ptr(),
                elems.as_mut_ptr(),
                cmd_params.as_mut_ptr(),
            );

            // Free our pkg allocations
            for p in &to_free {
                opensips_rs_pkg_free(*p);
            }

            Ok(result as i32)
        }
    }
}
