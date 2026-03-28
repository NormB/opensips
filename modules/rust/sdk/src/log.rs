//! OpenSIPS logging via C shim.
//!
//! Since dprint() and LM_GEN1() are variadic, we use a thin C wrapper
//! `opensips_rs_log()` compiled by build.rs.

use std::ffi::{c_char, c_int, CString};

extern "C" {
    fn opensips_rs_log(level: c_int, module: *const c_char, msg: *const c_char);
}

/// Log levels matching OpenSIPS constants.
pub const L_ALERT: c_int = -3;
pub const L_CRIT: c_int = -2;
pub const L_ERR: c_int = -1;
pub const L_WARN: c_int = 1;
pub const L_NOTICE: c_int = 2;
pub const L_INFO: c_int = 3;
pub const L_DBG: c_int = 4;

/// Log a message at the given level.
///
/// Strips interior null bytes before creating CString so that messages
/// containing `\0` (e.g., `format!("{:?}", binary_data)`) are logged
/// rather than silently dropped. This is especially important for
/// panic messages routed through `log_err`.
pub fn log_msg(level: c_int, module: &str, msg: &str) {
    let module_clean = module.replace('\0', "");
    let msg_clean = msg.replace('\0', "\u{FFFD}");
    if let (Ok(m), Ok(s)) = (CString::new(module_clean), CString::new(msg_clean)) {
        unsafe {
            opensips_rs_log(level, m.as_ptr(), s.as_ptr());
        }
    }
}

/// Log an error message (used internally for panic reporting).
pub fn log_err(msg: &str) {
    log_msg(L_ERR, "rust", msg);
}

/// Log a message using OpenSIPS's logging system.
///
/// Usage:
/// ```ignore
/// opensips_log!(ERR, "rust", "rate limit exceeded for {}", ip);
/// opensips_log!(DBG, "rust", "cache hit for {}", ruri);
/// ```
#[macro_export]
macro_rules! opensips_log {
    (ALERT, $module:expr, $($arg:tt)*) => {
        $crate::log::log_msg($crate::log::L_ALERT, $module, &format!($($arg)*))
    };
    (CRIT, $module:expr, $($arg:tt)*) => {
        $crate::log::log_msg($crate::log::L_CRIT, $module, &format!($($arg)*))
    };
    (ERR, $module:expr, $($arg:tt)*) => {
        $crate::log::log_msg($crate::log::L_ERR, $module, &format!($($arg)*))
    };
    (WARN, $module:expr, $($arg:tt)*) => {
        $crate::log::log_msg($crate::log::L_WARN, $module, &format!($($arg)*))
    };
    (NOTICE, $module:expr, $($arg:tt)*) => {
        $crate::log::log_msg($crate::log::L_NOTICE, $module, &format!($($arg)*))
    };
    (INFO, $module:expr, $($arg:tt)*) => {
        $crate::log::log_msg($crate::log::L_INFO, $module, &format!($($arg)*))
    };
    (DBG, $module:expr, $($arg:tt)*) => {
        $crate::log::log_msg($crate::log::L_DBG, $module, &format!($($arg)*))
    };
}
