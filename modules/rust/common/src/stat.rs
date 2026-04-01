//! Safe wrappers for OpenSIPS native statistics (stat_var).
//!
//! Statistics registered via `module_exports.stats` are automatically
//! aggregated across all worker processes by OpenSIPS core. The
//! `statistics:get` MI command returns the summed values.

use std::ffi::c_int;

extern "C" {
    fn opensips_rs_update_stat(var: *mut StatVarOpaque, n: c_int);
    fn opensips_rs_reset_stat(var: *mut StatVarOpaque);
    fn opensips_rs_get_stat_val(var: *mut StatVarOpaque) -> std::ffi::c_ulong;
}

/// Opaque C type -- we only use pointers.
#[repr(C)]
pub struct StatVarOpaque {
    _opaque: [u8; 0],
}

/// Safe wrapper around an OpenSIPS `stat_var` pointer.
///
/// The stat_var is allocated in shared memory by OpenSIPS core during
/// module registration. All workers share the same physical counter.
///
/// # Usage
///
/// Declare a static mutable pointer in your module:
/// ```ignore
/// static mut STAT_CHECKED: *mut StatVarOpaque = std::ptr::null_mut();
/// ```
///
/// Register it in your `MOD_STATS` array (see stat_export_t pattern).
/// After `mod_init`, OpenSIPS fills in the pointer. Wrap it for safe access:
/// ```ignore
/// let checked = StatVar::from_raw(unsafe { STAT_CHECKED });
/// checked.inc();
/// ```
pub struct StatVar(*mut StatVarOpaque);

impl StatVar {
    /// Wrap a raw stat_var pointer. Returns `None` if null.
    pub fn from_raw(ptr: *mut StatVarOpaque) -> Option<Self> {
        if ptr.is_null() { None } else { Some(Self(ptr)) }
    }

    /// Increment the counter by 1.
    pub fn inc(&self) {
        unsafe { opensips_rs_update_stat(self.0, 1); }
    }

    /// Decrement the counter by 1.
    pub fn dec(&self) {
        unsafe { opensips_rs_update_stat(self.0, -1); }
    }

    /// Add `n` to the counter (can be negative).
    pub fn update(&self, n: i32) {
        unsafe { opensips_rs_update_stat(self.0, n as c_int); }
    }

    /// Read the current aggregated value (summed across all workers).
    pub fn get(&self) -> u64 {
        unsafe { opensips_rs_get_stat_val(self.0) as u64 }
    }

    /// Reset the counter to 0.
    pub fn reset(&self) {
        unsafe { opensips_rs_reset_stat(self.0); }
    }
}
