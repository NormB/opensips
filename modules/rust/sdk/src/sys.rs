//! Raw bindgen-generated FFI bindings.
//!
//! This module includes the auto-generated bindings from build.rs.
//! All types and functions here are unsafe and should not be used directly.
//! Use the safe wrappers in sibling modules instead.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(improper_ctypes)]
#![allow(clippy::all)]

include!(concat!(env!("OUT_DIR"), "/sys.rs"));
