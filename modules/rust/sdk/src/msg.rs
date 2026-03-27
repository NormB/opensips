//! Safe SIP message wrapper.
//!
//! SipMessage wraps the raw `sip_msg` pointer and provides safe access
//! to message fields through C shim functions (since sip_msg is too
//! complex and deeply nested to fully replicate in Rust).

use crate::sys;
use std::ffi::{c_char, c_int, c_void, CStr};
use std::marker::PhantomData;

/// SIP message type: request (INVITE, REGISTER, etc.)
const SIP_REQUEST: c_int = 1;
/// SIP message type: reply (200 OK, 404 Not Found, etc.)
const SIP_REPLY: c_int = 2;

/// Safe wrapper around an OpenSIPS `sip_msg*`.
///
/// The lifetime `'a` ties this to the scope of the script function call.
/// The raw pointer is valid for the duration of the route processing.
pub struct SipMessage<'a> {
    pub(crate) raw: *mut sys::sip_msg,
    _lifetime: PhantomData<&'a mut sys::sip_msg>,
}

// C shim declarations
extern "C" {
    fn opensips_rs_msg_method(msg: *mut sys::sip_msg, out: *mut *const c_char, len: *mut c_int) -> c_int;
    fn opensips_rs_msg_ruri(msg: *mut sys::sip_msg, out: *mut *const c_char, len: *mut c_int) -> c_int;
    fn opensips_rs_msg_status(msg: *mut sys::sip_msg, out: *mut *const c_char, len: *mut c_int) -> c_int;
    fn opensips_rs_msg_status_code(msg: *mut sys::sip_msg) -> c_int;
    fn opensips_rs_msg_src_ip(msg: *mut sys::sip_msg) -> *const c_char;
    fn opensips_rs_msg_src_port(msg: *mut sys::sip_msg) -> u16;
    fn opensips_rs_msg_type(msg: *mut sys::sip_msg) -> c_int;
    fn opensips_rs_msg_flags(msg: *mut sys::sip_msg) -> u32;
    fn opensips_rs_msg_set_flag(msg: *mut sys::sip_msg, flag: u32);
    fn opensips_rs_msg_headers(msg: *mut sys::sip_msg) -> *mut c_void;
    fn opensips_rs_hdr_name(hdr: *mut c_void, out: *mut *const c_char, len: *mut c_int) -> c_int;
    fn opensips_rs_hdr_body(hdr: *mut c_void, out: *mut *const c_char, len: *mut c_int) -> c_int;
    fn opensips_rs_hdr_next(hdr: *mut c_void) -> *mut c_void;
    fn opensips_rs_parse_headers(msg: *mut sys::sip_msg) -> c_int;
}

impl<'a> SipMessage<'a> {
    /// Create a SipMessage from a raw pointer.
    ///
    /// # Safety
    /// The pointer must be valid and the sip_msg must outlive 'a.
    #[inline]
    pub unsafe fn from_raw(raw: *mut sys::sip_msg) -> Self {
        SipMessage {
            raw,
            _lifetime: PhantomData,
        }
    }

    /// Get the raw pointer (for passing to C functions).
    #[inline]
    pub fn as_raw(&self) -> *mut sys::sip_msg {
        self.raw
    }

    /// Get the SIP method (INVITE, REGISTER, etc.). Returns None for replies.
    pub fn method(&self) -> Option<&str> {
        unsafe {
            let mut ptr: *const c_char = std::ptr::null();
            let mut len: c_int = 0;
            if opensips_rs_msg_method(self.raw, &mut ptr, &mut len) != 0 {
                return None;
            }
            str_from_raw(ptr, len)
        }
    }

    /// Get the Request-URI. Returns None for replies.
    pub fn ruri(&self) -> Option<&str> {
        unsafe {
            let mut ptr: *const c_char = std::ptr::null();
            let mut len: c_int = 0;
            if opensips_rs_msg_ruri(self.raw, &mut ptr, &mut len) != 0 {
                return None;
            }
            str_from_raw(ptr, len)
        }
    }

    /// Get the reply status string. Returns None for requests.
    pub fn status(&self) -> Option<&str> {
        unsafe {
            let mut ptr: *const c_char = std::ptr::null();
            let mut len: c_int = 0;
            if opensips_rs_msg_status(self.raw, &mut ptr, &mut len) != 0 {
                return None;
            }
            str_from_raw(ptr, len)
        }
    }

    /// Get the reply status code as integer. Returns None for requests.
    #[inline]
    pub fn status_code(&self) -> Option<u32> {
        unsafe {
            let code = opensips_rs_msg_status_code(self.raw);
            if code < 0 { None } else { Some(code as u32) }
        }
    }

    /// Get the source IP address as a string.
    pub fn source_ip(&self) -> String {
        unsafe {
            let ptr = opensips_rs_msg_src_ip(self.raw);
            if ptr.is_null() {
                return String::new();
            }
            CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    }

    /// Get the source port.
    #[inline]
    pub fn source_port(&self) -> u16 {
        unsafe { opensips_rs_msg_src_port(self.raw) }
    }

    /// Check if this is a SIP request.
    #[inline]
    pub fn is_request(&self) -> bool {
        unsafe { opensips_rs_msg_type(self.raw) == SIP_REQUEST }
    }

    /// Check if this is a SIP reply.
    #[inline]
    pub fn is_reply(&self) -> bool {
        unsafe { opensips_rs_msg_type(self.raw) == SIP_REPLY }
    }

    /// Get message flags.
    #[inline]
    pub fn flags(&self) -> u32 {
        unsafe { opensips_rs_msg_flags(self.raw) }
    }

    /// Set a message flag by bit position.
    #[inline]
    pub fn set_flag(&mut self, flag: u32) {
        unsafe { opensips_rs_msg_set_flag(self.raw, flag) }
    }

    /// Find a header by name (case-insensitive). Parses all headers first.
    pub fn header(&self, name: &str) -> Option<&str> {
        // Parse all headers first
        unsafe { opensips_rs_parse_headers(self.raw); }

        for (hname, hbody) in self.header_iter() {
            if hname.eq_ignore_ascii_case(name) {
                return Some(hbody);
            }
        }
        None
    }

    /// Iterate over all headers as (name, body) pairs.
    pub fn header_iter(&self) -> HeaderIter<'_> {
        // Ensure headers are parsed
        unsafe { opensips_rs_parse_headers(self.raw); }
        let first = unsafe { opensips_rs_msg_headers(self.raw) };
        HeaderIter { current: first, _phantom: PhantomData }
    }
}

/// Iterator over SIP message headers.
pub struct HeaderIter<'a> {
    current: *mut c_void,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> Iterator for HeaderIter<'a> {
    type Item = (&'a str, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        if self.current.is_null() {
            return None;
        }

        unsafe {
            let mut name_ptr: *const c_char = std::ptr::null();
            let mut name_len: c_int = 0;
            let mut body_ptr: *const c_char = std::ptr::null();
            let mut body_len: c_int = 0;

            if opensips_rs_hdr_name(self.current, &mut name_ptr, &mut name_len) != 0 {
                return None;
            }
            if opensips_rs_hdr_body(self.current, &mut body_ptr, &mut body_len) != 0 {
                return None;
            }

            let name = str_from_raw(name_ptr, name_len).unwrap_or("");
            let body = str_from_raw(body_ptr, body_len).unwrap_or("");

            self.current = opensips_rs_hdr_next(self.current);

            Some((name, body))
        }
    }
}

/// Convert a raw C string pointer + length to a Rust &str.
unsafe fn str_from_raw<'a>(ptr: *const c_char, len: c_int) -> Option<&'a str> {
    if ptr.is_null() || len <= 0 {
        return None;
    }
    let slice = std::slice::from_raw_parts(ptr as *const u8, len as usize);
    std::str::from_utf8(slice).ok()
}
