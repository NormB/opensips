//! rust_sst — SIP Session Timers (RFC 4028) for OpenSIPS.
//!
//! Rustc 1.94 aarch64 cdylib miscompiles trait vtable dispatch: any code
//! using `HashMap`, `Vec`, `String`, `Box`, `format!`, `to_string()`,
//! `catch_unwind`, or `core::fmt::Write` in a post-fork path SIGSEGVs.
//! This implementation therefore uses:
//!   - A fixed-capacity libc-calloc'd table keyed on (h_entry<<32|h_id)
//!   - Stack byte-buffers for all string formatting
//!   - A thin C shim (src/sst_shim.c) for dialog-cell accessors, so the
//!     callback trampolines touch only primitives + raw pointers
//!
//! The `sst_check()` script function and its arithmetic logic are
//! preserved verbatim from the previous "script-only" rewrite.
//!
//! # OpenSIPS config
//!
//! ```text
//! loadmodule "rust_sst.so"
//! modparam("rust_sst", "default_interval", 1800)
//! modparam("rust_sst", "default_min_se", 90)
//! modparam("rust_sst", "default_refresher", "uas")
//!
//! route {
//!     if (is_method("INVITE")) {
//!         if (sst_check("1800", "90") == -1) {
//!             append_hf("Min-SE: $var(sst_min_se)\r\n");
//!             sl_send_reply(422, "Session Interval Too Small");
//!             exit;
//!         }
//!     }
//! }
//! ```

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]

use opensips_rs::command::CommandFunctionParam;
use opensips_rs::dlg;
use opensips_rs::param::{Integer, ModString};
use opensips_rs::sys;
use opensips_rs::{cstr_lit, opensips_log};

use rust_common::mi_resp::{mi_ok, MiObject};
use rust_common::stat::{StatVar, StatVarOpaque};

use std::cell::UnsafeCell;
use std::ffi::{c_char, c_int, c_uint, c_void};
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};

// SyncArray: wrapper to satisfy Rust's Sync trait requirement for
// static arrays of C structs containing raw pointers.
#[repr(transparent)]
struct SyncArray<T, const N: usize>([T; N]);
unsafe impl<T, const N: usize> Sync for SyncArray<T, N> {}

// ── libc + C shim FFI ─────────────────────────────────────────────
extern "C" {
    fn calloc(nmemb: usize, size: usize) -> *mut c_void;
    fn free(p: *mut c_void);

    // Local shim (src/sst_shim.c)
    fn rust_sst_dlg_ids(
        dlg_ptr: *mut c_void,
        h_entry: *mut c_uint,
        h_id: *mut c_uint,
        lifetime: *mut c_uint,
        start_ts: *mut c_uint,
    ) -> c_int;
    fn rust_sst_now_unix() -> i64;

    // opensips_rs_log is already exported by the SDK's shim.c
    fn opensips_rs_log(level: c_int, module: *const c_char, msg: *const c_char);
}

const MOD_CSTR: *const c_char = b"rust_sst\0".as_ptr() as *const c_char;
const L_INFO_C: c_int = 3;
#[allow(dead_code)] const L_WARN_C: c_int = 1;
#[allow(dead_code)] const L_ERR_C: c_int = -1;

// ── Zero-allocation formatter ────────────────────────────────────
// Mirrors the pattern that keeps rust_concurrent_calls crash-free on
// aarch64: stack byte buffer, inherent methods only, no traits.
struct StackBuf<const N: usize> {
    buf: [u8; N],
    pos: usize,
}

impl<const N: usize> StackBuf<N> {
    #[inline(always)]
    fn new() -> Self { Self { buf: [0u8; N], pos: 0 } }

    #[inline(always)]
    fn as_cstr(&mut self) -> *const c_char {
        let p = if self.pos >= N { N - 1 } else { self.pos };
        self.buf[p] = 0;
        self.buf.as_ptr() as *const c_char
    }

    #[inline(always)]
    fn push_bytes(&mut self, data: &[u8]) {
        let remaining = N.saturating_sub(1).saturating_sub(self.pos);
        let n = data.len().min(remaining);
        if n > 0 {
            self.buf[self.pos..self.pos + n].copy_from_slice(&data[..n]);
            self.pos += n;
        }
    }

    #[inline(always)]
    fn push_u64(&mut self, mut v: u64) {
        if v == 0 { self.push_bytes(b"0"); return; }
        let mut digits = [0u8; 20];
        let mut i = 0;
        while v > 0 { digits[i] = b'0' + (v % 10) as u8; v /= 10; i += 1; }
        while i > 0 { i -= 1; self.push_bytes(&[digits[i]]); }
    }

    #[inline(always)]
    fn push_u32(&mut self, v: u32) { self.push_u64(v as u64); }
}

#[inline(always)]
fn log_raw(level: c_int, buf: &mut StackBuf<256>) {
    unsafe { opensips_rs_log(level, MOD_CSTR, buf.as_cstr()); }
}

// ── Native statistics ────────────────────────────────────────────
static STAT_CHECKED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_ACCEPTED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_REJECTED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_ACTIVE: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_EXPIRED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());

#[allow(dead_code)]
use opensips_rs::stat_flags::NO_RESET as STAT_NO_RESET;

// ── Module parameters ────────────────────────────────────────────
static DEFAULT_INTERVAL: Integer = Integer::with_default(1800);
static DEFAULT_MIN_SE: Integer = Integer::with_default(90);
static DEFAULT_REFRESHER: ModString = ModString::new();
static PUBLISH_EVENTS: Integer = Integer::with_default(0);

// ── Pure arithmetic helpers (unchanged; load-bearing for sst_check) ──

fn parse_u32(b: &[u8]) -> Option<u32> {
    if b.is_empty() { return None; }
    let mut val: u32 = 0;
    for &c in b {
        if !(b'0'..=b'9').contains(&c) { return None; }
        val = val.checked_mul(10)?.checked_add((c - b'0') as u32)?;
    }
    Some(val)
}

fn trim_bytes(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&c| c != b' ' && c != b'\t' && c != b'\r' && c != b'\n').unwrap_or(b.len());
    let end = b.iter().rposition(|&c| c != b' ' && c != b'\t' && c != b'\r' && c != b'\n').map_or(start, |e| e + 1);
    if start >= end { &[] } else { &b[start..end] }
}

fn parse_str_param(s: &str) -> u32 {
    parse_u32(trim_bytes(s.as_bytes())).unwrap_or(0)
}

fn sst_check_logic(requested_interval: u32, requested_min_se: u32, our_min_se: u32) -> (bool, u32, u32) {
    let effective_min_se = if requested_min_se > our_min_se { requested_min_se } else { our_min_se };
    if requested_interval > 0 && requested_interval < effective_min_se {
        (false, 0, effective_min_se)
    } else {
        let interval = if requested_interval > 0 {
            requested_interval
        } else {
            let doubled = our_min_se * 2;
            if doubled > effective_min_se { doubled } else { effective_min_se }
        };
        (true, interval, effective_min_se)
    }
}

// ── Dialog-tracking table (per-worker, libc-calloc backed) ───────
//
// Each slot is either empty (occupied=0) or holds one dialog's SST
// state. Key = ((h_entry as u64)<<32) | h_id. FNV-1a + linear probing.
//
// Why per-worker: OpenSIPS dispatches a given dialog's callbacks to the
// same worker that created it, so the create→terminate pair lands on the
// same map. The MI process (PROC_MODULE, rank -2) has its own empty map
// and cannot see worker state — demo-control's splice of dlg_list MI
// + statistics:get remains the audience-visible view. This lands the
// architecturally-clean shape (callback-driven per-dialog tracker,
// structured MI output) without re-introducing the shm_malloc crash
// class seen in rust_concurrent_calls commit 50c346dbe.

const MAP_CAPACITY: usize = 512;
const MAX_CALLID_LEN: usize = 128;

#[allow(dead_code)] const REFRESHER_NONE: u8 = 0;
const REFRESHER_UAC:  u8 = 1;
const REFRESHER_UAS:  u8 = 2;

#[repr(C)]
struct DlgSlot {
    occupied:     u8,           // 0 = empty, 1 = live
    refresher:    u8,           // REFRESHER_*
    _pad:         [u8; 2],
    h_entry:      u32,
    h_id:         u32,
    se_interval:  u32,
    min_se:       u32,
    created_unix: u64,
    expires_unix: u64,
    callid_len:   u16,
    _pad2:        [u8; 6],
    callid:       [u8; MAX_CALLID_LEN],
}

struct DlgMap {
    slots:    *mut DlgSlot,
    capacity: usize,
    len:      UnsafeCell<usize>,
}

unsafe impl Send for DlgMap {}

#[inline(always)]
fn make_key(h_entry: u32, h_id: u32) -> u64 {
    ((h_entry as u64) << 32) | (h_id as u64)
}

#[inline(always)]
fn fnv1a64(key: u64) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for i in 0..8 {
        let b = ((key >> (i * 8)) & 0xff) as u8;
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

impl DlgMap {
    fn new() -> Self {
        let slots = unsafe {
            calloc(MAP_CAPACITY, core::mem::size_of::<DlgSlot>())
        } as *mut DlgSlot;
        assert!(!slots.is_null(), "calloc failed for DlgMap");
        DlgMap { slots, capacity: MAP_CAPACITY, len: UnsafeCell::new(0) }
    }

    /// Insert-or-update the entry for (h_entry, h_id). Returns true on
    /// success, false if the table is full.
    fn insert(
        &self,
        h_entry: u32, h_id: u32,
        se_interval: u32, min_se: u32, refresher: u8,
        created_unix: u64, expires_unix: u64,
        callid: &[u8],
    ) -> bool {
        let key = make_key(h_entry, h_id);
        let mut idx = (fnv1a64(key) as usize) % self.capacity;
        for _ in 0..self.capacity {
            let slot = unsafe { &mut *self.slots.add(idx) };
            let is_match = slot.occupied != 0 && slot.h_entry == h_entry && slot.h_id == h_id;
            if slot.occupied == 0 || is_match {
                let was_empty = slot.occupied == 0;
                slot.h_entry      = h_entry;
                slot.h_id         = h_id;
                slot.se_interval  = se_interval;
                slot.min_se       = min_se;
                slot.refresher    = refresher;
                slot.created_unix = created_unix;
                slot.expires_unix = expires_unix;
                let n = callid.len().min(MAX_CALLID_LEN);
                slot.callid[..n].copy_from_slice(&callid[..n]);
                if n < MAX_CALLID_LEN { slot.callid[n] = 0; }
                slot.callid_len = n as u16;
                slot.occupied   = 1;
                if was_empty { unsafe { *self.len.get() += 1; } }
                return true;
            }
            idx = (idx + 1) % self.capacity;
        }
        false
    }

    /// Remove the entry for (h_entry, h_id). Returns true if removed.
    fn remove(&self, h_entry: u32, h_id: u32) -> bool {
        let key = make_key(h_entry, h_id);
        let mut idx = (fnv1a64(key) as usize) % self.capacity;
        for _ in 0..self.capacity {
            let slot = unsafe { &mut *self.slots.add(idx) };
            if slot.occupied == 0 { return false; }
            if slot.h_entry == h_entry && slot.h_id == h_id {
                slot.occupied = 0;
                unsafe {
                    let len = self.len.get();
                    if *len > 0 { *len -= 1; }
                }
                return true;
            }
            idx = (idx + 1) % self.capacity;
        }
        false
    }

    #[allow(dead_code)]
    fn len(&self) -> usize { unsafe { *self.len.get() } }

    fn for_each<F: FnMut(&DlgSlot)>(&self, mut f: F) {
        for i in 0..self.capacity {
            let slot = unsafe { &*self.slots.add(i) };
            if slot.occupied != 0 { f(slot); }
        }
    }
}

impl Drop for DlgMap {
    fn drop(&mut self) {
        if !self.slots.is_null() {
            unsafe { free(self.slots as *mut c_void); }
            self.slots = ptr::null_mut();
        }
    }
}

thread_local! {
    static DLG_MAP: DlgMap = DlgMap::new();
}

// ── Refresher string parsing ─────────────────────────────────────
fn refresher_from_modparam() -> u8 {
    // Safety: DEFAULT_REFRESHER lives for the module lifetime.
    let s = unsafe { DEFAULT_REFRESHER.get_value() };
    match s.map(|x| x.as_bytes()) {
        Some(b"uac") | Some(b"UAC") => REFRESHER_UAC,
        Some(b"uas") | Some(b"UAS") => REFRESHER_UAS,
        _ => REFRESHER_UAS,
    }
}

#[inline(always)]
fn refresher_str(r: u8) -> &'static str {
    match r {
        REFRESHER_UAC => "uac",
        REFRESHER_UAS => "uas",
        _ => "none",
    }
}

// ── Module lifecycle ─────────────────────────────────────────────

unsafe extern "C" fn mod_init() -> c_int {
    let interval = DEFAULT_INTERVAL.get();
    let min_se = DEFAULT_MIN_SE.get();

    if interval < 0 {
        opensips_log!(WARN, "rust_sst",
            "default_interval={} is negative, clamping to 1800", interval);
    } else if interval > 0 && interval < 90 {
        opensips_log!(WARN, "rust_sst",
            "default_interval={} is below RFC 4028 minimum of 90", interval);
    }

    if min_se < 90 {
        opensips_log!(WARN, "rust_sst",
            "default_min_se={} is below RFC 4028 minimum of 90", min_se);
    }

    // Load the dialog module API. dialog.so must be loaded before rust_sst
    // in opensips.cfg; if it isn't, we fall back to script-only mode so
    // sst_check() still works.
    let dlg_ok = match dlg::load_api() {
        Ok(()) => {
            // Register one global DLGCB_CREATED callback. Firing it
            // once per new dialog is the hook that populates the
            // per-worker DlgMap and registers a per-dialog TERMINATED
            // callback for cleanup.
            let rc = unsafe {
                dlg::register_global_cb(
                    dlg::DLGCB_CREATED,
                    Some(sst_on_created),
                    ptr::null_mut(),
                    None,
                )
            };
            match rc {
                Ok(()) => true,
                Err(e) => {
                    opensips_log!(WARN, "rust_sst",
                        "register_global_cb(DLGCB_CREATED) failed: {} — MI sst_show will be empty", e);
                    false
                }
            }
        }
        Err(e) => {
            opensips_log!(WARN, "rust_sst",
                "dialog API not available: {} — running in script-only mode", e);
            false
        }
    };

    opensips_log!(INFO, "rust_sst",
        "module initialized (dialog_callbacks={})",
        if dlg_ok { "enabled" } else { "disabled" });
    opensips_log!(INFO, "rust_sst",
        "  default_interval={}, default_min_se={}, publish_events={}",
        interval, min_se, PUBLISH_EVENTS.get());
    0
}

unsafe extern "C" fn mod_destroy() {
    opensips_log!(INFO, "rust_sst", "module destroyed");
}

// ── Dialog callback trampolines (no vtable dispatch path) ────────

/// DLGCB_CREATED global callback: called once per new INVITE dialog.
///
/// Stays in primitives + raw pointers only: one calloc'd table slot
/// insert, one raw opensips_rs_log call, one per-dialog callback
/// registration (pure FFI). No std collections, no format!, no
/// catch_unwind, no Drop-on-error paths.
unsafe extern "C" fn sst_on_created(
    dlg: *mut sys::dlg_cell,
    _cb_type: c_int,
    _params: *mut sys::dlg_cb_params,
) {
    if dlg.is_null() { return; }

    let mut h_entry: c_uint = 0;
    let mut h_id: c_uint = 0;
    let mut lifetime: c_uint = 0;
    let mut start_ts: c_uint = 0;
    let rc = unsafe {
        rust_sst_dlg_ids(
            dlg as *mut c_void,
            &mut h_entry, &mut h_id, &mut lifetime, &mut start_ts,
        )
    };
    if rc < 0 { return; }

    // Call-ID as a short byte slice. callid() returns Option<&'static str>
    // which is just a pointer + length into the dialog's shm copy —
    // zero heap alloc on this path.
    let mut callid_buf = [0u8; MAX_CALLID_LEN];
    let callid_len = match unsafe { dlg::callid(dlg as *mut c_void) } {
        Some(s) => {
            let b = s.as_bytes();
            let n = b.len().min(MAX_CALLID_LEN);
            callid_buf[..n].copy_from_slice(&b[..n]);
            n
        }
        None => 0,
    };

    // Defaults from modparams: best signal we have at CREATED time
    // (per-call Session-Expires parsing from the INVITE is post-summit
    // work). lifetime is what the dialog module actually uses to fire
    // the expiry timer, so it's the authoritative "remaining" driver.
    let now = unsafe { rust_sst_now_unix() } as u64;
    let dlg_start = if start_ts > 0 { start_ts as u64 } else { now };
    let se_interval = if lifetime > 0 {
        lifetime
    } else {
        let v = DEFAULT_INTERVAL.get();
        if v > 0 { v as u32 } else { 1800 }
    };
    let min_se = {
        let v = DEFAULT_MIN_SE.get();
        if v < 90 { 90 } else { v as u32 }
    };
    let refresher = refresher_from_modparam();
    let expires_unix = dlg_start + se_interval as u64;

    DLG_MAP.with(|map| {
        map.insert(
            h_entry, h_id,
            se_interval, min_se, refresher,
            dlg_start, expires_unix,
            &callid_buf[..callid_len],
        );
    });

    // Per-dialog cleanup callback. Registering on the same dlg ensures
    // TERMINATED|EXPIRED|FAILED land on this worker and drain the slot.
    let cb_types = dlg::DLGCB_TERMINATED | dlg::DLGCB_EXPIRED | dlg::DLGCB_FAILED;
    let _ = unsafe {
        dlg::register_dlg_cb(
            dlg as *mut c_void,
            cb_types,
            Some(sst_on_terminated),
            ptr::null_mut(),
            None,
        )
    };

    if let Some(sv) = StatVar::from_raw(STAT_ACTIVE.load(Ordering::Relaxed)) { sv.inc(); }

    let mut b = StackBuf::<256>::new();
    b.push_bytes(b"sst tracked h_entry=");
    b.push_u32(h_entry);
    b.push_bytes(b" h_id=");
    b.push_u32(h_id);
    b.push_bytes(b" interval=");
    b.push_u32(se_interval);
    b.push_bytes(b" expires_in=");
    b.push_u32(se_interval);
    log_raw(L_INFO_C, &mut b);
}

/// DLGCB_TERMINATED / DLGCB_EXPIRED / DLGCB_FAILED per-dialog callback:
/// drain the slot.
unsafe extern "C" fn sst_on_terminated(
    dlg: *mut sys::dlg_cell,
    cb_type: c_int,
    _params: *mut sys::dlg_cb_params,
) {
    if dlg.is_null() { return; }

    let mut h_entry: c_uint = 0;
    let mut h_id: c_uint = 0;
    let mut lifetime: c_uint = 0;
    let mut start_ts: c_uint = 0;
    let rc = unsafe {
        rust_sst_dlg_ids(
            dlg as *mut c_void,
            &mut h_entry, &mut h_id, &mut lifetime, &mut start_ts,
        )
    };
    if rc < 0 { return; }

    // Try to drain our per-worker slot. A miss is expected when the
    // TERMINATED callback lands on a different worker than the CREATED
    // one — per-worker thread_local state does not migrate across
    // processes. The aggregate active-dialog count lives in the shared
    // StatVar, so we decrement unconditionally (each dialog fires
    // exactly one terminating callback, so this is one dec per dlg).
    let _ = DLG_MAP.with(|map| map.remove(h_entry, h_id));

    if let Some(sv) = StatVar::from_raw(STAT_ACTIVE.load(Ordering::Relaxed)) { sv.dec(); }
    let is_expired = (cb_type as u32 & dlg::DLGCB_EXPIRED) != 0;
    if is_expired {
        if let Some(sv) = StatVar::from_raw(STAT_EXPIRED.load(Ordering::Relaxed)) { sv.inc(); }
    }
}

// ── Script function: sst_check(interval, min_se) — UNCHANGED ────

unsafe extern "C" fn w_rust_sst_check(
    msg: *mut sys::sip_msg,
    p0: *mut c_void,
    p1: *mut c_void,
    _p2: *mut c_void,
    _p3: *mut c_void,
    _p4: *mut c_void,
    _p5: *mut c_void,
    _p6: *mut c_void,
    _p7: *mut c_void,
) -> c_int {
    let param_interval = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
        Ok(s) => parse_str_param(s),
        Err(_) => 0,
    };
    let param_min_se = match unsafe { <&str as CommandFunctionParam>::from_raw(p1) } {
        Ok(s) => parse_str_param(s),
        Err(_) => 0,
    };

    let our_min_se = {
        let v = DEFAULT_MIN_SE.get() as u32;
        if v < 90 { 90 } else { v }
    };

    let (acceptable, negotiated, effective_min_se) =
        sst_check_logic(param_interval, param_min_se, our_min_se);

    if let Some(sv) = StatVar::from_raw(STAT_CHECKED.load(Ordering::Relaxed)) { sv.inc(); }

    let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
    let _ = sip_msg.set_pv_int("$var(sst_interval)", negotiated as i32);
    let _ = sip_msg.set_pv_int("$var(sst_min_se)", effective_min_se as i32);

    if acceptable {
        if let Some(sv) = StatVar::from_raw(STAT_ACCEPTED.load(Ordering::Relaxed)) { sv.inc(); }
        opensips_log!(DBG, "rust_sst",
            "sst_check OK: interval={}, min_se={}", negotiated, effective_min_se);
        1
    } else {
        if let Some(sv) = StatVar::from_raw(STAT_REJECTED.load(Ordering::Relaxed)) { sv.inc(); }
        opensips_log!(DBG, "rust_sst",
            "sst_check REJECTED: requested={} < effective_min_se={}",
            param_interval, effective_min_se);
        -1
    }
}

// ── Stub functions (no-ops for removed features) ─────────────────

unsafe extern "C" fn w_noop(
    _msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int { 1 }

// ── MI: sst_show ──────────────────────────────────────────────────
//
// Response shape:
//   {
//     "dialogs": [
//       {"callid":"...", "se_interval":15, "min_se":90, "refresher":"uas",
//        "remaining":8, "expired":false},
//       ...
//     ],
//     "count": 1,
//     "process": "worker"|"mi"
//   }
//
// Note on cross-process visibility: each OpenSIPS worker has its own
// DLG_MAP. The MI command runs in the MI process (PROC_MODULE, rank
// -2), which has its own (empty) map — so querying sst_show directly
// returns count=0. Per-worker state is populated correctly and drives
// native statistics. Audience-visible per-dialog rows come from
// demo-control's splice of dlg_list + statistics:get until a
// shared-memory rewrite lands post-summit.

const MOD_RESP_CALLID_BUF: usize = MAX_CALLID_LEN + 1;

unsafe extern "C" fn mi_sst_show(
    _params: *const sys::mi_params_t,
    _async_hdl: *mut sys::mi_handler,
) -> *mut sys::mi_response_t {
    let Some(resp) = MiObject::new() else {
        return mi_ok() as *mut _;
    };

    let Some(arr) = resp.add_array("dialogs") else {
        return resp.into_raw() as *mut _;
    };

    let now = unsafe { rust_sst_now_unix() } as u64;
    let mut count: u32 = 0;

    DLG_MAP.with(|map| {
        map.for_each(|slot| {
            count += 1;
            let Some(item) = arr.add_object("") else { return; };

            // callid: copy into a NUL-less &str view. callid bytes are
            // ASCII in practice; unchecked-from-utf8 is safe for the MI
            // string writer which just memcpy's and length-records.
            let n = slot.callid_len as usize;
            let cid: &[u8] = &slot.callid[..n.min(MOD_RESP_CALLID_BUF)];
            let cid_str = unsafe { core::str::from_utf8_unchecked(cid) };
            item.add_str("callid", cid_str);

            item.add_num("se_interval", slot.se_interval as f64);
            item.add_num("min_se", slot.min_se as f64);
            item.add_str("refresher", refresher_str(slot.refresher));
            item.add_num("created_unix", slot.created_unix as f64);
            item.add_num("expires_unix", slot.expires_unix as f64);

            let remaining = if slot.expires_unix > now {
                (slot.expires_unix - now) as u32
            } else {
                0
            };
            item.add_num("remaining", remaining as f64);
            item.add_bool("expired", remaining == 0);
        });
    });

    resp.add_num("count", count as f64);

    // Hint to the caller whether this response came from a worker (may
    // be populated) vs the MI process (always empty in the current
    // per-worker design). Consumers can decide whether to splice.
    if count > 0 {
        resp.add_str("process", "worker");
    } else {
        resp.add_str("process", "mi");
    }

    resp.into_raw() as *mut _
}

// ── MI table scaffolding ─────────────────────────────────────────

const NULL_RECIPE: sys::mi_recipe_ = sys::mi_recipe_ { cmd: None, params: [ptr::null_mut(); 20] };

const NULL_MI: sys::mi_export_ = sys::mi_export_ {
    name: ptr::null_mut(), help: ptr::null_mut(), flags: 0, init_f: None,
    recipes: [NULL_RECIPE; 48], aliases: [ptr::null(); 4],
};

macro_rules! mi_entry {
    ($name:expr, $help:expr, $handler:expr) => {
        sys::mi_export_ {
            name: cstr_lit!($name) as *mut _,
            help: cstr_lit!($help) as *mut _,
            flags: 0,
            init_f: None,
            recipes: {
                let mut r = [NULL_RECIPE; 48];
                r[0].cmd = Some($handler);
                r
            },
            aliases: [ptr::null(); 4],
        }
    };
}

// ── Static export arrays ─────────────────────────────────────────

const EMPTY_PARAMS: [sys::cmd_param; 9] = [sys::cmd_param { flags: 0, fixup: None, free_fixup: None }; 9];

const TWO_STR_PARAMS: [sys::cmd_param; 9] = {
    let mut p = [sys::cmd_param { flags: 0, fixup: None, free_fixup: None }; 9];
    p[0].flags = opensips_rs::command::CMD_PARAM_STR;
    p[1].flags = opensips_rs::command::CMD_PARAM_STR;
    p
};

static CMDS: SyncArray<sys::cmd_export_, 7> = SyncArray([
    sys::cmd_export_ {
        name: cstr_lit!("sst_check"),
        function: Some(w_rust_sst_check),
        params: TWO_STR_PARAMS,
        flags: opensips_rs::route_flags::REQUEST,
    },
    sys::cmd_export_ {
        name: cstr_lit!("sst_update"),
        function: Some(w_noop),
        params: EMPTY_PARAMS,
        flags: opensips_rs::route_flags::REQUEST | opensips_rs::route_flags::ONREPLY,
    },
    sys::cmd_export_ {
        name: cstr_lit!("sst_stats"),
        function: Some(w_noop),
        params: EMPTY_PARAMS,
        flags: opensips_rs::route::REQ_FAIL_ONREPLY,
    },
    sys::cmd_export_ {
        name: cstr_lit!("sst_status"),
        function: Some(w_noop),
        params: EMPTY_PARAMS,
        flags: opensips_rs::route::REQ_FAIL_ONREPLY,
    },
    sys::cmd_export_ {
        name: cstr_lit!("sst_reload"),
        function: Some(w_noop),
        params: EMPTY_PARAMS,
        flags: opensips_rs::route::REQ_FAIL_ONREPLY,
    },
    sys::cmd_export_ {
        name: cstr_lit!("sst_prometheus"),
        function: Some(w_noop),
        params: EMPTY_PARAMS,
        flags: opensips_rs::route::REQ_FAIL_ONREPLY,
    },
    sys::cmd_export_ {
        name: ptr::null(),
        function: None,
        params: EMPTY_PARAMS,
        flags: 0,
    },
]);

static ACMDS: SyncArray<sys::acmd_export_, 1> = SyncArray([
    sys::acmd_export_ { name: ptr::null(), function: None, params: EMPTY_PARAMS },
]);

static PARAMS: SyncArray<sys::param_export_, 5> = SyncArray([
    sys::param_export_ {
        name: cstr_lit!("default_interval"),
        type_: opensips_rs::param_type::INT,
        param_pointer: DEFAULT_INTERVAL.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("default_min_se"),
        type_: opensips_rs::param_type::INT,
        param_pointer: DEFAULT_MIN_SE.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("default_refresher"),
        type_: opensips_rs::param_type::STR,
        param_pointer: DEFAULT_REFRESHER.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("publish_events"),
        type_: opensips_rs::param_type::INT,
        param_pointer: PUBLISH_EVENTS.as_ptr(),
    },
    sys::param_export_ {
        name: ptr::null(),
        type_: 0,
        param_pointer: ptr::null_mut(),
    },
]);

static MOD_STATS: SyncArray<sys::stat_export_, 6> = SyncArray([
    sys::stat_export_ { name: cstr_lit!("checked")  as *mut _, flags: 0, stat_pointer: &STAT_CHECKED  as *const _ as *mut _ },
    sys::stat_export_ { name: cstr_lit!("accepted") as *mut _, flags: 0, stat_pointer: &STAT_ACCEPTED as *const _ as *mut _ },
    sys::stat_export_ { name: cstr_lit!("rejected") as *mut _, flags: 0, stat_pointer: &STAT_REJECTED as *const _ as *mut _ },
    sys::stat_export_ { name: cstr_lit!("active")   as *mut _, flags: 0, stat_pointer: &STAT_ACTIVE   as *const _ as *mut _ },
    sys::stat_export_ { name: cstr_lit!("expired")  as *mut _, flags: 0, stat_pointer: &STAT_EXPIRED  as *const _ as *mut _ },
    sys::stat_export_ { name: ptr::null_mut(), flags: 0, stat_pointer: ptr::null_mut() },
]);

static MI_CMDS: SyncArray<sys::mi_export_, 2> = SyncArray([
    mi_entry!("sst_show", "Show per-worker SST dialog table", mi_sst_show),
    NULL_MI,
]);

static DEPS: opensips_rs::ffi::DepExportConcrete<1> = opensips_rs::ffi::DepExportConcrete {
    md: unsafe { std::mem::zeroed() },
    mpd: unsafe { std::mem::zeroed() },
};

/// The module_exports struct that OpenSIPS loads via dlsym("exports").
#[no_mangle]
pub static exports: sys::module_exports = sys::module_exports {
    name: cstr_lit!("rust_sst"),
    type_: opensips_rs::module_type::DEFAULT,
    ver_info: sys::module_exports__bindgen_ty_1 {
        version: cstr_lit!(env!("OPENSIPS_FULL_VERSION")),
        compile_flags: cstr_lit!(env!("OPENSIPS_COMPILE_FLAGS")),
        scm: sys::scm_version {
            type_: cstr_lit!(env!("OPENSIPS_SCM_TYPE")),
            rev: cstr_lit!(env!("OPENSIPS_SCM_REV")),
        },
    },
    dlflags: 0,
    load_f: None,
    deps: &DEPS as *const _ as *const sys::dep_export_,
    cmds: CMDS.0.as_ptr(),
    acmds: ACMDS.0.as_ptr(),
    params: PARAMS.0.as_ptr(),
    stats: MOD_STATS.0.as_ptr() as *const _,
    mi_cmds: MI_CMDS.0.as_ptr(),
    items: ptr::null(),
    trans: ptr::null(),
    procs: ptr::null(),
    preinit_f: None,
    init_f: Some(mod_init),
    response_f: None,
    destroy_f: Some(mod_destroy),
    init_child_f: None,
    reload_ack_f: None,
};

// ── Unit tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sst_check_acceptable() {
        let (ok, interval, min_se) = sst_check_logic(1800, 90, 90);
        assert!(ok);
        assert_eq!(interval, 1800);
        assert_eq!(min_se, 90);
    }

    #[test]
    fn test_sst_check_rejected() {
        let (ok, interval, min_se) = sst_check_logic(60, 0, 90);
        assert!(!ok);
        assert_eq!(interval, 0);
        assert_eq!(min_se, 90);
    }

    #[test]
    fn test_sst_check_no_interval() {
        let (ok, interval, min_se) = sst_check_logic(0, 0, 90);
        assert!(ok);
        assert_eq!(interval, 180); // 90 * 2
        assert_eq!(min_se, 90);
    }

    #[test]
    fn test_sst_check_remote_min_se_higher() {
        let (ok, interval, min_se) = sst_check_logic(1800, 120, 90);
        assert!(ok);
        assert_eq!(interval, 1800);
        assert_eq!(min_se, 120);
    }

    #[test]
    fn test_sst_check_rejected_with_remote_min_se() {
        let (ok, interval, min_se) = sst_check_logic(100, 120, 90);
        assert!(!ok);
        assert_eq!(interval, 0);
        assert_eq!(min_se, 120);
    }

    #[test]
    fn test_parse_u32_valid() {
        assert_eq!(parse_u32(b"1800"), Some(1800));
        assert_eq!(parse_u32(b"90"), Some(90));
        assert_eq!(parse_u32(b"0"), Some(0));
    }

    #[test]
    fn test_parse_u32_invalid() {
        assert_eq!(parse_u32(b""), None);
        assert_eq!(parse_u32(b"abc"), None);
        assert_eq!(parse_u32(b"-1"), None);
    }

    #[test]
    fn test_trim_bytes() {
        assert_eq!(trim_bytes(b"  1800  "), b"1800");
        assert_eq!(trim_bytes(b"90"), b"90");
        assert_eq!(trim_bytes(b"  "), &[] as &[u8]);
    }

    #[test]
    fn test_make_key() {
        assert_eq!(make_key(0, 0), 0);
        assert_eq!(make_key(1, 0), 1u64 << 32);
        assert_eq!(make_key(0, 1), 1);
        assert_eq!(make_key(0xdead_beef, 0xcafe_babe), 0xdead_beef_cafe_babe);
    }

    #[test]
    fn test_dlgmap_insert_find_remove() {
        let m = DlgMap::new();
        assert_eq!(m.len(), 0);
        assert!(m.insert(3, 7, 15, 90, REFRESHER_UAS, 1000, 1015, b"abc@host"));
        assert_eq!(m.len(), 1);
        let mut hits = 0;
        m.for_each(|s| {
            hits += 1;
            assert_eq!(s.h_entry, 3);
            assert_eq!(s.h_id, 7);
            assert_eq!(s.se_interval, 15);
            assert_eq!(s.refresher, REFRESHER_UAS);
            assert_eq!(&s.callid[..s.callid_len as usize], b"abc@host");
        });
        assert_eq!(hits, 1);
        // update in place
        assert!(m.insert(3, 7, 20, 90, REFRESHER_UAC, 1000, 1020, b"abc@host"));
        assert_eq!(m.len(), 1);
        // different key -> new slot
        assert!(m.insert(3, 8, 15, 90, REFRESHER_UAS, 1000, 1015, b"def@host"));
        assert_eq!(m.len(), 2);
        assert!(m.remove(3, 7));
        assert_eq!(m.len(), 1);
        assert!(!m.remove(3, 7));
    }

    #[test]
    fn test_refresher_parse() {
        assert_eq!(refresher_str(REFRESHER_UAC), "uac");
        assert_eq!(refresher_str(REFRESHER_UAS), "uas");
        assert_eq!(refresher_str(REFRESHER_NONE), "none");
    }
}
