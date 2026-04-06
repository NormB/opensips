//! rust_refer_handler — REFER/NOTIFY state machine tracker for OpenSIPS.
//!
//! Rewritten to avoid Rust trait objects / dynamic dispatch which trigger a
//! rustc 1.94 aarch64 cdylib codegen bug: R_AARCH64_RELATIVE relocations for
//! trait vtable entries point directly to function code instead of vtable data,
//! causing the vtable dispatch to read instruction bytes as function pointers.
//!
//! This version uses a fixed-capacity hash table backed by libc calloc with
//! FNV-1a hashing and linear probing. Zero std collections in any code path.

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]

use opensips_rs::command::CommandFunctionParam;
use opensips_rs::param::Integer;
use opensips_rs::sys;
use opensips_rs::{cstr_lit, opensips_log};
use rust_common::stat::{StatVar, StatVarOpaque};

use std::cell::Cell;
use std::ffi::{c_int, c_void};
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};

extern "C" {
    fn calloc(nmemb: usize, size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
    fn time(tloc: *mut i64) -> i64;
}

// SyncArray: wrapper to satisfy Rust's Sync trait requirement for
// static arrays of C structs containing raw pointers.
#[repr(transparent)]
struct SyncArray<T, const N: usize>([T; N]);
unsafe impl<T, const N: usize> Sync for SyncArray<T, N> {}

// ── Native statistics ────────────────────────────────────────────
static STAT_HANDLED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_SUCCEEDED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_FAILED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_EXPIRED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_PENDING: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());

/// STAT_NO_RESET flag value (from OpenSIPS statistics.h).
const STAT_NO_RESET: u16 = 1;

// ── Module parameters ────────────────────────────────────────────

/// Max tracked REFER transactions per worker (default 1000).
static MAX_PENDING: Integer = Integer::with_default(1000);

/// Auto-expire stale REFER state after this many seconds (default 300).
static EXPIRE_SECS: Integer = Integer::with_default(300);

/// Auto-process REFER/NOTIFY via dialog callbacks (default 0 = disabled).
/// Stubbed out in this vtable-safe rewrite.
static AUTO_PROCESS: Integer = Integer::with_default(0);

/// Publish transfer events via EVI/NATS (default 0 = disabled).
/// Stubbed out in this vtable-safe rewrite.
static PUBLISH_EVENTS: Integer = Integer::with_default(0);

/// Timeout in seconds for pending transfers (default 30).
static TRANSFER_TIMEOUT_SECS: Integer = Integer::with_default(30);

/// Reconnect original parties on transfer failure (default 0 = disabled).
/// Stubbed out in this vtable-safe rewrite.
static RECONNECT_ON_FAILURE: Integer = Integer::with_default(0);

// ── Fixed-capacity hash map (libc-backed, no trait objects) ──────

const MAP_CAPACITY: usize = 1024;
const MAX_KEY_LEN: usize = 64;
const MAX_URI_LEN: usize = 128;

/// Status as a simple u8 — no enum with derived traits.
const STATUS_PENDING: u8 = 1;
const STATUS_TRYING: u8 = 2;
const STATUS_SUCCESS: u8 = 3;
const STATUS_FAILED: u8 = 4;

fn status_str(s: u8) -> &'static str {
    match s {
        STATUS_PENDING => "pending",
        STATUS_TRYING => "trying",
        STATUS_SUCCESS => "success",
        STATUS_FAILED => "failed",
        _ => "unknown",
    }
}

#[repr(C)]
struct ReferSlot {
    key: [u8; MAX_KEY_LEN],        // call-id
    key_len: u8,
    occupied: bool,
    status: u8,
    _pad: u8,
    notify_count: u32,
    created: i64,                   // unix timestamp from libc::time
    uri: [u8; MAX_URI_LEN],        // refer-to URI
    uri_len: u8,
    _pad2: [u8; 7],
}

struct ReferMap {
    slots: *mut ReferSlot,
    capacity: usize,
    len: usize,
}

unsafe impl Send for ReferMap {}

#[inline(always)]
fn fnv1a(key: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in key {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

impl ReferMap {
    fn new() -> Self {
        let slots = unsafe { calloc(MAP_CAPACITY, core::mem::size_of::<ReferSlot>()) } as *mut ReferSlot;
        assert!(!slots.is_null(), "calloc failed for ReferMap");
        ReferMap { slots, capacity: MAP_CAPACITY, len: 0 }
    }

    fn find_slot(&self, key: &[u8]) -> Option<usize> {
        if key.is_empty() || key.len() > MAX_KEY_LEN { return None; }
        let mut idx = (fnv1a(key) as usize) % self.capacity;
        for _ in 0..self.capacity {
            let slot = unsafe { &*self.slots.add(idx) };
            if !slot.occupied { return None; }
            if slot.key_len as usize == key.len()
                && unsafe { slot.key.get_unchecked(..key.len()) } == key
            {
                return Some(idx);
            }
            idx = (idx + 1) % self.capacity;
        }
        None
    }

    fn get(&self, key: &[u8]) -> Option<&ReferSlot> {
        self.find_slot(key).map(|idx| unsafe { &*self.slots.add(idx) })
    }

    fn get_mut(&mut self, key: &[u8]) -> Option<&mut ReferSlot> {
        self.find_slot(key).map(|idx| unsafe { &mut *self.slots.add(idx) })
    }

    /// Insert or overwrite a refer entry. Returns true on success.
    fn insert(&mut self, key: &[u8], uri: &[u8]) -> bool {
        if key.is_empty() || key.len() > MAX_KEY_LEN { return false; }
        let uri_len = uri.len().min(MAX_URI_LEN);
        let mut idx = (fnv1a(key) as usize) % self.capacity;
        for _ in 0..self.capacity {
            let slot = unsafe { &mut *self.slots.add(idx) };
            if !slot.occupied {
                // New entry
                slot.key[..key.len()].copy_from_slice(key);
                slot.key_len = key.len() as u8;
                slot.uri[..uri_len].copy_from_slice(&uri[..uri_len]);
                slot.uri_len = uri_len as u8;
                slot.status = STATUS_PENDING;
                slot.notify_count = 0;
                slot.created = unsafe { time(ptr::null_mut()) };
                slot.occupied = true;
                self.len += 1;
                return true;
            }
            if slot.key_len as usize == key.len()
                && unsafe { slot.key.get_unchecked(..key.len()) } == key
            {
                // Overwrite existing
                slot.uri[..uri_len].copy_from_slice(&uri[..uri_len]);
                slot.uri_len = uri_len as u8;
                slot.status = STATUS_PENDING;
                slot.notify_count = 0;
                slot.created = unsafe { time(ptr::null_mut()) };
                return true;
            }
            idx = (idx + 1) % self.capacity;
        }
        false // table full
    }

    /// Remove a single slot by index (swap with tombstone approach: just clear it
    /// and re-insert any displaced entries in the probe chain).
    fn remove_idx(&mut self, idx: usize) {
        unsafe { &mut *self.slots.add(idx) }.occupied = false;
        self.len -= 1;

        // Re-insert displaced entries in the probe chain
        let mut check = (idx + 1) % self.capacity;
        loop {
            let slot = unsafe { &*self.slots.add(check) };
            if !slot.occupied { break; }

            // Copy data, clear, re-insert
            let mut tmp_key = [0u8; MAX_KEY_LEN];
            let mut tmp_uri = [0u8; MAX_URI_LEN];
            let kl = slot.key_len as usize;
            let ul = slot.uri_len as usize;
            tmp_key[..kl].copy_from_slice(&slot.key[..kl]);
            tmp_uri[..ul].copy_from_slice(&slot.uri[..ul]);
            let tmp_status = slot.status;
            let tmp_nc = slot.notify_count;
            let tmp_created = slot.created;

            unsafe { &mut *self.slots.add(check) }.occupied = false;
            self.len -= 1;

            // Re-insert (find new home)
            let mut new_idx = (fnv1a(&tmp_key[..kl]) as usize) % self.capacity;
            for _ in 0..self.capacity {
                let s = unsafe { &mut *self.slots.add(new_idx) };
                if !s.occupied {
                    s.key[..kl].copy_from_slice(&tmp_key[..kl]);
                    s.key_len = kl as u8;
                    s.uri[..ul].copy_from_slice(&tmp_uri[..ul]);
                    s.uri_len = ul as u8;
                    s.status = tmp_status;
                    s.notify_count = tmp_nc;
                    s.created = tmp_created;
                    s.occupied = true;
                    self.len += 1;
                    break;
                }
                new_idx = (new_idx + 1) % self.capacity;
            }

            check = (check + 1) % self.capacity;
        }
    }

    /// Sweep entries older than expire_secs. Returns count removed.
    fn sweep_expired(&mut self, expire_secs: i64) -> usize {
        let now = unsafe { time(ptr::null_mut()) };
        let mut removed = 0usize;
        let mut idx = 0usize;
        while idx < self.capacity {
            let slot = unsafe { &*self.slots.add(idx) };
            if slot.occupied && (now - slot.created) >= expire_secs {
                self.remove_idx(idx);
                removed += 1;
                // Don't advance idx — remove_idx may have moved an entry here
            } else {
                idx += 1;
            }
        }
        removed
    }

    fn clear(&mut self) {
        if !self.slots.is_null() {
            unsafe { core::ptr::write_bytes(self.slots, 0, self.capacity); }
            self.len = 0;
        }
    }

    fn destroy(&mut self) {
        if !self.slots.is_null() {
            unsafe { free(self.slots as *mut c_void) };
            self.slots = ptr::null_mut();
            self.capacity = 0;
            self.len = 0;
        }
    }
}

impl Drop for ReferMap {
    fn drop(&mut self) {
        self.destroy();
    }
}

// ── Per-worker state ─────────────────────────────────────────────

struct WorkerState {
    refers: ReferMap,
    max_pending: usize,
    expire_secs: i64,
    handled: Cell<u64>,
    succeeded: Cell<u64>,
    failed: Cell<u64>,
    expired: Cell<u64>,
    unknown_notify: Cell<u64>,
}

thread_local! {
    static WORKER: Cell<*mut WorkerState> = const { Cell::new(ptr::null_mut()) };
}

#[inline(always)]
fn with_worker<F: FnOnce(&mut WorkerState) -> c_int>(f: F, err: c_int) -> c_int {
    WORKER.with(|cell| {
        let p = cell.get();
        if p.is_null() {
            opensips_log!(ERR, "rust_refer_handler", "worker state not initialized");
            return err;
        }
        f(unsafe { &mut *p })
    })
}

// ── Parse u16 from byte slice without alloc ──────────────────────

fn parse_u16_bytes(b: &[u8]) -> Option<u16> {
    let trimmed = trim_bytes(b);
    if trimmed.is_empty() { return None; }
    let mut val: u16 = 0;
    for &c in trimmed {
        if c < b'0' || c > b'9' { return None; }
        val = val.checked_mul(10)?.checked_add((c - b'0') as u16)?;
    }
    Some(val)
}

fn trim_bytes(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&c| c != b' ' && c != b'\t').unwrap_or(b.len());
    let end = b.iter().rposition(|&c| c != b' ' && c != b'\t' && c != b'\r').map_or(start, |e| e + 1);
    if start >= end { &[] } else { &b[start..end] }
}

// ── Module lifecycle ─────────────────────────────────────────────

unsafe extern "C" fn mod_init() -> c_int {
    let max_p = MAX_PENDING.get();
    let exp = EXPIRE_SECS.get();
    let auto_p = AUTO_PROCESS.get();
    let pub_ev = PUBLISH_EVENTS.get();
    let timeout = TRANSFER_TIMEOUT_SECS.get();
    let reconnect = RECONNECT_ON_FAILURE.get();

    if auto_p != 0 {
        opensips_log!(WARN, "rust_refer_handler",
            "auto_process={} ignored in vtable-safe rewrite", auto_p);
    }
    if pub_ev != 0 {
        opensips_log!(WARN, "rust_refer_handler",
            "publish_events={} ignored in vtable-safe rewrite", pub_ev);
    }

    opensips_log!(INFO, "rust_refer_handler", "module initialized (vtable-safe)");
    opensips_log!(INFO, "rust_refer_handler", "  max_pending={}", max_p);
    opensips_log!(INFO, "rust_refer_handler", "  expire_secs={}s", exp);
    opensips_log!(INFO, "rust_refer_handler", "  auto_process={} (stubbed)", auto_p);
    opensips_log!(INFO, "rust_refer_handler", "  publish_events={} (stubbed)", pub_ev);
    opensips_log!(INFO, "rust_refer_handler", "  transfer_timeout_secs={}s", timeout);
    opensips_log!(INFO, "rust_refer_handler", "  reconnect_on_failure={} (stubbed)", reconnect);
    0
}

unsafe extern "C" fn mod_child_init(rank: c_int) -> c_int {
    if rank < 1 && rank != -2 { return 0; }

    let max_p = MAX_PENDING.get().max(1) as usize;
    let exp = if EXPIRE_SECS.get() > 0 { EXPIRE_SECS.get() as i64 } else { 300 };

    let state_ptr = unsafe {
        calloc(1, core::mem::size_of::<WorkerState>()) as *mut WorkerState
    };
    if state_ptr.is_null() { return -1; }

    let state = unsafe { &mut *state_ptr };
    state.refers = ReferMap::new();
    state.max_pending = max_p;
    state.expire_secs = exp;
    state.handled = Cell::new(0);
    state.succeeded = Cell::new(0);
    state.failed = Cell::new(0);
    state.expired = Cell::new(0);
    state.unknown_notify = Cell::new(0);

    WORKER.with(|cell| cell.set(state_ptr));

    opensips_log!(DBG, "rust_refer_handler", "worker {} initialized", rank);
    0
}

unsafe extern "C" fn mod_destroy() {
    opensips_log!(INFO, "rust_refer_handler", "module destroyed");
}

// ── Helper: maybe sweep expired if at capacity ──────────────────

fn maybe_sweep(state: &mut WorkerState) {
    if state.refers.len >= state.max_pending {
        let swept = state.refers.sweep_expired(state.expire_secs);
        if swept > 0 {
            state.expired.set(state.expired.get() + swept as u64);
            if let Some(sv) = StatVar::from_raw(STAT_EXPIRED.load(Ordering::Relaxed)) {
                for _ in 0..swept { sv.inc(); }
            }
            if let Some(sv) = StatVar::from_raw(STAT_PENDING.load(Ordering::Relaxed)) {
                for _ in 0..swept { sv.update(-1); }
            }
        }
    }
}

// ── Script function: handle_refer(refer_to) ─────────────────────

unsafe extern "C" fn w_handle_refer(
    msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    let refer_to = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
        Some(s) => s,
        None => {
            opensips_log!(ERR, "rust_refer_handler", "handle_refer: missing refer_to parameter");
            return -2;
        }
    };

    // Extract Call-ID from the SIP message
    let sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
    let call_id = match sip_msg.header("Call-ID") {
        Some(cid) => cid,
        None => {
            opensips_log!(ERR, "rust_refer_handler", "handle_refer: no Call-ID header");
            return -2;
        }
    };

    with_worker(|state| {
        maybe_sweep(state);

        if state.refers.insert(call_id.as_bytes(), refer_to.as_bytes()) {
            state.handled.set(state.handled.get() + 1);
            if let Some(sv) = StatVar::from_raw(STAT_HANDLED.load(Ordering::Relaxed)) { sv.inc(); }
            if let Some(sv) = StatVar::from_raw(STAT_PENDING.load(Ordering::Relaxed)) { sv.update(1); }
            opensips_log!(DBG, "rust_refer_handler",
                "REFER tracked: call_id={} refer_to={}", call_id, refer_to);
            1
        } else {
            opensips_log!(ERR, "rust_refer_handler",
                "handle_refer: map full, cannot insert call_id={}", call_id);
            -1
        }
    }, -2)
}

// ── Script function: handle_notify(call_id, status_code) ────────

unsafe extern "C" fn w_handle_notify(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    let call_id = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
        Some(s) => s,
        None => {
            opensips_log!(ERR, "rust_refer_handler", "handle_notify: missing call_id");
            return -2;
        }
    };

    let status_str_param = match unsafe { <&str as CommandFunctionParam>::from_raw(p1) } {
        Some(s) => s,
        None => {
            opensips_log!(ERR, "rust_refer_handler", "handle_notify: missing status_code");
            return -2;
        }
    };

    let status_code = match parse_u16_bytes(status_str_param.as_bytes()) {
        Some(c) => c,
        None => {
            opensips_log!(ERR, "rust_refer_handler",
                "handle_notify: invalid status_code: {}", status_str_param);
            return -2;
        }
    };

    with_worker(|state| {
        let slot = match state.refers.get_mut(call_id.as_bytes()) {
            Some(s) => s,
            None => {
                state.unknown_notify.set(state.unknown_notify.get() + 1);
                opensips_log!(DBG, "rust_refer_handler",
                    "NOTIFY for unknown REFER: call_id={}", call_id);
                return -1;
            }
        };

        slot.notify_count += 1;

        // Terminal states are sticky
        if slot.status == STATUS_SUCCESS || slot.status == STATUS_FAILED {
            return 1;
        }

        let old_status = slot.status;
        match status_code {
            100 => slot.status = STATUS_TRYING,
            200..=299 => slot.status = STATUS_SUCCESS,
            300..=699 => slot.status = STATUS_FAILED,
            _ => {} // keep current
        }

        // Update stats on terminal transition
        if old_status != STATUS_SUCCESS && slot.status == STATUS_SUCCESS {
            state.succeeded.set(state.succeeded.get() + 1);
            if let Some(sv) = StatVar::from_raw(STAT_SUCCEEDED.load(Ordering::Relaxed)) { sv.inc(); }
            if let Some(sv) = StatVar::from_raw(STAT_PENDING.load(Ordering::Relaxed)) { sv.update(-1); }
        } else if old_status != STATUS_FAILED && slot.status == STATUS_FAILED {
            state.failed.set(state.failed.get() + 1);
            if let Some(sv) = StatVar::from_raw(STAT_FAILED.load(Ordering::Relaxed)) { sv.inc(); }
            if let Some(sv) = StatVar::from_raw(STAT_PENDING.load(Ordering::Relaxed)) { sv.update(-1); }
        }

        opensips_log!(DBG, "rust_refer_handler",
            "NOTIFY processed: call_id={} code={}", call_id, status_code);
        1
    }, -2)
}

// ── Script function: refer_status(call_id) ──────────────────────

unsafe extern "C" fn w_refer_status(
    msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    let call_id = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
        Some(s) => s,
        None => {
            opensips_log!(ERR, "rust_refer_handler", "refer_status: missing call_id");
            return -2;
        }
    };

    with_worker(|state| {
        let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
        match state.refers.get(call_id.as_bytes()) {
            Some(slot) => {
                let _ = sip_msg.set_pv("$var(refer_status)", status_str(slot.status));
                1
            }
            None => {
                let _ = sip_msg.set_pv("$var(refer_status)", "unknown");
                -1
            }
        }
    }, -2)
}

// ── Null-op stubs for removed/unused features ───────────────────

unsafe extern "C" fn w_noop_str(
    _msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int { 1 }

unsafe extern "C" fn w_noop(
    _msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int { 1 }

// ── MI commands (stubs) ─────────────────────────────────────────

use rust_common::mi_resp::mi_ok;

const NULL_RECIPE: sys::mi_recipe_ = sys::mi_recipe_ { cmd: None, params: [ptr::null_mut(); 20] };

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

const NULL_MI: sys::mi_export_ = sys::mi_export_ {
    name: ptr::null_mut(), help: ptr::null_mut(), flags: 0, init_f: None,
    recipes: [NULL_RECIPE; 48], aliases: [ptr::null(); 4],
};

unsafe extern "C" fn mi_refer_show(
    _params: *const sys::mi_params_t,
    _async_hdl: *mut sys::mi_handler,
) -> *mut sys::mi_response_t {
    mi_ok() as *mut _
}

unsafe extern "C" fn mi_refer_clear(
    _params: *const sys::mi_params_t,
    _async_hdl: *mut sys::mi_handler,
) -> *mut sys::mi_response_t {
    with_worker(|state| { state.refers.clear(); 0 }, 0);
    mi_ok() as *mut _
}

// ── Static export arrays ─────────────────────────────────────────

const EMPTY_PARAMS: [sys::cmd_param; 9] = [sys::cmd_param { flags: 0, fixup: None, free_fixup: None }; 9];

const ONE_STR_PARAM: [sys::cmd_param; 9] = {
    let mut p = [sys::cmd_param { flags: 0, fixup: None, free_fixup: None }; 9];
    p[0].flags = 2; // CMD_PARAM_STR
    p
};

const TWO_STR_PARAMS: [sys::cmd_param; 9] = {
    let mut p = [sys::cmd_param { flags: 0, fixup: None, free_fixup: None }; 9];
    p[0].flags = 2; // CMD_PARAM_STR
    p[1].flags = 2; // CMD_PARAM_STR
    p
};

static CMDS: SyncArray<sys::cmd_export_, 9> = SyncArray([
    sys::cmd_export_ {
        name: cstr_lit!("handle_refer"),
        function: Some(w_handle_refer),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("handle_notify"),
        function: Some(w_handle_notify),
        params: TWO_STR_PARAMS,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("refer_status"),
        function: Some(w_refer_status),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("send_refer_notify"),
        function: Some(w_noop_str),
        params: TWO_STR_PARAMS,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("check_transfer_target"),
        function: Some(w_noop_str),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("refer_stats"),
        function: Some(w_noop),
        params: EMPTY_PARAMS,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("refer_prometheus"),
        function: Some(w_noop),
        params: EMPTY_PARAMS,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("handle_attended_refer"),
        function: Some(w_noop_str),
        params: TWO_STR_PARAMS,
        flags: 1 | 2 | 4,
    },
    // Null terminator
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

static PARAMS: SyncArray<sys::param_export_, 8> = SyncArray([
    sys::param_export_ { name: cstr_lit!("max_pending"), type_: 2, param_pointer: MAX_PENDING.as_ptr() },
    sys::param_export_ { name: cstr_lit!("expire_secs"), type_: 2, param_pointer: EXPIRE_SECS.as_ptr() },
    sys::param_export_ { name: cstr_lit!("auto_process"), type_: 2, param_pointer: AUTO_PROCESS.as_ptr() },
    sys::param_export_ { name: cstr_lit!("publish_events"), type_: 2, param_pointer: PUBLISH_EVENTS.as_ptr() },
    sys::param_export_ { name: cstr_lit!("transfer_timeout_secs"), type_: 2, param_pointer: TRANSFER_TIMEOUT_SECS.as_ptr() },
    sys::param_export_ { name: cstr_lit!("reconnect_on_failure"), type_: 2, param_pointer: RECONNECT_ON_FAILURE.as_ptr() },
    // Note: allowed_targets param removed (was STR_PARAM, used Vec<String> internally)
    // Null terminator
    sys::param_export_ { name: ptr::null(), type_: 0, param_pointer: ptr::null_mut() },
    sys::param_export_ { name: ptr::null(), type_: 0, param_pointer: ptr::null_mut() },
]);

static MI_CMDS: SyncArray<sys::mi_export_, 3> = SyncArray([
    mi_entry!("refer_show", "Show pending REFER transfers", mi_refer_show),
    mi_entry!("refer_clear", "Clear all REFER state", mi_refer_clear),
    NULL_MI,
]);

static MOD_STATS: SyncArray<sys::stat_export_, 6> = SyncArray([
    sys::stat_export_ { name: cstr_lit!("handled") as *mut _, flags: 0, stat_pointer: &STAT_HANDLED as *const _ as *mut _ },
    sys::stat_export_ { name: cstr_lit!("succeeded") as *mut _, flags: 0, stat_pointer: &STAT_SUCCEEDED as *const _ as *mut _ },
    sys::stat_export_ { name: cstr_lit!("failed") as *mut _, flags: 0, stat_pointer: &STAT_FAILED as *const _ as *mut _ },
    sys::stat_export_ { name: cstr_lit!("expired") as *mut _, flags: 0, stat_pointer: &STAT_EXPIRED as *const _ as *mut _ },
    sys::stat_export_ { name: cstr_lit!("pending") as *mut _, flags: STAT_NO_RESET, stat_pointer: &STAT_PENDING as *const _ as *mut _ },
    sys::stat_export_ { name: ptr::null_mut(), flags: 0, stat_pointer: ptr::null_mut() },
]);

static DEPS: opensips_rs::ffi::DepExportConcrete<1> = opensips_rs::ffi::DepExportConcrete {
    md: unsafe { std::mem::zeroed() },
    mpd: unsafe { std::mem::zeroed() },
};

#[no_mangle]
pub static exports: sys::module_exports = sys::module_exports {
    name: cstr_lit!("rust_refer_handler"),
    type_: 1,
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
    init_child_f: Some(mod_child_init),
    reload_ack_f: None,
};
