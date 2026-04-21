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

use std::cell::{Cell, UnsafeCell};
use std::ffi::{c_int, c_void};
use std::ptr;
use std::sync::atomic::{AtomicI64, AtomicPtr, AtomicU8, AtomicU32, AtomicUsize, Ordering};

extern "C" {
    fn calloc(nmemb: usize, size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
    fn time(tloc: *mut i64) -> i64;
    // OpenSIPS shared memory allocator. See rust_concurrent_calls for
    // why this matters: per-worker thread_local state is invisible to
    // the MI process, so `refer_show` reads a shared shm-backed table.
    fn opensips_rs_shm_malloc(size: std::ffi::c_ulong) -> *mut c_void;
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
use opensips_rs::stat_flags::NO_RESET as STAT_NO_RESET;

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

// Shm slot state machine: EMPTY → WRITING → READY → TOMBSTONE.
// Workers insert by claiming EMPTY/TOMBSTONE → WRITING via
// compare_exchange, write the payload, then publish READY. Tombstones
// mark logical deletes; probes skip them but inserters can reclaim.
const SLOT_EMPTY: u8 = 0;
const SLOT_WRITING: u8 = 1;
const SLOT_READY: u8 = 2;
const SLOT_TOMBSTONE: u8 = 3;

#[repr(C)]
struct ReferSlot {
    state: AtomicU8,
    status: AtomicU8,
    key_len: AtomicU8,
    uri_len: AtomicU8,
    _pad: [u8; 4],
    notify_count: AtomicU32,
    created: AtomicI64,
    // Interior-mutable byte storage. Writes are gated by the slot
    // state machine; readers obtain bytes via `.get()` after observing
    // the Release store on `state`.
    key: UnsafeCell<[u8; MAX_KEY_LEN]>,   // call-id
    uri: UnsafeCell<[u8; MAX_URI_LEN]>,   // refer-to URI
}

// Safety: interior-mutable fields are synchronised by the Acquire/
// Release ordering on `state` (and on `key_len`/`uri_len`).
unsafe impl Sync for ReferSlot {}

#[repr(C)]
struct ReferMap {
    slots: [ReferSlot; MAP_CAPACITY],
}

unsafe impl Send for ReferMap {}
unsafe impl Sync for ReferMap {}

static REFER_MAP: AtomicPtr<ReferMap> = AtomicPtr::new(ptr::null_mut());
/// Approximate count of READY slots, atomically maintained by insert/sweep.
static REFER_LEN: AtomicUsize = AtomicUsize::new(0);

fn refer_map() -> Option<&'static ReferMap> {
    let p = REFER_MAP.load(Ordering::Acquire);
    if p.is_null() { None } else { Some(unsafe { &*p }) }
}

#[inline(always)]
fn fnv1a(key: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in key {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[inline]
unsafe fn slot_key_bytes(slot: &ReferSlot) -> &[u8] {
    let kl = slot.key_len.load(Ordering::Acquire) as usize;
    let p = slot.key.get() as *const u8;
    core::slice::from_raw_parts(p, kl.min(MAX_KEY_LEN))
}

#[inline]
unsafe fn slot_uri_bytes(slot: &ReferSlot) -> &[u8] {
    let ul = slot.uri_len.load(Ordering::Acquire) as usize;
    let p = slot.uri.get() as *const u8;
    core::slice::from_raw_parts(p, ul.min(MAX_URI_LEN))
}

fn refer_find(key: &[u8]) -> Option<&'static ReferSlot> {
    let map = refer_map()?;
    if key.is_empty() || key.len() > MAX_KEY_LEN { return None; }
    let cap = MAP_CAPACITY;
    let mut idx = (fnv1a(key) as usize) % cap;
    for _ in 0..cap {
        let slot = &map.slots[idx];
        let st = slot.state.load(Ordering::Acquire);
        if st == SLOT_EMPTY { return None; }
        if st == SLOT_READY && unsafe { slot_key_bytes(slot) } == key {
            return Some(slot);
        }
        // SLOT_TOMBSTONE + SLOT_WRITING: keep probing.
        idx = (idx + 1) % cap;
    }
    None
}

fn refer_insert(key: &[u8], uri: &[u8]) -> bool {
    let Some(map) = refer_map() else { return false; };
    if key.is_empty() || key.len() > MAX_KEY_LEN { return false; }
    let uri_len = uri.len().min(MAX_URI_LEN);
    let cap = MAP_CAPACITY;
    let mut idx = (fnv1a(key) as usize) % cap;
    let mut first_reusable: Option<usize> = None;

    // Write the full payload into a slot we own (state == WRITING).
    let write_slot = |slot: &ReferSlot| unsafe {
        let kp = slot.key.get() as *mut u8;
        ptr::copy_nonoverlapping(key.as_ptr(), kp, key.len());
        slot.key_len.store(key.len() as u8, Ordering::Release);

        let up = slot.uri.get() as *mut u8;
        ptr::copy_nonoverlapping(uri.as_ptr(), up, uri_len);
        slot.uri_len.store(uri_len as u8, Ordering::Release);

        slot.status.store(STATUS_PENDING, Ordering::Relaxed);
        slot.notify_count.store(0, Ordering::Relaxed);
        slot.created.store(time(ptr::null_mut()), Ordering::Relaxed);
    };

    for _ in 0..cap {
        let slot = &map.slots[idx];
        let st = slot.state.load(Ordering::Acquire);
        if st == SLOT_READY && unsafe { slot_key_bytes(slot) } == key {
            // Overwrite existing entry: briefly re-enter WRITING.
            slot.state.store(SLOT_WRITING, Ordering::Release);
            write_slot(slot);
            slot.state.store(SLOT_READY, Ordering::Release);
            return true;
        }
        if st == SLOT_EMPTY {
            let target = first_reusable.unwrap_or(idx);
            let target_slot = &map.slots[target];
            let claim = if target == idx {
                target_slot.state.compare_exchange(
                    SLOT_EMPTY, SLOT_WRITING, Ordering::AcqRel, Ordering::Acquire,
                ).is_ok()
            } else {
                target_slot.state.compare_exchange(
                    SLOT_TOMBSTONE, SLOT_WRITING, Ordering::AcqRel, Ordering::Acquire,
                ).is_ok()
            };
            if !claim {
                std::hint::spin_loop();
                continue;
            }
            write_slot(target_slot);
            target_slot.state.store(SLOT_READY, Ordering::Release);
            REFER_LEN.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if st == SLOT_TOMBSTONE && first_reusable.is_none() {
            first_reusable = Some(idx);
        }
        idx = (idx + 1) % cap;
    }
    // Capacity exhausted; fall back to the first tombstone we saw.
    if let Some(target) = first_reusable {
        let slot = &map.slots[target];
        if slot.state.compare_exchange(
            SLOT_TOMBSTONE, SLOT_WRITING, Ordering::AcqRel, Ordering::Acquire,
        ).is_ok() {
            write_slot(slot);
            slot.state.store(SLOT_READY, Ordering::Release);
            REFER_LEN.fetch_add(1, Ordering::Relaxed);
            return true;
        }
    }
    false
}

/// Sweep entries older than expire_secs; mark them TOMBSTONE.
fn refer_sweep_expired(expire_secs: i64) -> usize {
    let Some(map) = refer_map() else { return 0; };
    let now = unsafe { time(ptr::null_mut()) };
    let mut removed = 0usize;
    for slot in map.slots.iter() {
        if slot.state.load(Ordering::Acquire) == SLOT_READY {
            let created = slot.created.load(Ordering::Relaxed);
            if (now - created) >= expire_secs
                && slot.state.compare_exchange(
                    SLOT_READY, SLOT_TOMBSTONE, Ordering::AcqRel, Ordering::Acquire,
                ).is_ok()
            {
                removed += 1;
            }
        }
    }
    if removed > 0 {
        REFER_LEN.fetch_sub(removed, Ordering::Relaxed);
    }
    removed
}

fn refer_clear() {
    let Some(map) = refer_map() else { return; };
    for slot in map.slots.iter() {
        slot.state.store(SLOT_EMPTY, Ordering::Release);
    }
    REFER_LEN.store(0, Ordering::Relaxed);
}

fn refer_len() -> usize {
    REFER_LEN.load(Ordering::Relaxed)
}

fn refer_for_each<F: FnMut(&ReferSlot)>(mut f: F) {
    let Some(map) = refer_map() else { return; };
    for slot in map.slots.iter() {
        if slot.state.load(Ordering::Acquire) == SLOT_READY {
            f(slot);
        }
    }
}

/// Allocate the shm-backed ReferMap. Called from mod_init (pre-fork).
fn shm_refer_init() -> bool {
    if !REFER_MAP.load(Ordering::Acquire).is_null() {
        return true;
    }
    let sz = core::mem::size_of::<ReferMap>() as std::ffi::c_ulong;
    let raw = unsafe { opensips_rs_shm_malloc(sz) } as *mut ReferMap;
    if raw.is_null() {
        opensips_log!(ERR, "rust_refer_handler",
            "shm_malloc failed for ReferMap");
        return false;
    }
    // shm_malloc does not guarantee zero on all allocators.
    unsafe { ptr::write_bytes(raw as *mut u8, 0, sz as usize); }
    REFER_MAP.store(raw, Ordering::Release);
    true
}


// ── Per-worker state ─────────────────────────────────────────────

struct WorkerState {
    // refers moved to shm (REFER_MAP). WorkerState now carries only
    // per-worker config + local counters (authoritative aggregates live
    // in STAT_HANDLED / STAT_SUCCEEDED / ... StatVars).
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
    // Allocate shm-backed ReferMap BEFORE fork so every worker + the
    // MI process sees the same physical pages; without this the MI
    // process (which never serves SIP) reads its own empty per-process
    // copy and `refer_show` returns nothing.
    if !shm_refer_init() {
        return -1;
    }

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
    // Approximate shm-wide len; multiple workers may sweep concurrently
    // (safe, idempotent).
    if refer_len() >= state.max_pending {
        let swept = refer_sweep_expired(state.expire_secs);
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
        Ok(s) => s,
        Err(_) => {
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

        if refer_insert(call_id.as_bytes(), refer_to.as_bytes()) {
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
        Ok(s) => s,
        Err(_) => {
            opensips_log!(ERR, "rust_refer_handler", "handle_notify: missing call_id");
            return -2;
        }
    };

    let status_str_param = match unsafe { <&str as CommandFunctionParam>::from_raw(p1) } {
        Ok(s) => s,
        Err(_) => {
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
        let slot = match refer_find(call_id.as_bytes()) {
            Some(s) => s,
            None => {
                state.unknown_notify.set(state.unknown_notify.get() + 1);
                opensips_log!(DBG, "rust_refer_handler",
                    "NOTIFY for unknown REFER: call_id={}", call_id);
                return -1;
            }
        };

        slot.notify_count.fetch_add(1, Ordering::Relaxed);

        let old_status = slot.status.load(Ordering::Relaxed);
        // Terminal states are sticky.
        if old_status == STATUS_SUCCESS || old_status == STATUS_FAILED {
            return 1;
        }

        let new_status = match status_code {
            100         => STATUS_TRYING,
            200..=299   => STATUS_SUCCESS,
            300..=699   => STATUS_FAILED,
            _           => old_status,
        };

        // Only one worker wins the terminal-transition race (CAS).
        let terminal_ok = match new_status {
            STATUS_SUCCESS | STATUS_FAILED => slot.status.compare_exchange(
                old_status, new_status, Ordering::AcqRel, Ordering::Acquire,
            ).is_ok(),
            _ => {
                slot.status.store(new_status, Ordering::Relaxed);
                false
            }
        };

        if terminal_ok {
            if new_status == STATUS_SUCCESS {
                state.succeeded.set(state.succeeded.get() + 1);
                if let Some(sv) = StatVar::from_raw(STAT_SUCCEEDED.load(Ordering::Relaxed)) { sv.inc(); }
                if let Some(sv) = StatVar::from_raw(STAT_PENDING.load(Ordering::Relaxed)) { sv.update(-1); }
            } else {
                state.failed.set(state.failed.get() + 1);
                if let Some(sv) = StatVar::from_raw(STAT_FAILED.load(Ordering::Relaxed)) { sv.inc(); }
                if let Some(sv) = StatVar::from_raw(STAT_PENDING.load(Ordering::Relaxed)) { sv.update(-1); }
            }
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
        Ok(s) => s,
        Err(_) => {
            opensips_log!(ERR, "rust_refer_handler", "refer_status: missing call_id");
            return -2;
        }
    };

    with_worker(|_state| {
        let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
        match refer_find(call_id.as_bytes()) {
            Some(slot) => {
                let st = slot.status.load(Ordering::Relaxed);
                let _ = sip_msg.set_pv("$var(refer_status)", status_str(st));
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

use rust_common::mi_resp::{mi_ok, MiObject};

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
    // Reads from the shm-backed ReferMap so the MI process (which
    // never serves SIP traffic) still sees live REFER state written by
    // UDP workers. Previously this handler was a no-op stub returning
    // empty — per-worker thread_local state would have been invisible
    // to MI anyway.
    let Some(resp) = MiObject::new() else { return mi_ok() as *mut _; };

    // Aggregate counters from the shared StatVars (not per-worker Cells).
    fn sv_get(ptr: *mut StatVarOpaque) -> u64 {
        StatVar::from_raw(ptr).map(|s| s.get()).unwrap_or(0)
    }
    resp.add_num("handled",   sv_get(STAT_HANDLED.load(Ordering::Relaxed))   as f64);
    resp.add_num("succeeded", sv_get(STAT_SUCCEEDED.load(Ordering::Relaxed)) as f64);
    resp.add_num("failed",    sv_get(STAT_FAILED.load(Ordering::Relaxed))    as f64);
    resp.add_num("pending",   sv_get(STAT_PENDING.load(Ordering::Relaxed))   as f64);
    resp.add_num("expired",   sv_get(STAT_EXPIRED.load(Ordering::Relaxed))   as f64);

    if let Some(arr) = resp.add_array("transfers") {
        refer_for_each(|slot| {
            let k_bytes = unsafe { slot_key_bytes(slot) };
            let u_bytes = unsafe { slot_uri_bytes(slot) };
            let call_id = core::str::from_utf8(k_bytes).unwrap_or("?");
            let uri     = core::str::from_utf8(u_bytes).unwrap_or("?");
            let status  = status_str(slot.status.load(Ordering::Relaxed));
            let nc      = slot.notify_count.load(Ordering::Relaxed);
            let created = slot.created.load(Ordering::Relaxed);
            if let Some(o) = arr.add_object("") {
                o.add_str("call_id", call_id);
                o.add_str("refer_to", uri);
                o.add_str("status", status);
                o.add_num("notify_count", nc as f64);
                o.add_num("created", created as f64);
            }
        });
    }

    resp.into_raw() as *mut _
}

unsafe extern "C" fn mi_refer_clear(
    _params: *const sys::mi_params_t,
    _async_hdl: *mut sys::mi_handler,
) -> *mut sys::mi_response_t {
    // Shm-backed clear — visible to every worker immediately.
    refer_clear();
    mi_ok() as *mut _
}

// ── Static export arrays ─────────────────────────────────────────

const EMPTY_PARAMS: [sys::cmd_param; 9] = [sys::cmd_param { flags: 0, fixup: None, free_fixup: None }; 9];

const ONE_STR_PARAM: [sys::cmd_param; 9] = {
    let mut p = [sys::cmd_param { flags: 0, fixup: None, free_fixup: None }; 9];
    p[0].flags = opensips_rs::command::CMD_PARAM_STR;
    p
};

const TWO_STR_PARAMS: [sys::cmd_param; 9] = {
    let mut p = [sys::cmd_param { flags: 0, fixup: None, free_fixup: None }; 9];
    p[0].flags = opensips_rs::command::CMD_PARAM_STR;
    p[1].flags = opensips_rs::command::CMD_PARAM_STR;
    p
};

static CMDS: SyncArray<sys::cmd_export_, 9> = SyncArray([
    sys::cmd_export_ {
        name: cstr_lit!("handle_refer"),
        function: Some(w_handle_refer),
        params: ONE_STR_PARAM,
        flags: opensips_rs::route::REQ_FAIL_ONREPLY,
    },
    sys::cmd_export_ {
        name: cstr_lit!("handle_notify"),
        function: Some(w_handle_notify),
        params: TWO_STR_PARAMS,
        flags: opensips_rs::route::REQ_FAIL_ONREPLY,
    },
    sys::cmd_export_ {
        name: cstr_lit!("refer_status"),
        function: Some(w_refer_status),
        params: ONE_STR_PARAM,
        flags: opensips_rs::route::REQ_FAIL_ONREPLY,
    },
    sys::cmd_export_ {
        name: cstr_lit!("send_refer_notify"),
        function: Some(w_noop_str),
        params: TWO_STR_PARAMS,
        flags: opensips_rs::route::REQ_FAIL_ONREPLY,
    },
    sys::cmd_export_ {
        name: cstr_lit!("check_transfer_target"),
        function: Some(w_noop_str),
        params: ONE_STR_PARAM,
        flags: opensips_rs::route::REQ_FAIL_ONREPLY,
    },
    sys::cmd_export_ {
        name: cstr_lit!("refer_stats"),
        function: Some(w_noop),
        params: EMPTY_PARAMS,
        flags: opensips_rs::route::REQ_FAIL_ONREPLY,
    },
    sys::cmd_export_ {
        name: cstr_lit!("refer_prometheus"),
        function: Some(w_noop),
        params: EMPTY_PARAMS,
        flags: opensips_rs::route::REQ_FAIL_ONREPLY,
    },
    sys::cmd_export_ {
        name: cstr_lit!("handle_attended_refer"),
        function: Some(w_noop_str),
        params: TWO_STR_PARAMS,
        flags: opensips_rs::route::REQ_FAIL_ONREPLY,
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
    sys::param_export_ { name: cstr_lit!("max_pending"), type_: opensips_rs::param_type::INT, param_pointer: MAX_PENDING.as_ptr() },
    sys::param_export_ { name: cstr_lit!("expire_secs"), type_: opensips_rs::param_type::INT, param_pointer: EXPIRE_SECS.as_ptr() },
    sys::param_export_ { name: cstr_lit!("auto_process"), type_: opensips_rs::param_type::INT, param_pointer: AUTO_PROCESS.as_ptr() },
    sys::param_export_ { name: cstr_lit!("publish_events"), type_: opensips_rs::param_type::INT, param_pointer: PUBLISH_EVENTS.as_ptr() },
    sys::param_export_ { name: cstr_lit!("transfer_timeout_secs"), type_: opensips_rs::param_type::INT, param_pointer: TRANSFER_TIMEOUT_SECS.as_ptr() },
    sys::param_export_ { name: cstr_lit!("reconnect_on_failure"), type_: opensips_rs::param_type::INT, param_pointer: RECONNECT_ON_FAILURE.as_ptr() },
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
    init_child_f: Some(mod_child_init),
    reload_ack_f: None,
};
