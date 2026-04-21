//! rust_concurrent_calls — Per-account concurrent call limiting for OpenSIPS.
//!
//! Rewritten to avoid Rust trait objects / dynamic dispatch which trigger a
//! rustc 1.94 aarch64 cdylib codegen bug: R_AARCH64_RELATIVE relocations for
//! trait vtable entries point directly to function code instead of vtable data,
//! causing the vtable dispatch to read instruction bytes as function pointers.
//!
//! This version uses fixed-capacity hash tables backed by libc calloc with
//! FNV-1a hashing and linear probing. Zero std collections in any code path.
//!
//! Features:
//! - Per-account concurrent call limits from CSV
//! - Cooldown period after blocking
//! - Burst detection via ring buffer
//! - Direction-aware inbound/outbound limits
//! - Dialog profile integration (direct FFI, no Rust allocations)
//! - Event publishing via opensips_log!
//! - Runtime limit overrides
//! - MI commands: show, override, reset

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(dead_code)]

use opensips_rs::command::CommandFunctionParam;
use opensips_rs::param::{Integer, ModString};
use opensips_rs::sys;
use opensips_rs::cstr_lit;
use rust_common::stat::{StatVar, StatVarOpaque};

use std::cell::{Cell, UnsafeCell};
#[allow(unused_imports)]
use std::ffi::{c_char, c_int, c_long, c_void};
use std::ptr;
use std::sync::atomic::{AtomicI64, AtomicPtr, AtomicU8, AtomicU32, Ordering};

extern "C" {
    fn calloc(nmemb: usize, size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
    fn fopen(path: *const c_char, mode: *const c_char) -> *mut c_void;
    fn fclose(stream: *mut c_void) -> c_int;
    fn fgets(buf: *mut c_char, size: c_int, stream: *mut c_void) -> *mut c_char;
    fn opensips_rs_log(level: c_int, module: *const c_char, msg: *const c_char);
    // OpenSIPS shared memory allocator. Allocated regions are mapped
    // into all worker processes at the same virtual address, so
    // pointers stored pre-fork remain valid post-fork in every worker
    // + the MI process.
    fn opensips_rs_shm_malloc(size: std::ffi::c_ulong) -> *mut c_void;
}

// ── Zero-allocation logging ──────────────────────────────────────
// opensips_log! uses format!() + String::replace() + CString::new() = 4-6 heap
// allocations per call, any of which can trigger the aarch64 vtable bug.
// safe_log! writes to a stack buffer via core::fmt::Write (no heap allocation).

struct StackBuf<const N: usize> {
    buf: [u8; N],
    pos: usize,
}

impl<const N: usize> StackBuf<N> {
    #[inline(always)]
    fn new() -> Self { Self { buf: [0u8; N], pos: 0 } }
    #[inline(always)]
    fn as_cstr(&mut self) -> *const c_char {
        if self.pos >= N { self.pos = N - 1; }
        self.buf[self.pos] = 0;
        self.buf.as_ptr() as *const c_char
    }
}

impl<const N: usize> StackBuf<N> {
    #[inline(always)]
    fn push_str(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let remaining = N.saturating_sub(1).saturating_sub(self.pos);
        let n = bytes.len().min(remaining);
        if n > 0 {
            self.buf[self.pos..self.pos + n].copy_from_slice(&bytes[..n]);
            self.pos += n;
        }
    }
    #[inline(always)]
    fn push_u32(&mut self, mut v: u32) {
        if v == 0 { self.push_str("0"); return; }
        let mut digits = [0u8; 10];
        let mut i = 0;
        while v > 0 { digits[i] = b'0' + (v % 10) as u8; v /= 10; i += 1; }
        while i > 0 { i -= 1; self.push_byte(digits[i]); }
    }
    #[inline(always)]
    fn push_i32(&mut self, v: i32) {
        if v < 0 { self.push_byte(b'-'); self.push_u32((-v) as u32); }
        else { self.push_u32(v as u32); }
    }
    #[inline(always)]
    fn push_i64(&mut self, v: i64) {
        if v < 0 { self.push_byte(b'-'); self.push_u64((-v) as u64); }
        else { self.push_u64(v as u64); }
    }
    #[inline(always)]
    fn push_u64(&mut self, mut v: u64) {
        if v == 0 { self.push_str("0"); return; }
        let mut digits = [0u8; 20];
        let mut i = 0;
        while v > 0 { digits[i] = b'0' + (v % 10) as u8; v /= 10; i += 1; }
        while i > 0 { i -= 1; self.push_byte(digits[i]); }
    }
    #[inline(always)]
    fn push_byte(&mut self, b: u8) {
        if self.pos < N - 1 { self.buf[self.pos] = b; self.pos += 1; }
    }
}

const L_DBG: c_int = 4;
const L_INFO: c_int = 3;
const L_NOTICE: c_int = 2;
const L_WARN: c_int = 1;
const L_ERR: c_int = 0;

const MOD_NAME: *const c_char = b"rust_concurrent_calls\0".as_ptr() as *const c_char;

#[inline(always)]
fn log_raw(level: c_int, buf: &mut StackBuf<512>) {
    unsafe { opensips_rs_log(level, MOD_NAME, buf.as_cstr()); }
}

// safe_log! — zero-allocation logging. Accepts pairs of (str_literal, value)
// fragments concatenated via push operations. No format parsing, no traits,
// no panic paths, no cleanup code.
macro_rules! safe_log {
    ($level:expr, $($part:expr),+ $(,)?) => {{
        let mut _b = StackBuf::<512>::new();
        $( _b.push_auto($part); )+
        log_raw($level, &mut _b);
    }};
}

// push_auto dispatches at compile time based on literal type.
// Uses inherent methods only — no trait dispatch.
impl StackBuf<512> {
    #[inline(always)] fn push_auto_str(&mut self, s: &str) { self.push_str(s); }
    #[inline(always)] fn push_auto_u32(&mut self, v: u32) { self.push_u32(v); }
    #[inline(always)] fn push_auto_i32(&mut self, v: i32) { self.push_i32(v); }
    #[inline(always)] fn push_auto_i64(&mut self, v: i64) { self.push_i64(v); }

    // Overloaded push_auto via a helper trait resolved at monomorphization
    #[inline(always)] fn push_auto<T: AutoPush>(&mut self, v: T) { v.push_into(self); }
}

trait AutoPush { fn push_into(self, buf: &mut StackBuf<512>); }
impl AutoPush for &str { #[inline(always)] fn push_into(self, buf: &mut StackBuf<512>) { buf.push_str(self); } }
impl AutoPush for u32 { #[inline(always)] fn push_into(self, buf: &mut StackBuf<512>) { buf.push_u32(self); } }
impl AutoPush for i32 { #[inline(always)] fn push_into(self, buf: &mut StackBuf<512>) { buf.push_i32(self); } }
impl AutoPush for i64 { #[inline(always)] fn push_into(self, buf: &mut StackBuf<512>) { buf.push_i64(self); } }
impl AutoPush for u64 { #[inline(always)] fn push_into(self, buf: &mut StackBuf<512>) { buf.push_u64(self); } }

extern "C" {
    fn time(tloc: *mut i64) -> i64;
    fn opensips_rs_pkg_malloc(size: std::ffi::c_ulong) -> *mut c_void;
    fn opensips_rs_pkg_free(p: *mut c_void);
}

// SyncArray: wrapper to satisfy Rust's Sync trait requirement for
// static arrays of C structs containing raw pointers.
#[repr(transparent)]
struct SyncArray<T, const N: usize>([T; N]);
unsafe impl<T, const N: usize> Sync for SyncArray<T, N> {}

// ── Native statistics ────────────────────────────────────────────
static STAT_CHECKED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_ALLOWED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_BLOCKED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_ACTIVE_CALLS: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());

// ── Module parameters ────────────────────────────────────────────
static LIMITS_FILE: ModString = ModString::new();
static DEFAULT_LIMIT: Integer = Integer::with_default(10);
static AUTO_TRACK: Integer = Integer::with_default(1);
static ACCOUNT_VAR: ModString = ModString::new();
static USE_DIALOG_PROFILES: Integer = Integer::with_default(0);
static PROFILE_NAME: ModString = ModString::new();
static DIRECTION_AWARE: Integer = Integer::with_default(0);
static COOLDOWN_SECS: Integer = Integer::with_default(0);
static BURST_THRESHOLD: Integer = Integer::with_default(0);
static BURST_WINDOW_SECS: Integer = Integer::with_default(10);
static PUBLISH_EVENTS: Integer = Integer::with_default(0);

// ── Constants ────────────────────────────────────────────────────

const MAP_CAPACITY: usize = 512;
const MAX_KEY_LEN: usize = 64;
const BURST_RING_SIZE: usize = 8;

// route_struct.h enum values for dialog profile FFI
const NUMBER_ST: c_int = 3;
const STR_ST: c_int = 12;

// ── Slot state machine (EMPTY → WRITING → READY) for shm-concurrent
//    inserts. Modelled on rust_acl's shm counter table. Inserters claim
//    a slot via compare_exchange (EMPTY → WRITING) then publish READY.
//    Concurrent INC/DEC on a READY slot uses atomic fetch_add/fetch_sub.

const SLOT_EMPTY: u8 = 0;
const SLOT_WRITING: u8 = 1;
const SLOT_READY: u8 = 2;

#[inline(always)]
fn fnv1a(key: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in key {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

// ── OverrideMap: shm-backed u32 map for per-account limit overrides ──
//
// Allocated once in mod_init (pre-fork). All workers + the MI process
// see the same physical pages, so `concurrent_override` MI calls are
// visible globally and `concurrent_show` reads the same state UDP
// workers wrote to.

#[repr(C)]
struct OverrideSlot {
    state: AtomicU8,
    key_len: AtomicU8,
    _pad: [u8; 2],
    value: AtomicU32,
    // Interior-mutable byte storage. Writes are gated by the slot
    // state machine (only the slot-owner writes between WRITING and
    // READY); readers obtain the bytes via `.get()` after observing
    // the Release store on `state`.
    key: UnsafeCell<[u8; MAX_KEY_LEN]>,
}

// Safety: interior mutability on `key` is synchronised by the
// Acquire/Release ordering on `state`.
unsafe impl Sync for OverrideSlot {}

#[repr(C)]
struct OverrideMap {
    slots: [OverrideSlot; MAP_CAPACITY],
}

unsafe impl Send for OverrideMap {}
unsafe impl Sync for OverrideMap {}

static OVERRIDE_MAP: AtomicPtr<OverrideMap> = AtomicPtr::new(ptr::null_mut());

fn override_map() -> Option<&'static OverrideMap> {
    let p = OVERRIDE_MAP.load(Ordering::Acquire);
    if p.is_null() { None } else { Some(unsafe { &*p }) }
}

#[inline]
unsafe fn override_key_bytes(slot: &OverrideSlot) -> &[u8] {
    let kl = slot.key_len.load(Ordering::Acquire) as usize;
    let p = slot.key.get() as *const u8;
    core::slice::from_raw_parts(p, kl.min(MAX_KEY_LEN))
}

fn override_get(key: &[u8]) -> Option<u32> {
    let map = override_map()?;
    if key.is_empty() || key.len() > MAX_KEY_LEN { return None; }
    let cap = MAP_CAPACITY;
    let mut idx = (fnv1a(key) as usize) % cap;
    for _ in 0..cap {
        let slot = &map.slots[idx];
        let st = slot.state.load(Ordering::Acquire);
        if st == SLOT_EMPTY { return None; }
        if st == SLOT_READY && unsafe { override_key_bytes(slot) } == key {
            return Some(slot.value.load(Ordering::Relaxed));
        }
        idx = (idx + 1) % cap;
    }
    None
}

fn override_insert(key: &[u8], value: u32) -> bool {
    let Some(map) = override_map() else { return false; };
    if key.is_empty() || key.len() > MAX_KEY_LEN { return false; }
    let cap = MAP_CAPACITY;
    let mut idx = (fnv1a(key) as usize) % cap;
    for _ in 0..cap {
        let slot = &map.slots[idx];
        let st = slot.state.load(Ordering::Acquire);
        if st == SLOT_READY && unsafe { override_key_bytes(slot) } == key {
            slot.value.store(value, Ordering::Relaxed);
            return true;
        }
        if st == SLOT_EMPTY {
            if slot.state.compare_exchange(
                SLOT_EMPTY, SLOT_WRITING, Ordering::AcqRel, Ordering::Acquire,
            ).is_ok() {
                unsafe {
                    let kp = slot.key.get() as *mut u8;
                    ptr::copy_nonoverlapping(key.as_ptr(), kp, key.len());
                }
                slot.key_len.store(key.len() as u8, Ordering::Release);
                slot.value.store(value, Ordering::Relaxed);
                slot.state.store(SLOT_READY, Ordering::Release);
                return true;
            }
            std::hint::spin_loop();
            continue;
        }
        std::hint::spin_loop();
    }
    false
}

fn override_clear() {
    let Some(map) = override_map() else { return; };
    for slot in map.slots.iter() {
        slot.value.store(0, Ordering::Relaxed);
        slot.state.store(SLOT_EMPTY, Ordering::Release);
    }
}


// ── CountMap: shm-backed per-account counters + burst ring ──────
//
// Allocated once in mod_init (pre-fork); all workers + the MI process
// see the same physical pages, so `concurrent_show` returns the true
// aggregate state. Counters are atomic so multi-worker updates are
// race-free. The burst ring is protected by a per-slot spinlock
// because it's multi-word; burst contention is rare and brief.

const BURST_UNLOCKED: u8 = 0;
const BURST_LOCKED: u8 = 1;

#[repr(C)]
struct CountSlot {
    state: AtomicU8,
    key_len: AtomicU8,
    _pad: [u8; 2],
    count: AtomicU32,
    inbound_count: AtomicU32,
    outbound_count: AtomicU32,
    cooldown_until: AtomicI64,
    burst_lock: AtomicU8,
    _pad2: [u8; 7],
    // Interior-mutable burst ring, key, burst_head, burst_len.
    // key is published under the state machine; the ring + head/len
    // indices are synchronised by `burst_lock`.
    key: UnsafeCell<[u8; MAX_KEY_LEN]>,
    burst_head: UnsafeCell<u8>,
    burst_len: UnsafeCell<u8>,
    _pad3: [u8; 6],
    burst_ring: UnsafeCell<[(i64, u32); BURST_RING_SIZE]>,
}

// Safety: interior-mutable members are synchronised either by the
// state machine (key) or by burst_lock (ring + head/len).
unsafe impl Sync for CountSlot {}

#[repr(C)]
struct CountMap {
    slots: [CountSlot; MAP_CAPACITY],
}

unsafe impl Send for CountMap {}
unsafe impl Sync for CountMap {}

static COUNT_MAP: AtomicPtr<CountMap> = AtomicPtr::new(ptr::null_mut());

fn count_map() -> Option<&'static CountMap> {
    let p = COUNT_MAP.load(Ordering::Acquire);
    if p.is_null() { None } else { Some(unsafe { &*p }) }
}

#[inline]
unsafe fn count_key_bytes(slot: &CountSlot) -> &[u8] {
    let kl = slot.key_len.load(Ordering::Acquire) as usize;
    let p = slot.key.get() as *const u8;
    core::slice::from_raw_parts(p, kl.min(MAX_KEY_LEN))
}

fn count_find(key: &[u8]) -> Option<&'static CountSlot> {
    let map = count_map()?;
    if key.is_empty() || key.len() > MAX_KEY_LEN { return None; }
    let cap = MAP_CAPACITY;
    let mut idx = (fnv1a(key) as usize) % cap;
    for _ in 0..cap {
        let slot = &map.slots[idx];
        let st = slot.state.load(Ordering::Acquire);
        if st == SLOT_EMPTY { return None; }
        if st == SLOT_READY && unsafe { count_key_bytes(slot) } == key {
            return Some(slot);
        }
        idx = (idx + 1) % cap;
    }
    None
}

fn count_find_or_insert(key: &[u8]) -> Option<&'static CountSlot> {
    let map = count_map()?;
    if key.is_empty() || key.len() > MAX_KEY_LEN { return None; }
    let cap = MAP_CAPACITY;
    let mut idx = (fnv1a(key) as usize) % cap;
    for _ in 0..cap {
        let slot = &map.slots[idx];
        let st = slot.state.load(Ordering::Acquire);
        if st == SLOT_READY {
            if unsafe { count_key_bytes(slot) } == key {
                return Some(slot);
            }
            idx = (idx + 1) % cap;
            continue;
        }
        if st == SLOT_EMPTY {
            if slot.state.compare_exchange(
                SLOT_EMPTY, SLOT_WRITING, Ordering::AcqRel, Ordering::Acquire,
            ).is_ok() {
                unsafe {
                    let kp = slot.key.get() as *mut u8;
                    ptr::copy_nonoverlapping(key.as_ptr(), kp, key.len());
                }
                slot.key_len.store(key.len() as u8, Ordering::Release);
                // Counters already zero (shm was zeroed at init).
                slot.state.store(SLOT_READY, Ordering::Release);
                return Some(slot);
            }
            std::hint::spin_loop();
            continue;
        }
        std::hint::spin_loop();
    }
    None
}

fn count_get(key: &[u8]) -> u32 {
    count_find(key).map_or(0, |s| s.count.load(Ordering::Relaxed))
}

fn count_get_inbound(key: &[u8]) -> u32 {
    count_find(key).map_or(0, |s| s.inbound_count.load(Ordering::Relaxed))
}

fn count_get_outbound(key: &[u8]) -> u32 {
    count_find(key).map_or(0, |s| s.outbound_count.load(Ordering::Relaxed))
}

fn count_inc(key: &[u8]) -> u32 {
    match count_find_or_insert(key) {
        Some(s) => s.count.fetch_add(1, Ordering::Relaxed).saturating_add(1),
        None => 0,
    }
}

// Saturating atomic sub via CAS (AtomicU32 has no native saturating_sub).
fn sat_dec_u32(a: &AtomicU32) -> u32 {
    let mut cur = a.load(Ordering::Relaxed);
    loop {
        let new = cur.saturating_sub(1);
        match a.compare_exchange_weak(cur, new, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return new,
            Err(actual) => cur = actual,
        }
    }
}

fn count_dec(key: &[u8]) -> u32 {
    let Some(s) = count_find(key) else { return 0; };
    sat_dec_u32(&s.count)
}

fn count_inc_inbound(key: &[u8]) -> u32 {
    match count_find_or_insert(key) {
        Some(s) => {
            s.count.fetch_add(1, Ordering::Relaxed);
            s.inbound_count.fetch_add(1, Ordering::Relaxed).saturating_add(1)
        }
        None => 0,
    }
}

fn count_dec_inbound(key: &[u8]) -> u32 {
    let Some(s) = count_find(key) else { return 0; };
    let new = sat_dec_u32(&s.inbound_count);
    sat_dec_u32(&s.count);
    new
}

fn count_inc_outbound(key: &[u8]) -> u32 {
    match count_find_or_insert(key) {
        Some(s) => {
            s.count.fetch_add(1, Ordering::Relaxed);
            s.outbound_count.fetch_add(1, Ordering::Relaxed).saturating_add(1)
        }
        None => 0,
    }
}

fn count_dec_outbound(key: &[u8]) -> u32 {
    let Some(s) = count_find(key) else { return 0; };
    let new = sat_dec_u32(&s.outbound_count);
    sat_dec_u32(&s.count);
    new
}

fn count_set_cooldown(key: &[u8], until: i64) {
    if let Some(s) = count_find_or_insert(key) {
        s.cooldown_until.store(until, Ordering::Relaxed);
    }
}

fn count_in_cooldown(key: &[u8], now: i64) -> bool {
    count_find(key).is_some_and(|s| s.cooldown_until.load(Ordering::Relaxed) > now)
}

fn count_record_and_check_burst(key: &[u8], now: i64, threshold: u32, window_secs: i64) -> bool {
    let Some(s) = count_find_or_insert(key) else { return false; };
    while s.burst_lock.compare_exchange(
        BURST_UNLOCKED, BURST_LOCKED, Ordering::Acquire, Ordering::Relaxed,
    ).is_err() {
        std::hint::spin_loop();
    }
    // Safety: burst_lock held; exclusive access to ring / head / len.
    let current_count = s.count.load(Ordering::Relaxed);
    let head_ptr = s.burst_head.get();
    let len_ptr = s.burst_len.get();
    let ring_ptr = s.burst_ring.get();

    unsafe {
        let head = *head_ptr as usize;
        (*ring_ptr)[head] = (now, current_count);
        *head_ptr = ((head + 1) % BURST_RING_SIZE) as u8;
        if (*len_ptr as usize) < BURST_RING_SIZE {
            *len_ptr += 1;
        }

        let ring_len = *len_ptr as usize;
        let mut result = false;
        for i in 0..ring_len {
            let idx = if head >= i { head - i } else { BURST_RING_SIZE - (i - head) };
            let idx = idx % BURST_RING_SIZE;
            let (ts, old_count) = (*ring_ptr)[idx];
            if now - ts <= window_secs
                && current_count >= old_count
                && current_count - old_count >= threshold
            {
                result = true;
                break;
            }
        }
        s.burst_lock.store(BURST_UNLOCKED, Ordering::Release);
        result
    }
}

fn count_clear() {
    let Some(map) = count_map() else { return; };
    for slot in map.slots.iter() {
        slot.count.store(0, Ordering::Relaxed);
        slot.inbound_count.store(0, Ordering::Relaxed);
        slot.outbound_count.store(0, Ordering::Relaxed);
        slot.cooldown_until.store(0, Ordering::Relaxed);
        slot.state.store(SLOT_EMPTY, Ordering::Release);
    }
}

fn count_for_each<F: FnMut(&[u8], &CountSlot)>(mut f: F) {
    let Some(map) = count_map() else { return; };
    for slot in map.slots.iter() {
        if slot.state.load(Ordering::Acquire) != SLOT_READY { continue; }
        let kl = slot.key_len.load(Ordering::Acquire) as usize;
        if kl == 0 || kl > MAX_KEY_LEN { continue; }
        // Safety: state == READY implies key bytes are initialised.
        let k_bytes = unsafe {
            core::slice::from_raw_parts(slot.key.get() as *const u8, kl)
        };
        f(k_bytes, slot);
    }
}

/// Allocate the shm-backed maps. Called from mod_init (pre-fork).
fn shm_maps_init() -> bool {
    unsafe {
        if COUNT_MAP.load(Ordering::Acquire).is_null() {
            let sz = core::mem::size_of::<CountMap>() as std::ffi::c_ulong;
            let raw = opensips_rs_shm_malloc(sz) as *mut CountMap;
            if raw.is_null() {
                safe_log!(L_ERR, "shm_malloc failed for CountMap");
                return false;
            }
            // shm_malloc does not guarantee zero on all allocators.
            ptr::write_bytes(raw as *mut u8, 0, sz as usize);
            COUNT_MAP.store(raw, Ordering::Release);
        }
        if OVERRIDE_MAP.load(Ordering::Acquire).is_null() {
            let sz = core::mem::size_of::<OverrideMap>() as std::ffi::c_ulong;
            let raw = opensips_rs_shm_malloc(sz) as *mut OverrideMap;
            if raw.is_null() {
                safe_log!(L_ERR, "shm_malloc failed for OverrideMap");
                return false;
            }
            ptr::write_bytes(raw as *mut u8, 0, sz as usize);
            OVERRIDE_MAP.store(raw, Ordering::Release);
        }
    }
    true
}


// ── LimitMap: per-account limits with direction-aware fields ─────

#[repr(C)]
struct LimitSlot {
    key: [u8; MAX_KEY_LEN],
    key_len: u8,
    occupied: bool,
    _pad: [u8; 2],
    limit: u32,
    inbound_limit: u32,
    outbound_limit: u32,
}

struct LimitMap {
    slots: *mut LimitSlot,
    capacity: usize,
    len: usize,
}

unsafe impl Send for LimitMap {}

impl LimitMap {
    fn new() -> Self {
        let slots = unsafe {
            calloc(MAP_CAPACITY, core::mem::size_of::<LimitSlot>())
        } as *mut LimitSlot;
        assert!(!slots.is_null(), "calloc failed for LimitMap");
        LimitMap { slots, capacity: MAP_CAPACITY, len: 0 }
    }

    fn find_slot(&self, key: &[u8]) -> Option<*mut LimitSlot> {
        if key.is_empty() || key.len() > MAX_KEY_LEN { return None; }
        let mut idx = (fnv1a(key) as usize) % self.capacity;
        for _ in 0..self.capacity {
            let slot = unsafe { &*self.slots.add(idx) };
            if !slot.occupied { return None; }
            if slot.key_len as usize == key.len()
                && unsafe { slot.key.get_unchecked(..key.len()) } == key
            {
                return Some(unsafe { self.slots.add(idx) });
            }
            idx = (idx + 1) % self.capacity;
        }
        None
    }

    fn get_limit(&self, key: &[u8]) -> Option<u32> {
        match self.find_slot(key) {
            Some(p) => Some(unsafe { (*p).limit }),
            None => None,
        }
    }

    fn get_inbound_limit(&self, key: &[u8]) -> Option<u32> {
        match self.find_slot(key) {
            Some(p) => Some(unsafe { (*p).inbound_limit }),
            None => None,
        }
    }

    fn get_outbound_limit(&self, key: &[u8]) -> Option<u32> {
        match self.find_slot(key) {
            Some(p) => Some(unsafe { (*p).outbound_limit }),
            None => None,
        }
    }

    /// Insert with single limit (non-direction-aware CSV: "account,limit").
    fn insert(&mut self, key: &[u8], limit: u32) -> bool {
        if key.is_empty() || key.len() > MAX_KEY_LEN { return false; }
        let mut idx = (fnv1a(key) as usize) % self.capacity;
        for _ in 0..self.capacity {
            let slot = unsafe { &mut *self.slots.add(idx) };
            if !slot.occupied {
                slot.key[..key.len()].copy_from_slice(key);
                slot.key_len = key.len() as u8;
                slot.limit = limit;
                slot.inbound_limit = limit;
                slot.outbound_limit = limit;
                slot.occupied = true;
                self.len += 1;
                return true;
            }
            if slot.key_len as usize == key.len()
                && unsafe { slot.key.get_unchecked(..key.len()) } == key
            {
                slot.limit = limit;
                slot.inbound_limit = limit;
                slot.outbound_limit = limit;
                return true;
            }
            idx = (idx + 1) % self.capacity;
        }
        false
    }

    /// Insert with direction-aware limits (CSV: "account,max_inbound,max_outbound").
    fn insert_directional(&mut self, key: &[u8], inbound: u32, outbound: u32) -> bool {
        if key.is_empty() || key.len() > MAX_KEY_LEN { return false; }
        let total = inbound.saturating_add(outbound);
        let mut idx = (fnv1a(key) as usize) % self.capacity;
        for _ in 0..self.capacity {
            let slot = unsafe { &mut *self.slots.add(idx) };
            if !slot.occupied {
                slot.key[..key.len()].copy_from_slice(key);
                slot.key_len = key.len() as u8;
                slot.limit = total;
                slot.inbound_limit = inbound;
                slot.outbound_limit = outbound;
                slot.occupied = true;
                self.len += 1;
                return true;
            }
            if slot.key_len as usize == key.len()
                && unsafe { slot.key.get_unchecked(..key.len()) } == key
            {
                slot.limit = total;
                slot.inbound_limit = inbound;
                slot.outbound_limit = outbound;
                return true;
            }
            idx = (idx + 1) % self.capacity;
        }
        false
    }

    fn clear(&mut self) {
        if !self.slots.is_null() {
            unsafe {
                core::ptr::write_bytes(self.slots, 0, self.capacity);
            }
            self.len = 0;
        }
    }
}

impl Drop for LimitMap {
    fn drop(&mut self) {
        if !self.slots.is_null() {
            unsafe { free(self.slots as *mut c_void) };
            self.slots = ptr::null_mut();
        }
    }
}

// ── Simple per-worker stats (no HashMap, just named fields) ──────

struct SimpleStats {
    checked: Cell<u64>,
    allowed: Cell<u64>,
    blocked: Cell<u64>,
    incremented: Cell<u64>,
    decremented: Cell<u64>,
}

impl SimpleStats {
    fn new() -> Self {
        SimpleStats {
            checked: Cell::new(0),
            allowed: Cell::new(0),
            blocked: Cell::new(0),
            incremented: Cell::new(0),
            decremented: Cell::new(0),
        }
    }
}

// ── Stack-based byte writer (no format!, no String) ──────────────

struct ByteWriter {
    buf: [u8; 256],
    pos: usize,
}

impl ByteWriter {
    fn new() -> Self {
        ByteWriter { buf: [0u8; 256], pos: 0 }
    }

    fn push_bytes(&mut self, data: &[u8]) {
        let avail = 256 - self.pos;
        let n = if data.len() < avail { data.len() } else { avail };
        self.buf[self.pos..self.pos + n].copy_from_slice(&data[..n]);
        self.pos += n;
    }

    fn push_u32(&mut self, mut val: u32) {
        if val == 0 {
            self.push_bytes(b"0");
            return;
        }
        let mut digits = [0u8; 10];
        let mut i = 0usize;
        while val > 0 {
            digits[i] = b'0' + (val % 10) as u8;
            val /= 10;
            i += 1;
        }
        // Reverse
        while i > 0 {
            i -= 1;
            self.push_bytes(&[digits[i]]);
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.pos]
    }
}

// ── Dialog profile via C helper (avoids Rust vtable cleanup bug) ─

extern "C" {
    fn call_set_dlg_profile_c(
        msg: *mut sys::sip_msg,
        profile_name: *const c_char, profile_len: c_int,
        account: *const c_char, account_len: c_int,
    ) -> c_int;
}

/// Call set_dlg_profile(profile_name, account) via the C helper.
/// The entire find_cmd → fix_cmd → call → cleanup happens in C,
/// so the Rust compiler generates zero cleanup code.
#[inline(always)]
unsafe fn call_set_dlg_profile(msg: *mut sys::sip_msg, profile_name: &[u8], account: &[u8]) {
    call_set_dlg_profile_c(
        msg,
        profile_name.as_ptr() as *const c_char, profile_name.len() as c_int,
        account.as_ptr() as *const c_char, account.len() as c_int,
    );
}

// ── Event publishing helper ──────────────────────────────────────

fn publish_blocked_event(account: &str, count: u32, limit: u32) {
    let mut w = ByteWriter::new();
    w.push_bytes(b"BLOCKED account=");
    w.push_bytes(account.as_bytes());
    w.push_bytes(b" count=");
    w.push_u32(count);
    w.push_bytes(b" limit=");
    w.push_u32(limit);

    // Use opensips_log! which is confirmed safe (no Rust heap alloc)
    // We need to convert to &str for the macro; the ByteWriter content is valid UTF-8
    // since we only wrote ASCII bytes.
    let msg_bytes = w.as_bytes();
    // Safety: all bytes written are ASCII
    let msg_str = unsafe { core::str::from_utf8_unchecked(msg_bytes) };
    safe_log!(L_WARN, msg_str);
}

// ── Per-worker state ─────────────────────────────────────────────

struct WorkerState {
    // counts + limit_overrides live in shm (COUNT_MAP, OVERRIDE_MAP).
    // WorkerState carries only per-worker private state: the CSV-loaded
    // LimitMap (immutable after load) and local stats counters
    // (logging-only; authoritative aggregates live in STAT_* StatVars).
    limits: LimitMap,
    stats: SimpleStats,
    default_limit: u32,
    cooldown_secs: i64,
    burst_threshold: u32,
    burst_window_secs: i64,
    direction_aware: bool,
    use_dialog_profiles: bool,
    publish_events: bool,
}

thread_local! {
    static WORKER: Cell<*mut WorkerState> = const { Cell::new(ptr::null_mut()) };
}

/// Get the per-worker state, or return the given error code if not initialized.
#[inline(always)]
fn with_worker<F: FnOnce(&mut WorkerState) -> c_int>(f: F, err: c_int) -> c_int {
    WORKER.with(|cell| {
        let p = cell.get();
        if p.is_null() {
            safe_log!(L_ERR, "worker state not initialized");
            return err;
        }
        f(unsafe { &mut *p })
    })
}

/// Get the effective limit for an account: override > CSV limit > default.
fn effective_limit(state: &WorkerState, key: &[u8]) -> u32 {
    if let Some(ov) = override_get(key) {
        return ov;
    }
    state.limits.get_limit(key).unwrap_or(state.default_limit)
}

fn effective_inbound_limit(state: &WorkerState, key: &[u8]) -> u32 {
    if let Some(ov) = override_get(key) {
        return ov;
    }
    state.limits.get_inbound_limit(key).unwrap_or(state.default_limit)
}

fn effective_outbound_limit(state: &WorkerState, key: &[u8]) -> u32 {
    if let Some(ov) = override_get(key) {
        return ov;
    }
    state.limits.get_outbound_limit(key).unwrap_or(state.default_limit)
}

// ── CSV file loading (libc I/O, no Rust allocations) ─────────────

fn load_limits_file(path: &[u8], map: &mut LimitMap, direction_aware: bool) -> c_int {
    let mut path_buf = [0u8; 256];
    if path.len() >= path_buf.len() { return -1; }
    path_buf[..path.len()].copy_from_slice(path);
    path_buf[path.len()] = 0;

    let fp = unsafe { fopen(path_buf.as_ptr() as *const c_char, b"r\0".as_ptr() as *const c_char) };
    if fp.is_null() { return -1; }

    let mut line_buf = [0u8; 256];
    let mut count = 0i32;

    loop {
        let ret = unsafe {
            fgets(line_buf.as_mut_ptr() as *mut c_char, line_buf.len() as c_int, fp)
        };
        if ret.is_null() { break; }

        let len = line_buf.iter().position(|&b| b == b'\n' || b == 0).unwrap_or(line_buf.len());
        let line = &line_buf[..len];

        if line.is_empty() || line[0] == b'#' { continue; }

        // Find first comma
        let first_comma = match line.iter().position(|&b| b == b',') {
            Some(p) => p,
            None => continue,
        };
        let account = trim_bytes(&line[..first_comma]);
        if account.is_empty() { continue; }

        let rest = &line[first_comma + 1..];

        if direction_aware {
            // Parse "account,max_inbound,max_outbound"
            if let Some(second_comma) = rest.iter().position(|&b| b == b',') {
                let inbound_str = trim_bytes(&rest[..second_comma]);
                let outbound_str = trim_bytes(&rest[second_comma + 1..]);
                if let (Some(inbound), Some(outbound)) = (parse_u32(inbound_str), parse_u32(outbound_str)) {
                    map.insert_directional(account, inbound, outbound);
                    count += 1;
                }
            } else {
                // Fallback: single limit even in direction-aware mode
                let limit_str = trim_bytes(rest);
                if let Some(limit) = parse_u32(limit_str) {
                    map.insert(account, limit);
                    count += 1;
                }
            }
        } else {
            // Parse "account,limit"
            let limit_str = trim_bytes(rest);
            if let Some(limit) = parse_u32(limit_str) {
                map.insert(account, limit);
                count += 1;
            }
        }
    }
    unsafe { fclose(fp) };
    count
}

fn trim_bytes(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&c| c != b' ' && c != b'\t').unwrap_or(b.len());
    let end = b.iter().rposition(|&c| c != b' ' && c != b'\t' && c != b'\r').map_or(start, |e| e + 1);
    if start >= end { &[] } else { &b[start..end] }
}

fn parse_u32(b: &[u8]) -> Option<u32> {
    let mut val: u32 = 0;
    if b.is_empty() { return None; }
    for &c in b {
        if c < b'0' || c > b'9' { return None; }
        val = val.checked_mul(10)?.checked_add((c - b'0') as u32)?;
    }
    Some(val)
}

fn now_secs() -> i64 {
    unsafe { time(ptr::null_mut()) }
}

// ── Module lifecycle ─────────────────────────────────────────────

unsafe extern "C" fn mod_init() -> c_int {
    let file = match unsafe { LIMITS_FILE.get_value() } {
        Some(f) => f,
        None => {
            safe_log!(L_ERR, "limits_file parameter is required");
            return -1;
        }
    };
    let default = DEFAULT_LIMIT.get();

    // Allocate shm-backed CountMap + OverrideMap BEFORE fork so every
    // worker + MI process sees the same pages; otherwise the MI process
    // reads its own empty per-process copy.
    if !shm_maps_init() {
        safe_log!(L_ERR, "shm_maps_init failed — aborting module init");
        return -1;
    }

    safe_log!(L_INFO, "module initialized");
    safe_log!(L_INFO, "  limits_file=", file);
    safe_log!(L_INFO, "  default_limit=", default);
    safe_log!(L_INFO, "  auto_track=", AUTO_TRACK.get());
    safe_log!(L_INFO, "  account_var=", unsafe { ACCOUNT_VAR.get_value() }.unwrap_or("$fU"));
    safe_log!(L_INFO, "  use_dialog_profiles=", USE_DIALOG_PROFILES.get());
    safe_log!(L_INFO, "  profile_name=", unsafe { PROFILE_NAME.get_value() }.unwrap_or("concurrent_calls"));
    safe_log!(L_INFO, "  direction_aware=", DIRECTION_AWARE.get());
    safe_log!(L_INFO, "  cooldown_secs=", COOLDOWN_SECS.get());
    safe_log!(L_INFO, "  burst_threshold=", BURST_THRESHOLD.get());
    safe_log!(L_INFO, "  burst_window_secs=", BURST_WINDOW_SECS.get());
    safe_log!(L_INFO, "  publish_events=", PUBLISH_EVENTS.get());
    0
}

unsafe extern "C" fn mod_child_init(rank: c_int) -> c_int {
    if rank < 1 && rank != -2 { return 0; }

    let file = match unsafe { LIMITS_FILE.get_value() } {
        Some(f) => f,
        None => return -1,
    };
    let default_limit = DEFAULT_LIMIT.get().max(0) as u32;
    let direction_aware = DIRECTION_AWARE.get() != 0;

    // Allocate worker state with libc
    let state_ptr = unsafe {
        calloc(1, core::mem::size_of::<WorkerState>()) as *mut WorkerState
    };
    if state_ptr.is_null() { return -1; }

    let state = unsafe { &mut *state_ptr };
    state.limits = LimitMap::new();
    state.stats = SimpleStats::new();
    state.default_limit = default_limit;
    state.cooldown_secs = COOLDOWN_SECS.get().max(0) as i64;
    state.burst_threshold = BURST_THRESHOLD.get().max(0) as u32;
    state.burst_window_secs = BURST_WINDOW_SECS.get().max(0) as i64;
    state.direction_aware = direction_aware;
    state.use_dialog_profiles = USE_DIALOG_PROFILES.get() != 0;
    state.publish_events = PUBLISH_EVENTS.get() != 0;

    // Load limits from CSV
    let entry_count = load_limits_file(file.as_bytes(), &mut state.limits, direction_aware);
    if entry_count < 0 {
        safe_log!(L_ERR, "failed to load limits file: ", file);
    }

    WORKER.with(|cell| cell.set(state_ptr));

    safe_log!(L_DBG, "worker ", rank as i32, " loaded ", entry_count.max(0), " account limits");
    0
}

unsafe extern "C" fn mod_destroy() {
    safe_log!(L_INFO, "module destroyed");
}

// ── Script function: check_concurrent(account) ──────────────────

unsafe extern "C" fn w_check_concurrent(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let key = account.as_bytes();

    with_worker(|state| {
        state.stats.checked.set(state.stats.checked.get() + 1);
        if let Some(s) = StatVar::from_raw(STAT_CHECKED.load(Ordering::Relaxed)) { s.inc(); }

        // Cooldown check
        if state.cooldown_secs > 0 {
            let now = now_secs();
            if count_in_cooldown(key, now) {
                state.stats.blocked.set(state.stats.blocked.get() + 1);
                if let Some(s) = StatVar::from_raw(STAT_BLOCKED.load(Ordering::Relaxed)) { s.inc(); }
                safe_log!(L_DBG, "check ", account, ": in cooldown, auto-rejected");
                return -1;
            }
        }

        let count = count_get(key);
        let limit = effective_limit(state, key);

        if count < limit {
            state.stats.allowed.set(state.stats.allowed.get() + 1);
            if let Some(s) = StatVar::from_raw(STAT_ALLOWED.load(Ordering::Relaxed)) { s.inc(); }
            1
        } else {
            state.stats.blocked.set(state.stats.blocked.get() + 1);
            if let Some(s) = StatVar::from_raw(STAT_BLOCKED.load(Ordering::Relaxed)) { s.inc(); }

            // Set cooldown
            if state.cooldown_secs > 0 {
                let now = now_secs();
                count_set_cooldown(key, now + state.cooldown_secs);
            }

            // Publish event
            if state.publish_events {
                publish_blocked_event(account, count, limit);
            }

            -1
        }
    }, -2)
}

// ── Script function: check_concurrent_inbound(account) ───────────

unsafe extern "C" fn w_check_concurrent_inbound(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let key = account.as_bytes();

    with_worker(|state| {
        state.stats.checked.set(state.stats.checked.get() + 1);
        if let Some(s) = StatVar::from_raw(STAT_CHECKED.load(Ordering::Relaxed)) { s.inc(); }

        if !state.direction_aware {
            // Fall back to total count check
            let count = count_get(key);
            let limit = effective_limit(state, key);
            return if count < limit { 1 } else { -1 };
        }

        // Cooldown check
        if state.cooldown_secs > 0 && count_in_cooldown(key, now_secs()) {
            state.stats.blocked.set(state.stats.blocked.get() + 1);
            if let Some(s) = StatVar::from_raw(STAT_BLOCKED.load(Ordering::Relaxed)) { s.inc(); }
            return -1;
        }

        let count = count_get_inbound(key);
        let limit = effective_inbound_limit(state, key);

        if count < limit {
            state.stats.allowed.set(state.stats.allowed.get() + 1);
            if let Some(s) = StatVar::from_raw(STAT_ALLOWED.load(Ordering::Relaxed)) { s.inc(); }
            1
        } else {
            state.stats.blocked.set(state.stats.blocked.get() + 1);
            if let Some(s) = StatVar::from_raw(STAT_BLOCKED.load(Ordering::Relaxed)) { s.inc(); }

            if state.cooldown_secs > 0 {
                let now = now_secs();
                count_set_cooldown(key, now + state.cooldown_secs);
            }
            if state.publish_events {
                publish_blocked_event(account, count, limit);
            }
            -1
        }
    }, -2)
}

// ── Script function: check_concurrent_outbound(account) ──────────

unsafe extern "C" fn w_check_concurrent_outbound(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let key = account.as_bytes();

    with_worker(|state| {
        state.stats.checked.set(state.stats.checked.get() + 1);
        if let Some(s) = StatVar::from_raw(STAT_CHECKED.load(Ordering::Relaxed)) { s.inc(); }

        if !state.direction_aware {
            let count = count_get(key);
            let limit = effective_limit(state, key);
            return if count < limit { 1 } else { -1 };
        }

        if state.cooldown_secs > 0 && count_in_cooldown(key, now_secs()) {
            state.stats.blocked.set(state.stats.blocked.get() + 1);
            if let Some(s) = StatVar::from_raw(STAT_BLOCKED.load(Ordering::Relaxed)) { s.inc(); }
            return -1;
        }

        let count = count_get_outbound(key);
        let limit = effective_outbound_limit(state, key);

        if count < limit {
            state.stats.allowed.set(state.stats.allowed.get() + 1);
            if let Some(s) = StatVar::from_raw(STAT_ALLOWED.load(Ordering::Relaxed)) { s.inc(); }
            1
        } else {
            state.stats.blocked.set(state.stats.blocked.get() + 1);
            if let Some(s) = StatVar::from_raw(STAT_BLOCKED.load(Ordering::Relaxed)) { s.inc(); }

            if state.cooldown_secs > 0 {
                let now = now_secs();
                count_set_cooldown(key, now + state.cooldown_secs);
            }
            if state.publish_events {
                publish_blocked_event(account, count, limit);
            }
            -1
        }
    }, -2)
}

// ── Script function: concurrent_inc(account) ─────────────────────

unsafe extern "C" fn w_concurrent_inc(
    msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
        Ok(s) => s,
        Err(_) => return -2,
    };

    // Read dialog profile settings before entering with_worker
    // (cannot borrow static params inside the closure that borrows state)
    let do_dlg_profile = USE_DIALOG_PROFILES.get() != 0;

    with_worker(|state| {
        let new_count = count_inc(account.as_bytes());
        state.stats.incremented.set(state.stats.incremented.get() + 1);
        if let Some(s) = StatVar::from_raw(STAT_ACTIVE_CALLS.load(Ordering::Relaxed)) { s.inc(); }
        safe_log!(L_DBG, "inc ", account, ": now ", new_count);

        // Dialog profile integration via C helper (avoids Rust vtable bug)
        if do_dlg_profile {
            let profile_name = unsafe { PROFILE_NAME.get_value() }
                .unwrap_or("concurrent_calls");
            unsafe {
                call_set_dlg_profile(msg, profile_name.as_bytes(), account.as_bytes());
            }
        }

        1
    }, -2)
}

// ── Script function: concurrent_dec(account) ─────────────────────

unsafe extern "C" fn w_concurrent_dec(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
        Ok(s) => s,
        Err(_) => return -2,
    };

    with_worker(|state| {
        // Check pre-dec count before firing the stat-var decrement. If
        // there's no active count (e.g. BYE on a dialog rejected before
        // inc), skip the stat update to avoid underflowing the u64
        // active_calls stat to UINT64_MAX.
        let had_active = count_get(account.as_bytes()) > 0;
        let new_count = count_dec(account.as_bytes());
        if had_active {
            state.stats.decremented.set(state.stats.decremented.get() + 1);
            if let Some(s) = StatVar::from_raw(STAT_ACTIVE_CALLS.load(Ordering::Relaxed)) {
                s.update(-1);
            }
        }
        safe_log!(L_DBG, "dec ", account, ": now ", new_count);
        1
    }, -2)
}

// ── Script function: concurrent_reload() ─────────────────────────

unsafe extern "C" fn w_concurrent_reload(
    _msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    let file = match unsafe { LIMITS_FILE.get_value() } {
        Some(f) => f,
        None => return -1,
    };
    with_worker(|state| {
        state.limits.clear();
        let n = load_limits_file(file.as_bytes(), &mut state.limits, state.direction_aware);
        safe_log!(L_INFO, "reloaded ", n, " limits from ", file);
        1
    }, -1)
}

// ── Script function: concurrent_stats() ──────────────────────────

unsafe extern "C" fn w_concurrent_stats(
    _msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    with_worker(|state| {
        safe_log!(L_INFO,
            "stats: checked=", state.stats.checked.get(),
            " allowed=", state.stats.allowed.get(),
            " blocked=", state.stats.blocked.get(),
            " inc=", state.stats.incremented.get(),
            " dec=", state.stats.decremented.get());
        1
    }, -2)
}

// ── Script function: check_burst(account) ────────────────────────

unsafe extern "C" fn w_check_burst(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let key = account.as_bytes();

    with_worker(|state| {
        if state.burst_threshold == 0 {
            // Burst detection disabled
            return 1;
        }

        let now = now_secs();
        let is_burst = count_record_and_check_burst(
            key, now, state.burst_threshold, state.burst_window_secs,
        );

        if is_burst {
            safe_log!(L_WARN, "burst detected for ", account, ": threshold=", state.burst_threshold, " window=", state.burst_window_secs, "s");
            if state.publish_events {
                let mut w = ByteWriter::new();
                w.push_bytes(b"BURST account=");
                w.push_bytes(account.as_bytes());
                w.push_bytes(b" threshold=");
                w.push_u32(state.burst_threshold);
                let msg_str = unsafe { core::str::from_utf8_unchecked(w.as_bytes()) };
                safe_log!(L_WARN, msg_str);
            }
            -1
        } else {
            1
        }
    }, -2)
}

// ── Script function: concurrent_status(account) ──────────────────

unsafe extern "C" fn w_concurrent_status(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let key = account.as_bytes();

    with_worker(|state| {
        let count = count_get(key);
        let limit = effective_limit(state, key);
        if state.direction_aware {
            let inb = count_get_inbound(key);
            let outb = count_get_outbound(key);
            safe_log!(L_INFO, "status ", account, ": count=", count, "/", limit, " in=", inb, " out=", outb);
        } else {
            safe_log!(L_INFO, "status ", account, ": count=", count, "/", limit);
        }
        1
    }, -2)
}

// ── Script function: concurrent_set_limit(account, limit) ────────

unsafe extern "C" fn w_concurrent_set_limit(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let limit_str = match unsafe { <&str as CommandFunctionParam>::from_raw(p1) } {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let limit = match parse_u32(limit_str.as_bytes()) {
        Some(v) => v,
        None => return -2,
    };

    with_worker(|_state| {
        override_insert(account.as_bytes(), limit);
        safe_log!(L_INFO, "set override limit for ", account, ": ", limit);
        1
    }, -2)
}

// ── Script function: concurrent_prometheus() ─────────────────────

unsafe extern "C" fn w_concurrent_prometheus(
    _msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    // Prometheus metrics are exposed via the native stat framework
    1
}

// ── MI commands ──────────────────────────────────────────────────

use rust_common::mi_resp::{mi_ok, mi_error, MiObject};

// FFI for MI string params - declared locally to avoid using the wrapper
// that allocates a String.
extern "C" {
    fn try_get_mi_string_param(
        params: *const sys::mi_params_t, name: *mut c_char,
        value: *mut *mut c_char, value_len: *mut c_int,
    ) -> c_int;
}

/// Extract an MI string param as a &[u8] without any Rust heap allocation.
unsafe fn mi_get_str_param<'a>(params: *const sys::mi_params_t, name: &str) -> Option<&'a [u8]> {
    let mut val: *mut c_char = ptr::null_mut();
    let mut val_len: c_int = 0;
    let rc = try_get_mi_string_param(
        params as *const _,
        name.as_ptr() as *mut c_char,
        &mut val,
        &mut val_len,
    );
    if rc != 0 || val.is_null() || val_len <= 0 {
        return None;
    }
    Some(core::slice::from_raw_parts(val as *const u8, val_len as usize))
}

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

#[allow(unused_macros)]
macro_rules! mi_entry_params {
    ($name:expr, $help:expr, $handler:expr, $params:expr) => {
        sys::mi_export_ {
            name: cstr_lit!($name) as *mut _,
            help: cstr_lit!($help) as *mut _,
            flags: 0,
            init_f: None,
            recipes: {
                let mut r = [NULL_RECIPE; 48];
                r[0].cmd = Some($handler);
                r[0].params = $params;
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

unsafe extern "C" fn mi_show(
    _params: *const sys::mi_params_t,
    _async_hdl: *mut sys::mi_handler,
) -> *mut sys::mi_response_t {
    // Build JSON response with all active accounts
    let resp = MiObject::new();
    let resp = match resp {
        Some(r) => r,
        None => return mi_ok() as *mut _,
    };

    if let Some(accounts_arr) = resp.add_array("accounts") {
        // CSV limits live in per-worker LimitMap (loaded identically by
        // the MI process); fall back to DEFAULT_LIMIT if WorkerState is
        // absent (defensive — shouldn't happen for rank == -2).
        let worker_ptr = WORKER.with(|cell| cell.get());

        count_for_each(|key_bytes, slot| {
            let cnt  = slot.count.load(Ordering::Relaxed);
            let inb  = slot.inbound_count.load(Ordering::Relaxed);
            let outb = slot.outbound_count.load(Ordering::Relaxed);
            let cd   = slot.cooldown_until.load(Ordering::Relaxed);
            if cnt == 0 && inb == 0 && outb == 0 && cd == 0 {
                // Skip slots with no live data so output stays tidy
                // (the slot may be a tombstone from a prior decrement).
                return;
            }

            let key_str = core::str::from_utf8(key_bytes).unwrap_or("?");
            if let Some(entry) = accounts_arr.add_object("") {
                entry.add_str("account", key_str);
                entry.add_num("count", cnt as f64);
                entry.add_num("inbound", inb as f64);
                entry.add_num("outbound", outb as f64);

                let limit = if let Some(ov) = override_get(key_bytes) {
                    ov
                } else if !worker_ptr.is_null() {
                    let state = &*worker_ptr;
                    state.limits.get_limit(key_bytes).unwrap_or(state.default_limit)
                } else {
                    DEFAULT_LIMIT.get().max(0) as u32
                };
                entry.add_num("limit", limit as f64);

                if cd > 0 {
                    entry.add_num("cooldown_until", cd as f64);
                }
            }
        });
    }

    resp.into_raw() as *mut _
}

unsafe extern "C" fn mi_override(
    params: *const sys::mi_params_t,
    _async_hdl: *mut sys::mi_handler,
) -> *mut sys::mi_response_t {
    let account = match mi_get_str_param(params, "account\0") {
        Some(a) => a,
        None => return mi_error(400, "missing account parameter") as *mut _,
    };
    let limit_bytes = match mi_get_str_param(params, "limit\0") {
        Some(l) => l,
        None => return mi_error(400, "missing limit parameter") as *mut _,
    };
    let limit = match parse_u32(limit_bytes) {
        Some(v) => v,
        None => return mi_error(400, "invalid limit value") as *mut _,
    };

    // Write to shm-backed OverrideMap so every worker picks up the new
    // override on its next check_concurrent / effective_limit call.
    override_insert(account, limit);
    mi_ok() as *mut _
}

unsafe extern "C" fn mi_reset(
    _params: *const sys::mi_params_t,
    _async_hdl: *mut sys::mi_handler,
) -> *mut sys::mi_response_t {
    // Shm-backed clear — visible to every worker immediately.
    count_clear();
    override_clear();
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

static CMDS: SyncArray<sys::cmd_export_, 12> = SyncArray([
    sys::cmd_export_ { name: cstr_lit!("check_concurrent"), function: Some(w_check_concurrent), params: ONE_STR_PARAM, flags: opensips_rs::route::REQ_FAIL_ONREPLY },
    sys::cmd_export_ { name: cstr_lit!("concurrent_inc"), function: Some(w_concurrent_inc), params: ONE_STR_PARAM, flags: opensips_rs::route::REQ_FAIL_ONREPLY },
    sys::cmd_export_ { name: cstr_lit!("concurrent_dec"), function: Some(w_concurrent_dec), params: ONE_STR_PARAM, flags: opensips_rs::route::REQ_FAIL_ONREPLY },
    sys::cmd_export_ { name: cstr_lit!("concurrent_reload"), function: Some(w_concurrent_reload), params: EMPTY_PARAMS, flags: opensips_rs::route::REQ_FAIL_ONREPLY },
    sys::cmd_export_ { name: cstr_lit!("concurrent_stats"), function: Some(w_concurrent_stats), params: EMPTY_PARAMS, flags: opensips_rs::route::REQ_FAIL_ONREPLY },
    sys::cmd_export_ { name: cstr_lit!("check_burst"), function: Some(w_check_burst), params: ONE_STR_PARAM, flags: opensips_rs::route::REQ_FAIL_ONREPLY },
    sys::cmd_export_ { name: cstr_lit!("concurrent_status"), function: Some(w_concurrent_status), params: ONE_STR_PARAM, flags: opensips_rs::route::REQ_FAIL_ONREPLY },
    sys::cmd_export_ { name: cstr_lit!("concurrent_set_limit"), function: Some(w_concurrent_set_limit), params: TWO_STR_PARAMS, flags: opensips_rs::route::REQ_FAIL_ONREPLY },
    sys::cmd_export_ { name: cstr_lit!("check_concurrent_inbound"), function: Some(w_check_concurrent_inbound), params: ONE_STR_PARAM, flags: opensips_rs::route::REQ_FAIL_ONREPLY },
    sys::cmd_export_ { name: cstr_lit!("check_concurrent_outbound"), function: Some(w_check_concurrent_outbound), params: ONE_STR_PARAM, flags: opensips_rs::route::REQ_FAIL_ONREPLY },
    sys::cmd_export_ { name: cstr_lit!("concurrent_prometheus"), function: Some(w_concurrent_prometheus), params: EMPTY_PARAMS, flags: opensips_rs::route::REQ_FAIL_ONREPLY },
    sys::cmd_export_ { name: ptr::null(), function: None, params: EMPTY_PARAMS, flags: 0 },
]);

static ACMDS: SyncArray<sys::acmd_export_, 1> = SyncArray([
    sys::acmd_export_ { name: ptr::null(), function: None, params: EMPTY_PARAMS },
]);

static PARAMS: SyncArray<sys::param_export_, 12> = SyncArray([
    sys::param_export_ { name: cstr_lit!("limits_file"), type_: opensips_rs::param_type::STR, param_pointer: LIMITS_FILE.as_ptr() },
    sys::param_export_ { name: cstr_lit!("default_limit"), type_: opensips_rs::param_type::INT, param_pointer: DEFAULT_LIMIT.as_ptr() },
    sys::param_export_ { name: cstr_lit!("auto_track"), type_: opensips_rs::param_type::INT, param_pointer: AUTO_TRACK.as_ptr() },
    sys::param_export_ { name: cstr_lit!("account_var"), type_: opensips_rs::param_type::STR, param_pointer: ACCOUNT_VAR.as_ptr() },
    sys::param_export_ { name: cstr_lit!("use_dialog_profiles"), type_: opensips_rs::param_type::INT, param_pointer: USE_DIALOG_PROFILES.as_ptr() },
    sys::param_export_ { name: cstr_lit!("profile_name"), type_: opensips_rs::param_type::STR, param_pointer: PROFILE_NAME.as_ptr() },
    sys::param_export_ { name: cstr_lit!("direction_aware"), type_: opensips_rs::param_type::INT, param_pointer: DIRECTION_AWARE.as_ptr() },
    sys::param_export_ { name: cstr_lit!("cooldown_secs"), type_: opensips_rs::param_type::INT, param_pointer: COOLDOWN_SECS.as_ptr() },
    sys::param_export_ { name: cstr_lit!("burst_threshold"), type_: opensips_rs::param_type::INT, param_pointer: BURST_THRESHOLD.as_ptr() },
    sys::param_export_ { name: cstr_lit!("burst_window_secs"), type_: opensips_rs::param_type::INT, param_pointer: BURST_WINDOW_SECS.as_ptr() },
    sys::param_export_ { name: cstr_lit!("publish_events"), type_: opensips_rs::param_type::INT, param_pointer: PUBLISH_EVENTS.as_ptr() },
    sys::param_export_ { name: ptr::null(), type_: 0, param_pointer: ptr::null_mut() },
]);

static MI_CMDS: SyncArray<sys::mi_export_, 4> = SyncArray([
    mi_entry!("concurrent_show", "Show concurrent call accounts", mi_show),
    // concurrent_override takes two named params (account, limit) — declare them
    // on the recipe so the MI dispatcher accepts the call. Without the params
    // array, the dispatcher matches the zero-param recipe and rejects every
    // call with "Too few or too many parameters".
    mi_entry_params!("concurrent_override", "Set temporary limit override", mi_override,
        {
            let mut p: [*mut c_char; 20] = [ptr::null_mut(); 20];
            p[0] = cstr_lit!("account") as *mut _;
            p[1] = cstr_lit!("limit") as *mut _;
            p
        }),
    mi_entry!("concurrent_reset", "Reset call counts", mi_reset),
    NULL_MI,
]);

static MOD_STATS: SyncArray<sys::stat_export_, 5> = SyncArray([
    sys::stat_export_ { name: cstr_lit!("concurrent_checked") as *mut _, flags: 0, stat_pointer: &STAT_CHECKED as *const _ as *mut _ },
    sys::stat_export_ { name: cstr_lit!("concurrent_allowed") as *mut _, flags: 0, stat_pointer: &STAT_ALLOWED as *const _ as *mut _ },
    sys::stat_export_ { name: cstr_lit!("concurrent_blocked") as *mut _, flags: 0, stat_pointer: &STAT_BLOCKED as *const _ as *mut _ },
    sys::stat_export_ { name: cstr_lit!("concurrent_active") as *mut _, flags: opensips_rs::stat_flags::NO_RESET, stat_pointer: &STAT_ACTIVE_CALLS as *const _ as *mut _ },
    sys::stat_export_ { name: ptr::null_mut(), flags: 0, stat_pointer: ptr::null_mut() },
]);

static DEPS: opensips_rs::ffi::DepExportConcrete<1> = opensips_rs::ffi::DepExportConcrete {
    md: unsafe { std::mem::zeroed() },
    mpd: unsafe { std::mem::zeroed() },
};

#[no_mangle]
pub static exports: sys::module_exports = sys::module_exports {
    name: cstr_lit!("rust_concurrent_calls"),
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

// ── Unit tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trim_bytes_handles_empty_and_whitespace() {
        assert_eq!(trim_bytes(b""), b"");
        assert_eq!(trim_bytes(b"   "), b"");
        assert_eq!(trim_bytes(b"\t\t"), b"");
        assert_eq!(trim_bytes(b"  alice  "), b"alice");
        assert_eq!(trim_bytes(b"alice\r"), b"alice");
        assert_eq!(trim_bytes(b"  alice\t\r"), b"alice");
    }

    #[test]
    fn trim_bytes_preserves_interior_whitespace() {
        // Only leading/trailing are stripped; interior spaces remain.
        assert_eq!(trim_bytes(b"  alice bob  "), b"alice bob");
    }

    #[test]
    fn parse_u32_accepts_digits_only() {
        assert_eq!(parse_u32(b"0"), Some(0));
        assert_eq!(parse_u32(b"5"), Some(5));
        assert_eq!(parse_u32(b"100"), Some(100));
        assert_eq!(parse_u32(b"4294967295"), Some(u32::MAX));
    }

    #[test]
    fn parse_u32_rejects_invalid() {
        assert_eq!(parse_u32(b""), None);
        assert_eq!(parse_u32(b"abc"), None);
        assert_eq!(parse_u32(b"-1"), None);
        assert_eq!(parse_u32(b"1.5"), None);
        assert_eq!(parse_u32(b" 5"), None);  // caller must trim first
        assert_eq!(parse_u32(b"5 "), None);
    }

    #[test]
    fn parse_u32_rejects_overflow() {
        // u32::MAX is 4_294_967_295 → one more digit overflows.
        assert_eq!(parse_u32(b"4294967296"), None);
        assert_eq!(parse_u32(b"99999999999"), None);
    }

    #[test]
    fn fnv1a_is_deterministic() {
        assert_eq!(fnv1a(b""), fnv1a(b""));
        assert_eq!(fnv1a(b"alice"), fnv1a(b"alice"));
    }

    #[test]
    fn fnv1a_distinguishes_inputs() {
        // Collision-free for this small set — sanity check, not a hash quality test.
        assert_ne!(fnv1a(b"alice"), fnv1a(b"bob"));
        assert_ne!(fnv1a(b"alice"), fnv1a(b"Alice"));
        assert_ne!(fnv1a(b"alice"), fnv1a(b""));
    }
}
