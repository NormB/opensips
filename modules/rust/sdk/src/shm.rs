//! Shared memory primitives for cross-worker state.
//!
//! `OpenSIPS` workers are separate processes (fork model). After fork,
//! each worker has its own private memory. To share state across workers,
//! data must live in `OpenSIPS` shared memory (shm), which is mapped into
//! all worker processes at the same virtual address.
//!
//! # Why Atomics Work Across Processes
//!
//! `AtomicI64::fetch_add()` compiles to a single `lock xadd` instruction
//! on x86-64. This instruction operates on the *physical* memory page,
//! not the process's virtual address space. Since all workers map the
//! same shared memory page, the atomic instruction is truly atomic across
//! all workers — no locks, no syscalls, just one CPU instruction.
//!
//! # When to Use What
//!
//! | Pattern | Memory | Scope | Atomicity | Use case |
//! |---------|--------|-------|-----------|----------|
//! | `thread_local!` | private | per-worker | N/A | rate limiters, caches |
//! | `$shv()` | shared | all workers | NOT atomic | simple flags, config |
//! | `SharedAtomicCounter` | shared | all workers | **atomic** | counters, statistics |
//!
//! # Lifecycle
//!
//! Allocate during `mod_init` (before fork). After fork, all workers
//! inherit the pointer and share the same physical counter. On module
//! destroy, the counter is freed from shared memory via `Drop`.

use std::ffi::c_void;
use std::sync::atomic::{AtomicI64, Ordering};

extern "C" {
    fn opensips_rs_shm_malloc(size: std::ffi::c_ulong) -> *mut c_void;
    fn opensips_rs_shm_free(p: *mut c_void);
}

/// An atomic 64-bit counter in `OpenSIPS` shared memory.
///
/// Visible to ALL worker processes. Uses hardware atomic instructions —
/// no locks needed, no syscalls, just a single CPU instruction per operation.
///
/// # Example (compiled-in module)
///
/// ```ignore
/// use opensips_rs::shm::SharedAtomicCounter;
/// use std::sync::OnceLock;
///
/// static COUNTER: OnceLock<SharedAtomicCounter> = OnceLock::new();
///
/// // In mod_init (before fork):
/// COUNTER.set(SharedAtomicCounter::new().expect("shm alloc failed"));
///
/// // In any worker (after fork):
/// let count = COUNTER.get().unwrap().increment(); // truly atomic
/// ```
pub struct SharedAtomicCounter {
    ptr: *mut AtomicI64,
}

// Safety: The counter lives in OpenSIPS shared memory, which is mapped into
// all worker processes. AtomicI64 operations use CPU-level atomic instructions
// that are safe across processes sharing the same physical memory page.
unsafe impl Send for SharedAtomicCounter {}
unsafe impl Sync for SharedAtomicCounter {}

impl SharedAtomicCounter {
    /// Allocate a new counter in shared memory, initialized to 0.
    ///
    /// Must be called before fork (during `mod_init`). After fork,
    /// all workers share the same physical counter.
    ///
    /// Returns `None` if shared memory allocation fails.
    pub fn new() -> Option<Self> {
        unsafe {
            let size = std::mem::size_of::<AtomicI64>() as std::ffi::c_ulong;
            let ptr = opensips_rs_shm_malloc(size) as *mut AtomicI64;
            if ptr.is_null() {
                return None;
            }
            // Write the initial AtomicI64 value into shared memory.
            // This is safe because we're the only accessor before fork.
            ptr.write(AtomicI64::new(0));
            Some(Self { ptr })
        }
    }

    /// Atomically increment by 1 and return the **new** value.
    ///
    /// Compiles to a single `lock xadd` instruction on x86-64.
    /// Safe across all worker processes.
    #[inline]
    pub fn increment(&self) -> i64 {
        unsafe { (*self.ptr).fetch_add(1, Ordering::Relaxed) + 1 }
    }

    /// Atomically add `n` and return the **new** value.
    #[inline]
    pub fn add(&self, n: i64) -> i64 {
        unsafe { (*self.ptr).fetch_add(n, Ordering::Relaxed) + n }
    }

    /// Read the current value (atomic load).
    #[inline]
    pub fn get(&self) -> i64 {
        unsafe { (*self.ptr).load(Ordering::Relaxed) }
    }

    /// Atomically reset to 0 and return the old value.
    #[inline]
    pub fn reset(&self) -> i64 {
        unsafe { (*self.ptr).swap(0, Ordering::Relaxed) }
    }
}

impl Drop for SharedAtomicCounter {
    fn drop(&mut self) {
        unsafe { opensips_rs_shm_free(self.ptr as *mut c_void); }
    }
}
