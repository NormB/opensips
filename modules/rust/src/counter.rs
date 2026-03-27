//! Atomic cross-worker request counter using shared memory.
//!
//! Demonstrates the pattern that is impossible in Python/Lua/Perl modules:
//! a truly atomic counter shared across all `OpenSIPS` worker processes,
//! using hardware atomic instructions with zero locking overhead.
//!
//! # How It Works
//!
//! 1. During `mod_init` (before fork), we allocate an `AtomicI64` in
//!    OpenSIPS shared memory via `shm_malloc`.
//! 2. After fork, all workers inherit the pointer to the same physical
//!    memory page.
//! 3. `fetch_add(1, Relaxed)` compiles to `lock xadd` on x86-64 — a single
//!    CPU instruction that atomically increments the counter across all
//!    processes. No locks, no syscalls.
//!
//! # Why Not $shv()?
//!
//! `$shv()` shared variables (from cfgutils) support read and write, but
//! the read → increment → write sequence is NOT atomic:
//!
//!   Worker A reads: 42          Worker B reads: 42
//!   Worker A writes: 43         Worker B writes: 43  ← lost one count!
//!
//! With `AtomicI64::fetch_add`, the CPU guarantees the increment is atomic:
//!
//!   Worker A: fetch_add(1) → 43    Worker B: fetch_add(1) → 44  ← correct!
//!
//! # Rust Concepts Demonstrated
//!
//! - **`OnceLock<T>`**: write-once container for the counter. Initialized
//!   during `mod_init`, then immutably shared.
//! - **`AtomicI64`**: lock-free atomic integer from `std::sync::atomic`.
//!   Operations map directly to CPU atomic instructions.
//! - **`Ordering::Relaxed`**: the weakest memory ordering. Sufficient for
//!   a simple counter because we only need the increment to be atomic,
//!   not to synchronize other memory accesses.
//! - **`SharedAtomicCounter`**: SDK type that allocates the atomic in
//!   OpenSIPS shared memory so all forked workers share it.

use opensips_rs::shm::SharedAtomicCounter;
use opensips_rs::{opensips_log, SipMessage};
use std::ffi::c_int;
use std::sync::OnceLock;

/// Global atomic counter. Allocated in shm during mod_init, shared
/// across all workers after fork. OnceLock ensures one-time init.
static REQUEST_COUNTER: OnceLock<SharedAtomicCounter> = OnceLock::new();

/// Initialize the shared counter. Called from mod_init (before fork).
pub fn init() {
    match SharedAtomicCounter::new() {
        Some(counter) => {
            if REQUEST_COUNTER.set(counter).is_err() {
                opensips_log!(WARN, "rust", "request counter already initialized");
            } else {
                opensips_log!(INFO, "rust", "shared atomic counter initialized in shm");
            }
        }
        None => {
            opensips_log!(ERR, "rust", "failed to allocate shared counter (shm_malloc)");
        }
    }
}

/// Atomically increment the request counter and write the value
/// to $var(shared_count).
///
/// Returns 1 on success, -1 if the counter isn't initialized.
pub fn counter_inc(msg: &mut SipMessage) -> c_int {
    let counter = match REQUEST_COUNTER.get() {
        Some(c) => c,
        None => {
            opensips_log!(ERR, "rust", "counter_inc: counter not initialized");
            return -1;
        }
    };

    // Truly atomic: compiles to a single `lock xadd` instruction.
    // All workers increment the same physical memory location.
    let new_val = counter.increment();

    // Write to $var(shared_count) so the config can read it.
    if let Err(e) = msg.set_pv_int("$var(shared_count)", new_val as i32) {
        opensips_log!(ERR, "rust", "counter_inc: set $var(shared_count) failed: {}", e);
        return -1;
    }

    1
}
