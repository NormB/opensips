//! Per-caller rate limiter using thread-local state.
//!
//! Each OpenSIPS worker process has its own rate table, so no locking
//! is needed. This is a pattern that cannot be safely done in Python/Lua
//! because those interpreters share mutable state across calls.
//!
//! # Rust Concepts Demonstrated
//!
//! - **`thread_local!` macro**: Declares a variable unique to each OS thread.
//!   After OpenSIPS forks workers, each worker is single-threaded, so
//!   `thread_local!` gives each worker its own independent rate table.
//!   No Mutex, no locking overhead, no data races — by design.
//!
//! - **`RefCell` interior mutability**: `thread_local!` only gives us a
//!   shared reference via `.with()`. But we need to mutate the HashMap.
//!   `RefCell` moves Rust's borrow rules from compile-time to runtime:
//!   `.borrow()` for read, `.borrow_mut()` for write. Panics on double
//!   mutable borrow (but that can't happen here — single-threaded).
//!
//! - **`HashMap::entry()` API**: Look up or insert in one hash computation.
//!   `rates.entry(key).or_insert(default)` avoids the contains+insert
//!   double-lookup pattern common in C/Python.
//!
//! - **`Instant` monotonic clock**: `Instant::now()` uses CLOCK_MONOTONIC,
//!   which never goes backwards (immune to NTP adjustments). Perfect for
//!   measuring elapsed time in rate windows.
//!
//! - **`Duration` arithmetic**: `now.duration_since(start) >= window`
//!   compares time spans naturally. No manual millisecond math.
//!
//! - **Why no `Mutex`?**: OpenSIPS workers are separate processes (fork),
//!   not threads. A Mutex would protect nothing and add overhead.
//!   `thread_local! + RefCell` is the correct pattern here.

use opensips_rs::{opensips_log, SipMessage};
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::c_int;
use std::time::Instant;

/// Tracks request count within a sliding time window for one caller IP.
struct RateEntry {
    count: u32,           // requests seen in current window
    window_start: Instant, // when this window opened (monotonic)
}

// thread_local! creates per-worker state. Each forked OpenSIPS process
// gets its own RATES HashMap — completely independent, no sharing.
// The RefCell wrapper enables mutation through the shared reference
// that .with() provides.
thread_local! {
    static RATES: RefCell<HashMap<String, RateEntry>> = RefCell::new(HashMap::with_capacity(64));
}

/// Check if the caller (identified by source IP) has exceeded the rate limit.
///
/// Returns 1 (allow) or -1 (rate limited, sends 429 reply).
pub fn check_rate(msg: &mut SipMessage, max_rate: c_int, window_seconds: c_int) -> c_int {
    let caller_ip = msg.source_ip();
    if caller_ip.is_empty() {
        opensips_log!(WARN, "rust", "check_rate: could not determine source IP");
        return 1; // allow on error
    }

    // Convert C int params to Rust types with safe defaults.
    let max_rate = if max_rate > 0 { max_rate as u32 } else { 100 };
    let window = if window_seconds > 0 {
        std::time::Duration::from_secs(window_seconds as u64)
    } else {
        std::time::Duration::from_secs(60)
    };

    // .with() accesses the thread-local via a closure. The closure
    // receives &RefCell<HashMap<...>>. We call .borrow_mut() to get
    // a mutable reference to the HashMap inside.
    let allowed = RATES.with(|rates| {
        let mut rates = rates.borrow_mut();
        let now = Instant::now();

        // entry() API: one hash lookup does both "find" and "insert if missing".
        // or_insert() provides the default value for new entries.
        // Returns a &mut reference to the value (new or existing).
        let entry = rates.entry(caller_ip.clone()).or_insert(RateEntry {
            count: 0,
            window_start: now,
        });

        // Duration arithmetic: duration_since() returns how much time
        // has elapsed. The >= comparison is natural and readable.
        let result = if now.duration_since(entry.window_start) >= window {
            // Window expired — reset counter and start a new window.
            entry.count = 1;
            entry.window_start = now;
            true
        } else if entry.count < max_rate {
            // Within window and under limit — increment and allow.
            entry.count += 1;
            true
        } else {
            // Within window but over limit — reject.
            false
        };

        // Evict expired entries when the table grows too large.
        // Prevents unbounded growth from distributed sources (e.g.,
        // thousands of unique IPs in a scan). Single pass, no timers.
        if rates.len() > 10_000 {
            rates.retain(|_, e| now.duration_since(e.window_start) < window);
        }

        result
    });

    if allowed {
        1
    } else {
        opensips_log!(WARN, "rust", "rate limit exceeded for {}", caller_ip);

        // msg.call() dispatches to another module's function.
        // "sl_send_reply" is from the sl (stateless) module.
        if let Err(e) = msg.call("sl_send_reply", &["429", "Rate Limited"]) {
            opensips_log!(ERR, "rust", "failed to send 429 reply: {}", e);
        }

        -1
    }
}
