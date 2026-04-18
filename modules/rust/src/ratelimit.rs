//! Per-caller rate limiter using thread-local state.
//!
//! Each `OpenSIPS` worker process has its own rate table, so no locking
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

/// Outcome of a rate-limit check against one entry. Pure-logic helper
/// extracted so it can be unit-tested independent of FFI / IO.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WindowOutcome {
    /// Window expired — entry was reset and request counted.
    Reset,
    /// Within window, under limit — count incremented.
    Incremented,
    /// Within window, at or over limit — request rejected.
    Rejected,
}

/// Evaluate one rate-limit entry without touching global state.
/// `elapsed_within_limit` encodes whether `elapsed < window`.
///
/// Returns the outcome; caller mutates `count`/`window_start`
/// accordingly (see `WindowOutcome`).
pub(crate) fn evaluate_window(
    count: u32,
    max_rate: u32,
    elapsed_within_limit: bool,
) -> WindowOutcome {
    if !elapsed_within_limit {
        WindowOutcome::Reset
    } else if count < max_rate {
        WindowOutcome::Incremented
    } else {
        WindowOutcome::Rejected
    }
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
        // has elapsed. Delegate the decision to the pure helper (unit-tested
        // separately) and apply its outcome by mutating the entry.
        let elapsed_within = now.duration_since(entry.window_start) < window;
        let result = match evaluate_window(entry.count, max_rate, elapsed_within) {
            WindowOutcome::Reset => {
                entry.count = 1;
                entry.window_start = now;
                true
            }
            WindowOutcome::Incremented => {
                entry.count += 1;
                true
            }
            WindowOutcome::Rejected => false,
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
        use opensips_rs::CallArg::{Int, Str};
        if let Err(e) = msg.call("sl_send_reply", &[Int(429), Str("Rate Limited")]) {
            opensips_log!(ERR, "rust", "failed to send 429 reply: {}", e);
        }

        -1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_reset_on_expiry() {
        // elapsed >= window → reset, regardless of count
        assert_eq!(evaluate_window(9999, 100, false), WindowOutcome::Reset);
        assert_eq!(evaluate_window(0, 100, false), WindowOutcome::Reset);
    }

    #[test]
    fn window_incremented_under_limit() {
        assert_eq!(evaluate_window(0, 100, true), WindowOutcome::Incremented);
        assert_eq!(evaluate_window(99, 100, true), WindowOutcome::Incremented);
    }

    #[test]
    fn window_rejected_at_or_over_limit() {
        // count == max_rate → reject. This is the boundary; the caller
        // passes count-so-far, and the limit is inclusive.
        assert_eq!(evaluate_window(100, 100, true), WindowOutcome::Rejected);
        assert_eq!(evaluate_window(999, 100, true), WindowOutcome::Rejected);
    }

    #[test]
    fn zero_limit_always_rejects_until_reset() {
        // max_rate = 0 is a degenerate config (no requests allowed within window).
        assert_eq!(evaluate_window(0, 0, true), WindowOutcome::Rejected);
        // But still allows reset when the window has elapsed.
        assert_eq!(evaluate_window(0, 0, false), WindowOutcome::Reset);
    }
}
