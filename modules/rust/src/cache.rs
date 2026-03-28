//! In-memory routing cache with TTL.
//!
//! Stores destination URI ($du) indexed by Request-URI user ($rU).
//! Thread-local storage means each worker has its own cache — no locking,
//! no data races. A pattern impossible in Python/Lua shared interpreters.
//!
//! # Rust Concepts Demonstrated
//!
//! - **`match` with guard clauses**: `Some(u) if !u.is_empty()` combines
//!   pattern matching with a boolean condition. This is more expressive
//!   than C's `if (val != NULL && strlen(val) > 0)` — the compiler ensures
//!   you handle all cases.
//!
//! - **`msg.pv()` for PV reads**: reads an OpenSIPS pseudo-variable and
//!   returns `Option<String>`. `$rU` = R-URI user part, `$du` = destination
//!   URI. Returns None if the PV is empty/undefined.
//!
//! - **`msg.set_pv()` for PV writes**: writes a string value to a writable
//!   PV. Returns `Result<(), Error>` — the caller must handle potential
//!   failure (e.g., PV not writable, parse error).
//!
//! - **`Option` chaining**: multiple match/if-let steps extract values
//!   while handling the "absent" case at each step. No null pointer
//!   dereference possible.
//!
//! - **`.clone()` and when it's needed**: we clone strings when they need
//!   to outlive the borrow from RefCell. Rust requires explicit cloning —
//!   no implicit copies of heap data. This makes the cost visible.

use opensips_rs::{opensips_log, SipMessage};
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::c_int;
use std::time::Instant;

struct CacheEntry {
    destination: String,
    inserted: Instant,
}

thread_local! {
    static ROUTE_CACHE: RefCell<HashMap<String, CacheEntry>> = RefCell::new(HashMap::with_capacity(64));
}

/// Look up a cached destination for the current request's R-URI user.
///
/// On cache hit: sets $du to the cached destination and returns 1.
/// On cache miss: returns -1.
pub fn cache_lookup(msg: &mut SipMessage, cache_ttl: c_int) -> c_int {
    let ttl = if cache_ttl > 0 {
        std::time::Duration::from_secs(cache_ttl as u64)
    } else {
        std::time::Duration::from_secs(300)
    };

    // match with guard clause: `Some(u) if !u.is_empty()`
    // This matches Option::Some AND checks the inner value isn't empty.
    // The `_` arm catches both None and Some("").
    let ruri_user = match msg.pv("$rU") {
        Some(u) if !u.is_empty() => u,
        _ => {
            opensips_log!(DBG, "rust", "cache_lookup: no R-URI user");
            return -1;
        }
    };

    let destination = ROUTE_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        let now = Instant::now();

        let result = if let Some(entry) = cache.get(&ruri_user) {
            if now.duration_since(entry.inserted) < ttl {
                opensips_log!(DBG, "rust", "cache hit for {} -> {}", ruri_user, entry.destination);
                // .clone() creates an owned copy of the String.
                // We need this because `entry` borrows from the RefCell,
                // and we can't return a reference that outlives the borrow.
                Some(entry.destination.clone())
            } else {
                opensips_log!(DBG, "rust", "cache expired for {}", ruri_user);
                cache.remove(&ruri_user);
                None
            }
        } else {
            None
        };

        // Evict expired entries when the cache grows too large.
        // Prevents unbounded growth from diverse R-URI patterns.
        if cache.len() > 10_000 {
            cache.retain(|_, e| now.duration_since(e.inserted) < ttl);
        }

        result
    });

    // match on Option to handle hit vs miss.
    match destination {
        Some(dst) => {
            // set_pv writes to $du — sets the destination URI for t_relay().
            if let Err(e) = msg.set_pv("$du", &dst) {
                opensips_log!(ERR, "rust", "cache_lookup: failed to set $du: {}", e);
                return -1;
            }
            1
        }
        None => {
            opensips_log!(DBG, "rust", "cache miss for {}", ruri_user);
            -1
        }
    }
}

/// Store the current destination ($du) in the cache for the R-URI user.
///
/// Returns 1 on success, -1 on failure.
pub fn cache_store(msg: &mut SipMessage) -> c_int {
    // Same match-with-guard pattern as cache_lookup.
    let ruri_user = match msg.pv("$rU") {
        Some(u) if !u.is_empty() => u,
        _ => {
            opensips_log!(WARN, "rust", "cache_store: no R-URI user");
            return -1;
        }
    };

    let dst_uri = match msg.pv("$du") {
        Some(d) if !d.is_empty() => d,
        _ => {
            opensips_log!(WARN, "rust", "cache_store: no destination URI ($du)");
            return -1;
        }
    };

    ROUTE_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        // .insert() replaces any existing entry for the same key.
        // .clone() on both key and value because HashMap takes ownership.
        cache.insert(
            ruri_user.clone(),
            CacheEntry {
                destination: dst_uri.clone(),
                inserted: Instant::now(),
            },
        );
    });

    opensips_log!(DBG, "rust", "cached {} -> {}", ruri_user, dst_uri);
    1
}
