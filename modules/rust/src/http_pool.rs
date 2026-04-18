//! Persistent HTTP connection pool using `reqwest`.
//!
//! Demonstrates a pattern that Python/Lua modules cannot do safely:
//! persistent connections that survive across SIP transactions.
//! The reqwest Client maintains a connection pool internally,
//! reusing TCP connections to the same host.
//!
//! # Rust Concepts Demonstrated
//!
//! - **`OnceLock` for one-time initialization**: `OnceLock<T>` stores a
//!   value that is initialized exactly once, then immutably shared.
//!   Perfect for connection pools that are created in child_init and
//!   used for the lifetime of the worker process. Similar to a global
//!   singleton, but safe — `.set()` returns Err if already initialized,
//!   `.get()` returns Option<&T>.
//!
//! - **Builder pattern**: `Client::builder().timeout(d).build()` — a
//!   common Rust idiom where you configure an object step by step,
//!   then finalize with `.build()`. Each method returns `self`, enabling
//!   chaining. The builder validates all options at `.build()` time.
//!
//! - **`unwrap_or_else` for fallback on error**: like `unwrap_or` but
//!   takes a closure that's only called on Err. Use this when the
//!   fallback is expensive (like constructing a new Client).
//!   `unwrap_or` evaluates eagerly, `unwrap_or_else` evaluates lazily.
//!
//! - **Nested `match` for HTTP response handling**: outer match handles
//!   send() result (network error), inner match handles text() result
//!   (body decoding error). Each level of nesting handles one failure mode.

use opensips_rs::{opensips_log, SipMessage};
use std::ffi::c_int;
use std::sync::OnceLock;
use std::time::Duration;

// OnceLock<T>: write-once, read-many global. Initialized in child_init
// (once per worker process), then immutably shared for all SIP requests.
// Unlike a Mutex, reads are lock-free after initialization.
static HTTP_CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();

/// Initialize the HTTP client pool. Called from child_init.
pub fn init_pool(timeout_seconds: c_int, pool_size: c_int) {
    let timeout = if timeout_seconds > 0 {
        Duration::from_secs(timeout_seconds as u64)
    } else {
        Duration::from_secs(2)
    };

    let pool = if pool_size > 0 {
        pool_size as usize
    } else {
        4
    };

    // Builder pattern: configure the HTTP client step by step.
    // Each method returns the builder (Self), enabling chaining.
    // .build() validates and constructs the final Client.
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)                          // per-request timeout
        .pool_max_idle_per_host(pool)              // connection pool size
        .pool_idle_timeout(Duration::from_secs(90)) // idle connection lifetime
        .user_agent("OpenSIPS-Rust/0.1")           // default User-Agent
        .build()
        // unwrap_or_else: only constructs the fallback Client if build() fails.
        // The closure |e| captures the error for logging before returning
        // a default client. This is lazy evaluation — the fallback is never
        // constructed if build() succeeds.
        .unwrap_or_else(|e| {
            opensips_log!(ERR, "rust", "failed to build HTTP client: {}", e);
            reqwest::blocking::Client::new()
        });

    // OnceLock::set() returns Err if already initialized.
    // This is safe (not a panic) — we just log and continue.
    if HTTP_CLIENT.set(client).is_err() {
        opensips_log!(DBG, "rust", "HTTP client already initialized (worker reuse)");
    } else {
        opensips_log!(INFO, "rust", "HTTP connection pool initialized (timeout={}s, pool={})",
            timeout.as_secs(), pool);
    }
}

/// Execute an HTTP GET request and store the response body in $var(http_result).
///
/// Returns 1 on success, -1 on failure.
pub fn http_query(msg: &mut SipMessage, url: &str) -> c_int {
    if url.is_empty() {
        opensips_log!(ERR, "rust", "http_query: empty URL");
        return -1;
    }

    // OnceLock::get() returns Option<&T>: Some if initialized, None if not.
    let client = match HTTP_CLIENT.get() {
        Some(c) => c,
        None => {
            opensips_log!(ERR, "rust", "http_query: HTTP client not initialized");
            return -1;
        }
    };

    opensips_log!(DBG, "rust", "http_query: GET {}", url);

    // Nested match: outer handles network errors, inner handles body errors.
    // Each match level addresses one failure mode explicitly.
    match client.get(url).send() {
        Ok(resp) => {
            let status = resp.status().as_u16();
            match resp.text() {
                Ok(body) => {
                    opensips_log!(DBG, "rust", "http_query: {} {} ({} bytes)",
                        url, status, body.len());

                    // Store result in $var(http_result) via PV write.
                    if let Err(e) = msg.set_pv("$var(http_result)", &body) {
                        opensips_log!(ERR, "rust", "http_query: failed to set $var(http_result): {}", e);
                        return -1;
                    }

                    // Store status code — convert u16 to String for PV write.
                    let status_str = status.to_string();
                    if let Err(e) = msg.set_pv("$var(http_status)", &status_str) {
                        opensips_log!(ERR, "rust", "http_query: failed to set $var(http_status): {}", e);
                    }

                    1
                }
                Err(e) => {
                    opensips_log!(ERR, "rust", "http_query: failed to read response body: {}", e);
                    -1
                }
            }
        }
        Err(e) => {
            opensips_log!(ERR, "rust", "http_query: request failed: {}", e);
            -1
        }
    }
}
