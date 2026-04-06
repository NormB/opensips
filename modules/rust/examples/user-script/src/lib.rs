//! Example user scripts for `rust_exec()` — A Teaching Reference
//!
//! This file contains 19 self-contained handler functions, each one a lesson
//! that maps Rust programming concepts to SIP message processing patterns.
//! Every handler is heavily commented for developers coming from C, Python,
//! or other languages who are new to Rust.
//!
//! Build:
//!   cd examples/user-script
//!   cargo build --release
//!
//! The resulting .so is at:
//!   target/release/libmy_opensips_handler.so
//!
//! Configure in opensips.cfg:
//!   modparam("rust", "script_name", "/path/to/libmy_opensips_handler.so")
//!
//!   route {
//!       rust_exec("hello_world");
//!       rust_exec("greet", "howdy");
//!       rust_exec("caller_screening");
//!       rust_exec("rate_limit_by_ua", "50");
//!       # ... see each handler's USAGE line below
//!   }
//!
//! HANDLER INDEX:
//!   1.  hello_world        — opensips_handler! macro basics
//!   2.  greet              — Option<&str> and default values
//!   3.  log_user_agent     — header access
//!   4.  append_custom_header — msg.call() cross-module dispatch
//!   5.  route_by_header    — header reads + PV writes
//!   6.  caller_screening   — thread_local! HashSet for IP blocking
//!   7.  number_portability — thread_local! HashMap with TTL
//!   8.  request_logger     — header iteration + PV reads
//!   9.  rate_limit_by_ua   — per-UA rate limiting
//!   10. set_routing_flags  — message flags + $var PVs
//!   11. reply_handler      — SIP reply classification
//!   12. variable_exchange  — bidirectional PV exchange (config ↔ Rust)
//!   13. call_counter       — persistent per-worker state + PV output
//!   14. shared_counter     — cross-worker shared state via $shv()
//!   15. pv_manipulation    — pseudo-variable reads, writes, types
//!   16. avp_operations     — AVPs: transaction-scoped variables
//!   17. pv_edge_cases      — null/deleted/empty PV robustness test
//!   18. http_query          — external HTTP call via raw TCP
//!   19. json_parse          — JSON parsing with serde_json
//!   20. async_http_query    — async HTTP: non-blocking I/O with resume callback

#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::ptr_as_ptr)]
#![allow(clippy::borrow_as_ptr)]
#![allow(clippy::ref_as_ptr)]
#![allow(clippy::use_self)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::redundant_else)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::as_ptr_cast_mut)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::pub_underscore_fields)]
#![allow(clippy::elidable_lifetime_names)]
#![allow(clippy::single_match_else)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::similar_names)]
#![allow(clippy::wildcard_imports)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::unused_self)]
#![allow(static_mut_refs)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::bool_to_int_with_if)]
#![allow(clippy::if_not_else)]
#![allow(clippy::missing_const_for_thread_local)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::single_char_pattern)]
#![allow(clippy::redundant_guards)]
#![allow(clippy::or_fun_call)]

// ┌──────────────────────────────────────────────────────────────────────────┐
// │ IMPORTS                                                                 │
// │                                                                         │
// │ `opensips_rs::prelude::*` brings in three items:                        │
// │   - opensips_handler!  — macro that generates the extern "C" wrapper    │
// │   - opensips_log!      — macro for OpenSIPS-native logging             │
// │   - SipMessage         — safe wrapper around the raw sip_msg pointer   │
// │                                                                         │
// │ Rust's standard library items are imported individually. Unlike C's     │
// │ #include, Rust's `use` only brings names into scope — no code is        │
// │ compiled unless actually used.                                          │
// └──────────────────────────────────────────────────────────────────────────┘
use opensips_rs::prelude::*;
use opensips_rs::sys;

use std::cell::RefCell;              // Interior mutability without a Mutex
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};          // Traits for TcpStream I/O
use std::net::TcpStream;             // Raw TCP socket for HTTP
#[cfg(unix)]
use std::os::unix::io::AsRawFd;     // Extract raw fd from TcpStream
use std::time::{Duration, Instant};  // Monotonic clock — no NTP surprises


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Handler 1: hello_world
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PURPOSE: Minimal handler — log the SIP method and return success.
//
// RUST CONCEPTS:
//   - `opensips_handler!` macro: generates an `extern "C"` function with
//     the ABI that the rust module's dlsym-based loader expects.
//   - Closures: `|msg| { ... }` — the one-arg form gives you a SipMessage.
//   - `Option::unwrap_or()`: extracts the value or uses a default.
//     `msg.method()` returns `Option<&str>` — it's `None` for SIP replies.
//   - Return value: `1` = success (continue route), `-1` = failure.
//
// SIP CONCEPTS: method name (INVITE, REGISTER, OPTIONS, etc.)
// USAGE:        rust_exec("hello_world")
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
opensips_handler!(hello_world, |msg| {
    // msg.method() returns Option<&str>:
    //   Some("INVITE") for requests, None for replies.
    // unwrap_or("?") provides a fallback — no null pointer risk like in C.
    opensips_log!(INFO, "rust-script", "hello_world called for {}",
        msg.method().unwrap_or("?"));
    1 // success — route processing continues
});


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Handler 2: greet
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PURPOSE: Demonstrate the optional parameter passed from opensips.cfg.
//
// RUST CONCEPTS:
//   - Two-arg closure `|msg, param|`: `param` is `Option<&str>`.
//     When called as `rust_exec("greet")`, param is `None`.
//     When called as `rust_exec("greet", "howdy")`, param is `Some("howdy")`.
//   - `Option<&str>` is Rust's null alternative — the compiler forces you
//     to handle the "no value" case. No segfaults from dereferencing NULL.
//   - `unwrap_or("hello")` provides a default value if None.
//   - `format!` macro: like sprintf() but type-safe at compile time.
//
// SIP CONCEPTS: source IP identification
// USAGE:        rust_exec("greet", "howdy")  OR  rust_exec("greet")
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
opensips_handler!(greet, |msg, param| {
    // `param` is Option<&str>:
    //   - rust_exec("greet")        → param = None
    //   - rust_exec("greet", "yo")  → param = Some("yo")
    let greeting = param.unwrap_or("hello");

    // msg.source_ip() returns a String (owned), not &str (borrowed).
    // This is because the C shim allocates the IP string from a static buffer,
    // and we need to own a copy to be safe.
    opensips_log!(INFO, "rust-script", "{} from {}", greeting, msg.source_ip());
    1
});


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Handler 3: log_user_agent
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PURPOSE: Read and log a SIP header value.
//
// RUST CONCEPTS:
//   - `msg.header("Name")` returns `Option<&str>` — None if header missing.
//     The lookup is case-insensitive (SIP headers are case-insensitive per
//     RFC 3261 §7.3.1).
//   - `_param`: the underscore prefix tells the Rust compiler "I know this
//     exists but I'm intentionally not using it." Without it, you'd get a
//     compiler warning. Rust catches unused variables at compile time.
//
// SIP CONCEPTS: User-Agent header, header parsing
// USAGE:        rust_exec("log_user_agent")
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
opensips_handler!(log_user_agent, |msg, _param| {
    // header() parses all headers on first call, then searches by name.
    // Returns Option<&str> — the &str borrows directly from the parsed
    // message buffer (zero-copy).
    let ua = msg.header("User-Agent").unwrap_or("unknown");
    opensips_log!(INFO, "rust-script", "User-Agent: {}", ua);
    1
});


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Handler 4: append_custom_header
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PURPOSE: Add a custom header via msg.call() cross-module dispatch.
//
// RUST CONCEPTS:
//   - `msg.call_str("function", &["arg1", "arg2"])` calls any loaded OpenSIPS
//     module function by name with string args. Returns `Result<i32, Error>`.
//   - `msg.call("function", &[Int(code), Str("reason")])` for typed args
//     (needed when the target function expects CMD_PARAM_INT).
//   - `Result<T, E>` vs `Option<T>`:
//       Option = value might be absent (like nullable)
//       Result = operation might fail (like exceptions, but checked)
//   - `match` expression: like switch/case but exhaustive — the compiler
//     ensures every variant is handled. No fall-through bugs.
//   - `format!` builds a String; SIP headers need `\r\n` line endings.
//
// SIP CONCEPTS: append_hf (textops module), custom headers, CRLF
// USAGE:        rust_exec("append_custom_header", "my-tag")
// REQUIRES:     loadmodule "textops.so" in opensips.cfg
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
opensips_handler!(append_custom_header, |msg, param| {
    // Build the header value. SIP headers MUST end with \r\n.
    let tag = param.unwrap_or("rust");
    let header = format!("X-Rust-Processed: {}\r\n", tag);

    // msg.call() dispatches to another module's exported function.
    // "append_hf" is from the textops module — it appends a header to the
    // SIP message. The function takes one string argument.
    //
    // `match` on Result:
    //   Ok(rc)  — the function succeeded; rc is the return code
    //   Err(e)  — the function failed (not found, fixup error, etc.)
    match msg.call_str("append_hf", &[&header]) {
        Ok(_rc) => {
            opensips_log!(DBG, "rust-script", "appended header: X-Rust-Processed: {}", tag);
            1 // success
        }
        Err(e) => {
            // Display trait (Rust's toString): the `{}` format calls e.to_string()
            opensips_log!(ERR, "rust-script", "append_hf failed: {}", e);
            -1 // failure
        }
    }
});


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Handler 5: route_by_header
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PURPOSE: Read an X-Route-To header and set $du (destination URI).
//
// RUST CONCEPTS:
//   - `if let Some(val) = expr` — Rust's pattern-matching if statement.
//     Combines a test ("is it Some?") with extraction ("bind the value")
//     in one step. Cleaner than: val = expr; if (val != NULL) { ... }
//   - `msg.set_pv("$du", val)` — writes a pseudo-variable.
//     Returns Result<(), Error>: Ok(()) on success, Err on failure.
//   - Early returns: returning -1 immediately when the header is missing
//     avoids deep nesting (Rust style: handle errors first, happy path last).
//
// SIP CONCEPTS: $du (destination URI), custom routing headers
// USAGE:        rust_exec("route_by_header")
// NOTE:         Caller must add X-Route-To header, e.g.:
//               append_hf("X-Route-To: sip:10.0.0.1:5060\r\n")
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
opensips_handler!(route_by_header, |msg, _param| {
    // msg.header() returns Option<&str> that BORROWS from msg.
    // Since we need &mut msg later (for set_pv), we must .to_string()
    // to create an owned copy first. This is a common Rust pattern:
    // convert borrowed data to owned before mutating the source.
    let dest = match msg.header("X-Route-To") {
        Some(d) => d.trim().to_string(),  // own it before we mutate msg
        None => {
            opensips_log!(DBG, "rust-script", "route_by_header: no X-Route-To header");
            return -1;
        }
    };

    if dest.is_empty() {
        opensips_log!(WARN, "rust-script", "route_by_header: empty X-Route-To");
        return -1; // early return — avoids nesting
    }

    // Now msg is no longer borrowed, so we can call &mut self methods.
    // set_pv writes to OpenSIPS pseudo-variables.
    // $du = destination URI — where OpenSIPS sends the request.
    match msg.set_pv("$du", &dest) {
        Ok(()) => {
            opensips_log!(INFO, "rust-script", "route_by_header: $du = {}", dest);
            1
        }
        Err(e) => {
            opensips_log!(ERR, "rust-script", "route_by_header: set_pv failed: {}", e);
            -1
        }
    }
});


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Handler 6: caller_screening
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PURPOSE: Block calls from blacklisted source IPs (sends 403 Forbidden).
//
// RUST CONCEPTS:
//   - `thread_local!` macro: declares a variable that is unique to each
//     thread (and therefore each OpenSIPS worker process after fork()).
//     This is THE key pattern for per-worker state in OpenSIPS Rust modules.
//
//     WHY thread_local! IS SAFE IN OPENSIPS:
//     OpenSIPS forks worker processes in main → child_init. After fork,
//     each worker is single-threaded. thread_local! gives each worker its
//     own copy — no locking, no data races, no Mutex overhead. This is
//     impossible to do safely in Python/Lua because those interpreters
//     share mutable state across calls.
//
//   - `RefCell`: provides "interior mutability" — lets you mutate data
//     behind a shared reference. The borrow rules are checked at runtime
//     instead of compile time. We need this because thread_local! only
//     gives us a shared reference via .with().
//
//   - `HashSet`: unordered collection of unique values. O(1) lookup via
//     .contains(). Perfect for blacklists.
//
//   - `.with(|bl| ...)`: access the thread-local value via a closure.
//     The closure gets a &RefCell<HashSet<...>>, and you call .borrow()
//     to get a read reference.
//
// SIP CONCEPTS: source IP filtering, sl_send_reply(403)
// USAGE:        rust_exec("caller_screening")
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// thread_local! declares per-worker state. Each OpenSIPS worker process
// gets its own independent copy after fork(). The macro is evaluated lazily
// on first access in each worker.
thread_local! {
    /// Blacklisted source IPs. In production, you'd load these from a
    /// database or config file. Here we hardcode a few for demonstration.
    static BLOCKED_IPS: RefCell<HashSet<&'static str>> = RefCell::new({
        let mut set = HashSet::new();
        // These are example IPs — replace with your actual blacklist.
        set.insert("10.99.99.1");
        set.insert("10.99.99.2");
        set.insert("10.99.99.3");
        set.insert("192.168.99.1");
        set
    });
}

opensips_handler!(caller_screening, |msg, _param| {
    let src_ip = msg.source_ip();

    // .with() accesses the thread-local value via a closure.
    // The closure receives &RefCell<HashSet<...>>.
    // .borrow() gets a shared (read-only) reference to the HashSet.
    let is_blocked = BLOCKED_IPS.with(|bl| {
        let blacklist = bl.borrow();  // runtime borrow check (cheap, ~1ns)

        // .contains() on HashSet is O(1) average — much faster than
        // iterating a Vec. For 1000+ entries, the difference is dramatic.
        //
        // We need .as_str() to convert String → &str for the lookup,
        // because our HashSet stores &str values.
        blacklist.contains(src_ip.as_str())
    });

    if is_blocked {
        opensips_log!(WARN, "rust-script", "BLOCKED caller from {}", src_ip);

        // Send 403 Forbidden via the sl (stateless) module.
        // msg.call() dispatches to sl_send_reply.
        use opensips_rs::CallArg::{Int, Str};
        if let Err(e) = msg.call("sl_send_reply", &[Int(403), Str("Forbidden")]) {
            opensips_log!(ERR, "rust-script", "sl_send_reply(403) failed: {}", e);
        }
        -1 // tell OpenSIPS to stop route processing
    } else {
        1 // allowed — continue route processing
    }
});


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Handler 7: number_portability
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PURPOSE: Local Number Portability (LNP) cache — maps dialed numbers to
//          their current carrier's routing prefix, with TTL expiration.
//
// RUST CONCEPTS:
//   - `struct` definitions: Rust structs are like C structs but with no
//     null fields (every field must be initialized). No constructors needed.
//   - `Instant` + `Duration`: monotonic clock types. Instant::now() never
//     goes backwards (unlike wall clock). Duration represents elapsed time.
//   - `HashMap::entry()` API: the "entry" pattern avoids double lookups.
//     Instead of: if !map.contains(k) { map.insert(k, v); }
//     You write:  map.entry(k).or_insert(v);
//     One hash computation instead of two.
//   - `.clone()`: explicit deep copy. Rust doesn't copy by default (unlike
//     C's struct assignment). You must opt-in with .clone(). This prevents
//     accidental expensive copies.
//
// SIP CONCEPTS: $rU (R-URI user part), number translation, $du
// USAGE:        rust_exec("number_portability")
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// A cached LNP entry: the routing destination and when it was cached.
/// In Rust, struct fields are private by default. We keep them private
/// because only this module needs to access them.
struct LnpEntry {
    destination: String,   // e.g., "sip:+15551234567@carrier-b.example.com"
    cached_at: Instant,    // monotonic timestamp — immune to NTP jumps
}

thread_local! {
    /// LNP cache: maps dialed number → routing destination.
    /// Each worker has its own cache (thread_local!), so no locking needed.
    static LNP_CACHE: RefCell<HashMap<String, LnpEntry>> = RefCell::new(HashMap::with_capacity(64));
}

/// TTL for LNP cache entries. In production, this would be a modparam.
const LNP_TTL: Duration = Duration::from_secs(3600); // 1 hour

opensips_handler!(number_portability, |msg, _param| {
    // Read $rU — the user part of the Request-URI (typically the dialed number).
    // msg.pv() reads OpenSIPS pseudo-variables and returns Option<String>.
    let dialed = match msg.pv("$rU") {
        Some(n) if !n.is_empty() => n,
        _ => {
            opensips_log!(DBG, "rust-script", "number_portability: no $rU");
            return -1;
        }
    };

    // Look up in the LNP cache.
    let cached_dest = LNP_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut(); // mutable borrow for potential removal
        let now = Instant::now();

        if let Some(entry) = cache.get(&dialed) {
            // Check TTL: duration_since returns how long ago it was cached.
            if now.duration_since(entry.cached_at) < LNP_TTL {
                // Cache hit! Clone the destination string because we can't
                // return a reference into the RefCell (it would outlive the
                // borrow). .clone() makes an independent copy.
                return Some(entry.destination.clone());
            }
            // Expired — remove the stale entry.
            cache.remove(&dialed);
        }
        None // cache miss
    });

    match cached_dest {
        Some(dest) => {
            // Cache hit — set $du to route to the ported number's carrier.
            match msg.set_pv("$du", &dest) {
                Ok(()) => {
                    opensips_log!(INFO, "rust-script",
                        "LNP cache hit: {} -> {}", dialed, dest);
                    1
                }
                Err(e) => {
                    opensips_log!(ERR, "rust-script",
                        "number_portability: set_pv($du) failed: {}", e);
                    -1
                }
            }
        }
        None => {
            // Cache miss — in production, you'd query an LNP database here.
            // For this demo, we simulate a lookup with a simple prefix rule.
            let simulated_dest = format!("sip:{}@lnp-gateway.local", dialed);

            // Store in cache using the entry() API.
            LNP_CACHE.with(|cache| {
                let mut cache = cache.borrow_mut();
                // entry() returns an Entry enum:
                //   Occupied — key exists (someone raced us)
                //   Vacant — key is new
                // or_insert() fills only if vacant.
                cache.entry(dialed.clone()).or_insert(LnpEntry {
                    destination: simulated_dest.clone(),
                    cached_at: Instant::now(),
                });
            });

            // Set $du for this request.
            match msg.set_pv("$du", &simulated_dest) {
                Ok(()) => {
                    opensips_log!(INFO, "rust-script",
                        "LNP cache miss (stored): {} -> {}", dialed, simulated_dest);
                    1
                }
                Err(e) => {
                    opensips_log!(ERR, "rust-script",
                        "number_portability: set_pv($du) failed: {}", e);
                    -1
                }
            }
        }
    }
});


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Handler 8: request_logger
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PURPOSE: CDR-like structured logging of call metadata — dump key fields
//          from the SIP message for debugging or audit trails.
//
// RUST CONCEPTS:
//   - `msg.header_iter()`: returns an Iterator over (name, body) tuples.
//     Iterators are Rust's zero-cost abstraction for sequences — they're
//     as fast as hand-written loops but compose beautifully.
//   - Tuple destructuring `(name, body)`: pattern-match on the fly.
//     In C you'd need: struct { char *name; char *body; } and access
//     via hdr.name, hdr.body. In Rust, tuples are lightweight and typed.
//   - `msg.pv("$fU")` reads the From-URI user part.
//   - `msg.pv("$ci")` reads the Call-ID.
//   - Chaining: multiple unwrap_or() calls make code read top-to-bottom
//     like a data pipeline.
//
// SIP CONCEPTS: Call-ID, From user, To user, CSeq, header iteration
// USAGE:        rust_exec("request_logger")
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
opensips_handler!(request_logger, |msg, _param| {
    // Read pseudo-variables for call metadata.
    // Each .pv() call returns Option<String>; unwrap_or provides defaults.
    let call_id  = msg.pv("$ci").unwrap_or_else(|| "?".to_string());
    let from_user = msg.pv("$fU").unwrap_or_else(|| "?".to_string());
    let to_user   = msg.pv("$tU").unwrap_or_else(|| "?".to_string());
    let method    = msg.method().unwrap_or("?");
    let src_ip    = msg.source_ip();

    // Log the structured summary.
    opensips_log!(INFO, "rust-script",
        "REQUEST: {} from={}  to={}  call-id={}  src={}",
        method, from_user, to_user, call_id, src_ip);

    // Iterate ALL headers and log them.
    // header_iter() returns an Iterator<Item = (&str, &str)>.
    // The `for (name, body) in ...` syntax destructures each tuple.
    let mut header_count = 0u32;
    for (name, body) in msg.header_iter() {
        // Trim header bodies — they often have leading whitespace.
        opensips_log!(DBG, "rust-script", "  HDR: {} = {}", name, body.trim());
        header_count += 1;
    }

    opensips_log!(DBG, "rust-script", "  total headers: {}", header_count);
    1
});


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Handler 9: rate_limit_by_ua
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PURPOSE: Rate limit requests keyed by User-Agent header.
//          This is the same pattern as the compiled-in rust_check_rate()
//          but demonstrates it in user-script form, keyed by UA instead
//          of source IP.
//
// RUST CONCEPTS:
//   - Same `thread_local! + RefCell + HashMap` pattern as the compiled-in
//     rate limiter — this is the canonical pattern for per-worker state.
//   - `.parse::<u32>()`: converts a string to a number. Returns
//     `Result<u32, ParseIntError>`. The turbofish `::<u32>` tells the
//     parser what type to target (Rust doesn't have implicit conversions).
//   - Chained `.unwrap_or()`: provides defaults at each step of a
//     fallible pipeline.
//
// SIP CONCEPTS: User-Agent header, 429 Too Many Requests
// USAGE:        rust_exec("rate_limit_by_ua", "50")  — max 50 req/minute
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Per-UA rate tracking entry.
struct UaRateEntry {
    count: u32,
    window_start: Instant,
}

thread_local! {
    /// Rate limiter state: User-Agent string → request count + window.
    static UA_RATES: RefCell<HashMap<String, UaRateEntry>> =
        RefCell::new(HashMap::with_capacity(64));
}

/// Rate limit window. In production, make this a modparam.
const UA_RATE_WINDOW: Duration = Duration::from_secs(60);

opensips_handler!(rate_limit_by_ua, |msg, param| {
    // Parse the max-rate from the optional parameter.
    // Pipeline: param (Option<&str>) → unwrap_or → parse → unwrap_or
    //
    // Step by step:
    //   param = Some("50") or None
    //   .unwrap_or("100") → "50" or "100"
    //   .parse::<u32>()   → Ok(50) or Err(...)
    //   .unwrap_or(100)   → 50 or 100
    let max_rate: u32 = param
        .unwrap_or("100")         // default string if no param
        .parse::<u32>()           // try to convert to u32
        .unwrap_or(100);          // default number if parse fails

    // Get the User-Agent header (our rate-limit key).
    let ua = msg.header("User-Agent").unwrap_or("unknown").to_string();

    // Check/update the rate counter.
    let allowed = UA_RATES.with(|rates| {
        let mut rates = rates.borrow_mut();
        let now = Instant::now();

        // entry() API: look up or create in one step.
        let entry = rates.entry(ua.clone()).or_insert(UaRateEntry {
            count: 0,
            window_start: now,
        });

        // Has the window expired? Reset if so.
        if now.duration_since(entry.window_start) >= UA_RATE_WINDOW {
            entry.count = 1;
            entry.window_start = now;
            true // allowed (new window)
        } else if entry.count < max_rate {
            entry.count += 1;
            true // allowed (under limit)
        } else {
            false // rate exceeded
        }
    });

    if allowed {
        1
    } else {
        opensips_log!(WARN, "rust-script", "UA rate limit exceeded for: {}", ua);

        // Send 429 reply. `if let Err(e)` handles only the error case.
        use opensips_rs::CallArg::{Int, Str};
        if let Err(e) = msg.call("sl_send_reply", &[Int(429), Str("Too Many Requests")]) {
            opensips_log!(ERR, "rust-script", "sl_send_reply(429) failed: {}", e);
        }
        -1
    }
});


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Handler 10: set_routing_flags
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PURPOSE: Set message flags and $var() pseudo-variables for downstream
//          route logic. Demonstrates how Rust can make routing decisions
//          that the OpenSIPS config script reads later.
//
// RUST CONCEPTS:
//   - `msg.flags()` returns u32, `msg.set_flag(n)` sets bit n.
//     These map directly to OpenSIPS's setflag()/isflag() in the config.
//   - `starts_with()`: string prefix check — returns bool.
//   - Multiple `set_pv()` calls: write different variables in sequence.
//     Each returns Result, and we use `if let Err` to handle failures
//     without deep nesting.
//
// SIP CONCEPTS: message flags (for branch routing), $var() variables
// USAGE:        rust_exec("set_routing_flags")
// CONFIG:       After this handler runs, check flags in opensips.cfg:
//               if (isflag(1)) { /* INVITE handling */ }
//               if ($var(call_type) == "international") { ... }
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// Flag bit assignments — using constants prevents magic numbers in code.
// In a bigger project, these might live in a shared constants module.
const FLAG_IS_INVITE: u32 = 1;
const FLAG_IS_REGISTER: u32 = 2;
const FLAG_RUST_PROCESSED: u32 = 20;

opensips_handler!(set_routing_flags, |msg, _param| {
    // msg.method() returns Option<&str> borrowing from msg.
    // We need to own it because set_flag/set_pv require &mut msg.
    // .unwrap_or("").to_string() creates an owned String, releasing
    // the immutable borrow on msg.
    let method = msg.method().unwrap_or("").to_string();

    // Set method-specific flags.
    // starts_with() checks the prefix — useful for matching SIP methods.
    if method == "INVITE" {
        msg.set_flag(FLAG_IS_INVITE);
    } else if method == "REGISTER" {
        msg.set_flag(FLAG_IS_REGISTER);
    }

    // Always mark as processed by Rust.
    msg.set_flag(FLAG_RUST_PROCESSED);

    // Classify the call type based on the dialed number.
    // $rU = R-URI user part (the dialed number).
    // msg.pv() returns Option<String> (already owned), so no borrow conflict.
    let call_type = match msg.pv("$rU") {
        Some(ref ruser) if ruser.starts_with("+1") => "domestic",
        Some(ref ruser) if ruser.starts_with("+")  => "international",
        Some(_) => "local",
        None => "unknown",
    };

    // Write the classification to $var(call_type) so the OpenSIPS config
    // can branch on it: if ($var(call_type) == "international") { ... }
    if let Err(e) = msg.set_pv("$var(call_type)", call_type) {
        opensips_log!(ERR, "rust-script", "set_routing_flags: set $var(call_type) failed: {}", e);
        return -1;
    }

    // Also store the method for downstream reference.
    if let Err(e) = msg.set_pv("$var(sip_method)", &method) {
        opensips_log!(ERR, "rust-script", "set_routing_flags: set $var(sip_method) failed: {}", e);
        return -1;
    }

    opensips_log!(DBG, "rust-script",
        "set_routing_flags: method={}, call_type={}, flags=0x{:x}",
        method, call_type, msg.flags());
    1
});


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Handler 11: reply_handler
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PURPOSE: Classify SIP replies by status code range and log the result.
//          Useful in failure_route or onreply_route.
//
// RUST CONCEPTS:
//   - `msg.is_reply()` → bool: checks if this is a SIP response.
//   - `msg.status_code()` → `Option<u32>`: the numeric status code.
//     Returns None for requests (no status code on requests).
//   - `match` with range patterns: `200..=299` matches any value from
//     200 to 299 inclusive. This is Rust's range pattern syntax.
//     Much cleaner than: if (code >= 200 && code <= 299)
//   - The `_` arm is the catch-all (like `default:` in C switch).
//
// SIP CONCEPTS: reply status codes (1xx provisional, 2xx success,
//               3xx redirect, 4xx client error, 5xx server error, 6xx global)
// USAGE:        rust_exec("reply_handler")
// CONFIG:       Best used in onreply_route (rust_exec has ONREPLY_ROUTE flag):
//               onreply_route[replies] {
//                   rust_exec("reply_handler");
//               }
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
opensips_handler!(reply_handler, |msg, _param| {
    // Guard: only process replies, not requests.
    if !msg.is_reply() {
        opensips_log!(DBG, "rust-script", "reply_handler: not a reply, skipping");
        return 1; // not an error — just nothing to do
    }

    // status_code() returns Option<u32>: Some(200) for replies, None for requests.
    // Since we checked is_reply() above, this should always be Some.
    let code = match msg.status_code() {
        Some(c) => c,
        None => {
            opensips_log!(WARN, "rust-script", "reply_handler: no status code on reply");
            return -1;
        }
    };

    // Classify the reply using match with range patterns.
    // Each arm covers a SIP status code range.
    let category = match code {
        100..=199 => "provisional",   // 100 Trying, 180 Ringing, etc.
        200..=299 => "success",       // 200 OK
        300..=399 => "redirect",      // 301/302 Moved
        400..=499 => "client-error",  // 403 Forbidden, 404 Not Found, 486 Busy
        500..=599 => "server-error",  // 500 Internal Error, 503 Unavailable
        600..=699 => "global-error",  // 600 Busy Everywhere, 603 Decline
        _         => "unknown",       // catch-all for anything else
    };

    opensips_log!(INFO, "rust-script", "REPLY: {} {} ({})",
        code, msg.status().unwrap_or(""), category);

    // Store the category in $var(reply_category) for the config to use.
    if let Err(e) = msg.set_pv("$var(reply_category)", category) {
        opensips_log!(ERR, "rust-script", "reply_handler: set_pv failed: {}", e);
    }

    1
});


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Handler 12: variable_exchange
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PURPOSE: Bidirectional pseudo-variable exchange between OpenSIPS config
//          and Rust. The config sets $var(input) BEFORE calling this handler,
//          Rust reads it, processes it, and writes $var(output) + $var(rc)
//          BACK so the config can branch on the results.
//
// THIS IS THE KEY PATTERN for config ↔ Rust communication:
//
//   Config → Rust:   $var(input) set before rust_exec()
//   Rust → Config:   $var(output), $var(rc) set during rust_exec()
//
// RUST CONCEPTS:
//   - `msg.pv("$var(name)")` → `Option<String>`: reads a PV set by config.
//     Returns None if the variable is unset or empty.
//   - `msg.set_pv("$var(name)", "value")` → `Result<(), Error>`: writes
//     a PV that the config can read after rust_exec() returns.
//   - `str::splitn(2, ':')`: splits at most into 2 parts on the first ':'.
//     Efficient — stops scanning after the first delimiter.
//   - `to_uppercase()`, `chars().rev().collect()`: String transformations.
//   - `match` on string slices for command dispatch.
//
// SIP CONCEPTS: $var() script variables, inter-module data exchange
// USAGE:
//   In opensips.cfg:
//     $var(input) = "uppercase:hello world";
//     rust_exec("variable_exchange");
//     xlog("result=$var(output), status=$var(rc)\n");
//
//   Supported commands:
//     "uppercase:text"  → "TEXT"
//     "reverse:text"    → "txet"
//     "len:text"        → "4"
//     "prefix:text"     → "+1text" (adds +1 prefix, useful for SIP URIs)
//
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
opensips_handler!(variable_exchange, |msg, _param| {
    // ── Step 1: Read input from config ──
    // The config must set $var(input) before calling rust_exec().
    // msg.pv() returns Option<String> — already owned, no borrow issues.
    let input = match msg.pv("$var(input)") {
        Some(s) if !s.is_empty() => s,
        _ => {
            opensips_log!(WARN, "rust-script",
                "variable_exchange: $var(input) is empty or unset");
            // Write error status back so the config can detect it.
            let _ = msg.set_pv("$var(rc)", "error");
            let _ = msg.set_pv("$var(output)", "");
            return -1;
        }
    };

    // ── Step 2: Parse the command ──
    // Format: "command:argument"
    // splitn(2, ':') splits into at most 2 parts at the first ':'.
    // This is efficient — it stops scanning after the delimiter.
    let mut parts = input.splitn(2, ':');
    let command = parts.next().unwrap_or("");  // before ':'
    let argument = parts.next().unwrap_or(""); // after ':' (everything else)

    // ── Step 3: Execute the command ──
    // match on &str: dispatches to the right operation.
    let result = match command {
        "uppercase" => argument.to_uppercase(),
        "reverse"   => argument.chars().rev().collect::<String>(),
        "len"       => argument.len().to_string(),
        "prefix"    => format!("+1{}", argument),
        _ => {
            opensips_log!(WARN, "rust-script",
                "variable_exchange: unknown command '{}'", command);
            let _ = msg.set_pv("$var(rc)", "error");
            let _ = msg.set_pv("$var(output)", "");
            return -1;
        }
    };

    // ── Step 4: Write results back to config ──
    // After rust_exec() returns, the config can read $var(output) and $var(rc).
    if let Err(e) = msg.set_pv("$var(output)", &result) {
        opensips_log!(ERR, "rust-script",
            "variable_exchange: set $var(output) failed: {}", e);
        let _ = msg.set_pv("$var(rc)", "error");
        return -1;
    }
    if let Err(e) = msg.set_pv("$var(rc)", "ok") {
        opensips_log!(ERR, "rust-script",
            "variable_exchange: set $var(rc) failed: {}", e);
        return -1;
    }

    opensips_log!(INFO, "rust-script",
        "variable_exchange: {}({}) = {}", command, argument, result);
    1
});


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Handler 13: call_counter
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PURPOSE: Persistent per-worker request counter. Demonstrates state that
//          survives across SIP transactions and writes the count back to
//          the config via $var(count).
//
//          Unlike the HashMap-based handlers, this shows the simplest
//          possible thread_local state: a single integer.
//
// RUST CONCEPTS:
//   - `thread_local! { static COUNT: RefCell<u64> }`: the simplest
//     thread_local pattern — just a counter instead of a HashMap.
//   - `*c += 1`: dereference and increment. The `*` operator dereferences
//     the RefMut<u64> to get at the u64 inside.
//   - `u64::to_string()`: convert number to string for PV write.
//     PVs are string-based, so numeric values need conversion.
//
// SIP CONCEPTS: per-worker statistics, $var() output
// USAGE:
//   rust_exec("call_counter");
//   xlog("this worker has processed $var(count) requests\n");
//
//   With optional param (counter name stored in $var(counter_name)):
//   rust_exec("call_counter", "invites");
//   xlog("counter '$var(counter_name)' = $var(count)\n");
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

thread_local! {
    /// Named counters: param → count. Each worker has independent counters.
    /// Using HashMap lets you track multiple named counters in one handler.
    static COUNTERS: RefCell<HashMap<String, u64>> =
        RefCell::new(HashMap::with_capacity(8));
}

opensips_handler!(call_counter, |msg, param| {
    // Use the param as the counter name, default to "default".
    let name = param.unwrap_or("default");

    // Increment the named counter and get the new value.
    let count = COUNTERS.with(|counters| {
        let mut counters = counters.borrow_mut();
        // entry() + or_insert(0): create counter at 0 if new.
        let c = counters.entry(name.to_string()).or_insert(0);
        *c += 1; // dereference RefMut to increment the u64
        *c       // return the new count
    });

    // Write results back to config PVs.
    let count_str = count.to_string();
    if let Err(e) = msg.set_pv("$var(count)", &count_str) {
        opensips_log!(ERR, "rust-script",
            "call_counter: set $var(count) failed: {}", e);
        return -1;
    }

    // Also write the counter name so config can log it.
    if let Err(e) = msg.set_pv("$var(counter_name)", name) {
        opensips_log!(ERR, "rust-script",
            "call_counter: set $var(counter_name) failed: {}", e);
    }

    opensips_log!(DBG, "rust-script",
        "call_counter: {}={}", name, count);
    1
});


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Handler 14: shared_counter
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PURPOSE: Truly atomic cross-worker request counter.
//
//          Unlike call_counter (handler 13) which uses thread_local! and gives
//          each worker its own independent counter, this handler increments a
//          counter in OpenSIPS SHARED MEMORY — visible to ALL worker processes
//          simultaneously, using a hardware atomic instruction.
//
// HOW OPENSIPS MEMORY WORKS:
//   After startup, OpenSIPS forks worker processes. Each worker has:
//     - Private memory (pkg): per-worker, fast, no locking needed
//     - Shared memory (shm): visible to all workers, allocated via shm_malloc
//
//   thread_local!/RefCell  → private memory (per-worker, isolated)
//   SharedAtomicCounter    → shared memory (all workers, truly atomic)
//
// WHY NOT $shv()?
//   $shv() (from cfgutils) supports read/write but the read → increment →
//   write sequence is NOT atomic across workers:
//
//     Worker A reads: 42       Worker B reads: 42
//     Worker A writes: 43      Worker B writes: 43  ← LOST ONE COUNT!
//
//   SharedAtomicCounter uses AtomicI64::fetch_add which compiles to a
//   single `lock xadd` CPU instruction — truly atomic across all workers:
//
//     Worker A: fetch_add(1) → 43   Worker B: fetch_add(1) → 44  ← CORRECT!
//
//   No locks, no syscalls, one CPU instruction. This is impossible in
//   Python/Lua/Perl modules.
//
// HOW THIS HANDLER WORKS:
//   The compiled-in rust module allocates the counter in shared memory
//   during mod_init (before fork). This handler calls the compiled-in
//   rust_counter_inc() function via msg.call(), which atomically
//   increments the shared counter and sets $var(shared_count).
//
// RUST CONCEPTS:
//   - `msg.call_str("rust_counter_inc", &[])` → calls a compiled-in function
//     from a user script. The compiled-in function uses AtomicI64 in shm.
//   - Cross-crate patterns: SDK provides SharedAtomicCounter, the compiled-in
//     module uses it, user scripts call the function via msg.call_str().
//
// SIP CONCEPTS: cross-worker shared state, atomic counters
// USAGE:        rust_exec("shared_counter")
//   OR directly in config: rust_counter_inc()
//
// COMPARE WITH call_counter (handler 13):
//   call_counter:   thread_local! → per-worker → worker A=100, B=95, C=105
//   shared_counter: shm AtomicI64 → all workers → total=300 (exact, atomic)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
opensips_handler!(shared_counter, |msg, _param| {
    // Call the compiled-in rust_counter_inc function.
    // This function:
    //   1. Uses AtomicI64::fetch_add(1) in shared memory (truly atomic)
    //   2. Sets $var(shared_count) with the new value
    //
    // msg.call() dispatches to any loaded module function by name.
    // Since rust_counter_inc is registered in the rust module's CMDS array,
    // it's callable from user scripts just like sl_send_reply or append_hf.
    match msg.call_str("rust_counter_inc", &[]) {
        Ok(_) => {
            opensips_log!(DBG, "rust-script", "shared_counter: incremented (atomic)");
            1
        }
        Err(e) => {
            opensips_log!(ERR, "rust-script",
                "shared_counter: rust_counter_inc failed: {}", e);
            -1
        }
    }
});


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Handler 15: pv_manipulation
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PURPOSE: Pseudo-variable read/write stress test.
//          Increments an integer counter each call and cycles a string PV
//          through varying lengths (short → long → short). This exercises
//          OpenSIPS's PV memory allocator across thousands of calls — any
//          leak or buffer overflow will show up as memory growth or a crash.
//
// MEMORY STRESS STRATEGY:
//   On each call:
//   1. Read $var(pv_counter) (integer) → increment → write back.
//   2. Based on the counter, write a string PV whose length CYCLES:
//        counter % 20 < 10:  length grows from 8 to 2048 bytes
//        counter % 20 >= 10: length shrinks from 2048 back to 8 bytes
//      This forces OpenSIPS to repeatedly reallocate the PV string buffer
//      to larger sizes, then to smaller sizes, then larger again — the
//      exact pattern that exposes realloc leaks and off-by-one overflows.
//   3. Read back both values to verify the round-trip.
//
// OPENSIPS PV TYPES:
//   $var(name)  — Script variables. Route-scoped: live only during the
//                 current route execution. Fastest, no shared-memory cost.
//   $ru         — Request-URI (writable). Changes where the request goes.
//   $rd         — R-URI domain part (read-only via pv()).
//   $rU         — R-URI user part (read-only via pv()).
//   $du         — Destination URI (writable). Overrides routing.
//   $si / $sp   — Source IP / source port (read-only).
//
// THREE WAYS TO READ PVs:
//   1. msg.pv("$var(x)")      → Option<String>
//      Uses pv_parse_format + pv_printf. Handles format strings like
//      "$fU@$fd" (concatenation). Always returns a string.
//
//   2. msg.pv_get("$var(x)")  → Option<PvValue>
//      Uses pv_parse_spec + pv_get_spec_value. Returns the RAW value:
//      PvValue::Int(42), PvValue::Str("text"), or PvValue::Null.
//      Use this when you need to know the TYPE of the value.
//
//   3. msg.header("Name")     → Option<&str>
//      Direct header access (not a PV). Faster for known headers.
//
// TWO WAYS TO WRITE PVs:
//   1. msg.set_pv("$var(x)", "text")  → Result<(), Error>
//      Writes a string value. PV_VAL_STR flag.
//
//   2. msg.set_pv_int("$var(x)", 42)  → Result<(), Error>
//      Writes an integer value. PV_VAL_INT flag. Needed when downstream
//      code expects an integer (e.g., arithmetic in config).
//
// RUST CONCEPTS:
//   - `PvValue` enum: Rust's algebraic data types. Like C unions but
//     type-safe — the compiler tracks which variant is active.
//   - `match` on PvValue: exhaustive pattern matching on enum variants.
//   - `"X".repeat(n)`: creates a String of n copies of "X".
//   - `thread_local!` counter to track calls across the per-worker lifetime.
//
// SIP CONCEPTS: pseudo-variable system, $var vs $avp vs core PVs
// USAGE:
//   $var(pv_counter) = 0;   # optional — Rust reads and increments
//   rust_exec("pv_manipulation");
//   # After: $var(pv_counter) = N (incremented)
//   #         $var(pv_str) = variable-length string (8 to 2048 bytes)
//   #         $var(pv_str_len) = length of $var(pv_str) as integer
//   #         $var(pv_type) = "string"/"integer"/"null"/"unset"
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

thread_local! {
    /// Per-worker call counter for pv_manipulation. Used to cycle the
    /// string length so each request gets a different-sized PV value.
    static PV_CALL_COUNT: RefCell<u32> = RefCell::new(0);
}

/// String length schedule: cycles through 20 steps.
/// Steps 0-9:  grow from 8 → 2048 bytes (exponential-ish)
/// Steps 10-19: shrink from 2048 → 8 bytes
/// This pattern maximizes realloc churn in OpenSIPS's PV string buffers.
fn pv_string_length(counter: u32) -> usize {
    // Lengths: 8, 16, 32, 64, 128, 256, 512, 1024, 1536, 2048,
    //          2048, 1536, 1024, 512, 256, 128, 64, 32, 16, 8
    const LENGTHS: [usize; 20] = [
        8, 16, 32, 64, 128, 256, 512, 1024, 1536, 2048,
        2048, 1536, 1024, 512, 256, 128, 64, 32, 16, 8,
    ];
    LENGTHS[(counter % 20) as usize]
}

opensips_handler!(pv_manipulation, |msg, _param| {
    // ── 1. Increment the per-worker call counter ──
    let counter = PV_CALL_COUNT.with(|c| {
        let mut count = c.borrow_mut();
        *count += 1;
        *count
    });

    // ── 2. Read $var(pv_counter) from config, increment, write back ──
    // pv_get() returns the raw PvValue — we extract the integer if present.
    // On first call, $var(pv_counter) may be unset (Null) or 0.
    let prev_counter = match msg.pv_get("$var(pv_counter)") {
        Some(PvValue::Int(n)) => n,
        Some(PvValue::Str(ref s)) => s.parse::<i32>().unwrap_or(0),
        _ => 0,
    };
    let new_counter = prev_counter + 1;

    // Write back as integer — config can do arithmetic on this:
    //   if ($var(pv_counter) > 100) { ... }
    if let Err(e) = msg.set_pv_int("$var(pv_counter)", new_counter) {
        opensips_log!(ERR, "rust-script",
            "pv_manipulation: set $var(pv_counter) failed: {}", e);
        return -1;
    }

    // ── 3. Write a variable-length string PV ──
    // The length cycles through the schedule, forcing OpenSIPS to
    // repeatedly grow and shrink the PV string buffer. If there's a
    // memory leak in the realloc path, VmRSS will grow steadily.
    let str_len = pv_string_length(counter);
    let payload = "X".repeat(str_len);

    if let Err(e) = msg.set_pv("$var(pv_str)", &payload) {
        opensips_log!(ERR, "rust-script",
            "pv_manipulation: set $var(pv_str) failed (len={}): {}", str_len, e);
        return -1;
    }

    // Write the length as an integer PV so the config can verify.
    if let Err(e) = msg.set_pv_int("$var(pv_str_len)", str_len as i32) {
        opensips_log!(ERR, "rust-script",
            "pv_manipulation: set $var(pv_str_len) failed: {}", e);
        return -1;
    }

    // ── 4. Read back and verify ──
    // Round-trip: Rust writes → OpenSIPS stores → Rust reads.
    let readback = msg.pv("$var(pv_str)").unwrap_or_default();
    if readback.len() != str_len {
        opensips_log!(ERR, "rust-script",
            "pv_manipulation: MISMATCH wrote {} bytes, read back {} bytes",
            str_len, readback.len());
        return -1;
    }

    // Also read back the counter to verify integer round-trip.
    let counter_readback = match msg.pv_get("$var(pv_counter)") {
        Some(PvValue::Int(n)) => n,
        Some(PvValue::Str(ref s)) => s.parse::<i32>().unwrap_or(-1),
        _ => -1,
    };
    if counter_readback != new_counter {
        opensips_log!(ERR, "rust-script",
            "pv_manipulation: counter MISMATCH wrote {}, read back {}",
            new_counter, counter_readback);
        return -1;
    }

    // ── 5. Also inspect type of $var(pv_input) from config if set ──
    let input_type = match msg.pv_get("$var(pv_input)") {
        Some(PvValue::Str(_)) => "string",
        Some(PvValue::Int(_)) => "integer",
        Some(PvValue::Null)   => "null",
        None                  => "unset",
    };
    if let Err(e) = msg.set_pv("$var(pv_type)", input_type) {
        opensips_log!(ERR, "rust-script",
            "pv_manipulation: set $var(pv_type) failed: {}", e);
        return -1;
    }

    opensips_log!(DBG, "rust-script",
        "pv_manipulation: counter={} str_len={} input_type={}",
        new_counter, str_len, input_type);
    1
});


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Handler 16: avp_operations
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PURPOSE: AVP read/write stress test with integer increment and
//          variable-length string cycling. AVPs are THE critical mechanism
//          for passing data across SIP transaction boundaries.
//
// MEMORY STRESS STRATEGY:
//   On each call:
//   1. Increment an integer AVP ($avp(rust_seq)) — tests integer PV path.
//   2. Write a variable-length string AVP that cycles 8 → 2048 → 8 bytes,
//      same pattern as pv_manipulation but through the AVP allocator
//      (linked-list backed, different code path than $var()).
//   3. Stack multiple AVPs on $avp(rust_tag) — tests LIFO stack alloc/free.
//   4. Read back all values to verify integrity.
//
// $avp(name) vs $var(name) — WHEN TO USE EACH:
//
//   ┌─────────────┬──────────────────────────────────┬────────────────────────────┐
//   │ Feature     │ $var(name)                       │ $avp(name)                 │
//   ├─────────────┼──────────────────────────────────┼────────────────────────────┤
//   │ Scope       │ Current route execution ONLY     │ Full SIP transaction       │
//   │ Lifetime    │ Dies when route{} ends           │ Lives through t_relay(),   │
//   │             │                                  │ failure_route, onreply     │
//   │ Memory      │ Private (pkg), per-worker        │ Private (pkg), per-worker  │
//   │ Stacking    │ No (single value)                │ YES — multiple values per  │
//   │             │                                  │ name, LIFO stack           │
//   │ Speed       │ Fastest                          │ Slightly slower (linked    │
//   │             │                                  │ list traversal)            │
//   │ Use case    │ Scratch variables within a route │ Data that must survive     │
//   │             │                                  │ t_relay / failure_route    │
//   └─────────────┴──────────────────────────────────┴────────────────────────────┘
//
// CRITICAL SIP USE CASES FOR AVPs:
//   - Store caller info before t_relay(), read it in failure_route
//   - Tag calls with metadata that onreply_route can see
//   - Accumulate multiple values (e.g., Via hop list) via AVP stacking
//   - Pass routing decisions from request processing to reply handling
//
// AVP STACKING:
//   Writing $avp(x) multiple times creates a LIFO stack:
//     set_pv("$avp(x)", "first");
//     set_pv("$avp(x)", "second");
//     set_pv("$avp(x)", "third");
//   Reading $avp(x) returns "third" (top of stack).
//   In config: $(avp(x)[0]) = "third", $(avp(x)[1]) = "second", etc.
//
// RUST CONCEPTS:
//   - Same set_pv()/set_pv_int()/pv()/pv_get() API works for AVPs.
//   - `"Y".repeat(n)` for variable-length string generation.
//   - AVPs are allocated from pkg memory per-request and freed when the
//     transaction completes — different lifecycle than $var().
//
// SIP CONCEPTS: AVP lifecycle, transaction scope, t_relay, failure_route
// USAGE:
//   rust_exec("avp_operations");
//   # After: $avp(rust_seq) = N (incremented integer)
//   #         $avp(rust_caller_ip) = source IP
//   #         $avp(rust_call_type) = "invite"/"register"/"other"
//   #         $avp(rust_payload) = variable-length string (8-2048 bytes)
//   #         $avp(rust_tag) = stacked: param value, "rust-module"
//
//   # These AVPs survive t_relay() and are readable in failure_route:
//   failure_route[1] {
//       xlog("caller=$avp(rust_caller_ip) seq=$avp(rust_seq)\n");
//   }
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

thread_local! {
    /// Per-worker AVP call counter. Used to cycle the string length
    /// through the same schedule as pv_manipulation.
    static AVP_CALL_COUNT: RefCell<u32> = RefCell::new(0);
}

opensips_handler!(avp_operations, |msg, param| {
    // ── 1. Increment per-worker counter (controls string length cycle) ──
    let counter = AVP_CALL_COUNT.with(|c| {
        let mut count = c.borrow_mut();
        *count += 1;
        *count
    });

    // ── 2. Increment integer AVP ──
    // Read $avp(rust_seq) from previous stacking (if any), increment, write.
    // pv_get returns the TOP of the AVP stack.
    let prev_seq = match msg.pv_get("$avp(rust_seq)") {
        Some(PvValue::Int(n)) => n,
        Some(PvValue::Str(ref s)) => s.parse::<i32>().unwrap_or(0),
        _ => 0,
    };
    let new_seq = prev_seq + 1;

    if let Err(e) = msg.set_pv_int("$avp(rust_seq)", new_seq) {
        opensips_log!(ERR, "rust-script",
            "avp_operations: set $avp(rust_seq) failed: {}", e);
        return -1;
    }

    // ── 3. Write caller info AVPs ──
    let src_ip = msg.source_ip();
    if let Err(e) = msg.set_pv("$avp(rust_caller_ip)", &src_ip) {
        opensips_log!(ERR, "rust-script",
            "avp_operations: set $avp(rust_caller_ip) failed: {}", e);
        return -1;
    }

    let method = msg.method().unwrap_or("").to_string();
    let call_type = match method.as_str() {
        "INVITE"   => "invite",
        "REGISTER" => "register",
        "OPTIONS"  => "options",
        "BYE"      => "bye",
        "CANCEL"   => "cancel",
        "ACK"      => "ack",
        _          => "other",
    };
    if let Err(e) = msg.set_pv("$avp(rust_call_type)", call_type) {
        opensips_log!(ERR, "rust-script",
            "avp_operations: set $avp(rust_call_type) failed: {}", e);
        return -1;
    }

    // ── 4. Variable-length string AVP (memory stress) ──
    // Uses the same length schedule as pv_manipulation but through the
    // AVP allocator. AVPs use a per-transaction linked list in pkg memory,
    // which is a DIFFERENT allocation path than $var() storage.
    let str_len = pv_string_length(counter);
    let payload = "Y".repeat(str_len);

    if let Err(e) = msg.set_pv("$avp(rust_payload)", &payload) {
        opensips_log!(ERR, "rust-script",
            "avp_operations: set $avp(rust_payload) failed (len={}): {}", str_len, e);
        return -1;
    }

    // ── 5. AVP stacking — multiple writes create a LIFO stack ──
    if let Err(e) = msg.set_pv("$avp(rust_tag)", "rust-module") {
        opensips_log!(ERR, "rust-script",
            "avp_operations: set $avp(rust_tag) base failed: {}", e);
        return -1;
    }
    let tag = param.unwrap_or("processed");
    if let Err(e) = msg.set_pv("$avp(rust_tag)", tag) {
        opensips_log!(ERR, "rust-script",
            "avp_operations: set $avp(rust_tag) top failed: {}", e);
        return -1;
    }

    // ── 6. Read back and verify ──
    let readback_payload = msg.pv("$avp(rust_payload)").unwrap_or_default();
    if readback_payload.len() != str_len {
        opensips_log!(ERR, "rust-script",
            "avp_operations: MISMATCH wrote {} bytes, read back {} bytes",
            str_len, readback_payload.len());
        return -1;
    }

    let readback_seq = match msg.pv_get("$avp(rust_seq)") {
        Some(PvValue::Int(n)) => n,
        _ => -1,
    };
    if readback_seq != new_seq {
        opensips_log!(ERR, "rust-script",
            "avp_operations: seq MISMATCH wrote {}, read back {}",
            new_seq, readback_seq);
        return -1;
    }

    opensips_log!(DBG, "rust-script",
        "avp_operations: seq={} type={} str_len={} tag={}",
        new_seq, call_type, str_len, tag);
    1
});


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Handler 17: pv_edge_cases
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PURPOSE: Test robustness against PV/AVP edge cases that would crash a
//          naive C module. The config INTENTIONALLY feeds bad/missing data
//          to this handler, and Rust must handle every case gracefully —
//          no crashes, no undefined behavior, clear error reporting.
//
// EDGE CASES TESTED:
//   1. Deleted AVP — config creates $avp(edge_test), sets it to $null,
//      then calls this handler. pv_get() must return Null, not crash.
//   2. Never-set PV — reading $var(nonexistent) must return None.
//   3. Empty string PV — $var(edge_empty) = "" must return Some("").
//   4. Very long string — write a 3800-byte string (near the 4096-byte
//      pv_printf buffer limit) and verify it round-trips correctly.
//   5. Integer overflow — write i32::MAX (2147483647) and read it back.
//   6. Negative integer — write -1 and read it back.
//   7. Writing to read-only PV — attempt set_pv on $ci (Call-ID),
//      which is read-only. Must return Err, not crash.
//   8. Invalid PV spec — attempt to read "$invalid(" (malformed).
//      Must return None, not crash.
//
// WHY THIS MATTERS:
//   In C, any of these cases could produce a segfault, buffer overflow,
//   or undefined behavior. In Rust, the type system (Option, Result)
//   forces you to handle every case. This handler PROVES that the SDK's
//   PV wrappers are defensive against every edge case OpenSIPS can throw.
//
// RUST CONCEPTS:
//   - `Option::is_none()` / `Option::is_some()` for presence checks
//   - `Result::is_err()` for expected failure detection
//   - `match` with `PvValue::Null` arm for deleted/unset PVs
//   - `i32::MAX`, `i32::MIN` for integer boundary testing
//   - Defensive programming: test failures you EXPECT, don't just
//     test the happy path.
//
// SIP CONCEPTS: PV lifecycle, $null assignment, read-only PVs
// USAGE:
//   In opensips.cfg:
//     # Set up edge cases BEFORE calling the handler
//     $avp(edge_test) = "exists";
//     $avp(edge_test) = NULL;      # delete it
//     rust_exec("pv_edge_cases");
//     # After: $var(edge_result) = "pass" or details about what failed
//     #         $var(edge_checks) = number of checks passed (integer)
//
//   NOTE: OpenSIPS config parser doesn't support empty string literals ("").
//   The handler writes and tests empty strings from Rust itself.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
opensips_handler!(pv_edge_cases, |msg, _param| {
    let mut passed = 0i32;
    let mut failed = 0i32;

    // Helper: log a check result. Can't use a closure that captures &mut msg
    // because of borrow rules, so we track pass/fail with plain integers.

    // ── 1. Deleted AVP (set to $null by config) ──
    // The config should have done: $avp(edge_test) = "exists"; $avp(edge_test) = NULL;
    // After deletion, pv_get must return Null or None, never crash.
    match msg.pv_get("$avp(edge_test)") {
        Some(PvValue::Null) | None => {
            opensips_log!(DBG, "rust-script",
                "pv_edge_cases: [PASS] deleted AVP returned Null/None");
            passed += 1;
        }
        Some(other) => {
            opensips_log!(ERR, "rust-script",
                "pv_edge_cases: [FAIL] deleted AVP returned {:?} (expected Null/None)", other);
            failed += 1;
        }
    }

    // Also test pv() (format-string path) on the deleted AVP.
    // Should return None or an empty string.
    match msg.pv("$avp(edge_test)") {
        None => {
            opensips_log!(DBG, "rust-script",
                "pv_edge_cases: [PASS] pv() on deleted AVP returned None");
            passed += 1;
        }
        Some(ref s) if s.is_empty() => {
            opensips_log!(DBG, "rust-script",
                "pv_edge_cases: [PASS] pv() on deleted AVP returned empty string");
            passed += 1;
        }
        Some(ref s) => {
            opensips_log!(ERR, "rust-script",
                "pv_edge_cases: [FAIL] pv() on deleted AVP returned \"{}\"", s);
            failed += 1;
        }
    }

    // ── 2. Never-set PV ──
    // $var(pv_never_set_xyzzy) was never assigned in config or Rust.
    match msg.pv_get("$var(pv_never_set_xyzzy)") {
        Some(PvValue::Null) | None => {
            opensips_log!(DBG, "rust-script",
                "pv_edge_cases: [PASS] never-set PV returned Null/None");
            passed += 1;
        }
        Some(other) => {
            opensips_log!(ERR, "rust-script",
                "pv_edge_cases: [FAIL] never-set PV returned {:?}", other);
            failed += 1;
        }
    }

    // ── 3. Empty string PV ──
    // OpenSIPS config parser doesn't support "" literals, so we write
    // an empty string from Rust and test the round-trip.
    if let Err(e) = msg.set_pv("$var(edge_empty)", "") {
        opensips_log!(ERR, "rust-script",
            "pv_edge_cases: [FAIL] writing empty string failed: {}", e);
        failed += 1;
    } else {
        match msg.pv("$var(edge_empty)") {
            Some(ref s) if s.is_empty() => {
                opensips_log!(DBG, "rust-script",
                    "pv_edge_cases: [PASS] empty string round-trip OK");
                passed += 1;
            }
            None => {
                // OpenSIPS may treat empty strings as NULL internally
                opensips_log!(DBG, "rust-script",
                    "pv_edge_cases: [PASS] empty string returned None (OS treats empty as null)");
                passed += 1;
            }
            Some(ref s) => {
                opensips_log!(ERR, "rust-script",
                    "pv_edge_cases: [FAIL] empty string PV returned \"{}\"", s);
                failed += 1;
            }
        }
    }

    // ── 4. Near-limit string (3800 bytes, close to 4096 buffer) ──
    let long_str = "Z".repeat(3800);
    if let Err(e) = msg.set_pv("$var(edge_long)", &long_str) {
        opensips_log!(ERR, "rust-script",
            "pv_edge_cases: [FAIL] set 3800-byte string failed: {}", e);
        failed += 1;
    } else {
        let readback = msg.pv("$var(edge_long)").unwrap_or_default();
        if readback.len() == 3800 {
            opensips_log!(DBG, "rust-script",
                "pv_edge_cases: [PASS] 3800-byte string round-trip OK");
            passed += 1;
        } else {
            opensips_log!(ERR, "rust-script",
                "pv_edge_cases: [FAIL] 3800-byte string: wrote 3800, got {} back",
                readback.len());
            failed += 1;
        }
    }

    // ── 5. Integer boundary: i32::MAX (2147483647) ──
    if let Err(e) = msg.set_pv_int("$var(edge_max_int)", i32::MAX) {
        opensips_log!(ERR, "rust-script",
            "pv_edge_cases: [FAIL] set i32::MAX failed: {}", e);
        failed += 1;
    } else {
        match msg.pv_get("$var(edge_max_int)") {
            Some(PvValue::Int(n)) if n == i32::MAX => {
                opensips_log!(DBG, "rust-script",
                    "pv_edge_cases: [PASS] i32::MAX round-trip OK ({})", n);
                passed += 1;
            }
            other => {
                opensips_log!(ERR, "rust-script",
                    "pv_edge_cases: [FAIL] i32::MAX readback: {:?}", other);
                failed += 1;
            }
        }
    }

    // ── 6. Negative integer: -1 ──
    if let Err(e) = msg.set_pv_int("$var(edge_neg)", -1) {
        opensips_log!(ERR, "rust-script",
            "pv_edge_cases: [FAIL] set -1 failed: {}", e);
        failed += 1;
    } else {
        match msg.pv_get("$var(edge_neg)") {
            Some(PvValue::Int(-1)) => {
                opensips_log!(DBG, "rust-script",
                    "pv_edge_cases: [PASS] -1 round-trip OK");
                passed += 1;
            }
            other => {
                opensips_log!(ERR, "rust-script",
                    "pv_edge_cases: [FAIL] -1 readback: {:?}", other);
                failed += 1;
            }
        }
    }

    // ── 7. Write to read-only PV ($ci = Call-ID) ──
    // This MUST return Err (NotWritable), not crash.
    match msg.set_pv("$ci", "fake-call-id") {
        Err(_) => {
            opensips_log!(DBG, "rust-script",
                "pv_edge_cases: [PASS] writing $ci correctly returned Err");
            passed += 1;
        }
        Ok(()) => {
            opensips_log!(ERR, "rust-script",
                "pv_edge_cases: [FAIL] writing $ci succeeded (should be read-only!)");
            failed += 1;
        }
    }

    // ── 8. Malformed PV spec ──
    // "$invalid(" is not a valid PV specifier. Must return None, not crash.
    match msg.pv("$invalid(") {
        None => {
            opensips_log!(DBG, "rust-script",
                "pv_edge_cases: [PASS] malformed PV spec returned None");
            passed += 1;
        }
        Some(ref s) if s.is_empty() => {
            opensips_log!(DBG, "rust-script",
                "pv_edge_cases: [PASS] malformed PV spec returned empty (acceptable)");
            passed += 1;
        }
        Some(ref s) => {
            opensips_log!(ERR, "rust-script",
                "pv_edge_cases: [FAIL] malformed PV spec returned \"{}\"", s);
            failed += 1;
        }
    }

    // ── 9. Write to deleted AVP (overwrite after $null) ──
    // After the config deletes $avp(edge_test), we should be able to
    // write a new value to it and read it back successfully.
    if let Err(e) = msg.set_pv("$avp(edge_test)", "resurrected") {
        opensips_log!(ERR, "rust-script",
            "pv_edge_cases: [FAIL] writing to deleted AVP failed: {}", e);
        failed += 1;
    } else {
        match msg.pv("$avp(edge_test)") {
            Some(ref s) if s == "resurrected" => {
                opensips_log!(DBG, "rust-script",
                    "pv_edge_cases: [PASS] re-wrote deleted AVP successfully");
                passed += 1;
            }
            other => {
                opensips_log!(ERR, "rust-script",
                    "pv_edge_cases: [FAIL] re-wrote deleted AVP but readback = {:?}", other);
                failed += 1;
            }
        }
    }

    // ── Write results back to config ──
    let total = passed + failed;
    if let Err(e) = msg.set_pv_int("$var(edge_checks)", total) {
        opensips_log!(ERR, "rust-script",
            "pv_edge_cases: set $var(edge_checks) failed: {}", e);
    }

    let result = if failed == 0 { "pass" } else { "fail" };
    if let Err(e) = msg.set_pv("$var(edge_result)", result) {
        opensips_log!(ERR, "rust-script",
            "pv_edge_cases: set $var(edge_result) failed: {}", e);
    }

    opensips_log!(INFO, "rust-script",
        "pv_edge_cases: {}/{} checks passed ({})",
        passed, total, result);

    // Return -1 if ANY check failed — the config can detect this.
    if failed > 0 { -1 } else { 1 }
});


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Handler 18: http_query
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PURPOSE: Call an external HTTP service and return the response data to
//          OpenSIPS via pseudo-variables. Demonstrates making network calls
//          from Rust using only the standard library (zero external deps).
//
// HOW IT WORKS:
//   1. Parse the URL into host:port + path
//   2. Open a raw TCP connection with a timeout
//   3. Send an HTTP/1.0 GET request
//   4. Read the response, parse status code and body
//   5. Write results to $var(http_status), $var(http_body),
//      $var(http_time_ms), $var(http_error)
//
// WHY RAW TCP INSTEAD OF A LIBRARY:
//   Using std::net::TcpStream directly means zero external dependencies.
//   This is intentional for a teaching example — it shows exactly what an
//   HTTP request looks like at the wire level. For production use, you'd
//   add `ureq` or `reqwest` to Cargo.toml for HTTPS, connection pooling,
//   redirects, and proper header parsing.
//
// BLOCKING vs ASYNC:
//   This handler blocks the OpenSIPS worker process while the HTTP call
//   completes. For true non-blocking behavior, you'd need to integrate
//   with OpenSIPS's async() framework at the compiled-in module level.
//   A 2-second timeout prevents the worker from being blocked too long.
//
//   In opensips.cfg, you can wrap the call in async() if the compiled-in
//   module supports it:
//     async(rust_exec("http_query", "http://api.example.com/data"), resume);
//
// RUST CONCEPTS:
//   - `std::net::TcpStream`: raw TCP socket from the standard library.
//   - `Read` and `Write` traits: Rust's I/O abstraction. Any type that
//     implements Read can be read from; any that implements Write can be
//     written to. TcpStream implements both.
//   - `Result` chaining with `map_err()`: convert library errors into
//     our own error strings without nested match blocks.
//   - `Duration` for timeouts: type-safe time representation.
//   - `split_once()`: split a string at the first occurrence of a char.
//     Returns Option<(&str, &str)> — None if the char isn't found.
//
// SIP CONCEPTS: external service integration, $var() output
// USAGE:
//   rust_exec("http_query", "http://httpbin.org/get");
//   # After: $var(http_status) = 200
//   #         $var(http_body) = response body (truncated to 3800 bytes)
//   #         $var(http_time_ms) = elapsed milliseconds
//   #         $var(http_error) = "" on success, error message on failure
//
//   # Or read URL from a PV:
//   $var(http_url) = "http://10.0.0.5:8080/api/lookup";
//   rust_exec("http_query", "$var(http_url)");
//
//   # Without a URL parameter, writes placeholder results (for testing):
//   rust_exec("http_query");
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Make a raw HTTP/1.0 GET request using only std::net.
/// Returns (status_code, body) on success, or an error string.
///
/// HTTP/1.0 (not 1.1) because the server closes the connection after the
/// response, so we know when we've read everything. No chunked encoding
/// to worry about.
fn simple_http_get(url: &str, timeout_secs: u64) -> Result<(u16, String), String> {
    // ── Parse URL ──
    // Only supports http:// (no TLS). For HTTPS, use ureq or reqwest.
    let rest = url.strip_prefix("http://")
        .ok_or_else(|| "only http:// URLs supported (no TLS in std)".to_string())?;

    // Split host:port from path at the first '/'
    let (host_port, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp, format!("/{}", p)),
        None => (rest, "/".to_string()),
    };

    // Split host from port (default 80)
    let (host, port) = match host_port.split_once(':') {
        Some((h, p)) => {
            let port = p.parse::<u16>().map_err(|e| format!("bad port: {}", e))?;
            (h, port)
        }
        None => (host_port, 80u16),
    };

    // ── Connect with timeout ──
    // TcpStream::connect() does DNS resolution + TCP handshake.
    // We set read/write timeouts after connecting.
    let timeout = Duration::from_secs(timeout_secs);
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect(&addr)
        .map_err(|e| format!("connect to {} failed: {}", addr, e))?;

    stream.set_read_timeout(Some(timeout))
        .map_err(|e| format!("set read timeout: {}", e))?;
    stream.set_write_timeout(Some(timeout))
        .map_err(|e| format!("set write timeout: {}", e))?;

    // ── Send HTTP/1.0 request ──
    // HTTP/1.0 means the server will close the connection after the
    // response. This simplifies reading — we just read until EOF.
    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: opensips-rust/1.0\r\nAccept: */*\r\n\r\n",
        path, host
    );
    stream.write_all(request.as_bytes())
        .map_err(|e| format!("write request: {}", e))?;

    // ── Read response ──
    // Read everything into a String. The server closes the connection
    // when done (HTTP/1.0), so read_to_string returns when EOF is hit.
    let mut response = String::new();
    stream.read_to_string(&mut response)
        .map_err(|e| format!("read response: {}", e))?;

    // ── Parse status line ──
    // First line: "HTTP/1.0 200 OK\r\n"
    let status_line = response.lines().next()
        .ok_or_else(|| "empty response".to_string())?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("bad status line: {}", status_line))?;

    // ── Extract body (after blank line) ──
    // HTTP headers end with \r\n\r\n. Everything after that is the body.
    let body = response
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or("")
        .to_string();

    Ok((status_code, body))
}

opensips_handler!(http_query, |msg, param| {
    // ── Get URL from param or $var(http_url) ──
    let url = match param {
        Some(u) if !u.is_empty() => u.to_string(),
        _ => match msg.pv("$var(http_url)") {
            Some(u) if !u.is_empty() => u,
            _ => {
                // No URL provided — write placeholder results.
                // This allows the handler to be called in test configs
                // without making actual HTTP calls.
                let _ = msg.set_pv_int("$var(http_status)", 0);
                let _ = msg.set_pv("$var(http_body)", "");
                let _ = msg.set_pv("$var(http_error)", "no URL: set param or $var(http_url)");
                let _ = msg.set_pv_int("$var(http_time_ms)", 0);
                opensips_log!(DBG, "rust-script",
                    "http_query: no URL provided, skipping");
                return 1; // not an error — just nothing to fetch
            }
        }
    };

    opensips_log!(DBG, "rust-script", "http_query: fetching {}", url);

    // ── Make HTTP GET with 2-second timeout ──
    let start = Instant::now();
    match simple_http_get(&url, 2) {
        Ok((status, body)) => {
            let elapsed_ms = start.elapsed().as_millis() as i32;

            let _ = msg.set_pv_int("$var(http_status)", status as i32);
            // Truncate body to 3800 bytes (pv_printf buffer is 4096)
            let truncated = if body.len() > 3800 { &body[..3800] } else { &body };
            let _ = msg.set_pv("$var(http_body)", truncated);
            let _ = msg.set_pv("$var(http_error)", "");
            let _ = msg.set_pv_int("$var(http_time_ms)", elapsed_ms);

            opensips_log!(INFO, "rust-script",
                "http_query: {} {} ({}ms, {} bytes)",
                url, status, elapsed_ms, body.len());
            1
        }
        Err(e) => {
            let elapsed_ms = start.elapsed().as_millis() as i32;

            let _ = msg.set_pv_int("$var(http_status)", 0);
            let _ = msg.set_pv("$var(http_body)", "");
            let _ = msg.set_pv("$var(http_error)", &e);
            let _ = msg.set_pv_int("$var(http_time_ms)", elapsed_ms);

            opensips_log!(ERR, "rust-script",
                "http_query: {} failed ({}ms): {}", url, elapsed_ms, e);
            -1
        }
    }
});


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Handler 19: json_parse
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PURPOSE: Parse a JSON string and extract fields into PVs. Demonstrates
//          the Rust ecosystem's serde_json crate — the standard for JSON
//          handling in Rust — and how to bridge structured data between
//          OpenSIPS config and Rust.
//
// TWO MODES:
//   1. Config provides JSON via $var(json_input):
//        $var(json_input) = $json(my_data);    # from json.so module
//        rust_exec("json_parse");
//
//   2. No input — handler builds JSON from the SIP message itself:
//        rust_exec("json_parse");
//      This creates JSON like:
//        {"method":"INVITE","src_ip":"10.0.0.1","src_port":5060,
//         "user_agent":"SIPp","call_id":"abc@host"}
//      Then parses it back to prove the round-trip.
//
// WHAT THE HANDLER WRITES TO PVs:
//   $var(json_parsed)  = "yes" if parsing succeeded
//   $var(json_method)  = extracted "method" field (or "N/A")
//   $var(json_src_ip)  = extracted "src_ip" field (or "N/A")
//   $var(json_fields)  = comma-separated list of top-level field names
//   $var(json_raw)     = the JSON string that was parsed (for verification)
//
// RUST CONCEPTS:
//   - `serde_json::Value`: untyped JSON representation. Like a Python dict
//     but type-safe — you can't accidentally treat a string as a number.
//   - `serde_json::from_str()` → `Result<Value, Error>`: parsing that
//     returns a clear error on malformed input instead of crashing.
//   - `value["key"]` indexing returns `Value::Null` for missing keys
//     (never panics, unlike array indexing).
//   - `value.as_str()` → `Option<&str>`: safe downcast from Value to
//     a specific type. Returns None if the value isn't a string.
//   - `value.as_object()` → `Option<&Map>`: access JSON object fields.
//   - External crates: `serde_json` is added to Cargo.toml as a
//     dependency. Rust's package manager (cargo) downloads, compiles,
//     and statically links it into the .so. No runtime dependencies.
//
// SIP CONCEPTS: structured data exchange, JSON module integration
// USAGE:
//   # Mode 1: parse config-provided JSON
//   loadmodule "json.so"
//   $json(data/name) = "Alice";
//   $json(data/age) = 30;
//   $var(json_input) = $json(data);
//   rust_exec("json_parse");
//   xlog("parsed: method=$var(json_method) fields=$var(json_fields)\n");
//
//   # Mode 2: parse SIP message as JSON (self-contained test)
//   rust_exec("json_parse");
//   xlog("fields=$var(json_fields) method=$var(json_method)\n");
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
opensips_handler!(json_parse, |msg, _param| {
    // ── Step 1: Get JSON string ──
    // Try $var(json_input) first (config-provided), else build from SIP msg.
    let json_str = match msg.pv("$var(json_input)") {
        Some(s) if !s.is_empty() => s,
        _ => {
            // Build JSON from SIP message fields.
            // This demonstrates: Rust → JSON → parse → extract → PV.
            // In production, the config would provide the JSON string.
            let method = msg.method().unwrap_or("?").to_string();
            let src_ip = msg.source_ip();
            let src_port = msg.source_port();
            let ua = msg.header("User-Agent").unwrap_or("unknown").to_string();
            let call_id = msg.pv("$ci").unwrap_or_else(|| "?".to_string());

            // serde_json::json! macro builds a Value from literal syntax.
            // This is the idiomatic way to create JSON in Rust.
            let obj = serde_json::json!({
                "method": method,
                "src_ip": src_ip,
                "src_port": src_port,
                "user_agent": ua,
                "call_id": call_id
            });
            obj.to_string()
        }
    };

    // ── Step 2: Parse JSON ──
    // serde_json::from_str returns Result<Value, Error>.
    // On malformed JSON, we get Err with a clear error message
    // (line/column/what was expected) instead of a crash.
    let parsed: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(e) => {
            opensips_log!(ERR, "rust-script",
                "json_parse: invalid JSON: {}", e);
            let _ = msg.set_pv("$var(json_parsed)", "no");
            let _ = msg.set_pv("$var(json_error)", &e.to_string());
            return -1;
        }
    };

    let _ = msg.set_pv("$var(json_parsed)", "yes");

    // ── Step 3: Extract fields ──
    // value["key"] returns &Value. If the key doesn't exist, it returns
    // Value::Null — it NEVER panics. This is safe by design.
    //
    // .as_str() converts Value::String → Option<&str>.
    // Returns None for non-string types (numbers, bools, null).
    let method = parsed["method"].as_str().unwrap_or("N/A");
    let src_ip = parsed["src_ip"].as_str().unwrap_or("N/A");

    if let Err(e) = msg.set_pv("$var(json_method)", method) {
        opensips_log!(ERR, "rust-script",
            "json_parse: set $var(json_method) failed: {}", e);
        return -1;
    }
    if let Err(e) = msg.set_pv("$var(json_src_ip)", src_ip) {
        opensips_log!(ERR, "rust-script",
            "json_parse: set $var(json_src_ip) failed: {}", e);
        return -1;
    }

    // ── Step 4: List all top-level field names ──
    // .as_object() returns Option<&Map<String, Value>>.
    // Map implements Iterator, so we can collect field names.
    let field_names = match parsed.as_object() {
        Some(map) => {
            let names: Vec<&str> = map.keys().map(|k| k.as_str()).collect();
            names.join(",")
        }
        None => {
            // Not a JSON object (could be array, string, etc.)
            "not_an_object".to_string()
        }
    };

    if let Err(e) = msg.set_pv("$var(json_fields)", &field_names) {
        opensips_log!(ERR, "rust-script",
            "json_parse: set $var(json_fields) failed: {}", e);
        return -1;
    }

    // ── Step 5: Write raw JSON back for verification ──
    // Truncate to 3800 bytes for PV buffer safety.
    let raw = if json_str.len() > 3800 { &json_str[..3800] } else { &json_str };
    if let Err(e) = msg.set_pv("$var(json_raw)", raw) {
        opensips_log!(ERR, "rust-script",
            "json_parse: set $var(json_raw) failed: {}", e);
        return -1;
    }

    // ── Step 6: Extract numeric fields to demonstrate type handling ──
    // .as_u64() / .as_i64() / .as_f64() for numeric JSON values.
    if let Some(port) = parsed["src_port"].as_u64() {
        let _ = msg.set_pv_int("$var(json_src_port)", port as i32);
    }

    opensips_log!(INFO, "rust-script",
        "json_parse: fields=[{}] method={} src_ip={}",
        field_names, method, src_ip);
    1
});


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Handler 20: async_http_query
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PURPOSE: Non-blocking HTTP query using OpenSIPS async() framework.
//
//          Unlike handler 18 (http_query) which blocks the SIP worker for
//          the entire duration of the HTTP call, this handler:
//            1. Opens a non-blocking TCP connection
//            2. Sends the HTTP request
//            3. Hands the fd to OpenSIPS's reactor via async_ctx
//            4. Returns immediately — the worker is free for other SIP traffic
//            5. When the HTTP response arrives, the reactor calls our resume
//               function, which reads the data and writes results to PVs
//
// HOW OPENSIPS async() WORKS:
//   The config wraps the call:
//     async(rust_exec("http_query", "http://api.example.com/data"), resume_route);
//
//   The core calls our acmd function. We:
//     - Set async_status = fd (the TCP socket fd)
//     - Set ctx.resume_f = our resume callback
//     - Set ctx.resume_param = our state struct (heap-allocated)
//     - Return 1
//
//   The core adds the fd to the reactor. When the fd becomes readable:
//     - The reactor calls our resume_f(fd, msg, param)
//     - We read the HTTP response, parse it, write PVs
//     - Return ASYNC_DONE (-1) to signal completion
//     - The core runs the resume_route with the updated PVs
//
// RICH RESPONSE DATA:
//   Unlike the sync http_query which sets simple $var() PVs, this handler
//   demonstrates two patterns for returning structured data:
//
//   1. AVP list: Each HTTP response header is stored as a stacked AVP,
//      giving OpenSIPS a list-like data structure:
//        $avp(http_hdr) = "Content-Type: application/json"
//        $avp(http_hdr) = "Server: nginx"
//      The config can iterate with while($avp(http_hdr)).
//
//   2. JSON object: The full response metadata is packed into a JSON string
//      in $var(http_json), which the config can parse with json module or
//      pass directly to other systems:
//        {"status":200,"url":"...","body":"...","headers":{"Content-Type":"..."}}
//
// WHY NOT TOKIO/ASYNC-STD:
//   OpenSIPS IS the event loop. We don't need a Rust async runtime — we just
//   hand an fd to OpenSIPS's reactor and let it notify us when data arrives.
//   Raw std::net::TcpStream in non-blocking mode is all we need.
//
// MEMORY MODEL:
//   The resume parameter (AsyncHttpState) is allocated on the Rust heap via
//   Box::into_raw(). Since async() resumes in the SAME worker process,
//   regular heap memory survives. We recover it in the resume callback via
//   Box::from_raw() — Rust's ownership system ensures exactly one free.
//
// RUST CONCEPTS:
//   - `opensips_async_handler!` macro: like opensips_handler! but with
//     an AsyncContext parameter for setting up non-blocking I/O
//   - `TcpStream::set_nonblocking(true)`: switch socket to non-blocking mode
//   - `AsRawFd::as_raw_fd()`: extract the OS file descriptor from a TcpStream
//   - `Box::into_raw()` / `Box::from_raw()`: transfer ownership across FFI
//   - `std::mem::forget()`: prevent Rust from dropping a value (we need the
//     fd to stay open for the reactor to monitor it)
//
// SIP CONCEPTS: async() statement, resume routes, reactor fd monitoring
// USAGE:
//   async(rust_exec("http_query", "http://127.0.0.1:8080/api"), http_resume);
//   route[http_resume] {
//       xlog("status=$var(http_status) body=$var(http_body)\n");
//       xlog("json=$var(http_json)\n");
//       # Iterate response headers:
//       while ($avp(http_hdr)) {
//           xlog("  header: $avp(http_hdr)\n");
//           $avp(http_hdr) = NULL;  # pop from stack
//       }
//   }
//
//   # Without a URL: completes synchronously (no I/O), resume route still runs
//   async(rust_exec("http_query"), http_resume);
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// State preserved across the async gap between the initial call and the
/// resume callback. Heap-allocated via Box, recovered via Box::from_raw().
struct AsyncHttpState {
    stream: TcpStream,
    url: String,
    start: Instant,
}

/// Resume callback — called by the OpenSIPS reactor when the HTTP response
/// fd becomes readable. Reads the response, parses it, and writes results
/// to PVs and AVPs for the resume route.
///
/// Returns:
///   - ASYNC_DONE (-1): response read and parsed, continue to resume route
///   - ASYNC_CONTINUE (-5): partial read, keep monitoring (not used here
///     because HTTP/1.0 delivers everything before closing the connection)
unsafe extern "C" fn resume_http_query(
    _fd: i32,
    raw_msg: *mut sys::sip_msg,
    param: *mut std::ffi::c_void,
) -> i32 {
    // Recover ownership of the state struct. Box::from_raw() is the inverse
    // of Box::into_raw() — it reconstructs the Box so Rust will free the
    // memory when it goes out of scope.
    let state = Box::from_raw(param as *mut AsyncHttpState);
    let mut msg = SipMessage::from_raw(raw_msg);

    // Read the HTTP response. The stream is non-blocking, but by the time
    // the reactor calls us, data should be available (the fd was readable).
    // We set a short read timeout as a safety net.
    let mut response = String::new();
    let mut stream = state.stream;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));

    let read_result = {
        let mut buf = [0u8; 8192];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,  // EOF — server closed connection (HTTP/1.0)
                Ok(n) => response.push_str(
                    &String::from_utf8_lossy(&buf[..n])
                ),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Non-blocking socket: no more data right now. For HTTP/1.0
                    // with the fd reported as readable, this means we have
                    // everything (or the connection was slow — accept what we got).
                    if !response.is_empty() {
                        break;
                    }
                    // Try once more with a brief blocking read
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                    match stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            response.push_str(&String::from_utf8_lossy(&buf[..n]));
                            let _ = stream.set_nonblocking(true);
                        }
                        Err(_) => break,
                    }
                }
                Err(_) => break,
            }
        }
        Ok::<(), String>(())
    };

    let elapsed_ms = state.start.elapsed().as_millis() as i32;

    if read_result.is_err() || response.is_empty() {
        let _ = msg.set_pv_int("$var(http_status)", 0);
        let _ = msg.set_pv("$var(http_body)", "");
        let _ = msg.set_pv("$var(http_error)", "failed to read response");
        let _ = msg.set_pv_int("$var(http_time_ms)", elapsed_ms);
        let _ = msg.set_pv("$var(http_json)", "{}");
        return async_ctx::ASYNC_DONE;
    }

    // ── Parse status line ──
    let status_line = response.lines().next().unwrap_or("");
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    // ── Split headers and body at the blank line ──
    let (header_section, body) = match response.split_once("\r\n\r\n") {
        Some((h, b)) => (h, b.to_string()),
        None => ("", response.clone()),
    };

    // ── Write basic PVs ──
    let _ = msg.set_pv_int("$var(http_status)", status_code as i32);
    let truncated_body = if body.len() > 3800 { &body[..3800] } else { &body };
    let _ = msg.set_pv("$var(http_body)", truncated_body);
    let _ = msg.set_pv("$var(http_error)", "");
    let _ = msg.set_pv_int("$var(http_time_ms)", elapsed_ms);

    // ── Write response headers as stacked AVPs ──
    // Each header line becomes an $avp(http_hdr) value. The config can
    // iterate the list using while($avp(http_hdr)).
    // Skip the status line (first line of headers section).
    let mut header_map = HashMap::new();
    for line in header_section.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Write each header as a stacked AVP
        let _ = msg.set_pv("$avp(http_hdr)", line);

        // Also collect into a map for the JSON output
        if let Some((key, val)) = line.split_once(':') {
            header_map.insert(
                key.trim().to_string(),
                val.trim().to_string(),
            );
        }
    }

    // ── Build JSON response object ──
    // Pack everything into a JSON string that the config can parse with
    // the json module: $json(http_json/status), $json(http_json/headers/Content-Type)
    let headers_json: String = {
        let pairs: Vec<String> = header_map.iter()
            .map(|(k, v)| {
                format!("\"{}\":\"{}\"",
                    k.replace('\\', "\\\\").replace('"', "\\\""),
                    v.replace('\\', "\\\\").replace('"', "\\\""))
            })
            .collect();
        format!("{{{}}}", pairs.join(","))
    };

    let json_body_escaped = truncated_body
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");

    let url_escaped = state.url
        .replace('\\', "\\\\")
        .replace('"', "\\\"");

    let json_response = format!(
        "{{\"status\":{},\"url\":\"{}\",\"elapsed_ms\":{},\"headers\":{},\"body\":\"{}\"}}",
        status_code, url_escaped, elapsed_ms, headers_json, json_body_escaped
    );

    // Truncate JSON to PV buffer limit
    let json_truncated = if json_response.len() > 3800 {
        &json_response[..3800]
    } else {
        &json_response
    };
    let _ = msg.set_pv("$var(http_json)", json_truncated);

    opensips_log!(INFO, "rust-script",
        "async_http_query: resume {} -> {} ({}ms, {} bytes, {} headers)",
        state.url, status_code, elapsed_ms, body.len(), header_map.len());

    async_ctx::ASYNC_DONE
}

/// Helper: connect, send HTTP/1.0 GET, return the non-blocking stream.
/// Uses a short blocking connect + write, then switches to non-blocking
/// for the response read (which is handled by the async resume callback).
fn async_http_connect(url: &str) -> Result<(TcpStream, String, String), String> {
    let rest = url.strip_prefix("http://")
        .ok_or_else(|| "only http:// URLs supported (no TLS in std)".to_string())?;

    let (host_port, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp, format!("/{}", p)),
        None => (rest, "/".to_string()),
    };

    let (host, port) = match host_port.split_once(':') {
        Some((h, p)) => {
            let port = p.parse::<u16>().map_err(|e| format!("bad port: {}", e))?;
            (h, port)
        }
        None => (host_port, 80u16),
    };

    let addr = format!("{}:{}", host, port);

    // Connect with a short timeout. TcpStream::connect() handles DNS
    // resolution for hostnames. We keep this blocking (brief) since the
    // TCP handshake is typically <1ms on a LAN.
    let stream = TcpStream::connect_timeout(
        &addr.parse().map_err(|_| {
            // SocketAddr::parse fails for hostnames — fall back to blocking connect
            // with a write timeout as our connect timeout proxy.
            format!("_hostname_{}", addr)
        })?,
        Duration::from_millis(500),
    ).map_err(|e| format!("connect to {} failed: {}", addr, e))?;

    // Send HTTP/1.0 request (blocking — the request is small)
    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: opensips-rust/1.0\r\nAccept: */*\r\n\r\n",
        path, host
    );
    (&stream).write_all(request.as_bytes())
        .map_err(|e| format!("write request: {}", e))?;

    // Switch to non-blocking for the response (reactor will monitor fd)
    stream.set_nonblocking(true)
        .map_err(|e| format!("set_nonblocking: {}", e))?;

    Ok((stream, host.to_string(), path))
}

/// Fallback connect for hostnames (SocketAddr::parse fails on non-IP addresses).
fn async_http_connect_hostname(url: &str) -> Result<(TcpStream, String, String), String> {
    let rest = url.strip_prefix("http://")
        .ok_or_else(|| "only http:// URLs supported".to_string())?;

    let (host_port, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp, format!("/{}", p)),
        None => (rest, "/".to_string()),
    };

    let (host, _port) = match host_port.split_once(':') {
        Some((h, p)) => {
            let _ = p.parse::<u16>().map_err(|e| format!("bad port: {}", e))?;
            (h, p)
        }
        None => (host_port, "80"),
    };

    let stream = TcpStream::connect(host_port)
        .map_err(|e| format!("connect to {} failed: {}", host_port, e))?;

    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: opensips-rust/1.0\r\nAccept: */*\r\n\r\n",
        path, host
    );
    (&stream).write_all(request.as_bytes())
        .map_err(|e| format!("write request: {}", e))?;

    stream.set_nonblocking(true)
        .map_err(|e| format!("set_nonblocking: {}", e))?;

    Ok((stream, host.to_string(), path))
}

opensips_async_handler!(async_http_query, |msg, ctx, param| {
    // ── Get URL from param or $var(http_url) ──
    let url = match param {
        Some(u) if !u.is_empty() => u.to_string(),
        _ => match msg.pv("$var(http_url)") {
            Some(u) if !u.is_empty() => u,
            _ => {
                // No URL provided — complete synchronously with empty results.
                // The resume route still runs (ASYNC_SYNC), giving the config
                // a chance to check $var(http_status) == 0 and handle it.
                let _ = msg.set_pv_int("$var(http_status)", 0);
                let _ = msg.set_pv("$var(http_body)", "");
                let _ = msg.set_pv("$var(http_error)", "no URL: set param or $var(http_url)");
                let _ = msg.set_pv_int("$var(http_time_ms)", 0);
                let _ = msg.set_pv("$var(http_json)", "{}");
                opensips_log!(DBG, "rust-script",
                    "async_http_query: no URL, sync completion");
                ctx.done_sync();
                return 1;
            }
        }
    };

    opensips_log!(DBG, "rust-script", "async_http_query: connecting to {}", url);

    let start = Instant::now();

    // ── Connect and send request ──
    // Try SocketAddr parse first (for IP:port), fall back to hostname connect.
    let stream = match async_http_connect(&url) {
        Ok((s, _host, _path)) => s,
        Err(e) if e.starts_with("_hostname_") => {
            // SocketAddr parse failed — this is a hostname, use blocking DNS
            match async_http_connect_hostname(&url) {
                Ok((s, _host, _path)) => s,
                Err(e) => {
                    let _ = msg.set_pv_int("$var(http_status)", 0);
                    let _ = msg.set_pv("$var(http_error)", &e);
                    let _ = msg.set_pv("$var(http_json)", "{}");
                    ctx.done_sync();
                    return -1;
                }
            }
        }
        Err(e) => {
            let _ = msg.set_pv_int("$var(http_status)", 0);
            let _ = msg.set_pv("$var(http_error)", &e);
            let _ = msg.set_pv("$var(http_json)", "{}");
            ctx.done_sync();
            return -1;
        }
    };

    // ── Get the raw fd for the reactor ──
    let fd = stream.as_raw_fd();

    // ── Allocate resume state ──
    // Box::into_raw() transfers ownership to a raw pointer. The Box is NOT
    // dropped here — we'll recover it in resume_http_query via Box::from_raw().
    // This is safe because async() resumes in the same worker process.
    let state = Box::new(AsyncHttpState {
        stream,
        url: url.clone(),
        start,
    });
    let state_ptr = Box::into_raw(state) as *mut std::ffi::c_void;

    // ── Tell OpenSIPS to monitor this fd ──
    ctx.set_fd(fd);
    ctx.set_resume(resume_http_query);
    ctx.set_resume_param(state_ptr);
    ctx.set_timeout(5);

    opensips_log!(DBG, "rust-script",
        "async_http_query: fd={} monitoring for response from {}",
        fd, url);
    1
});
