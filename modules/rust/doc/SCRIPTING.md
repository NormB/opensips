# Rust Scripting for OpenSIPS — `rust_exec()`

## Overview

The `rust_exec()` function lets you write SIP processing logic in Rust and
load it at runtime, without rebuilding the Rust module. It works exactly like
`python_exec()` and `lua_exec()` — you point the module at a shared library,
and call exported functions from your OpenSIPS routes.

Both approaches coexist in the same module:

| Approach | How it works | When to use |
|---|---|---|
| **Compiled-in** | Functions like `rust_check_rate()` built into the module | Performance-critical, stateful patterns |
| **Runtime scripts** | `rust_exec("function_name")` dispatches to your `.so` | Custom logic, rapid iteration |

## Quick Start

### 1. Create a new crate

```bash
cargo new --lib my-opensips-handler
cd my-opensips-handler
```

### 2. Configure `Cargo.toml`

```toml
[package]
name = "my-opensips-handler"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
opensips-rs = { path = "/path/to/opensips-rust/modules/rust/opensips-rs" }
```

The `cdylib` crate type produces a `.so` file suitable for `dlopen`.

### 3. Write handlers

```rust
use opensips_rs::prelude::*;

opensips_handler!(hello_world, |msg| {
    opensips_log!(INFO, "my-handler", "hello from {}", msg.source_ip());
    1  // success
});

opensips_handler!(greet, |msg, param| {
    let greeting = param.unwrap_or("hello");
    opensips_log!(INFO, "my-handler", "{} from {}", greeting, msg.source_ip());
    1
});
```

### 4. Build

```bash
cargo build --release
# Output: target/release/libmy_opensips_handler.so
```

### 5. Configure OpenSIPS

```
loadmodule "rust.so"
modparam("rust", "script_name", "/usr/local/lib64/opensips/scripts/libmy_opensips_handler.so")

route {
    rust_exec("hello_world");
    rust_exec("greet", "howdy");
}
```

## ABI Contract

User scripts export `extern "C"` functions with this signature:

```rust
extern "C" fn(msg: *mut c_void, param: *const c_char, param_len: c_int) -> c_int
```

| Argument | Type | Description |
|---|---|---|
| `msg` | `*mut c_void` | Opaque pointer to OpenSIPS `sip_msg` |
| `param` | `*const c_char` | Optional parameter string (null if omitted) |
| `param_len` | `c_int` | Length of param (0 if omitted) |
| **return** | `c_int` | `1` = success, `-1` = failure |

The `opensips_handler!` macro hides this ABI and gives you:
- `msg`: a `SipMessage` with safe accessors
- `param`: an `Option<&str>`

## Available `SipMessage` Methods

| Method | Returns | Description |
|---|---|---|
| `msg.method()` | `Option<&str>` | SIP method (INVITE, REGISTER, etc.) |
| `msg.ruri()` | `Option<&str>` | Request-URI |
| `msg.status()` | `Option<&str>` | Reply status string |
| `msg.status_code()` | `Option<u32>` | Reply status code |
| `msg.source_ip()` | `String` | Source IP address |
| `msg.source_port()` | `u16` | Source port |
| `msg.is_request()` | `bool` | True for SIP requests |
| `msg.is_reply()` | `bool` | True for SIP replies |
| `msg.flags()` | `u32` | Message flags |
| `msg.set_flag(n)` | `()` | Set a message flag |
| `msg.header("Name")` | `Option<&str>` | Find header by name (case-insensitive) |
| `msg.header_iter()` | `Iterator` | Iterate all headers as `(name, body)` |
| `msg.pv("$var")` | `Option<String>` | Read a pseudo-variable format string |
| `msg.pv_get("$var")` | `Option<PvValue>` | Read a raw PV value (Int/Str/Null) |
| `msg.set_pv("$var", val)` | `Result<(), Error>` | Write a string pseudo-variable |
| `msg.set_pv_int("$var", n)` | `Result<(), Error>` | Write an integer pseudo-variable |
| `msg.call("func", &[..])` | `Result<i32, Error>` | Call another module's function |

## Example Handlers

### Rate-limit by User-Agent

```rust
opensips_handler!(check_ua_rate, |msg, param| {
    let max: i32 = param.unwrap_or("100").parse().unwrap_or(100);
    let ua = msg.header("User-Agent").unwrap_or("unknown");
    opensips_log!(DBG, "my-handler", "UA={} max={}", ua, max);
    // ... your rate limiting logic ...
    1
});
```

**Usage**: `rust_exec("check_ua_rate", "50")`

### Set a pseudo-variable

```rust
opensips_handler!(tag_request, |msg, param| {
    let tag = param.unwrap_or("default");
    match msg.set_pv("$var(tag)", tag) {
        Ok(()) => 1,
        Err(e) => {
            opensips_log!(ERR, "my-handler", "set_pv failed: {}", e);
            -1
        }
    }
});
```

**Usage**: `rust_exec("tag_request", "premium")`

### Call another module's function

```rust
opensips_handler!(send_reply, |msg, param| {
    let code = param.unwrap_or("200");
    match msg.call("sl_send_reply", &[code, "OK"]) {
        Ok(_) => 1,
        Err(e) => {
            opensips_log!(ERR, "my-handler", "sl_send_reply failed: {}", e);
            -1
        }
    }
});
```

## Example Handlers Reference

The `modules/rust/examples/user-script/src/lib.rs` file contains 19 self-contained handlers,
each one a teaching lesson that maps Rust concepts to SIP processing patterns.

### Quick Reference

| # | Handler | Usage | Rust Concepts |
|---|---|---|---|
| 1 | `hello_world` | `rust_exec("hello_world")` | `opensips_handler!` macro, `Option::unwrap_or`, closures |
| 2 | `greet` | `rust_exec("greet", "howdy")` | `Option<&str>`, default values, `format!` |
| 3 | `log_user_agent` | `rust_exec("log_user_agent")` | `msg.header()`, case-insensitive lookup |
| 4 | `append_custom_header` | `rust_exec("append_custom_header", "tag")` | `msg.call()`, `Result<T,E>` vs `Option<T>`, `match` |
| 5 | `route_by_header` | `rust_exec("route_by_header")` | `if let Some(...)`, `msg.set_pv()`, early returns |
| 6 | `caller_screening` | `rust_exec("caller_screening")` | `thread_local!`, `RefCell`, `HashSet`, closures |
| 7 | `number_portability` | `rust_exec("number_portability")` | `struct`, `Instant`+`Duration` TTL, `HashMap::entry()` |
| 8 | `request_logger` | `rust_exec("request_logger")` | `msg.header_iter()`, tuple destructuring, `msg.pv()` |
| 9 | `rate_limit_by_ua` | `rust_exec("rate_limit_by_ua", "50")` | `thread_local!`+`RefCell`+`HashMap`, `.parse::<u32>()` |
| 10 | `set_routing_flags` | `rust_exec("set_routing_flags")` | `msg.flags()`, `msg.set_flag()`, `starts_with()`, `set_pv()` |
| 11 | `reply_handler` | `rust_exec("reply_handler")` | `msg.is_reply()`, `msg.status_code()`, match range patterns |
| 12 | `variable_exchange` | `rust_exec("variable_exchange")` | bidirectional PV exchange, `splitn()`, string transforms |
| 13 | `call_counter` | `rust_exec("call_counter", "name")` | persistent per-worker state, `u64` counter, PV output |
| 14 | `shared_counter` | `rust_exec("shared_counter")` | cross-worker atomic counter via `SharedAtomicCounter` in shm |
| 15 | `pv_manipulation` | `rust_exec("pv_manipulation")` | `pv()` vs `pv_get()`, `set_pv()` vs `set_pv_int()`, `PvValue` enum |
| 16 | `avp_operations` | `rust_exec("avp_operations")` | `$avp()` read/write, AVP stacking, transaction-scoped state |
| 17 | `pv_edge_cases` | `rust_exec("pv_edge_cases")` | null/deleted AVPs, empty strings, read-only PVs, boundary ints |
| 18 | `http_query` | `rust_exec("http_query", "http://...")` | raw TCP HTTP/1.0, `TcpStream`, `Duration` timeout, `Result` chaining |
| 19 | `json_parse` | `rust_exec("json_parse")` | `serde_json::Value`, `as_str()`/`as_u64()`, `as_object()` iteration |
| 20 | `async_http_query` | `async(rust_exec("http_query", "http://..."), resume)` | `opensips_async_handler!`, `AsyncContext`, non-blocking I/O, resume callbacks |

### Handler Details

#### 4. append_custom_header

Adds an `X-Rust-Processed` header to the SIP message using `msg.call("append_hf", ...)`.
Teaches cross-module dispatch via `msg.call()`, the difference between `Result<T,E>` and
`Option<T>`, and SIP header `\r\n` line ending requirements.

**Requires**: `loadmodule "textops.so"` in your config.

#### 5. route_by_header

Reads an `X-Route-To` custom header and sets `$du` (destination URI) accordingly.
Demonstrates `if let Some(...)` pattern matching, PV writes with `msg.set_pv()`,
and the early-return style preferred in Rust.

#### 6. caller_screening

Blocks calls from a hardcoded IP blacklist using `thread_local! { HashSet }`.
This is the canonical pattern for per-worker state in OpenSIPS Rust modules.
Explains why `thread_local!` is safe (fork model), what `RefCell` does
(interior mutability), and why `HashSet` provides O(1) lookups.

#### 7. number_portability

LNP (Local Number Portability) cache with TTL expiration. Maps dialed numbers
to carrier routing destinations using `thread_local! { HashMap }`. Teaches Rust
struct definitions, `Instant` + `Duration` for monotonic time, and the
`HashMap::entry()` API that avoids double lookups.

#### 8. request_logger

CDR-like structured logging that dumps call metadata (Call-ID, From, To, method)
and iterates all SIP headers. Teaches `msg.header_iter()` which returns an
`Iterator<Item = (&str, &str)>`, tuple destructuring, and PV reads via `msg.pv()`.

#### 9. rate_limit_by_ua

Rate limiter keyed by User-Agent header instead of source IP. Uses the same
`thread_local! + RefCell + HashMap` pattern as the compiled-in `rust_check_rate()`.
Demonstrates `.parse::<u32>()` for string-to-number conversion and chained
`.unwrap_or()` for fallback defaults.

#### 10. set_routing_flags

Sets OpenSIPS message flags and `$var()` pseudo-variables for downstream routing
decisions. The config script can then check `isflag(1)` or `$var(call_type)`.
Teaches `msg.flags()`, `msg.set_flag()`, `starts_with()` string matching,
and writing multiple PVs in sequence.

#### 11. reply_handler

Classifies SIP replies by status code range (1xx provisional, 2xx success, etc.)
using Rust's `match` with range patterns (`200..=299`). Best used in
`onreply_route` or `failure_route`. Teaches `msg.is_reply()`,
`msg.status_code()`, and the exhaustive match pattern.

#### 12. variable_exchange

**Bidirectional PV exchange** — the key pattern for config ↔ Rust communication.
The config sets `$var(input)` before calling `rust_exec("variable_exchange")`,
Rust reads it, processes the command (uppercase/reverse/len/prefix), and writes
`$var(output)` + `$var(rc)` back so the config can branch on the results.

```
# In opensips.cfg:
$var(input) = "uppercase:hello world";
rust_exec("variable_exchange");
# Now: $var(output) = "HELLO WORLD", $var(rc) = "ok"
```

Teaches `msg.pv()` for reading config-set variables, `msg.set_pv()` for writing
results back, `splitn()` for parsing, and `match` on string slices for dispatch.

#### 13. call_counter

Persistent per-worker request counter using `thread_local! { HashMap<String, u64> }`.
The simplest demonstration of state that survives across SIP transactions.
Writes `$var(count)` and `$var(counter_name)` back to the config.

```
rust_exec("call_counter", "invites");
xlog("counter: $var(counter_name) = $var(count)\n");
```

Teaches named counters via the optional param, `entry().or_insert(0)` for
default initialization, and `u64::to_string()` for numeric-to-PV conversion.

#### 14. shared_counter

**Truly atomic cross-worker counter** using `SharedAtomicCounter` (SDK type
that wraps `AtomicI64` in OpenSIPS shared memory). Unlike `$shv()` which has
a read-modify-write race condition, this uses `fetch_add` — a single CPU
instruction (`lock xadd` on x86-64) that is truly atomic across all workers.

```
# In opensips.cfg — call directly:
rust_counter_inc();
xlog("total requests: $var(shared_count)\n");

# Or from a user script:
rust_exec("shared_counter");
```

The compiled-in `rust_counter_inc()` allocates the `AtomicI64` in shared memory
during `mod_init` (before fork). After fork, all workers share the same physical
counter. The user-script handler calls it via `msg.call("rust_counter_inc", &[])`.

Teaches the difference between per-worker state (`thread_local!`), non-atomic
shared state (`$shv()`), and truly atomic shared state (`SharedAtomicCounter`).

#### 15. pv_manipulation

Comprehensive pseudo-variable manipulation — reads core SIP PVs (`$rm`, `$ru`,
`$rU`, `$rd`, `$si`, `$sp`), writes string PVs via `set_pv()`, writes integer PVs
via `set_pv_int()`, and inspects PV types via `pv_get()` returning the `PvValue`
enum (`Int`/`Str`/`Null`).

```
# In opensips.cfg:
$var(pv_input) = "test-value";
rust_exec("pv_manipulation");
# Now: $var(pv_type) = "string", $var(pv_int_test) = 42
```

Teaches the three ways to read PVs (`pv()` format strings, `pv_get()` raw values,
`header()` direct access), the two ways to write PVs (`set_pv()` for strings,
`set_pv_int()` for integers), and the `PvValue` enum for type-safe value inspection.

#### 16. avp_operations

**AVP (Attribute-Value Pair) operations** — the critical mechanism for passing
data across SIP transaction boundaries. Unlike `$var()` which dies when the
route ends, `$avp()` values survive `t_relay()` and are readable in
`failure_route` and `onreply_route`.

```
# In opensips.cfg:
rust_exec("avp_operations");
# AVPs survive t_relay:
t_on_failure("1");
t_relay();

failure_route[1] {
    xlog("caller was $avp(rust_caller_ip), type=$avp(rust_call_type)\n");
}
```

Demonstrates string AVPs (`$avp(rust_caller_ip)`, `$avp(rust_call_type)`),
integer AVPs (`$avp(rust_timestamp)` via `set_pv_int()`), and AVP stacking
(multiple writes to `$avp(rust_tag)` create a LIFO stack). The optional param
controls the top-of-stack tag value.

Teaches the critical difference between `$var()` (route-scoped) and `$avp()`
(transaction-scoped), when to use each, and AVP stacking semantics.

#### 17. pv_edge_cases

**Robustness test** — the config intentionally feeds bad/missing data to Rust:
deleted AVPs (`$null`), never-set PVs, empty strings, near-limit 3800-byte
strings, `i32::MAX` and `-1` boundary integers, writes to read-only PVs (`$ci`),
and malformed PV specs. Every case must return `None`/`Err` gracefully without
crashing OpenSIPS.

```
# In opensips.cfg:
$avp(edge_test) = "exists";
$avp(edge_test) = NULL;         # delete it
rust_exec("pv_edge_cases");
# Now: $var(edge_result) = "pass", $var(edge_checks) = 10
```

After deletion, writes `"resurrected"` back to `$avp(edge_test)` to prove
AVPs can be re-created after `$null` deletion. Reports pass/fail count via
`$var(edge_checks)` and overall result via `$var(edge_result)`.

Teaches defensive programming with Rust's type system: `Option::is_none()`,
`Result::is_err()`, `PvValue::Null` matching, and why testing failure paths
is as important as testing success paths.

#### 18. http_query

**Raw HTTP client using only `std`** — no external dependencies (no ureq, no
reqwest). Uses `std::net::TcpStream` with HTTP/1.0 (server closes connection,
giving simple EOF detection) and a 2-second timeout to prevent worker blocking.

```
# With a URL (real HTTP call):
rust_exec("http_query", "http://httpbin.org/get");
# Now: $var(http_status) = "200", $var(http_body) = response body

# Without a URL (test/placeholder mode):
rust_exec("http_query");
# Now: $var(http_status) = "0", $var(http_body) = "no URL provided"
```

Writes `$var(http_status)`, `$var(http_body)`, `$var(http_time_ms)`, and
`$var(http_error)`. The helper `simple_http_get()` demonstrates URL parsing
with `strip_prefix`/`split_once`, `Result` chaining with `map_err`, and
`Duration`-based timeouts on `TcpStream`. Only supports `http://` (no TLS
in std).

Teaches the tradeoff between blocking I/O in a SIP worker (simple but blocks
the worker for the duration of the HTTP call) vs async patterns (complex but
non-blocking). For production use, prefer the compiled-in `http_pool` module
which uses a dedicated thread pool.

#### 19. json_parse

**JSON parsing with `serde_json`** — the standard Rust JSON library. Two modes:
config-provided JSON via `$var(json_input)`, or auto-built JSON from SIP message
fields (method, source IP, source port).

```
# Mode 1: config provides JSON
$var(json_input) = "{\"method\":\"INVITE\",\"src_ip\":\"10.0.0.1\",\"src_port\":5060}";
rust_exec("json_parse");
# Now: $var(json_method) = "INVITE", $var(json_src_ip) = "10.0.0.1"

# Mode 2: auto-build from SIP message (no $var(json_input) set)
rust_exec("json_parse");
# Now: $var(json_method) = actual SIP method, etc.
```

Writes `$var(json_parsed)` ("ok"/"error"), `$var(json_method)`,
`$var(json_src_ip)`, `$var(json_fields)` (comma-separated top-level keys),
`$var(json_raw)` (echo of parsed JSON), and `$var(json_src_port)` (integer).

Teaches `serde_json::from_str` → `Result<Value, Error>`, dynamic field access
via `value["key"].as_str()`, numeric extraction via `as_u64()`, iterating
object keys via `as_object()`, and the `json!` macro for building JSON
programmatically. Handles malformed JSON gracefully by writing error details
to `$var(json_error)`.

#### 20. async_http_query

**Non-blocking HTTP query using OpenSIPS async() framework** — the key pattern
for calling external services without blocking SIP workers. Unlike handler 18
(`http_query`) which blocks the worker for the entire HTTP call duration, this
handler:

1. Opens a TCP connection and sends the request
2. Hands the fd to OpenSIPS's reactor
3. Returns immediately — the worker processes other SIP traffic
4. When the response arrives, the reactor calls the resume callback
5. The resume callback reads the response and writes PVs/AVPs
6. The resume route runs with the populated data

```
# In opensips.cfg:
async(rust_exec("http_query", "http://127.0.0.1:8080/api/lookup"), http_done);

route[http_done] {
    xlog("status=$var(http_status) body=$var(http_body)\n");
    xlog("json=$var(http_json)\n");

    # Iterate response headers (stacked AVPs):
    while ($avp(http_hdr)) {
        xlog("  header: $avp(http_hdr)\n");
        $avp(http_hdr) = NULL;  # pop from stack
    }
}
```

**Output PVs:**
- `$var(http_status)` — HTTP status code (integer)
- `$var(http_body)` — Response body (truncated to 3800 bytes)
- `$var(http_json)` — Full response as JSON: `{"status":200,"url":"...","headers":{...},"body":"..."}`
- `$var(http_error)` — Error message (empty on success)
- `$var(http_time_ms)` — Total elapsed time in milliseconds
- `$avp(http_hdr)` — Response headers as stacked AVPs (one per header line)

**Without a URL:** completes synchronously via `ASYNC_SYNC`, resume route still runs
with `$var(http_status)` = 0.

Teaches `opensips_async_handler!` macro, `AsyncContext` methods (`set_fd`, `set_resume`,
`set_resume_param`, `set_timeout`, `done_sync`), `Box::into_raw()`/`Box::from_raw()`
for cross-FFI state transfer, and AVP stacking for list-like data.

---

## Async Handlers

### How OpenSIPS async() works

The `async()` script statement suspends the current SIP transaction, monitors
a file descriptor for I/O readiness, then resumes a route when data arrives.
This is how modules like `rest_client` avoid blocking workers during HTTP calls.

```
# Config syntax:
async(rust_exec("handler_name", "param"), resume_route_name);
```

### Writing async handlers

Use the `opensips_async_handler!` macro instead of `opensips_handler!`:

```rust
use opensips_rs::prelude::*;

opensips_async_handler!(async_my_handler, |msg, ctx, param| {
    // ctx is an AsyncContext with methods to control the async lifecycle:
    //   ctx.set_fd(fd)            — tell reactor to monitor this fd
    //   ctx.set_resume(callback)  — function called when fd is readable
    //   ctx.set_resume_param(ptr) — opaque state for the resume callback
    //   ctx.set_timeout(secs)     — timeout before cancellation
    //   ctx.done_sync()           — completed synchronously, run resume route now
    //   ctx.no_io()               — no async I/O, continue script normally

    if no_work_needed {
        ctx.done_sync();
        return 1;
    }

    // ... set up non-blocking I/O ...
    ctx.set_fd(fd);
    ctx.set_resume(my_resume_fn);
    ctx.set_resume_param(state_ptr);
    ctx.set_timeout(5);
    1
});
```

**Handler naming convention:** The function name MUST be prefixed with `async_`.
When `rust_exec("http_query")` is called inside `async()`, the dispatch logic
looks for `async_http_query` in the loaded script. If found, it calls the async
variant. If not found, it falls back to the sync `http_query` handler — all 19
existing handlers work inside `async()` blocks without modification (they just
run synchronously).

### Async ABI contract

Async handlers export this signature (generated by `opensips_async_handler!`):

```rust
extern "C" fn(msg: *mut c_void, ctx: *mut c_void, param: *const c_char, param_len: c_int) -> c_int
```

| Argument | Type | Description |
|---|---|---|
| `msg` | `*mut c_void` | Opaque pointer to OpenSIPS `sip_msg` |
| `ctx` | `*mut c_void` | Opaque pointer to `async_ctx` (wrapped as `AsyncContext`) |
| `param` | `*const c_char` | Optional parameter string (null if omitted) |
| `param_len` | `c_int` | Length of param (0 if omitted) |
| **return** | `c_int` | `1` = success, `-1` = failure |

### Resume callbacks

The resume function is called by the OpenSIPS reactor when the monitored fd
becomes readable:

```rust
unsafe extern "C" fn my_resume(fd: i32, msg: *mut sip_msg, param: *mut c_void) -> i32 {
    let state = Box::from_raw(param as *mut MyState);  // recover ownership
    let mut msg = SipMessage::from_raw(msg);
    // ... read from fd, write PVs ...
    async_ctx::ASYNC_DONE  // -1: done, run resume route
}
```

Return values:
- `ASYNC_DONE` (-1): async complete, continue to resume route
- `ASYNC_DONE_CLOSE_FD` (-2): complete + close fd
- `ASYNC_CONTINUE` (-5): not done yet, keep monitoring

### Memory model

Since `async()` (script-level) resumes in the **same worker process**, regular
Rust heap allocation (`Box`) works for resume state. Use `Box::into_raw()` to
transfer ownership to the raw pointer, and `Box::from_raw()` in the resume
callback to recover it. Rust's ownership system ensures exactly one free.

For `async_launch()` (fire-and-forget where a different process may resume),
you would need `shm_malloc` instead.

## Safety Guarantees

1. **Panic isolation**: If your handler panics, the panic is caught at two
   boundaries (your function + the module dispatcher). OpenSIPS continues
   running and the route returns `-1`.

2. **Symbol isolation**: Your `.so` is loaded with `RTLD_LOCAL`, so its symbols
   don't leak into the OpenSIPS global namespace or conflict with other modules.

3. **Fail-fast loading**: `RTLD_NOW` ensures all symbols are resolved at load
   time. If your `.so` has missing dependencies, OpenSIPS will fail at startup
   with a clear error, not at runtime.

4. **Function caching**: After the first `dlsym` lookup, function pointers are
   cached in a HashMap. Subsequent calls to the same function avoid repeated
   symbol resolution.

## Troubleshooting

### "dlopen failed: cannot open shared object file"
- Check the path in `script_name` is absolute and readable by the OpenSIPS user
- Verify the `.so` exists: `ls -la /path/to/libmy_handler.so`
- Check library dependencies: `ldd /path/to/libmy_handler.so`

### "function not found in /path/to/lib.so"
- Ensure you used `opensips_handler!` (which applies `#[no_mangle]`)
- Check exported symbols: `nm -D /path/to/libmy_handler.so | grep your_function`
- Verify crate-type is `cdylib` in your Cargo.toml

### "rust_exec called but no script loaded"
- Add `modparam("rust", "script_name", "/path/to/lib.so")` to your config
- The `modparam` must appear *before* the route block

### Handler panics
- Check OpenSIPS logs for "panic in function_name(): ..." messages
- The panic message includes the Rust panic payload for debugging
- The route continues with return value `-1`

### Version mismatch
- Your script crate must use the same `opensips-rs` SDK version as the module
- Rebuild both the module and your script when upgrading OpenSIPS
