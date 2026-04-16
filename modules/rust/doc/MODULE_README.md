# rust Module

## Overview

The `rust` module is an OpenSIPS module written entirely in Rust. It provides
compiled-in SIP processing functions (rate limiting, routing cache, HTTP queries,
atomic counters) alongside a runtime scripting engine (`rust_exec()`) that loads
user-supplied handlers from shared libraries.

The module supports both **synchronous** and **asynchronous** execution. When
`rust_exec()` is called inside an `async()` block, handlers can perform blocking
I/O without tying up SIP worker processes — the same pattern used by the
`rest_client` module.

### Key Features

- **Per-caller rate limiting** — Thread-local counters that survive across SIP
  transactions without locking or shared state corruption.
- **In-memory routing cache** — TTL-based destination cache using thread-local
  storage, providing lock-free O(1) lookups.
- **Persistent HTTP connection pool** — Maintains TCP connections to external
  HTTP services across requests.
- **Cross-worker atomic counter** — Shared-memory atomic counter visible to all
  worker processes.
- **Runtime scripting** — Load user-written Rust handlers at startup via
  `dlopen`, callable from routes via `rust_exec()`.
- **Async I/O** — Handlers can perform blocking I/O inside `async()` blocks
  without tying up SIP worker processes.

### Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Design decisions: two-crate workspace, C shim strategy, `sip_msg` opacity, panic safety |
| [BUILDING.md](BUILDING.md) | Build guide: Docker, bare metal, OpenSIPS Make integration, deployment |
| [SCRIPTING.md](SCRIPTING.md) | Handler authoring guide: `opensips_handler!` macro, PV/AVP access, async patterns |

### Examples

| File | Description |
|------|-------------|
| [`examples/basic.cfg`](../examples/basic.cfg) | Compiled-in functions only (rate limit, cache, HTTP query) |
| [`examples/async.cfg`](../examples/async.cfg) | Async HTTP query with resume route and PV/AVP access |
| [`examples/scripting.cfg`](../examples/scripting.cfg) | Full `rust_exec()` usage with sync handlers |
| [`examples/user-script/`](../examples/user-script/) | Reference user script with 19 handlers — copy and modify for your own |
| [`opensips.cfg.example`](opensips.cfg.example) | Complete annotated configuration with all parameters and functions |

## Dependencies

### OpenSIPS Modules

| Module | Required By | Purpose |
|--------|-------------|---------|
| `signaling` | `rust_check_rate()` | Sending 429 replies |
| `sl` | `rust_check_rate()` | Stateless reply support |

### Build Dependencies

- Rust toolchain (1.70+, install via `rustup`)
- `clang`, `llvm-dev`, `libclang-dev` (for `bindgen`)
- `pkg-config`, `libssl-dev` (for `reqwest` HTTP client)
- OpenSIPS source tree (headers and Makefile infrastructure)

### Runtime Dependencies

None beyond OpenSIPS itself. All Rust dependencies are statically linked.

## Exported Parameters

### max_rate (integer)

Maximum number of requests allowed per source IP within the rate limiting
window. When exceeded, `rust_check_rate()` returns `-1` and sends a `429`
reply automatically.

Each worker maintains its own counter (thread-local). The effective global
rate limit is approximately `max_rate * udp_workers`.

Default value: **100**

```
modparam("rust", "max_rate", 50)
```

### window_seconds (integer)

Duration of the rate limiting window in seconds. Counters reset at the start
of each new window. Uses monotonic time (`Instant`) — immune to NTP adjustments.

Default value: **60**

```
modparam("rust", "window_seconds", 10)
```

### cache_ttl (integer)

Time-to-live for routing cache entries in seconds. Expired entries are lazily
evicted on the next lookup — no background timer thread.

Each worker has an independent cache (thread-local). There is no cache sharing
between workers.

Default value: **300**

```
modparam("rust", "cache_ttl", 600)
```

### http_timeout (integer)

Timeout for HTTP requests in seconds. Applies to connection establishment,
TLS handshake, and response transfer. Used by both `rust_http_query()` (the
compiled-in connection pool) and the user-script `http_query` handler.

Default value: **2**

```
modparam("rust", "http_timeout", 5)
```

### pool_size (integer)

Maximum number of idle HTTP connections to keep per host in the connection pool.
Initialized during `child_init` for each worker process.

Default value: **4**

```
modparam("rust", "pool_size", 8)
```

### script_name (string)

Absolute path to a user-supplied shared library (`.so`) containing handler
functions for `rust_exec()`. The library is loaded via `dlopen(RTLD_NOW |
RTLD_LOCAL)` during `mod_init`.

When not set, `rust_exec()` returns `-1` with an error log. All other
compiled-in functions operate normally regardless of this parameter.

See [SCRIPTING.md](SCRIPTING.md) for the handler authoring guide.

Default value: **not set**

```
modparam("rust", "script_name", "/usr/local/lib64/opensips/scripts/libmy_handler.so")
```

## Exported Functions

### Return Codes

All exported functions use the following return code convention unless otherwise
noted:

| Code | Meaning | Description |
|------|---------|-------------|
| `1` | Success | Operation completed successfully |
| `-1` | Failure | Operation failed; see function-specific error conditions below |

For `rust_exec()` in async mode, the return code is available via `$rc` in the
resume route.

---

### rust_check_rate()

Check whether the source IP of the current message has exceeded the configured
rate limit.

**Parameters**: none

**Return values**:
- `1` — Request is within the rate limit (allow)
- `-1` — Rate limit exceeded

**Side effects on success**: none

**Side effects on failure**: Sends a `429 Too Many Requests` reply via
`sl_send_reply`. The caller should `exit` after a `-1` return.

**Error conditions**:

| Condition | Behavior | Log Level |
|-----------|----------|-----------|
| Source IP extraction fails | Returns `-1`, no reply sent | ERR |
| `sl_send_reply` call fails | Returns `-1`, reply may not reach client | ERR |

**Available in routes**: request_route, failure_route

```
route {
    if (!rust_check_rate()) {
        # 429 already sent
        exit;
    }
}
```

---

### rust_cache_lookup()

Look up the R-URI user (`$rU`) in the per-worker routing cache. On a cache hit,
sets `$du` to the cached destination and returns `1`.

**Parameters**: none

**Return values**:
- `1` — Cache hit; `$du` has been set to the cached destination URI
- `-1` — Cache miss, expired entry, or empty `$rU`

**Pseudo-variables set on success**:

| Variable | Type | Description |
|----------|------|-------------|
| `$du` | string | Destination URI from cache |

**Error conditions**:

| Condition | Behavior | Log Level |
|-----------|----------|-----------|
| `$rU` is empty or not set | Returns `-1` | DBG |
| Cache entry expired (older than `cache_ttl`) | Entry evicted, returns `-1` | DBG |
| `set_dst_uri` fails | Returns `-1` | ERR |

**Available in routes**: request_route

```
route {
    if (rust_cache_lookup()) {
        xlog("L_DBG", "Cache hit: $rU -> $du\n");
        t_relay();
        exit;
    }
}
```

---

### rust_cache_store()

Store the current R-URI user (`$rU`) and destination URI (`$du`) in the
per-worker routing cache. The entry expires after `cache_ttl` seconds.

**Parameters**: none

**Return values**:
- `1` — Stored successfully
- `-1` — Failed to store (missing `$rU` or `$du`)

**Error conditions**:

| Condition | Behavior | Log Level |
|-----------|----------|-----------|
| `$rU` is empty or not set | Returns `-1` | ERR |
| `$du` is empty or not set | Returns `-1` | ERR |

**Available in routes**: request_route

```
route {
    $du = "sip:backend.example.com";
    rust_cache_store();
}
```

---

### rust_http_query(url)

Perform a blocking HTTP GET request using the persistent connection pool.
Stores the response in pseudo-variables.

This function **blocks the SIP worker** for the duration of the HTTP call
(up to `http_timeout` seconds). For non-blocking HTTP, use `rust_exec()` with
an async handler inside `async()` — see [Async Operations](#async-operations).

**Parameters**:
- `url` (string, required) — Target URL. Supports variable expansion.

**Return values**:
- `1` — HTTP request completed (check `$var(http_status)` for HTTP status code)
- `-1` — Request failed (connection error, timeout, etc.)

**Pseudo-variables set on success**:

| Variable | Type | Description |
|----------|------|-------------|
| `$var(http_result)` | string | HTTP response body |
| `$var(http_status)` | integer | HTTP status code (200, 404, etc.) |

**Pseudo-variables set on failure**:

| Variable | Type | Description |
|----------|------|-------------|
| `$var(http_result)` | string | Empty string |
| `$var(http_status)` | integer | `0` |

**Error conditions**:

| Condition | Behavior | Log Level |
|-----------|----------|-----------|
| Empty or null URL | Returns `-1` | ERR |
| DNS resolution failure | Returns `-1` | ERR |
| Connection refused | Returns `-1` | ERR |
| Connection timeout (>`http_timeout`) | Returns `-1` | ERR |
| Response read timeout (>`http_timeout`) | Returns `-1` | ERR |
| TLS handshake failure | Returns `-1` | ERR |
| HTTP pool not initialized | Returns `-1` | ERR |

**Available in routes**: request_route

```
route {
    if (rust_http_query("http://api.example.com/auth?user=$fU")) {
        xlog("L_INFO", "HTTP $var(http_status): $var(http_result)\n");
    } else {
        xlog("L_ERR", "HTTP query failed\n");
    }
}
```

---

### rust_counter_inc()

Increment the cross-worker atomic counter and store the new value in
`$var(shared_count)`. The counter is allocated in shared memory during
`mod_init` (before fork) and uses `fetch_add` — a single atomic CPU
instruction across all workers.

**Parameters**: none

**Return values**:
- `1` — Always succeeds

**Pseudo-variables set**:

| Variable | Type | Description |
|----------|------|-------------|
| `$var(shared_count)` | integer | Counter value after increment |

**Error conditions**: none (atomic operations cannot fail)

**Available in routes**: request_route, onreply_route

```
route {
    rust_counter_inc();
    xlog("L_DBG", "Total requests: $var(shared_count)\n");
}
```

---

### rust_exec(function [, param])

Call a function exported by the user script loaded via `script_name`.

#### Synchronous Mode

When called directly in a route, the handler runs in the current worker
process and returns when complete.

**Parameters**:
- `function` (string, required) — Name of the exported function in the user
  script. Must match a symbol declared with `opensips_handler!`.
- `param` (string, optional) — Argument passed to the handler as `Option<&str>`.
  Supports variable expansion.

**Return values**:
- The handler's return value (typically `1` for success, `-1` for failure)
- `-1` if no script is loaded, the function does not exist, or the handler panics

**Error conditions**:

| Condition | Behavior | Log Level |
|-----------|----------|-----------|
| `script_name` not configured | Returns `-1` | ERR |
| Function not found in script | Returns `-1` | ERR |
| Empty function name | Returns `-1` | ERR |
| Handler panic (Rust unwind) | Returns `-1`, panic message logged | ERR |
| `dlsym` resolution failure | Returns `-1`, cached as not-found | ERR |

**Available in routes**: request_route, failure_route, onreply_route

```
route {
    # No parameter
    rust_exec("hello_world");

    # With parameter
    rust_exec("greet", "howdy");

    # Routing decision
    if (!rust_exec("check_caller")) {
        sl_send_reply(403, "Forbidden");
        exit;
    }

    # Variable expansion in parameter
    rust_exec("lookup", "$rU");
}
```

#### Asynchronous Mode

When called inside an `async()` block, the module looks for an async-capable
handler (symbol prefixed with `async_`). If found, the handler can set up
non-blocking I/O and return immediately, freeing the worker. The resume route
executes when the I/O completes.

If no async handler is found, the sync handler runs as a fallback — the resume
route executes immediately after completion.

**Syntax**:

```
async(rust_exec("function" [, "param"]), resume_route_name);
```

**Resume route behavior**:
- `$rc` contains the handler's return code
- Pseudo-variables set by the handler are available
- AVPs set by the handler are available

**Error conditions (in addition to sync mode)**:

| Condition | Behavior | Log Level |
|-----------|----------|-----------|
| No async variant found | Falls back to sync execution | DBG |
| Async handler panic | Returns `-1`, resume route may not execute | ERR |
| Async fd monitoring timeout | Timeout callback invoked (if set), transaction cancelled | WARN |
| Resume callback panic | Returns ASYNC_DONE, PVs may be incomplete | ERR |

**Available in routes**: request_route

```
route {
    async(rust_exec("http_query", "http://api.internal/data"), api_done);
}

route[api_done] {
    if ($rc < 0) {
        sl_send_reply(503, "Service Unavailable");
        exit;
    }
    xlog("L_INFO", "API response: $var(http_status)\n");
    sl_send_reply(200, "OK");
}
```

## Async Operations

### Overview

The `rust` module supports OpenSIPS's `async()` statement for non-blocking
external service calls. This is the same mechanism used by the `rest_client`
module to avoid blocking SIP workers during HTTP requests.

### How It Works

1. The config calls `async(rust_exec("handler", "param"), resume_route)`.
2. The module resolves `async_handler` in the user script (prefix `async_`).
3. The async handler opens a non-blocking connection, sends the request, and
   tells the reactor which fd to monitor.
4. The worker is released — it processes other SIP traffic.
5. When the fd becomes readable, the reactor calls the resume callback.
6. The resume callback reads the response, writes PVs and AVPs.
7. The resume route executes with the populated data.

### Async Handler Resolution

| Script has | Config calls | Behavior |
|------------|-------------|----------|
| `async_http_query` | `async(rust_exec("http_query", ...), ...)` | Async handler runs, fd monitored |
| `http_query` only | `async(rust_exec("http_query", ...), ...)` | Sync fallback, resume route runs immediately |
| Neither | `async(rust_exec("http_query", ...), ...)` | Returns `-1`, function not found |

### Async Timeout

Async handlers can set a timeout (in seconds) via `ctx.set_timeout()`. If the
fd does not become readable within this period, the operation is cancelled and
the resume route executes with incomplete data.

### Example: async_http_query Handler

The reference user script includes `async_http_query` (handler 20), which
demonstrates the full async pattern. It sets the following data on completion:

**Pseudo-variables set by async_http_query**:

| Variable | Type | Description |
|----------|------|-------------|
| `$var(http_status)` | integer | HTTP status code (`200`, `404`, etc.), `0` on error |
| `$var(http_body)` | string | Response body (truncated to 3800 bytes) |
| `$var(http_json)` | string | Full response as JSON: `{"status":200,"url":"...","elapsed_ms":42,"headers":{...},"body":"..."}` |
| `$var(http_error)` | string | Error message (empty on success) |
| `$var(http_time_ms)` | integer | Total elapsed time in milliseconds |

**AVPs set by async_http_query**:

| AVP | Type | Description |
|-----|------|-------------|
| `$avp(http_hdr)` | string (stacked) | Response headers, one per AVP. Iterate with `while($avp(http_hdr))`. |

**JSON response format** (`$var(http_json)`):

```json
{
  "status": 200,
  "url": "http://api.internal/data",
  "elapsed_ms": 42,
  "headers": {
    "Content-Type": "application/json",
    "Server": "nginx/1.24"
  },
  "body": "response body content"
}
```

**Error conditions for async_http_query**:

| Condition | `$var(http_status)` | `$var(http_error)` | Async Behavior |
|-----------|---------------------|--------------------|----------------|
| No URL provided | `0` | `no URL: set param or $var(http_url)` | Sync completion (ASYNC_SYNC) |
| Non-http URL scheme | `0` | `only http:// URLs supported` | Sync completion (ASYNC_SYNC) |
| Invalid port in URL | `0` | `bad port in URL` | Sync completion (ASYNC_SYNC) |
| DNS resolution failure | `0` | `connect to host:port failed: ...` | Sync completion (ASYNC_SYNC) |
| Connection refused | `0` | `connect failed: Connection refused` | Sync completion (ASYNC_SYNC) |
| Connection timeout | `0` | `connect failed: ...` | Sync completion (ASYNC_SYNC) |
| Write failure | `0` | `write failed: ...` | Sync completion (ASYNC_SYNC) |
| Response read failure | `0` | `failed to read response` | Resume callback returns ASYNC_DONE |
| Response timeout (>5s) | `0` | depends on reactor | Reactor cancels fd monitoring |

**Usage**:

```
route {
    # Async HTTP query — worker released during the call
    async(rust_exec("http_query", "http://api.internal:8080/lookup/$rU"), api_done);
}

route[api_done] {
    if ($var(http_status) == 0) {
        xlog("L_ERR", "HTTP error: $var(http_error)\n");
        sl_send_reply(503, "Service Unavailable");
        exit;
    }

    xlog("L_INFO", "HTTP $var(http_status) in $var(http_time_ms)ms\n");

    # Access the JSON response
    xlog("L_DBG", "JSON: $var(http_json)\n");

    # Iterate response headers
    while ($avp(http_hdr)) {
        xlog("L_DBG", "  $avp(http_hdr)\n");
        $avp(http_hdr) = NULL;
    }

    if ($var(http_status) == 200) {
        # Route based on response body
        $du = $var(http_body);
        t_relay();
        exit;
    }

    sl_send_reply(404, "Not Found");
}
```

## User Script Handlers

The `rust_exec()` function dispatches to handlers in a user-supplied `.so` file.
Handlers are declared with the `opensips_handler!` macro (sync) or
`opensips_async_handler!` macro (async).

### Handler ABI

**Sync handler** (generated by `opensips_handler!`):

```
extern "C" fn(msg: *mut c_void, param: *const c_char, param_len: c_int) -> c_int
```

**Async handler** (generated by `opensips_async_handler!`):

```
extern "C" fn(msg: *mut c_void, ctx: *mut c_void, param: *const c_char, param_len: c_int) -> c_int
```

| Argument | Type | Description |
|----------|------|-------------|
| `msg` | `*mut c_void` | Opaque pointer to `sip_msg` |
| `ctx` | `*mut c_void` | Opaque pointer to `async_ctx` (async handlers only) |
| `param` | `*const c_char` | Optional parameter (null if not provided) |
| `param_len` | `c_int` | Parameter length (0 if not provided) |
| **return** | `c_int` | `1` = success, `-1` = failure |

### Resume Callback ABI

For async handlers, the resume callback has this signature:

```
extern "C" fn(fd: c_int, msg: *mut sip_msg, param: *mut c_void) -> c_int
```

| Return Value | Constant | Description |
|-------------|----------|-------------|
| `-1` | `ASYNC_DONE` | Complete, continue to resume route |
| `-2` | `ASYNC_DONE_CLOSE_FD` | Complete, close the monitored fd |
| `-3` | `ASYNC_DONE_NO_IO` | Complete, no more I/O |
| `-5` | `ASYNC_CONTINUE` | Not done, keep monitoring fd |
| `-4` | `ASYNC_CHANGE_FD` | Switch to a different fd |

### Available Handlers

The reference user script (`modules/rust/examples/user-script/src/lib.rs`) includes 20
handlers. See [SCRIPTING.md](SCRIPTING.md) for the complete guide.

| # | Handler | Sync | Async | Description |
|---|---------|------|-------|-------------|
| 1 | `hello_world` | yes | — | Log SIP method |
| 2 | `greet` | yes | — | Parameterized greeting |
| 3 | `log_user_agent` | yes | — | Header access |
| 4 | `append_custom_header` | yes | — | Cross-module dispatch |
| 5 | `route_by_header` | yes | — | Header-based routing |
| 6 | `caller_screening` | yes | — | IP blacklist |
| 7 | `number_portability` | yes | — | LNP cache with TTL |
| 8 | `request_logger` | yes | — | CDR-like logging |
| 9 | `rate_limit_by_ua` | yes | — | Per-UA rate limiting |
| 10 | `set_routing_flags` | yes | — | Message flags + PVs |
| 11 | `reply_handler` | yes | — | Reply classification |
| 12 | `variable_exchange` | yes | — | Bidirectional PV exchange |
| 13 | `call_counter` | yes | — | Per-worker counter |
| 14 | `shared_counter` | yes | — | Cross-worker atomic counter |
| 15 | `pv_manipulation` | yes | — | PV read/write/types |
| 16 | `avp_operations` | yes | — | Transaction-scoped AVPs |
| 17 | `pv_edge_cases` | yes | — | Robustness testing |
| 18 | `http_query` | yes | yes | HTTP GET (sync: blocking, async: non-blocking) |
| 19 | `json_parse` | yes | — | JSON parsing with serde_json |

## Example Configurations

Example configs are in `modules/rust/examples/`:

| File | Description |
|------|-------------|
| `basic.cfg` | Compiled-in functions only (rate limit, cache, HTTP query) |
| `async.cfg` | Async HTTP query with resume route and PV/AVP access |
| `scripting.cfg` | Full rust_exec() usage with sync handlers |

## Implementation Notes

### Thread-Local State

The rate limiter and routing cache use `thread_local!` storage. In OpenSIPS's
pre-fork worker model, each child process gets its own copy after `fork()`:

- No locking, no mutexes, no data races
- Each worker's rate counter is independent
- Each worker has its own cache (no sharing)

### Shared Memory

The cross-worker atomic counter (`rust_counter_inc`) allocates an `AtomicI64`
in OpenSIPS shared memory during `mod_init` (before fork). After fork, all
workers share the same counter. The `fetch_add` instruction is truly atomic —
no read-modify-write race.

### Panic Safety

Every Rust function at the FFI boundary is wrapped with `catch_unwind`. If a
panic occurs (e.g., index out of bounds, unwrap on None), it is caught and
converted to a `-1` return code. OpenSIPS continues running. The panic message
is logged at ERR level with the function name.

Async resume callbacks are also wrapped — a panic in a resume callback returns
`ASYNC_DONE` to prevent the reactor from re-calling a broken handler.

### Symbol Isolation

User scripts are loaded with `RTLD_LOCAL` — their symbols do not leak into the
global namespace. This prevents conflicts with OpenSIPS core symbols or other
modules. `RTLD_NOW` ensures all symbols are resolved at load time, failing fast
at startup rather than at runtime.

### Version Matching

The module extracts version strings from the OpenSIPS source tree at compile
time. Loading the module into a different OpenSIPS version produces a
"module version mismatch" error at startup. Always rebuild when upgrading
OpenSIPS.

### Async Memory Model

For `async()` operations, the resume callback state is allocated on the Rust
heap via `Box::into_raw()`. Since `async()` resumes in the **same worker
process**, regular heap memory survives the reactor loop. The resume callback
recovers ownership via `Box::from_raw()` — Rust's ownership system ensures
exactly one deallocation.

For `async_launch()` (fire-and-forget, different process may resume), shared
memory (`shm_malloc`) would be required. The current implementation targets
`async()` only.

## Further Reading

- [ARCHITECTURE.md](ARCHITECTURE.md) — Design decisions, C shim strategy, version probing
- [BUILDING.md](BUILDING.md) — Build from source (Docker, bare metal, in-tree Make integration)
- [SCRIPTING.md](SCRIPTING.md) — Writing `rust_exec()` handlers, `opensips_handler!` macro, PV/AVP access
- [examples/](../examples/) — Example OpenSIPS configs and the reference user script
- [tests/](../tests/) — SIPp scenarios, integration configs, memory leak test
