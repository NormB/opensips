# Architecture & Design Decisions

This document explains the key design decisions behind the opensips-rust workspace.

## Why Two Crates

The workspace is split into two crates:

- **`opensips-rs`** — A reusable SDK that any Rust module can depend on. It owns the build system integration, FFI bindings, the C shim, and panic-safe wrappers. Keeping this separate means a new module author can `cargo add opensips-rs` and immediately get a working build against their OpenSIPS installation without reinventing the plumbing.

- **`opensips-mod-rust`** — A concrete module that depends on the SDK. It contains only application logic (rate limiting, caching, HTTP pooling) and the `mod_export` table. This separation enforces a clean boundary: SDK concerns never leak into module code, and module-specific logic never pollutes the SDK.

This mirrors the pattern used by mature plugin ecosystems (e.g., Nginx modules, PostgreSQL extensions) where a stable C API layer sits beneath per-module logic.

## Build System: Flag Extraction via `make -n -B`

OpenSIPS does not provide a `pkg-config` file or a stable set of compiler flags for out-of-tree modules. Rather than hard-coding paths that break across versions and distros, `build.rs` runs:

```
make -n -B modules modules=modules/httpd 2>/dev/null
```

The `-n` (dry-run) and `-B` (unconditional rebuild) flags cause `make` to print every command it *would* execute without actually compiling anything. `build.rs` then parses the output for `-I`, `-L`, `-D`, and other flags, and forwards them to `bindgen` and `rustc`. This approach:

- Works on any system where OpenSIPS compiles successfully.
- Automatically picks up version-specific defines (`-DOPENSIPS_VER`, etc.).
- Requires no manual configuration beyond setting the OpenSIPS source path.

## The C Shim Strategy

Several parts of the OpenSIPS API cannot be called directly from Rust via bindgen:

1. **Variadic macros** — Logging macros like `LM_ERR(fmt, ...)` expand to variadic function calls through multiple layers of preprocessor indirection. Bindgen cannot generate Rust bindings for C macros, let alone variadic ones. The shim provides thin C wrapper functions (`shim_log_err`, etc.) that accept a single `const char *` and call the real macro internally.

2. **Static inline functions** — Functions like `pkg_malloc` and `pkg_free` are often defined as `static inline` in headers. Bindgen emits declarations for them, but no symbol exists in any `.so` for the linker to resolve. The shim wraps these in real (non-inline) C functions that the Rust side can link against.

3. **Complex preprocessor macros** — `pkg_malloc` and `shm_malloc` may be macros that expand differently depending on debug/profiling flags. Wrapping them in the shim provides a stable ABI regardless of how OpenSIPS was compiled.

The shim is compiled by `build.rs` using the `cc` crate with the exact flags extracted from OpenSIPS's build system.

## `sip_msg` as Opaque

The `struct sip_msg` in OpenSIPS is large, heavily nested, and changes between versions. Replicating it as a Rust struct would be fragile, hard to maintain, and would break on every OpenSIPS release.

Instead, the SDK treats `sip_msg` as an opaque pointer (`*mut c_void`) and accesses its fields through C accessor functions in the shim:

```c
const char *shim_get_method(struct sip_msg *msg);
const char *shim_get_ruri(struct sip_msg *msg);
```

This means:

- The Rust side never needs to know the layout of `sip_msg`.
- Adding a new accessor is a one-line C function + a one-line Rust extern declaration.
- Version compatibility is handled entirely in C, where it is natural.

## `catch_unwind_ffi` for Panic Safety

A Rust panic that unwinds across an FFI boundary into C is undefined behavior. Every Rust function exported to OpenSIPS is wrapped with `std::panic::catch_unwind`, which catches panics at the FFI boundary and converts them into a safe error return (-1).

The SDK provides a helper:

```rust
pub fn catch_unwind_ffi<F: FnOnce() -> c_int>(f: F) -> c_int {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(rc) => rc,
        Err(_) => {
            // Log the panic via the shim, return error
            shim_log_err("Rust panic caught at FFI boundary");
            -1
        }
    }
}
```

This ensures that even if module code has a bug, OpenSIPS continues running rather than crashing with a SIGABRT.

## `thread_local!` for Per-Worker State

OpenSIPS uses a pre-fork worker model: the main process forks N children, and each child handles SIP traffic independently. After `fork()`, each worker has its own copy of the address space, and workers never share memory (aside from explicit SHM regions).

This maps perfectly to `thread_local!` storage in Rust:

```rust
thread_local! {
    static RATE_LIMITER: RefCell<RateLimiter> = RefCell::new(RateLimiter::new());
    static CACHE: RefCell<LruCache<String, CacheEntry>> = ...;
    static HTTP_POOL: RefCell<HttpPool> = ...;
}
```

Why this is safe:

- Each OpenSIPS worker is a separate process (not a thread), so there is no concurrent access.
- `thread_local!` gives each worker its own instance, initialized lazily on first use after fork.
- No `Mutex`, no `Arc`, no synchronization overhead — just a `RefCell` for interior mutability.
- Worker-local state means the rate limiter, cache, and HTTP pool are isolated per worker, which is the correct semantic for OpenSIPS's architecture.

## Version Probe Strategy

The SDK needs to know the OpenSIPS version at build time for conditional compilation (e.g., API changes between 3.x and 4.x). Rather than asking the user to specify this manually, `build.rs` extracts the version from the build flags:

1. Parse `-DOPENSIPS_VER=0x0400` from the `make -n -B` output.
2. Convert to a semantic version and emit `cargo:rustc-cfg=opensips_ver="4.0"`.
3. Module code can then use `#[cfg(opensips_ver = "4.0")]` for version-specific logic.

This keeps version detection fully automatic and tied to the actual source tree being compiled against.
