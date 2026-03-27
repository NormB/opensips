//! Runtime script loader — dlopen/dlsym dispatch for user-supplied `.so` files.
//!
//! Mirrors the pattern used by OpenSIPS's python_exec() and lua_exec():
//!   modparam("rust", "script_name", "/path/to/libmy_handler.so")
//!   rust_exec("function_name")
//!   rust_exec("function_name", "optional_param")
//!
//! User scripts export `extern "C"` functions with this ABI:
//!   fn(msg: *mut c_void, param: *const c_char, param_len: c_int) -> c_int
//!
//! Safety model:
//!   - `SCRIPT` is a static mut Option — safe because OpenSIPS runs mod_init
//!     and mod_destroy in the main process (single-threaded), and workers are
//!     single-threaded after fork.
//!   - All user function calls are wrapped in catch_unwind to prevent panics
//!     from unwinding across the FFI boundary.
//!
//! # Rust Concepts Demonstrated
//!
//! - **`extern "C"` declarations for libc functions**: Rust can call any C
//!   function by declaring its signature in an `extern "C"` block. This is
//!   how we access dlopen/dlsym/dlclose/dlerror without linking to a Rust
//!   wrapper crate. The declarations are `unsafe` by nature — the compiler
//!   trusts you got the types right.
//!
//! - **`CString` for null-terminated C strings**: Rust strings are UTF-8
//!   byte slices WITHOUT a null terminator. C functions expect null-terminated
//!   strings. `CString::new(s)` adds the null byte and returns a type that
//!   keeps the allocation alive until dropped.
//!
//! - **`std::mem::transmute` for function pointer casting**: `dlsym` returns
//!   `*mut c_void`. We need `HandlerFn` (a typed function pointer). `transmute`
//!   does an unchecked type conversion — the most dangerous operation in Rust.
//!   We use it here because dlsym's return type is fundamentally untyped.
//!
//! - **`static mut` safety model**: `static mut` is globally mutable state,
//!   which Rust considers inherently unsafe (data races). In OpenSIPS this is
//!   safe because: (1) mod_init/mod_destroy run single-threaded in the main
//!   process, (2) after fork, each worker is single-threaded.
//!
//! - **`HashMap` as function pointer cache**: after the first dlsym lookup,
//!   the resolved function pointer is cached. Subsequent calls to the same
//!   function skip the dlsym overhead. HashMap provides O(1) average lookup.

use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};

use opensips_rs::opensips_log;

// ── libc dlopen/dlsym/dlclose/dlerror ────────────────────────────
//
// extern "C" block: declares C functions that the linker will resolve.
// These are standard POSIX functions available on Linux/macOS.
// Each function is implicitly `unsafe` — calling them requires an
// unsafe block because the compiler can't verify the arguments.

extern "C" {
    fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> c_int;
    fn dlerror() -> *const c_char;
}

// RTLD_NOW: resolve all symbols immediately at dlopen time.
// If the .so has missing dependencies, we find out NOW, not at runtime.
const RTLD_NOW: c_int = 0x2;
// RTLD_LOCAL: loaded symbols don't leak into the global namespace.
// Prevents user script symbols from conflicting with OpenSIPS or other modules.
const RTLD_LOCAL: c_int = 0x0;

/// Function pointer type for user-exported handlers (sync).
///
/// This is a Rust `type` alias for a function pointer. In C terms:
///   typedef int (*HandlerFn)(void *msg, const char *param, int param_len);
///
/// Return: 1 = success, -1 = failure
type HandlerFn = unsafe extern "C" fn(*mut c_void, *const c_char, c_int) -> c_int;

/// Function pointer type for async-capable user-exported handlers.
///
/// Like `HandlerFn` but with an additional `async_ctx` pointer. In C terms:
///   typedef int (*AsyncHandlerFn)(void *msg, void *ctx, const char *param, int param_len);
///
/// The handler receives the raw `async_ctx` pointer and is responsible for
/// setting `async_status` and populating the context (resume_f, resume_param).
type AsyncHandlerFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *const c_char, c_int) -> c_int;

/// Holds a loaded user script and its resolved function cache.
struct UserScript {
    handle: *mut c_void,                        // dlopen handle
    cache: HashMap<String, HandlerFn>,           // function name → pointer cache
    async_cache: HashMap<String, AsyncHandlerFn>, // async function name → pointer cache
    path: String,                                // for error messages
}

/// Global script state. See module-level safety comment.
///
/// `static mut` is Rust's equivalent of a C global variable. It's `unsafe`
/// to access because Rust can't prove at compile time that no data races
/// occur. We know it's safe here because OpenSIPS is single-threaded per
/// worker after fork().
static mut SCRIPT: Option<UserScript> = None;

/// Load a user script from disk via `dlopen(RTLD_NOW | RTLD_LOCAL)`.
///
/// Called from `mod_init` when `script_name` is configured.
/// Returns `Ok(())` on success, `Err(message)` on failure.
pub fn load_script(path: &str) -> Result<(), String> {
    let c_path = CString::new(path).map_err(|e| format!("invalid path: {}", e))?;

    unsafe {
        // Clear any stale dlerror
        dlerror();

        let handle = dlopen(c_path.as_ptr(), RTLD_NOW | RTLD_LOCAL);
        if handle.is_null() {
            let err = dlerror();
            let msg = if err.is_null() {
                "unknown dlopen error".to_string()
            } else {
                std::ffi::CStr::from_ptr(err).to_string_lossy().into_owned()
            };
            return Err(format!("dlopen({}) failed: {}", path, msg));
        }

        SCRIPT = Some(UserScript {
            handle,
            cache: HashMap::with_capacity(16),
            async_cache: HashMap::with_capacity(8),
            path: path.to_string(),
        });
    }

    opensips_log!(INFO, "rust", "loaded user script: {}", path);
    Ok(())
}

/// Resolve a function name to a cached `HandlerFn` via `dlsym`.
///
/// On first lookup the symbol is resolved and cached in the HashMap.
/// Returns `None` if the symbol doesn't exist in the loaded `.so`.
fn resolve_handler(script: &mut UserScript, name: &str) -> Option<HandlerFn> {
    // Hot path: check the HashMap cache first. After the first call to
    // a function, subsequent calls skip dlsym entirely. O(1) lookup.
    if let Some(&f) = script.cache.get(name) {
        return Some(f);
    }

    // Cold path: resolve the symbol via dlsym.
    // CString::new() adds a null terminator for the C function.
    // .ok()? converts Result to Option — returns None on invalid name.
    let c_name = CString::new(name).ok()?;
    unsafe {
        dlerror(); // clear any stale error
        let sym = dlsym(script.handle, c_name.as_ptr());
        if sym.is_null() {
            let err = dlerror();
            if !err.is_null() {
                let msg = std::ffi::CStr::from_ptr(err).to_string_lossy();
                opensips_log!(ERR, "rust", "dlsym({}) failed: {}", name, msg);
            } else {
                opensips_log!(ERR, "rust", "dlsym({}) returned null", name);
            }
            return None;
        }

        // transmute: reinterpret the raw void pointer as a typed function
        // pointer. This is the most dangerous operation in Rust — it trusts
        // that the symbol has the correct ABI. The opensips_handler! macro
        // in user scripts ensures the correct signature.
        let f: HandlerFn = std::mem::transmute(sym);
        script.cache.insert(name.to_string(), f);
        Some(f)
    }
}

/// Dispatch a call to a user script function.
///
/// Called from `w_rust_exec` in lib.rs. Resolves the function by name,
/// then calls it with the sip_msg pointer and optional parameter.
///
/// Returns:
/// - The user function's return code (typically 1 or -1)
/// - `-1` if no script is loaded, the function doesn't exist, or the call panics
pub fn dispatch(msg: *mut c_void, func: &str, param: Option<&str>) -> c_int {
    let script = unsafe { SCRIPT.as_mut() };

    let script = match script {
        Some(s) => s,
        None => {
            opensips_log!(ERR, "rust", "rust_exec(\"{}\") called but no script loaded \
                (set modparam \"script_name\")", func);
            return -1;
        }
    };

    let handler = match resolve_handler(script, func) {
        Some(f) => f,
        None => {
            opensips_log!(ERR, "rust", "rust_exec: function \"{}\" not found in {}",
                func, script.path);
            return -1;
        }
    };

    // Call the user function with catch_unwind to prevent panics from
    // unwinding into OpenSIPS C code.
    let (param_ptr, param_len) = match param {
        Some(s) => (s.as_ptr() as *const c_char, s.len() as c_int),
        None => (std::ptr::null(), 0),
    };

    match catch_unwind(AssertUnwindSafe(|| unsafe {
        handler(msg, param_ptr, param_len)
    })) {
        Ok(ret) => ret,
        Err(e) => {
            let panic_msg = if let Some(s) = e.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = e.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            opensips_log!(ERR, "rust", "rust_exec: panic in \"{}()\": {}", func, panic_msg);
            -1
        }
    }
}

/// Resolve an async handler by name via `dlsym`.
///
/// Looks for a symbol prefixed with `async_` (e.g., `async_http_query`).
/// Returns `None` if the symbol doesn't exist — this is expected for
/// handlers that don't support async, and triggers fallback to sync dispatch.
fn resolve_async_handler(script: &mut UserScript, name: &str) -> Option<AsyncHandlerFn> {
    let async_name = format!("async_{}", name);

    if let Some(&f) = script.async_cache.get(&async_name) {
        return Some(f);
    }

    let c_name = CString::new(async_name.as_str()).ok()?;
    unsafe {
        dlerror(); // clear stale error
        let sym = dlsym(script.handle, c_name.as_ptr());
        if sym.is_null() {
            // Not an error — most handlers won't have an async variant.
            // Silently return None to trigger sync fallback.
            return None;
        }

        let f: AsyncHandlerFn = std::mem::transmute(sym);
        script.async_cache.insert(async_name, f);
        Some(f)
    }
}

/// Dispatch an async call to a user script function.
///
/// Called from `w_async_rust_exec` in lib.rs when `rust_exec()` is used
/// inside an `async()` block.
///
/// Resolution strategy:
///   1. Try `dlsym(handle, "async_{func}")` — the async-capable variant
///   2. If found: call it with the `async_ctx` pointer. The handler is
///      responsible for setting `async_status` and populating the ctx.
///   3. If NOT found: fall back to the sync handler. `async_status` stays
///      at `ASYNC_NO_IO` (default), so the core treats it as synchronous.
///
/// This fallback is critical: all existing handlers work unchanged inside
/// `async()` blocks — they just run synchronously.
pub fn dispatch_async(msg: *mut c_void, ctx: *mut c_void, func: &str, param: Option<&str>) -> c_int {
    let script = unsafe { SCRIPT.as_mut() };

    let script = match script {
        Some(s) => s,
        None => {
            opensips_log!(ERR, "rust", "async rust_exec(\"{}\") called but no script loaded \
                (set modparam \"script_name\")", func);
            return -1;
        }
    };

    // Try async variant first: "async_{func}"
    if let Some(async_handler) = resolve_async_handler(script, func) {
        let (param_ptr, param_len) = match param {
            Some(s) => (s.as_ptr() as *const c_char, s.len() as c_int),
            None => (std::ptr::null(), 0),
        };

        return match catch_unwind(AssertUnwindSafe(|| unsafe {
            async_handler(msg, ctx, param_ptr, param_len)
        })) {
            Ok(ret) => ret,
            Err(e) => {
                let panic_msg = if let Some(s) = e.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = e.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "unknown panic".to_string()
                };
                opensips_log!(ERR, "rust", "async rust_exec: panic in \"async_{}()\": {}",
                    func, panic_msg);
                -1
            }
        };
    }

    // No async variant found — fall back to sync dispatch.
    // async_status stays at ASYNC_NO_IO (set by the core before calling us),
    // so the core treats this as synchronous completion.
    opensips_log!(DBG, "rust", "async rust_exec(\"{}\"): no async variant, sync fallback", func);
    dispatch(msg, func, param)
}

/// Check if a script is currently loaded.
pub fn is_loaded() -> bool {
    unsafe { SCRIPT.is_some() }
}

/// Unload the user script via `dlclose`.
///
/// Called from `mod_destroy`. Safe to call if no script is loaded.
pub fn unload() {
    unsafe {
        if let Some(script) = SCRIPT.take() {
            opensips_log!(INFO, "rust", "unloading user script: {}", script.path);
            dlclose(script.handle);
        }
    }
}
