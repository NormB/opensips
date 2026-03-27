//! rust_acl — Live-reload ACL (blocklist + allowlist) for OpenSIPS.
//!
//! Loads blocklist and optional allowlist files at startup into each worker
//! process. Files are parsed line-by-line (comments and blanks skipped).
//! Matching can be exact (HashSet) or prefix-based (Vec of prefixes).
//!
//! Allowlist takes precedence: if a value is in both lists, it is allowed.
//!
//! # OpenSIPS config
//!
//! ```text
//! loadmodule "rust_acl.so"
//! modparam("rust_acl", "blocklist_file", "/etc/opensips/blocklist.txt")
//! modparam("rust_acl", "allowlist_file", "/etc/opensips/allowlist.txt")
//! modparam("rust_acl", "match_mode", "prefix")
//!
//! route {
//!     # Check blocklist only
//!     if (!check_blocklist("$si")) {
//!         sl_send_reply(403, "Forbidden");
//!         exit;
//!     }
//!
//!     # Check allowlist first, then blocklist (allowlist wins)
//!     if (check_access("$ua") == -1) {
//!         sl_send_reply(403, "Forbidden");
//!         exit;
//!     }
//!
//!     # Temporary auto-block for 300 seconds
//!     auto_block("$si", "300");
//! }
//! ```

#![allow(clippy::doc_markdown)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::use_self)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::ptr_as_ptr)]
#![allow(clippy::borrow_as_ptr)]
#![allow(clippy::ref_as_ptr)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::redundant_else)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::as_ptr_cast_mut)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::pub_underscore_fields)]
#![allow(clippy::elidable_lifetime_names)]
#![allow(clippy::single_match_else)]
#![allow(clippy::let_and_return)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::bool_to_int_with_if)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::if_not_else)]
#![allow(clippy::missing_const_for_thread_local)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::single_char_pattern)]
#![allow(clippy::redundant_guards)]
#![allow(clippy::or_fun_call)]

use opensips_rs::command::CommandFunctionParam;
use opensips_rs::param::ModString;
use opensips_rs::sys;
use opensips_rs::{cstr_lit, opensips_log};
use rust_common::mi::Stats;
use rust_common::reload::{default_line_parser, FileLoader};

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ffi::{c_int, c_void};
use std::ptr;
use std::time::Instant;

// ── Module parameters ────────────────────────────────────────────

/// Path to blocklist file (required). One entry per line, # comments.
static BLOCKLIST_FILE: ModString = ModString::new();

/// Path to allowlist file (optional). One entry per line, # comments.
static ALLOWLIST_FILE: ModString = ModString::new();

/// Match mode: "exact" or "prefix" (default: "prefix").
static MATCH_MODE: ModString = ModString::new();

// ── ACL data structures ─────────────────────────────────────────

enum AclData {
    Exact(HashSet<String>),
    Prefix(Vec<String>),
}

// ── Pure check functions (testable without FFI) ──────────────────

fn check_exact(set: &HashSet<String>, value: &str) -> bool {
    set.contains(value)
}

fn check_prefix(prefixes: &[String], value: &str) -> bool {
    prefixes.iter().any(|p| value.starts_with(p.as_str()))
}

/// Check an AclData structure against a value.
fn check_acl_data(data: &AclData, value: &str) -> bool {
    match data {
        AclData::Exact(set) => check_exact(set, value),
        AclData::Prefix(prefixes) => check_prefix(prefixes, value),
    }
}

/// Rebuild AclData from raw entries and mode string.
fn build_acl_data(entries: &[String], mode: &str) -> AclData {
    match mode {
        "exact" => AclData::Exact(entries.iter().cloned().collect()),
        _ => AclData::Prefix(entries.to_vec()),
    }
}

// ── Auto-entry with TTL expiry ──────────────────────────────────

struct AutoEntry {
    expires: Instant,
}

/// Check if an auto-entry map contains a non-expired entry.
fn check_auto(map: &HashMap<String, AutoEntry>, value: &str) -> bool {
    matches!(map.get(value), Some(entry) if entry.expires > Instant::now())
}

/// Insert a temporary entry with TTL in seconds.
fn auto_insert(map: &mut HashMap<String, AutoEntry>, value: &str, ttl_secs: u64) {
    map.insert(value.to_string(), AutoEntry {
        expires: Instant::now() + std::time::Duration::from_secs(ttl_secs),
    });
}

/// Purge expired entries from an auto map.
fn purge_expired(map: &mut HashMap<String, AutoEntry>) {
    let now = Instant::now();
    map.retain(|_, entry| entry.expires > now);
}

// ── Per-worker state ─────────────────────────────────────────────

struct WorkerState {
    blocklist: AclData,
    blocklist_loader: FileLoader<Vec<String>>,
    allowlist: Option<AclData>,
    allowlist_loader: Option<FileLoader<Vec<String>>>,
    auto_blocked: HashMap<String, AutoEntry>,
    auto_allowed: HashMap<String, AutoEntry>,
    stats: Stats,
    mode: String,
}

thread_local! {
    static WORKER: RefCell<Option<WorkerState>> = const { RefCell::new(None) };
}

// ── Builder helpers for FileLoader ───────────────────────────────

fn build_vec(entries: Vec<String>) -> Vec<String> {
    entries
}

// ── Module lifecycle ─────────────────────────────────────────────

unsafe extern "C" fn mod_init() -> c_int {
    let file = match BLOCKLIST_FILE.get_value() {
        Some(f) if !f.is_empty() => f,
        _ => {
            opensips_log!(ERR, "rust_acl",
                "modparam blocklist_file is required but not set");
            return -1;
        }
    };

    let mode = MATCH_MODE.get_value().unwrap_or("prefix");
    if mode != "exact" && mode != "prefix" {
        opensips_log!(ERR, "rust_acl",
            "modparam match_mode must be exact or prefix, got {}", mode);
        return -1;
    }

    opensips_log!(INFO, "rust_acl", "module initialized");
    opensips_log!(INFO, "rust_acl", "  blocklist_file={}", file);
    if let Some(af) = ALLOWLIST_FILE.get_value() {
        if !af.is_empty() {
            opensips_log!(INFO, "rust_acl", "  allowlist_file={}", af);
        }
    }
    opensips_log!(INFO, "rust_acl", "  match_mode={}", mode);

    0
}

unsafe extern "C" fn mod_child_init(rank: c_int) -> c_int {
    if rank < 1 {
        return 0;
    }

    let file = match BLOCKLIST_FILE.get_value() {
        Some(f) => f.to_string(),
        None => return -1,
    };
    let mode = MATCH_MODE.get_value().unwrap_or("prefix").to_string();
    let mode_log = mode.clone();

    // Load blocklist
    let blocklist_loader = match FileLoader::new(&file, default_line_parser, build_vec) {
        Ok(l) => l,
        Err(e) => {
            opensips_log!(ERR, "rust_acl",
                "failed to load blocklist: {}", e);
            return -1;
        }
    };

    let blocklist_count = blocklist_loader.get().len();
    let blocklist = {
        let entries = blocklist_loader.get();
        build_acl_data(&entries, &mode)
    };

    // Load allowlist (optional)
    let (allowlist, allowlist_loader, allowlist_count) = match ALLOWLIST_FILE.get_value() {
        Some(af) if !af.is_empty() => {
            let af_owned = af.to_string();
            match FileLoader::new(&af_owned, default_line_parser, build_vec) {
                Ok(l) => {
                    let count = l.get().len();
                    let data = {
                        let entries = l.get();
                        build_acl_data(&entries, &mode)
                    };
                    (Some(data), Some(l), count)
                }
                Err(e) => {
                    opensips_log!(ERR, "rust_acl",
                        "failed to load allowlist: {}", e);
                    return -1;
                }
            }
        }
        _ => (None, None, 0),
    };

    let stats = Stats::new("rust_acl",
        &["checked", "blocked", "allowed", "auto_blocked", "auto_allowed",
          "entries_blocklist", "entries_allowlist", "reloads"]);
    stats.set("entries_blocklist", blocklist_count as u64);
    stats.set("entries_allowlist", allowlist_count as u64);

    WORKER.with(|w| {
        *w.borrow_mut() = Some(WorkerState {
            blocklist,
            blocklist_loader,
            allowlist,
            allowlist_loader,
            auto_blocked: HashMap::new(),
            auto_allowed: HashMap::new(),
            stats,
            mode,
        });
    });

    opensips_log!(DBG, "rust_acl",
        "worker {} loaded {} blocklist + {} allowlist entries (mode={})",
        rank, blocklist_count, allowlist_count, mode_log);
    0
}

unsafe extern "C" fn mod_destroy() {
    opensips_log!(INFO, "rust_acl", "module destroyed");
}

// ── Script function: check_blocklist(value) ──────────────────────

unsafe extern "C" fn w_check_blocklist(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let value = match <&str as CommandFunctionParam>::from_raw(p0) {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_acl",
                    "check_blocklist: missing or invalid parameter");
                return -2;
            }
        };

        WORKER.with(|w| {
            let borrow = w.borrow();
            match borrow.as_ref() {
                Some(state) => {
                    state.stats.inc("checked");

                    let blocked = check_acl_data(&state.blocklist, value)
                        || check_auto(&state.auto_blocked, value);

                    if blocked {
                        state.stats.inc("blocked");
                        -1
                    } else {
                        state.stats.inc("allowed");
                        1
                    }
                }
                None => {
                    opensips_log!(ERR, "rust_acl",
                        "ACL not initialized in this worker");
                    -2
                }
            }
        })
    })
}

// ── Script function: check_allowlist(value) ──────────────────────

unsafe extern "C" fn w_check_allowlist(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let value = match <&str as CommandFunctionParam>::from_raw(p0) {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_acl",
                    "check_allowlist: missing or invalid parameter");
                return -2;
            }
        };

        WORKER.with(|w| {
            let borrow = w.borrow();
            match borrow.as_ref() {
                Some(state) => {
                    let allowed = match &state.allowlist {
                        Some(data) => check_acl_data(data, value),
                        None => false,
                    } || check_auto(&state.auto_allowed, value);

                    if allowed { 1 } else { -1 }
                }
                None => {
                    opensips_log!(ERR, "rust_acl",
                        "ACL not initialized in this worker");
                    -2
                }
            }
        })
    })
}

// ── Script function: check_access(value) ─────────────────────────

unsafe extern "C" fn w_check_access(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let value = match <&str as CommandFunctionParam>::from_raw(p0) {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_acl",
                    "check_access: missing or invalid parameter");
                return -2;
            }
        };

        WORKER.with(|w| {
            let borrow = w.borrow();
            match borrow.as_ref() {
                Some(state) => {
                    state.stats.inc("checked");

                    // 1. Check auto-allow first
                    if check_auto(&state.auto_allowed, value) {
                        state.stats.inc("allowed");
                        return 1;
                    }

                    // 2. Check file-based allowlist
                    if let Some(ref al) = state.allowlist {
                        if check_acl_data(al, value) {
                            state.stats.inc("allowed");
                            return 1;
                        }
                    }

                    // 3. Check auto-block
                    if check_auto(&state.auto_blocked, value) {
                        state.stats.inc("blocked");
                        return -1;
                    }

                    // 4. Check file-based blocklist
                    if check_acl_data(&state.blocklist, value) {
                        state.stats.inc("blocked");
                        return -1;
                    }

                    // 5. Default: allow
                    state.stats.inc("allowed");
                    1
                }
                None => {
                    opensips_log!(ERR, "rust_acl",
                        "ACL not initialized in this worker");
                    -2
                }
            }
        })
    })
}

// ── Script function: blocklist_reload() ──────────────────────────

unsafe extern "C" fn w_blocklist_reload(
    _msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        WORKER.with(|w| {
            let mut borrow = w.borrow_mut();
            match borrow.as_mut() {
                Some(state) => {
                    match state.blocklist_loader.reload() {
                        Ok(count) => {
                            let entries = state.blocklist_loader.get();
                            state.blocklist = build_acl_data(&entries, &state.mode);
                            drop(entries);
                            state.stats.set("entries_blocklist", count as u64);
                            state.stats.inc("reloads");
                            opensips_log!(INFO, "rust_acl",
                                "blocklist reloaded: {} entries", count);
                            1
                        }
                        Err(e) => {
                            opensips_log!(ERR, "rust_acl",
                                "blocklist reload failed: {}", e);
                            -2
                        }
                    }
                }
                None => {
                    opensips_log!(ERR, "rust_acl",
                        "ACL not initialized in this worker");
                    -2
                }
            }
        })
    })
}

// ── Script function: allowlist_reload() ──────────────────────────

unsafe extern "C" fn w_allowlist_reload(
    _msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        WORKER.with(|w| {
            let mut borrow = w.borrow_mut();
            match borrow.as_mut() {
                Some(state) => {
                    match state.allowlist_loader.as_ref() {
                        Some(loader) => {
                            match loader.reload() {
                                Ok(count) => {
                                    let entries = loader.get();
                                    state.allowlist = Some(build_acl_data(&entries, &state.mode));
                                    drop(entries);
                                    state.stats.set("entries_allowlist", count as u64);
                                    state.stats.inc("reloads");
                                    opensips_log!(INFO, "rust_acl",
                                        "allowlist reloaded: {} entries", count);
                                    1
                                }
                                Err(e) => {
                                    opensips_log!(ERR, "rust_acl",
                                        "allowlist reload failed: {}", e);
                                    -2
                                }
                            }
                        }
                        None => {
                            opensips_log!(WARN, "rust_acl",
                                "allowlist_reload called but no allowlist_file configured");
                            -2
                        }
                    }
                }
                None => {
                    opensips_log!(ERR, "rust_acl",
                        "ACL not initialized in this worker");
                    -2
                }
            }
        })
    })
}

// ── Script function: auto_block(value, ttl_secs) ─────────────────

unsafe extern "C" fn w_auto_block(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let value = match <&str as CommandFunctionParam>::from_raw(p0) {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_acl",
                    "auto_block: missing or invalid value parameter");
                return -2;
            }
        };
        let ttl_str = match <&str as CommandFunctionParam>::from_raw(p1) {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_acl",
                    "auto_block: missing or invalid ttl_secs parameter");
                return -2;
            }
        };
        let ttl: u64 = match ttl_str.parse() {
            Ok(v) => v,
            Err(_) => {
                opensips_log!(ERR, "rust_acl",
                    "auto_block: ttl_secs '{}' is not a valid integer", ttl_str);
                return -2;
            }
        };

        WORKER.with(|w| {
            let mut borrow = w.borrow_mut();
            match borrow.as_mut() {
                Some(state) => {
                    auto_insert(&mut state.auto_blocked, value, ttl);
                    state.stats.inc("auto_blocked");
                    // Periodic purge of expired entries
                    purge_expired(&mut state.auto_blocked);
                    opensips_log!(DBG, "rust_acl",
                        "auto_block: {} for {}s", value, ttl);
                    1
                }
                None => {
                    opensips_log!(ERR, "rust_acl",
                        "ACL not initialized in this worker");
                    -2
                }
            }
        })
    })
}

// ── Script function: auto_allow(value, ttl_secs) ─────────────────

unsafe extern "C" fn w_auto_allow(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let value = match <&str as CommandFunctionParam>::from_raw(p0) {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_acl",
                    "auto_allow: missing or invalid value parameter");
                return -2;
            }
        };
        let ttl_str = match <&str as CommandFunctionParam>::from_raw(p1) {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_acl",
                    "auto_allow: missing or invalid ttl_secs parameter");
                return -2;
            }
        };
        let ttl: u64 = match ttl_str.parse() {
            Ok(v) => v,
            Err(_) => {
                opensips_log!(ERR, "rust_acl",
                    "auto_allow: ttl_secs '{}' is not a valid integer", ttl_str);
                return -2;
            }
        };

        WORKER.with(|w| {
            let mut borrow = w.borrow_mut();
            match borrow.as_mut() {
                Some(state) => {
                    auto_insert(&mut state.auto_allowed, value, ttl);
                    state.stats.inc("auto_allowed");
                    // Periodic purge of expired entries
                    purge_expired(&mut state.auto_allowed);
                    opensips_log!(DBG, "rust_acl",
                        "auto_allow: {} for {}s", value, ttl);
                    1
                }
                None => {
                    opensips_log!(ERR, "rust_acl",
                        "ACL not initialized in this worker");
                    -2
                }
            }
        })
    })
}

// ── Script function: access_stats() ──────────────────────────────

unsafe extern "C" fn w_access_stats(
    msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let json = WORKER.with(|w| {
            let borrow = w.borrow();
            match borrow.as_ref() {
                Some(state) => state.stats.to_json(),
                None => r#"{"error":"not_initialized"}"#.to_string(),
            }
        });
        let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
        let _ = sip_msg.set_pv("$var(acl_stats)", &json);
        1
    })
}

// ── Static arrays for module registration ────────────────────────

const EMPTY_PARAMS: [sys::cmd_param; 9] = unsafe { std::mem::zeroed() };

const ONE_STR_PARAM: [sys::cmd_param; 9] = {
    let mut arr: [sys::cmd_param; 9] = unsafe { std::mem::zeroed() };
    arr[0].flags = 2; // CMD_PARAM_STR
    arr
};

const TWO_STR_PARAM: [sys::cmd_param; 9] = {
    let mut arr: [sys::cmd_param; 9] = unsafe { std::mem::zeroed() };
    arr[0].flags = 2; // CMD_PARAM_STR
    arr[1].flags = 2; // CMD_PARAM_STR
    arr
};

#[repr(transparent)]
struct SyncArray<T, const N: usize>([T; N]);
unsafe impl<T, const N: usize> Sync for SyncArray<T, N> {}

static CMDS: SyncArray<sys::cmd_export_, 9> = SyncArray([
    sys::cmd_export_ {
        name: cstr_lit!("check_blocklist"),
        function: Some(w_check_blocklist),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("check_allowlist"),
        function: Some(w_check_allowlist),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("check_access"),
        function: Some(w_check_access),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("blocklist_reload"),
        function: Some(w_blocklist_reload),
        params: EMPTY_PARAMS,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("allowlist_reload"),
        function: Some(w_allowlist_reload),
        params: EMPTY_PARAMS,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("auto_block"),
        function: Some(w_auto_block),
        params: TWO_STR_PARAM,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("auto_allow"),
        function: Some(w_auto_allow),
        params: TWO_STR_PARAM,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("access_stats"),
        function: Some(w_access_stats),
        params: EMPTY_PARAMS,
        flags: 1 | 2 | 4,
    },
    // Null terminator
    sys::cmd_export_ {
        name: ptr::null(),
        function: None,
        params: EMPTY_PARAMS,
        flags: 0,
    },
]);

// No async commands
static ACMDS: SyncArray<sys::acmd_export_, 1> = SyncArray([
    sys::acmd_export_ {
        name: ptr::null(),
        function: None,
        params: EMPTY_PARAMS,
    },
]);

static PARAMS: SyncArray<sys::param_export_, 4> = SyncArray([
    sys::param_export_ {
        name: cstr_lit!("blocklist_file"),
        type_: 1, // STR_PARAM
        param_pointer: BLOCKLIST_FILE.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("allowlist_file"),
        type_: 1, // STR_PARAM
        param_pointer: ALLOWLIST_FILE.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("match_mode"),
        type_: 1, // STR_PARAM
        param_pointer: MATCH_MODE.as_ptr(),
    },
    // Null terminator
    sys::param_export_ {
        name: ptr::null(),
        type_: 0,
        param_pointer: ptr::null_mut(),
    },
]);

// No module dependencies
static DEPS: opensips_rs::ffi::DepExportConcrete<1> = opensips_rs::ffi::DepExportConcrete {
    md: unsafe { std::mem::zeroed() },
    mpd: unsafe { std::mem::zeroed() },
};

/// The module_exports struct that OpenSIPS loads via dlsym("exports").
#[no_mangle]
pub static exports: sys::module_exports = sys::module_exports {
    name: cstr_lit!("rust_acl"),
    type_: 1, // MOD_TYPE_DEFAULT
    ver_info: sys::module_exports__bindgen_ty_1 {
        version: cstr_lit!(env!("OPENSIPS_FULL_VERSION")),
        compile_flags: cstr_lit!(env!("OPENSIPS_COMPILE_FLAGS")),
        scm: sys::scm_version {
            type_: cstr_lit!(env!("OPENSIPS_SCM_TYPE")),
            rev: cstr_lit!(env!("OPENSIPS_SCM_REV")),
        },
    },
    dlflags: 0,
    load_f: None,
    deps: &DEPS as *const _ as *const sys::dep_export_,
    cmds: CMDS.0.as_ptr(),
    acmds: ACMDS.0.as_ptr(),
    params: PARAMS.0.as_ptr(),
    stats: ptr::null(),
    mi_cmds: ptr::null(),
    items: ptr::null(),
    trans: ptr::null(),
    procs: ptr::null(),
    preinit_f: None,
    init_f: Some(mod_init),
    response_f: None,
    destroy_f: Some(mod_destroy),
    init_child_f: Some(mod_child_init),
    reload_ack_f: None,
};

// ── Unit tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_exact_set(entries: &[&str]) -> HashSet<String> {
        entries.iter().map(|s| s.to_string()).collect()
    }

    fn make_prefix_vec(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|s| s.to_string()).collect()
    }

    // ── Exact mode tests ─────────────────────────────────────────

    #[test]
    fn test_exact_match() {
        let set = make_exact_set(&["192.168.1.100", "10.0.0.1", "bad-agent"]);
        assert!(check_exact(&set, "192.168.1.100"));
        assert!(check_exact(&set, "10.0.0.1"));
        assert!(check_exact(&set, "bad-agent"));
    }

    #[test]
    fn test_exact_no_match() {
        let set = make_exact_set(&["192.168.1.100", "10.0.0.1"]);
        assert!(!check_exact(&set, "192.168.1.101"));
        assert!(!check_exact(&set, "10.0.0.2"));
        assert!(!check_exact(&set, "completely-different"));
    }

    #[test]
    fn test_exact_case_sensitive() {
        let set = make_exact_set(&["friendly-scanner", "SIPVicious"]);
        assert!(check_exact(&set, "friendly-scanner"));
        assert!(!check_exact(&set, "Friendly-Scanner"));
        assert!(check_exact(&set, "SIPVicious"));
        assert!(!check_exact(&set, "sipvicious"));
    }

    #[test]
    fn test_exact_partial_not_matched() {
        let set = make_exact_set(&["192.168.1."]);
        assert!(!check_exact(&set, "192.168.1.100"));
        assert!(check_exact(&set, "192.168.1."));
    }

    // ── Prefix mode tests ────────────────────────────────────────

    #[test]
    fn test_prefix_match_ip() {
        let prefixes = make_prefix_vec(&["192.168.1.", "10.0.0."]);
        assert!(check_prefix(&prefixes, "192.168.1.100"));
        assert!(check_prefix(&prefixes, "192.168.1.1"));
        assert!(check_prefix(&prefixes, "10.0.0.42"));
    }

    #[test]
    fn test_prefix_match_user_agent() {
        let prefixes = make_prefix_vec(&["friendly-scanner", "SIPVicious"]);
        assert!(check_prefix(&prefixes, "friendly-scanner/1.8"));
        assert!(check_prefix(&prefixes, "friendly-scanner"));
        assert!(check_prefix(&prefixes, "SIPVicious/0.3"));
    }

    #[test]
    fn test_prefix_no_match() {
        let prefixes = make_prefix_vec(&["192.168.1.", "10.0.0."]);
        assert!(!check_prefix(&prefixes, "172.16.0.1"));
        assert!(!check_prefix(&prefixes, "192.168.2.1"));
        assert!(!check_prefix(&prefixes, "11.0.0.1"));
    }

    #[test]
    fn test_prefix_partial() {
        let prefixes = make_prefix_vec(&["192.168."]);
        assert!(check_prefix(&prefixes, "192.168.1.100"));
        assert!(check_prefix(&prefixes, "192.168.255.255"));
        assert!(!check_prefix(&prefixes, "192.169.0.1"));
    }

    #[test]
    fn test_prefix_case_sensitive() {
        let prefixes = make_prefix_vec(&["friendly-scanner"]);
        assert!(check_prefix(&prefixes, "friendly-scanner/1.8"));
        assert!(!check_prefix(&prefixes, "Friendly-Scanner/1.8"));
    }

    // ── Edge cases ───────────────────────────────────────────────

    #[test]
    fn test_empty_blocklist_exact() {
        let set: HashSet<String> = HashSet::new();
        assert!(!check_exact(&set, "anything"));
        assert!(!check_exact(&set, "192.168.1.1"));
        assert!(!check_exact(&set, ""));
    }

    #[test]
    fn test_empty_blocklist_prefix() {
        let prefixes: Vec<String> = Vec::new();
        assert!(!check_prefix(&prefixes, "anything"));
        assert!(!check_prefix(&prefixes, "192.168.1.1"));
        assert!(!check_prefix(&prefixes, ""));
    }

    #[test]
    fn test_empty_value_exact() {
        let set = make_exact_set(&["192.168.1.1", "bad-agent"]);
        assert!(!check_exact(&set, ""));
    }

    #[test]
    fn test_empty_value_prefix() {
        let prefixes = make_prefix_vec(&["192.168.1.", "bad"]);
        assert!(!check_prefix(&prefixes, ""));
    }

    #[test]
    fn test_empty_prefix_entry_matches_everything() {
        let prefixes = make_prefix_vec(&[""]);
        assert!(check_prefix(&prefixes, "anything"));
        assert!(check_prefix(&prefixes, ""));
    }

    #[test]
    fn test_exact_with_whitespace_preserved() {
        let set = make_exact_set(&["192.168.1.1"]);
        assert!(!check_exact(&set, " 192.168.1.1"));
        assert!(!check_exact(&set, "192.168.1.1 "));
    }

    #[test]
    fn test_prefix_single_char() {
        let prefixes = make_prefix_vec(&["+"]);
        assert!(check_prefix(&prefixes, "+15551234567"));
        assert!(!check_prefix(&prefixes, "15551234567"));
    }

    #[test]
    fn test_exact_domain_blocklist() {
        let set = make_exact_set(&["sip.spam.example.com", "evil.example.org"]);
        assert!(check_exact(&set, "sip.spam.example.com"));
        assert!(!check_exact(&set, "sip.spam.example.com:5060"));
        assert!(check_exact(&set, "evil.example.org"));
    }

    #[test]
    fn test_prefix_domain_blocklist() {
        let prefixes = make_prefix_vec(&["sip.spam.", "evil."]);
        assert!(check_prefix(&prefixes, "sip.spam.example.com"));
        assert!(check_prefix(&prefixes, "sip.spam.other.com"));
        assert!(check_prefix(&prefixes, "evil.example.org"));
        assert!(!check_prefix(&prefixes, "good.example.org"));
    }

    // ── check_blocklist via check_acl_data ───────────────────────

    #[test]
    fn test_check_blocklist_blocked() {
        let data = build_acl_data(
            &["192.168.1.100".to_string(), "bad-agent".to_string()],
            "exact",
        );
        assert!(check_acl_data(&data, "192.168.1.100"));
        assert!(check_acl_data(&data, "bad-agent"));
        assert!(!check_acl_data(&data, "good-agent"));
    }

    #[test]
    fn test_check_blocklist_allowed() {
        let data = build_acl_data(
            &["192.168.1.".to_string()],
            "prefix",
        );
        assert!(!check_acl_data(&data, "10.0.0.1"));
    }

    // ── check_allowlist ──────────────────────────────────────────

    #[test]
    fn test_check_allowlist_matching() {
        let data = build_acl_data(
            &["10.0.0.1".to_string(), "trusted-agent".to_string()],
            "exact",
        );
        assert!(check_acl_data(&data, "10.0.0.1"));
        assert!(check_acl_data(&data, "trusted-agent"));
    }

    #[test]
    fn test_check_allowlist_non_matching() {
        let data = build_acl_data(
            &["10.0.0.1".to_string()],
            "exact",
        );
        assert!(!check_acl_data(&data, "192.168.1.1"));
    }

    // ── check_access: allowlist override ─────────────────────────

    #[test]
    fn test_check_access_allowlist_wins() {
        // Value is in both blocklist and allowlist -> allowlist wins
        let blocklist = build_acl_data(
            &["10.0.0.1".to_string()],
            "exact",
        );
        let allowlist = build_acl_data(
            &["10.0.0.1".to_string()],
            "exact",
        );

        // Simulate check_access logic: allowlist first
        let value = "10.0.0.1";
        let result = if check_acl_data(&allowlist, value) {
            1 // allowed
        } else if check_acl_data(&blocklist, value) {
            -1 // blocked
        } else {
            1 // default allow
        };
        assert_eq!(result, 1); // allowlist wins
    }

    #[test]
    fn test_check_access_only_blocklist() {
        // No allowlist loaded, value in blocklist -> blocked
        let blocklist = build_acl_data(
            &["bad-ip".to_string()],
            "exact",
        );

        let value = "bad-ip";
        let result = if check_acl_data(&blocklist, value) {
            -1
        } else {
            1
        };
        assert_eq!(result, -1);
    }

    #[test]
    fn test_check_access_neither_list() {
        // Value in neither list -> default allow
        let blocklist = build_acl_data(
            &["bad-ip".to_string()],
            "exact",
        );

        let value = "good-ip";
        let result = if check_acl_data(&blocklist, value) {
            -1
        } else {
            1
        };
        assert_eq!(result, 1);
    }

    // ── auto_block / auto_allow with expiry ──────────────────────

    #[test]
    fn test_auto_block_active() {
        let mut map = HashMap::new();
        auto_insert(&mut map, "1.2.3.4", 300);
        assert!(check_auto(&map, "1.2.3.4"));
        assert!(!check_auto(&map, "5.6.7.8"));
    }

    #[test]
    fn test_auto_block_expired() {
        let mut map = HashMap::new();
        // Insert with 0-second TTL
        map.insert("1.2.3.4".to_string(), AutoEntry {
            expires: Instant::now() - std::time::Duration::from_secs(1),
        });
        assert!(!check_auto(&map, "1.2.3.4"));
    }

    #[test]
    fn test_auto_allow_active() {
        let mut map = HashMap::new();
        auto_insert(&mut map, "trusted-ip", 600);
        assert!(check_auto(&map, "trusted-ip"));
    }

    #[test]
    fn test_auto_allow_expired() {
        let mut map = HashMap::new();
        map.insert("trusted-ip".to_string(), AutoEntry {
            expires: Instant::now() - std::time::Duration::from_secs(1),
        });
        assert!(!check_auto(&map, "trusted-ip"));
    }

    #[test]
    fn test_purge_expired() {
        let mut map = HashMap::new();
        auto_insert(&mut map, "active", 300);
        map.insert("expired".to_string(), AutoEntry {
            expires: Instant::now() - std::time::Duration::from_secs(1),
        });
        assert_eq!(map.len(), 2);
        purge_expired(&mut map);
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("active"));
    }

    // ── Stats JSON output tests ──────────────────────────────────

    #[test]
    fn test_acl_stats_json() {
        use rust_common::mi::Stats;
        let stats = Stats::new("rust_acl",
            &["checked", "blocked", "allowed", "entries_blocklist", "entries_allowlist"]);
        stats.set("entries_blocklist", 42);
        stats.set("entries_allowlist", 5);
        stats.inc("checked");
        stats.inc("checked");
        stats.inc("blocked");
        stats.inc("allowed");

        let json = stats.to_json();
        assert!(json.starts_with("{"));
        assert!(json.ends_with("}"));
        assert!(json.contains(r#""entries_blocklist":42"#));
        assert!(json.contains(r#""entries_allowlist":5"#));
        assert!(json.contains(r#""checked":2"#));
        assert!(json.contains(r#""blocked":1"#));
        assert!(json.contains(r#""allowed":1"#));
    }

    // ── build_acl_data tests ─────────────────────────────────────

    #[test]
    fn test_build_acl_data_exact() {
        let entries = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let data = build_acl_data(&entries, "exact");
        match data {
            AclData::Exact(set) => {
                assert_eq!(set.len(), 3);
                assert!(set.contains("a"));
                assert!(set.contains("b"));
                assert!(set.contains("c"));
            }
            AclData::Prefix(_) => panic!("expected Exact"),
        }
    }

    #[test]
    fn test_build_acl_data_prefix() {
        let entries = vec!["192.168.".to_string(), "10.0.".to_string()];
        let data = build_acl_data(&entries, "prefix");
        match data {
            AclData::Prefix(v) => {
                assert_eq!(v.len(), 2);
                assert_eq!(v[0], "192.168.");
                assert_eq!(v[1], "10.0.");
            }
            AclData::Exact(_) => panic!("expected Prefix"),
        }
    }

    // ── Reload integration test (file-backed) ────────────────────

    #[test]
    fn test_reload_updates_data() {
        use rust_common::reload::{default_line_parser, FileLoader};
        use std::io::Write;

        let path = format!("{}/rust_acl_reload_test", std::env::temp_dir().display());

        // Create initial file
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "192.168.1.100").unwrap();
            writeln!(f, "10.0.0.1").unwrap();
        }

        let loader = FileLoader::new(&path, default_line_parser, build_vec).unwrap();
        let entries = loader.get();
        assert_eq!(entries.len(), 2);
        let data = build_acl_data(&entries, "prefix");
        drop(entries);

        // Verify initial data blocks 192.168.1.100
        assert!(check_acl_data(&data, "192.168.1.100"));

        // Update file: remove 192.168.1.100, add 172.16.0.
        std::fs::write(&path, "10.0.0.1\n172.16.0.\n").unwrap();

        let count = loader.reload().unwrap();
        assert_eq!(count, 2);

        let entries = loader.get();
        let data = build_acl_data(&entries, "prefix");
        drop(entries);

        // After reload: 192.168.1.100 no longer blocked, 172.16.0.1 is
        assert!(!check_acl_data(&data, "192.168.1.100"));
        assert!(check_acl_data(&data, "172.16.0.1"));
        assert!(check_acl_data(&data, "10.0.0.1"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_reload_file_error_returns_err() {
        use rust_common::reload::{default_line_parser, FileLoader};

        let path = format!("{}/rust_acl_reload_err_test", std::env::temp_dir().display());
        std::fs::write(&path, "entry1\n").unwrap();

        let loader = FileLoader::new(&path, default_line_parser, build_vec).unwrap();
        assert_eq!(loader.get().len(), 1);

        // Delete the file, then attempt reload
        std::fs::remove_file(&path).unwrap();
        let result = loader.reload();
        assert!(result.is_err());
    }

    // ── Reload both files test ───────────────────────────────────

    #[test]
    fn test_reload_both_files() {
        use rust_common::reload::{default_line_parser, FileLoader};
        use std::io::Write;

        let bl_path = format!("{}/rust_acl_bl_reload", std::env::temp_dir().display());
        let al_path = format!("{}/rust_acl_al_reload", std::env::temp_dir().display());

        {
            let mut f = std::fs::File::create(&bl_path).unwrap();
            writeln!(f, "bad-ip").unwrap();
        }
        {
            let mut f = std::fs::File::create(&al_path).unwrap();
            writeln!(f, "good-ip").unwrap();
        }

        let bl_loader = FileLoader::new(&bl_path, default_line_parser, build_vec).unwrap();
        let al_loader = FileLoader::new(&al_path, default_line_parser, build_vec).unwrap();

        assert_eq!(bl_loader.get().len(), 1);
        assert_eq!(al_loader.get().len(), 1);

        // Add entries and reload
        std::fs::write(&bl_path, "bad-ip\nbad-ip-2\n").unwrap();
        std::fs::write(&al_path, "good-ip\ngood-ip-2\ngood-ip-3\n").unwrap();

        assert_eq!(bl_loader.reload().unwrap(), 2);
        assert_eq!(al_loader.reload().unwrap(), 3);

        let bl_entries = bl_loader.get();
        let al_entries = al_loader.get();
        let bl = build_acl_data(&bl_entries, "exact");
        let al = build_acl_data(&al_entries, "exact");
        drop(bl_entries);
        drop(al_entries);

        assert!(check_acl_data(&bl, "bad-ip-2"));
        assert!(check_acl_data(&al, "good-ip-3"));

        let _ = std::fs::remove_file(&bl_path);
        let _ = std::fs::remove_file(&al_path);
    }
}
