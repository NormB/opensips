//! rust_dynamic_blacklist — Live-reload IP/UA/domain blacklist for OpenSIPS.
//!
//! Loads a blacklist file at startup into each worker process. The file is
//! parsed line-by-line (comments and blanks skipped). Matching can be exact
//! (HashSet) or prefix-based (Vec of prefixes).
//!
//! # OpenSIPS config
//!
//! ```text
//! loadmodule "rust_dynamic_blacklist.so"
//! modparam("rust_dynamic_blacklist", "blacklist_file", "/etc/opensips/blacklist.txt")
//! modparam("rust_dynamic_blacklist", "match_mode", "prefix")
//!
//! route {
//!     if (!rust_check_blacklist("$si")) {
//!         xlog("L_WARN", "blocked source $si\n");
//!         sl_send_reply(403, "Forbidden");
//!         exit;
//!     }
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
use std::collections::HashSet;
use std::ffi::{c_int, c_void};
use std::ptr;

// ── Module parameters ────────────────────────────────────────────

/// Path to blacklist file (required). One entry per line, # comments.
static BLACKLIST_FILE: ModString = ModString::new();

/// Match mode: "exact" or "prefix" (default: "prefix").
static MATCH_MODE: ModString = ModString::new();

// ── Blacklist data structures ────────────────────────────────────

enum BlacklistData {
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

/// Rebuild BlacklistData from raw entries and mode string.
fn build_blacklist_data(entries: &[String], mode: &str) -> BlacklistData {
    match mode {
        "exact" => BlacklistData::Exact(entries.iter().cloned().collect()),
        _ => BlacklistData::Prefix(entries.to_vec()),
    }
}

// ── Per-worker state ─────────────────────────────────────────────

struct WorkerState {
    data: BlacklistData,
    loader: FileLoader<Vec<String>>,
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
    let file = match BLACKLIST_FILE.get_value() {
        Some(f) if !f.is_empty() => f,
        _ => {
            opensips_log!(ERR, "rust_dynamic_blacklist",
                "modparam blacklist_file is required but not set");
            return -1;
        }
    };

    let mode = MATCH_MODE.get_value().unwrap_or("prefix");
    if mode != "exact" && mode != "prefix" {
        opensips_log!(ERR, "rust_dynamic_blacklist",
            "modparam match_mode must be exact or prefix, got {}", mode);
        return -1;
    }

    opensips_log!(INFO, "rust_dynamic_blacklist", "module initialized");
    opensips_log!(INFO, "rust_dynamic_blacklist", "  blacklist_file={}", file);
    opensips_log!(INFO, "rust_dynamic_blacklist", "  match_mode={}", mode);

    0
}

unsafe extern "C" fn mod_child_init(rank: c_int) -> c_int {
    if rank < 1 {
        return 0;
    }

    let file = match BLACKLIST_FILE.get_value() {
        Some(f) => f.to_string(),
        None => return -1,
    };
    let mode = MATCH_MODE.get_value().unwrap_or("prefix").to_string();
    let mode_log = mode.clone();

    let loader = match FileLoader::new(&file, default_line_parser, build_vec) {
        Ok(l) => l,
        Err(e) => {
            opensips_log!(ERR, "rust_dynamic_blacklist",
                "failed to load blacklist: {}", e);
            return -1;
        }
    };

    let entry_count = loader.get().len();

    let data = {
        let entries = loader.get();
        build_blacklist_data(&entries, &mode)
    };

    let stats = Stats::new("rust_dynamic_blacklist",
        &["checked", "blocked", "allowed", "entries", "reloads"]);
    stats.set("entries", entry_count as u64);

    WORKER.with(|w| {
        *w.borrow_mut() = Some(WorkerState { data, loader, stats, mode });
    });

    opensips_log!(DBG, "rust_dynamic_blacklist",
        "worker {} loaded {} entries (mode={})", rank, entry_count, mode_log);
    0
}

unsafe extern "C" fn mod_destroy() {
    opensips_log!(INFO, "rust_dynamic_blacklist", "module destroyed");
}

// ── Script function: rust_check_blacklist(value) ─────────────────

unsafe extern "C" fn w_rust_check_blacklist(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let value = match <&str as CommandFunctionParam>::from_raw(p0) {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_dynamic_blacklist",
                    "rust_check_blacklist: missing or invalid parameter");
                return -2;
            }
        };

        WORKER.with(|w| {
            let borrow = w.borrow();
            match borrow.as_ref() {
                Some(state) => {
                    state.stats.inc("checked");

                    let blocked = match &state.data {
                        BlacklistData::Exact(set) => check_exact(set, value),
                        BlacklistData::Prefix(prefixes) => check_prefix(prefixes, value),
                    };

                    if blocked {
                        state.stats.inc("blocked");
                        -1
                    } else {
                        state.stats.inc("allowed");
                        1
                    }
                }
                None => {
                    opensips_log!(ERR, "rust_dynamic_blacklist",
                        "blacklist not initialized in this worker");
                    -2
                }
            }
        })
    })
}

// ── Script function: rust_blacklist_reload() ─────────────────────

unsafe extern "C" fn w_rust_blacklist_reload(
    _msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        WORKER.with(|w| {
            let mut borrow = w.borrow_mut();
            match borrow.as_mut() {
                Some(state) => {
                    match state.loader.reload() {
                        Ok(count) => {
                            let entries = state.loader.get();
                            state.data = build_blacklist_data(&entries, &state.mode);
                            drop(entries);
                            state.stats.set("entries", count as u64);
                            state.stats.inc("reloads");
                            opensips_log!(INFO, "rust_dynamic_blacklist",
                                "reloaded {} entries", count);
                            1
                        }
                        Err(e) => {
                            opensips_log!(ERR, "rust_dynamic_blacklist",
                                "reload failed: {}", e);
                            -2
                        }
                    }
                }
                None => {
                    opensips_log!(ERR, "rust_dynamic_blacklist",
                        "blacklist not initialized in this worker");
                    -2
                }
            }
        })
    })
}

// ── Script function: rust_blacklist_stats() ──────────────────────

unsafe extern "C" fn w_rust_blacklist_stats(
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
        let _ = sip_msg.set_pv("$var(blacklist_stats)", &json);
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

#[repr(transparent)]
struct SyncArray<T, const N: usize>([T; N]);
unsafe impl<T, const N: usize> Sync for SyncArray<T, N> {}

static CMDS: SyncArray<sys::cmd_export_, 4> = SyncArray([
    sys::cmd_export_ {
        name: cstr_lit!("rust_check_blacklist"),
        function: Some(w_rust_check_blacklist),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("rust_blacklist_reload"),
        function: Some(w_rust_blacklist_reload),
        params: EMPTY_PARAMS,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("rust_blacklist_stats"),
        function: Some(w_rust_blacklist_stats),
        params: EMPTY_PARAMS,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
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

static PARAMS: SyncArray<sys::param_export_, 3> = SyncArray([
    sys::param_export_ {
        name: cstr_lit!("blacklist_file"),
        type_: 1, // STR_PARAM
        param_pointer: BLACKLIST_FILE.as_ptr(),
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
    name: cstr_lit!("rust_dynamic_blacklist"),
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
    fn test_empty_blacklist_exact() {
        let set: HashSet<String> = HashSet::new();
        assert!(!check_exact(&set, "anything"));
        assert!(!check_exact(&set, "192.168.1.1"));
        assert!(!check_exact(&set, ""));
    }

    #[test]
    fn test_empty_blacklist_prefix() {
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
    fn test_exact_domain_blacklist() {
        let set = make_exact_set(&["sip.spam.example.com", "evil.example.org"]);
        assert!(check_exact(&set, "sip.spam.example.com"));
        assert!(!check_exact(&set, "sip.spam.example.com:5060"));
        assert!(check_exact(&set, "evil.example.org"));
    }

    #[test]
    fn test_prefix_domain_blacklist() {
        let prefixes = make_prefix_vec(&["sip.spam.", "evil."]);
        assert!(check_prefix(&prefixes, "sip.spam.example.com"));
        assert!(check_prefix(&prefixes, "sip.spam.other.com"));
        assert!(check_prefix(&prefixes, "evil.example.org"));
        assert!(!check_prefix(&prefixes, "good.example.org"));
    }

    // ── Stats JSON output tests ──────────────────────────────────

    #[test]
    fn test_blacklist_stats_json() {
        use rust_common::mi::Stats;
        let stats = Stats::new("rust_dynamic_blacklist", &["checked", "blocked", "allowed", "entries"]);
        stats.set("entries", 42);
        stats.inc("checked");
        stats.inc("checked");
        stats.inc("blocked");
        stats.inc("allowed");

        let json = stats.to_json();
        assert!(json.starts_with("{"));
        assert!(json.ends_with("}"));
        assert!(json.contains(r#""entries":42"#));
        assert!(json.contains(r#""checked":2"#));
        assert!(json.contains(r#""blocked":1"#));
        assert!(json.contains(r#""allowed":1"#));
    }

    // ── build_blacklist_data tests ───────────────────────────────

    #[test]
    fn test_build_blacklist_data_exact() {
        let entries = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let data = build_blacklist_data(&entries, "exact");
        match data {
            BlacklistData::Exact(set) => {
                assert_eq!(set.len(), 3);
                assert!(set.contains("a"));
                assert!(set.contains("b"));
                assert!(set.contains("c"));
            }
            BlacklistData::Prefix(_) => panic!("expected Exact"),
        }
    }

    #[test]
    fn test_build_blacklist_data_prefix() {
        let entries = vec!["192.168.".to_string(), "10.0.".to_string()];
        let data = build_blacklist_data(&entries, "prefix");
        match data {
            BlacklistData::Prefix(v) => {
                assert_eq!(v.len(), 2);
                assert_eq!(v[0], "192.168.");
                assert_eq!(v[1], "10.0.");
            }
            BlacklistData::Exact(_) => panic!("expected Prefix"),
        }
    }

    // ── Reload integration test (file-backed) ────────────────────

    #[test]
    fn test_reload_updates_data() {
        use rust_common::reload::{default_line_parser, FileLoader};
        use std::io::Write;

        let path = format!("{}/rust_bl_reload_test", std::env::temp_dir().display());

        // Create initial file
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "192.168.1.100").unwrap();
            writeln!(f, "10.0.0.1").unwrap();
        }

        let loader = FileLoader::new(&path, default_line_parser, build_vec).unwrap();
        let entries = loader.get();
        assert_eq!(entries.len(), 2);
        let data = build_blacklist_data(&entries, "prefix");
        drop(entries);

        // Verify initial data blocks 192.168.1.100
        match &data {
            BlacklistData::Prefix(v) => assert!(check_prefix(v, "192.168.1.100")),
            _ => panic!("expected prefix"),
        }

        // Update file: remove 192.168.1.100, add 172.16.0.
        std::fs::write(&path, "10.0.0.1\n172.16.0.\n").unwrap();

        let count = loader.reload().unwrap();
        assert_eq!(count, 2);

        let entries = loader.get();
        let data = build_blacklist_data(&entries, "prefix");
        drop(entries);

        // After reload: 192.168.1.100 no longer blocked, 172.16.0.1 is
        match &data {
            BlacklistData::Prefix(v) => {
                assert!(!check_prefix(v, "192.168.1.100"));
                assert!(check_prefix(v, "172.16.0.1"));
                assert!(check_prefix(v, "10.0.0.1"));
            }
            _ => panic!("expected prefix"),
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_reload_file_error_returns_err() {
        use rust_common::reload::{default_line_parser, FileLoader};

        let path = format!("{}/rust_bl_reload_err_test", std::env::temp_dir().display());
        std::fs::write(&path, "entry1\n").unwrap();

        let loader = FileLoader::new(&path, default_line_parser, build_vec).unwrap();
        assert_eq!(loader.get().len(), 1);

        // Delete the file, then attempt reload
        std::fs::remove_file(&path).unwrap();
        let result = loader.reload();
        assert!(result.is_err());
    }
}
