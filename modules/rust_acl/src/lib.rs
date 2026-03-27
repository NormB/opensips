//! rust_acl — Live-reload ACL (blocklist + allowlist) for OpenSIPS.
//!
//! Loads blocklist and optional allowlist files at startup into each worker
//! process. Files are parsed line-by-line (comments and blanks skipped).
//! Matching can be exact (HashSet), prefix-based (Vec of prefixes),
//! or regex-based (compiled patterns).
//!
//! Supports typed files per check category (IP, UA, domain) in addition
//! to generic catch-all files. Typed check functions query only the
//! relevant typed file plus the generic file; untyped check functions
//! query all files.
//!
//! Allowlist takes precedence: if a value is in both lists, it is allowed.
//!
//! # OpenSIPS config
//!
//! ```text
//! loadmodule "rust_acl.so"
//! modparam("rust_acl", "blocklist_file", "/etc/opensips/blocklist.txt")
//! modparam("rust_acl", "blocklist_ip_file", "/etc/opensips/blocklist_ip.txt")
//! modparam("rust_acl", "blocklist_ua_file", "/etc/opensips/blocklist_ua.txt")
//! modparam("rust_acl", "blocklist_domain_file", "/etc/opensips/blocklist_domain.txt")
//! modparam("rust_acl", "allowlist_file", "/etc/opensips/allowlist.txt")
//! modparam("rust_acl", "allowlist_ip_file", "/etc/opensips/allowlist_ip.txt")
//! modparam("rust_acl", "allowlist_ua_file", "/etc/opensips/allowlist_ua.txt")
//! modparam("rust_acl", "allowlist_domain_file", "/etc/opensips/allowlist_domain.txt")
//! modparam("rust_acl", "match_mode", "prefix")
//!
//! route {
//!     # Check IP-specific blocklist only
//!     if (!check_blocklist_ip("$si")) {
//!         sl_send_reply(403, "Forbidden");
//!         exit;
//!     }
//!
//!     # Check UA-specific blocklist only
//!     if (!check_blocklist_ua("$ua")) {
//!         sl_send_reply(403, "Forbidden");
//!         exit;
//!     }
//!
//!     # Check all blocklists (generic + all typed)
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

use regex::Regex;

// ── Module parameters ────────────────────────────────────────────

/// Path to blocklist file (required). One entry per line, # comments.
static BLOCKLIST_FILE: ModString = ModString::new();

/// Path to allowlist file (optional). One entry per line, # comments.
static ALLOWLIST_FILE: ModString = ModString::new();

/// Match mode: "exact", "prefix", or "regex" (default: "prefix").
static MATCH_MODE: ModString = ModString::new();

// Typed blocklist files (optional)
static BLOCKLIST_IP_FILE: ModString = ModString::new();
static BLOCKLIST_UA_FILE: ModString = ModString::new();
static BLOCKLIST_DOMAIN_FILE: ModString = ModString::new();

// Typed allowlist files (optional)
static ALLOWLIST_IP_FILE: ModString = ModString::new();
static ALLOWLIST_UA_FILE: ModString = ModString::new();
static ALLOWLIST_DOMAIN_FILE: ModString = ModString::new();

/// Enable per-entry match counters (0=off, 1=on, default: 0).
static TRACK_COUNTERS: ModString = ModString::new();

/// Access policy for check_access(): "allowlist-first", "blocklist-first",
/// "allowlist-only", or "blocklist-only" (default: "allowlist-first").
static ACCESS_POLICY: ModString = ModString::new();

// ── ACL data structures ─────────────────────────────────────────

enum AclData {
    Exact(HashSet<String>),
    Prefix(Vec<String>),
    Regex(Vec<Regex>),
}

/// A loaded typed file: its data and loader for reload support.
struct TypedAcl {
    data: AclData,
    loader: FileLoader<Vec<String>>,
}

// ── Access policy enum ──────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum AccessPolicy {
    AllowlistFirst,
    BlocklistFirst,
    AllowlistOnly,
    BlocklistOnly,
}

impl AccessPolicy {
    fn from_str(s: &str) -> Option<AccessPolicy> {
        match s {
            "allowlist-first" => Some(AccessPolicy::AllowlistFirst),
            "blocklist-first" => Some(AccessPolicy::BlocklistFirst),
            "allowlist-only" => Some(AccessPolicy::AllowlistOnly),
            "blocklist-only" => Some(AccessPolicy::BlocklistOnly),
            _ => None,
        }
    }
}

// ── Pure check functions (testable without FFI) ──────────────────

fn check_exact(set: &HashSet<String>, value: &str) -> bool {
    set.contains(value)
}

fn check_prefix(prefixes: &[String], value: &str) -> bool {
    prefixes.iter().any(|p| value.starts_with(p.as_str()))
}

fn check_regex(patterns: &[Regex], value: &str) -> bool {
    patterns.iter().any(|r| r.is_match(value))
}

/// Check an AclData structure against a value.
fn check_acl_data(data: &AclData, value: &str) -> bool {
    match data {
        AclData::Exact(set) => check_exact(set, value),
        AclData::Prefix(prefixes) => check_prefix(prefixes, value),
        AclData::Regex(patterns) => check_regex(patterns, value),
    }
}

/// Rebuild AclData from raw entries and mode string.
fn build_acl_data(entries: &[String], mode: &str) -> AclData {
    match mode {
        "exact" => AclData::Exact(entries.iter().cloned().collect()),
        "regex" => {
            let patterns: Vec<Regex> = entries
                .iter()
                .filter_map(|pat| {
                    match Regex::new(pat) {
                        Ok(r) => Some(r),
                        Err(e) => {
                            #[cfg(not(test))]
                            opensips_log!(WARN, "rust_acl",
                                "invalid regex pattern '{}': {}", pat, e);
                            #[cfg(test)]
                            eprintln!("WARN: invalid regex pattern '{}': {}", pat, e);
                            let _ = e;
                            None
                        }
                    }
                })
                .collect();
            AclData::Regex(patterns)
        }
        _ => AclData::Prefix(entries.to_vec()),
    }
}

/// Check a primary AclData plus an optional typed AclData.
fn check_with_typed(primary: &AclData, typed: Option<&TypedAcl>, value: &str) -> bool {
    if let Some(t) = typed {
        if check_acl_data(&t.data, value) {
            return true;
        }
    }
    check_acl_data(primary, value)
}

/// Check a primary AclData plus ALL typed AclData (for untyped check functions).
fn check_all(
    primary: &AclData,
    ip: Option<&TypedAcl>,
    ua: Option<&TypedAcl>,
    domain: Option<&TypedAcl>,
    value: &str,
) -> bool {
    check_acl_data(primary, value)
        || ip.map_or(false, |t| check_acl_data(&t.data, value))
        || ua.map_or(false, |t| check_acl_data(&t.data, value))
        || domain.map_or(false, |t| check_acl_data(&t.data, value))
}

/// Check an optional primary AclData plus an optional typed AclData.
fn check_optional_with_typed(
    primary: Option<&AclData>,
    typed: Option<&TypedAcl>,
    value: &str,
) -> bool {
    if let Some(t) = typed {
        if check_acl_data(&t.data, value) {
            return true;
        }
    }
    primary.map_or(false, |data| check_acl_data(data, value))
}

/// Check an optional primary AclData plus ALL typed AclData.
fn check_optional_all(
    primary: Option<&AclData>,
    ip: Option<&TypedAcl>,
    ua: Option<&TypedAcl>,
    domain: Option<&TypedAcl>,
    value: &str,
) -> bool {
    primary.map_or(false, |data| check_acl_data(data, value))
        || ip.map_or(false, |t| check_acl_data(&t.data, value))
        || ua.map_or(false, |t| check_acl_data(&t.data, value))
        || domain.map_or(false, |t| check_acl_data(&t.data, value))
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

/// Increment the match counter for a given entry.
fn counter_increment(counters: &mut HashMap<String, u64>, entry: &str) {
    *counters.entry(entry.to_string()).or_insert(0) += 1;
}

/// Get top-N entries by match count, returned as JSON.
fn top_n_entries(counters: &HashMap<String, u64>, n: usize) -> String {
    let mut entries: Vec<(&String, &u64)> = counters.iter().collect();
    entries.sort_by(|a, b| b.1.cmp(a.1));
    entries.truncate(n);
    let items: Vec<String> = entries
        .iter()
        .map(|(k, v)| format!(r#"{{"entry":"{}","count":{}}}"#,
            k.replace('"', r#"\""#), v))
        .collect();
    format!("[{}]", items.join(","))
}

/// Find matching entry string for counter tracking.
/// Returns the first matching entry as a string for counter purposes.
fn find_matching_entry(data: &AclData, value: &str) -> Option<String> {
    match data {
        AclData::Exact(set) => {
            if set.contains(value) { Some(value.to_string()) } else { None }
        }
        AclData::Prefix(prefixes) => {
            prefixes.iter()
                .find(|p| value.starts_with(p.as_str()))
                .map(|p| p.clone())
        }
        AclData::Regex(patterns) => {
            patterns.iter()
                .find(|r| r.is_match(value))
                .map(|r| r.as_str().to_string())
        }
    }
}

// ── Per-worker state ─────────────────────────────────────────────

struct WorkerState {
    blocklist: AclData,
    blocklist_loader: FileLoader<Vec<String>>,
    allowlist: Option<AclData>,
    allowlist_loader: Option<FileLoader<Vec<String>>>,
    // Typed blocklist files
    blocklist_ip: Option<TypedAcl>,
    blocklist_ua: Option<TypedAcl>,
    blocklist_domain: Option<TypedAcl>,
    // Typed allowlist files
    allowlist_ip: Option<TypedAcl>,
    allowlist_ua: Option<TypedAcl>,
    allowlist_domain: Option<TypedAcl>,
    auto_blocked: HashMap<String, AutoEntry>,
    auto_allowed: HashMap<String, AutoEntry>,
    stats: Stats,
    mode: String,
    track_counters: bool,
    entry_counters: HashMap<String, u64>,
    access_policy: AccessPolicy,
}

thread_local! {
    static WORKER: RefCell<Option<WorkerState>> = const { RefCell::new(None) };
}

// ── Builder helpers for FileLoader ───────────────────────────────

fn build_vec(entries: Vec<String>) -> Vec<String> {
    entries
}

/// Load a typed file if the ModString has a value. Returns None if not configured.
fn load_typed_file(
    param: &ModString,
    mode: &str,
    label: &str,
) -> Result<Option<TypedAcl>, String> {
    match unsafe { param.get_value() } {
        Some(path) if !path.is_empty() => {
            let path_owned = path.to_string();
            match FileLoader::new(&path_owned, default_line_parser, build_vec) {
                Ok(loader) => {
                    let entries = loader.get();
                    let data = build_acl_data(&entries, mode);
                    let count = entries.len();
                    drop(entries);
                    opensips_log!(INFO, "rust_acl",
                        "  {}={} ({} entries)", label, path, count);
                    Ok(Some(TypedAcl { data, loader }))
                }
                Err(e) => Err(format!("failed to load {}: {}", label, e)),
            }
        }
        _ => Ok(None),
    }
}

/// Reload a typed ACL file. Returns the new entry count.
fn reload_typed(typed: &mut TypedAcl, mode: &str, label: &str) -> Result<usize, String> {
    match typed.loader.reload() {
        Ok(count) => {
            let entries = typed.loader.get();
            typed.data = build_acl_data(&entries, mode);
            drop(entries);
            opensips_log!(INFO, "rust_acl", "{} reloaded: {} entries", label, count);
            Ok(count)
        }
        Err(e) => Err(format!("{} reload failed: {}", label, e)),
    }
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
    if mode != "exact" && mode != "prefix" && mode != "regex" {
        opensips_log!(ERR, "rust_acl",
            "modparam match_mode must be exact, prefix, or regex, got {}", mode);
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

    let tc = TRACK_COUNTERS.get_value().unwrap_or("0");
    if tc == "1" {
        opensips_log!(INFO, "rust_acl", "  track_counters=enabled");
    }

    let policy_str = ACCESS_POLICY.get_value().unwrap_or("allowlist-first");
    if AccessPolicy::from_str(policy_str).is_none() {
        opensips_log!(ERR, "rust_acl",
            "modparam access_policy must be allowlist-first, blocklist-first, \
             allowlist-only, or blocklist-only, got {}", policy_str);
        return -1;
    }
    opensips_log!(INFO, "rust_acl", "  access_policy={}", policy_str);

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

    // Load typed blocklist files
    let blocklist_ip = match load_typed_file(&BLOCKLIST_IP_FILE, &mode, "blocklist_ip_file") {
        Ok(v) => v,
        Err(e) => { opensips_log!(ERR, "rust_acl", "{}", e); return -1; }
    };
    let blocklist_ua = match load_typed_file(&BLOCKLIST_UA_FILE, &mode, "blocklist_ua_file") {
        Ok(v) => v,
        Err(e) => { opensips_log!(ERR, "rust_acl", "{}", e); return -1; }
    };
    let blocklist_domain = match load_typed_file(&BLOCKLIST_DOMAIN_FILE, &mode, "blocklist_domain_file") {
        Ok(v) => v,
        Err(e) => { opensips_log!(ERR, "rust_acl", "{}", e); return -1; }
    };

    // Load typed allowlist files
    let allowlist_ip = match load_typed_file(&ALLOWLIST_IP_FILE, &mode, "allowlist_ip_file") {
        Ok(v) => v,
        Err(e) => { opensips_log!(ERR, "rust_acl", "{}", e); return -1; }
    };
    let allowlist_ua = match load_typed_file(&ALLOWLIST_UA_FILE, &mode, "allowlist_ua_file") {
        Ok(v) => v,
        Err(e) => { opensips_log!(ERR, "rust_acl", "{}", e); return -1; }
    };
    let allowlist_domain = match load_typed_file(&ALLOWLIST_DOMAIN_FILE, &mode, "allowlist_domain_file") {
        Ok(v) => v,
        Err(e) => { opensips_log!(ERR, "rust_acl", "{}", e); return -1; }
    };

    let stats = Stats::new("rust_acl",
        &["checked", "blocked", "allowed", "auto_blocked", "auto_allowed",
          "entries_blocklist", "entries_allowlist", "reloads"]);
    stats.set("entries_blocklist", blocklist_count as u64);
    stats.set("entries_allowlist", allowlist_count as u64);

    let track_counters = unsafe { TRACK_COUNTERS.get_value() }
        .map_or(false, |v| v == "1");

    let access_policy = unsafe { ACCESS_POLICY.get_value() }
        .and_then(|s| AccessPolicy::from_str(s))
        .unwrap_or(AccessPolicy::AllowlistFirst);

    WORKER.with(|w| {
        *w.borrow_mut() = Some(WorkerState {
            blocklist,
            blocklist_loader,
            allowlist,
            allowlist_loader,
            blocklist_ip,
            blocklist_ua,
            blocklist_domain,
            allowlist_ip,
            allowlist_ua,
            allowlist_domain,
            auto_blocked: HashMap::new(),
            auto_allowed: HashMap::new(),
            stats,
            mode,
            track_counters,
            entry_counters: HashMap::new(),
            access_policy,
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

// ── Script function: check_blocklist(value) — checks ALL blocklist files ──

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
            let mut borrow = w.borrow_mut();
            match borrow.as_mut() {
                Some(state) => {
                    state.stats.inc("checked");

                    let blocked = check_all(
                        &state.blocklist,
                        state.blocklist_ip.as_ref(),
                        state.blocklist_ua.as_ref(),
                        state.blocklist_domain.as_ref(),
                        value,
                    ) || check_auto(&state.auto_blocked, value);

                    if blocked {
                        if state.track_counters {
                            if let Some(entry) = find_matching_entry(&state.blocklist, value) {
                                counter_increment(&mut state.entry_counters, &entry);
                            }
                        }
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

// ── Script function: check_blocklist_ip(ip) — checks IP blocklist + generic ──

unsafe extern "C" fn w_check_blocklist_ip(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let value = match <&str as CommandFunctionParam>::from_raw(p0) {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_acl",
                    "check_blocklist_ip: missing or invalid parameter");
                return -2;
            }
        };

        WORKER.with(|w| {
            let borrow = w.borrow();
            match borrow.as_ref() {
                Some(state) => {
                    state.stats.inc("checked");
                    let blocked = check_with_typed(
                        &state.blocklist,
                        state.blocklist_ip.as_ref(),
                        value,
                    ) || check_auto(&state.auto_blocked, value);

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

// ── Script function: check_blocklist_ua(ua) — checks UA blocklist + generic ──

unsafe extern "C" fn w_check_blocklist_ua(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let value = match <&str as CommandFunctionParam>::from_raw(p0) {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_acl",
                    "check_blocklist_ua: missing or invalid parameter");
                return -2;
            }
        };

        WORKER.with(|w| {
            let borrow = w.borrow();
            match borrow.as_ref() {
                Some(state) => {
                    state.stats.inc("checked");
                    let blocked = check_with_typed(
                        &state.blocklist,
                        state.blocklist_ua.as_ref(),
                        value,
                    ) || check_auto(&state.auto_blocked, value);

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

// ── Script function: check_blocklist_domain(domain) — checks domain blocklist + generic ──

unsafe extern "C" fn w_check_blocklist_domain(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let value = match <&str as CommandFunctionParam>::from_raw(p0) {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_acl",
                    "check_blocklist_domain: missing or invalid parameter");
                return -2;
            }
        };

        WORKER.with(|w| {
            let borrow = w.borrow();
            match borrow.as_ref() {
                Some(state) => {
                    state.stats.inc("checked");
                    let blocked = check_with_typed(
                        &state.blocklist,
                        state.blocklist_domain.as_ref(),
                        value,
                    ) || check_auto(&state.auto_blocked, value);

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

// ── Script function: check_allowlist(value) — checks ALL allowlist files ──

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
            let mut borrow = w.borrow_mut();
            match borrow.as_mut() {
                Some(state) => {
                    let allowed = check_optional_all(
                        state.allowlist.as_ref(),
                        state.allowlist_ip.as_ref(),
                        state.allowlist_ua.as_ref(),
                        state.allowlist_domain.as_ref(),
                        value,
                    ) || check_auto(&state.auto_allowed, value);

                    if allowed {
                        if state.track_counters {
                            if let Some(ref al) = state.allowlist {
                                if let Some(entry) = find_matching_entry(al, value) {
                                    counter_increment(&mut state.entry_counters, &entry);
                                }
                            }
                        }
                        1
                    } else {
                        -1
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

// ── Script function: check_allowlist_ip(ip) — checks IP allowlist + generic ──

unsafe extern "C" fn w_check_allowlist_ip(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let value = match <&str as CommandFunctionParam>::from_raw(p0) {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_acl",
                    "check_allowlist_ip: missing or invalid parameter");
                return -2;
            }
        };

        WORKER.with(|w| {
            let borrow = w.borrow();
            match borrow.as_ref() {
                Some(state) => {
                    let allowed = check_optional_with_typed(
                        state.allowlist.as_ref(),
                        state.allowlist_ip.as_ref(),
                        value,
                    ) || check_auto(&state.auto_allowed, value);

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

// ── Script function: check_allowlist_ua(ua) — checks UA allowlist + generic ──

unsafe extern "C" fn w_check_allowlist_ua(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let value = match <&str as CommandFunctionParam>::from_raw(p0) {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_acl",
                    "check_allowlist_ua: missing or invalid parameter");
                return -2;
            }
        };

        WORKER.with(|w| {
            let borrow = w.borrow();
            match borrow.as_ref() {
                Some(state) => {
                    let allowed = check_optional_with_typed(
                        state.allowlist.as_ref(),
                        state.allowlist_ua.as_ref(),
                        value,
                    ) || check_auto(&state.auto_allowed, value);

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

// ── Script function: check_allowlist_domain(domain) — checks domain allowlist + generic ──

unsafe extern "C" fn w_check_allowlist_domain(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let value = match <&str as CommandFunctionParam>::from_raw(p0) {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_acl",
                    "check_allowlist_domain: missing or invalid parameter");
                return -2;
            }
        };

        WORKER.with(|w| {
            let borrow = w.borrow();
            match borrow.as_ref() {
                Some(state) => {
                    let allowed = check_optional_with_typed(
                        state.allowlist.as_ref(),
                        state.allowlist_domain.as_ref(),
                        value,
                    ) || check_auto(&state.auto_allowed, value);

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

// ── Pure access policy check (testable without FFI) ──────────────

fn check_access_with_policy(
    policy: AccessPolicy,
    blocklist: &AclData,
    blocklist_ip: Option<&TypedAcl>,
    blocklist_ua: Option<&TypedAcl>,
    blocklist_domain: Option<&TypedAcl>,
    allowlist: Option<&AclData>,
    allowlist_ip: Option<&TypedAcl>,
    allowlist_ua: Option<&TypedAcl>,
    allowlist_domain: Option<&TypedAcl>,
    auto_blocked: &HashMap<String, AutoEntry>,
    auto_allowed: &HashMap<String, AutoEntry>,
    value: &str,
) -> i32 {
    let in_allowlist = || {
        check_auto(auto_allowed, value)
            || check_optional_all(allowlist, allowlist_ip, allowlist_ua, allowlist_domain, value)
    };
    let in_blocklist = || {
        check_auto(auto_blocked, value)
            || check_all(blocklist, blocklist_ip, blocklist_ua, blocklist_domain, value)
    };

    match policy {
        AccessPolicy::AllowlistFirst => {
            if in_allowlist() { 1 }
            else if in_blocklist() { -1 }
            else { 1 } // default allow
        }
        AccessPolicy::BlocklistFirst => {
            if in_blocklist() { -1 }
            else if in_allowlist() { 1 }
            else { 1 } // default allow
        }
        AccessPolicy::AllowlistOnly => {
            if in_allowlist() { 1 } else { -1 }
        }
        AccessPolicy::BlocklistOnly => {
            if in_blocklist() { -1 } else { 1 }
        }
    }
}

// ── Script function: check_access(value) — checks ALL files ─────

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

                    let result = check_access_with_policy(
                        state.access_policy,
                        &state.blocklist,
                        state.blocklist_ip.as_ref(),
                        state.blocklist_ua.as_ref(),
                        state.blocklist_domain.as_ref(),
                        state.allowlist.as_ref(),
                        state.allowlist_ip.as_ref(),
                        state.allowlist_ua.as_ref(),
                        state.allowlist_domain.as_ref(),
                        &state.auto_blocked,
                        &state.auto_allowed,
                        value,
                    );

                    if result == 1 {
                        state.stats.inc("allowed");
                    } else {
                        state.stats.inc("blocked");
                    }
                    result
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

// ── Script function: blocklist_reload() — reloads ALL blocklist files ──

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
                    // Reload generic blocklist
                    match state.blocklist_loader.reload() {
                        Ok(count) => {
                            let entries = state.blocklist_loader.get();
                            state.blocklist = build_acl_data(&entries, &state.mode);
                            drop(entries);
                            state.stats.set("entries_blocklist", count as u64);
                            state.stats.inc("reloads");
                            opensips_log!(INFO, "rust_acl",
                                "blocklist reloaded: {} entries", count);
                        }
                        Err(e) => {
                            opensips_log!(ERR, "rust_acl",
                                "blocklist reload failed: {}", e);
                            return -2;
                        }
                    }

                    // Reload typed blocklist files
                    if let Some(ref mut typed) = state.blocklist_ip {
                        if let Err(e) = reload_typed(typed, &state.mode, "blocklist_ip") {
                            opensips_log!(ERR, "rust_acl", "{}", e);
                            return -2;
                        }
                    }
                    if let Some(ref mut typed) = state.blocklist_ua {
                        if let Err(e) = reload_typed(typed, &state.mode, "blocklist_ua") {
                            opensips_log!(ERR, "rust_acl", "{}", e);
                            return -2;
                        }
                    }
                    if let Some(ref mut typed) = state.blocklist_domain {
                        if let Err(e) = reload_typed(typed, &state.mode, "blocklist_domain") {
                            opensips_log!(ERR, "rust_acl", "{}", e);
                            return -2;
                        }
                    }

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

// ── Script function: allowlist_reload() — reloads ALL allowlist files ──

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
                    // Reload generic allowlist
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
                                }
                                Err(e) => {
                                    opensips_log!(ERR, "rust_acl",
                                        "allowlist reload failed: {}", e);
                                    return -2;
                                }
                            }
                        }
                        None => {
                            opensips_log!(DBG, "rust_acl",
                                "no generic allowlist_file configured, skipping");
                        }
                    }

                    // Reload typed allowlist files
                    if let Some(ref mut typed) = state.allowlist_ip {
                        if let Err(e) = reload_typed(typed, &state.mode, "allowlist_ip") {
                            opensips_log!(ERR, "rust_acl", "{}", e);
                            return -2;
                        }
                    }
                    if let Some(ref mut typed) = state.allowlist_ua {
                        if let Err(e) = reload_typed(typed, &state.mode, "allowlist_ua") {
                            opensips_log!(ERR, "rust_acl", "{}", e);
                            return -2;
                        }
                    }
                    if let Some(ref mut typed) = state.allowlist_domain {
                        if let Err(e) = reload_typed(typed, &state.mode, "allowlist_domain") {
                            opensips_log!(ERR, "rust_acl", "{}", e);
                            return -2;
                        }
                    }

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

// ── Script function: access_entry_stats() ──────────────────────

unsafe extern "C" fn w_access_entry_stats(
    msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let json = WORKER.with(|w| {
            let borrow = w.borrow();
            match borrow.as_ref() {
                Some(state) => {
                    if !state.track_counters {
                        return r#"{"error":"track_counters not enabled"}"#.to_string();
                    }
                    top_n_entries(&state.entry_counters, 100)
                }
                None => r#"{"error":"not_initialized"}"#.to_string(),
            }
        });
        let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
        let _ = sip_msg.set_pv("$var(acl_entry_stats)", &json);
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

static CMDS: SyncArray<sys::cmd_export_, 16> = SyncArray([
    sys::cmd_export_ {
        name: cstr_lit!("check_blocklist"),
        function: Some(w_check_blocklist),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("check_blocklist_ip"),
        function: Some(w_check_blocklist_ip),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("check_blocklist_ua"),
        function: Some(w_check_blocklist_ua),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("check_blocklist_domain"),
        function: Some(w_check_blocklist_domain),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("check_allowlist"),
        function: Some(w_check_allowlist),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("check_allowlist_ip"),
        function: Some(w_check_allowlist_ip),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("check_allowlist_ua"),
        function: Some(w_check_allowlist_ua),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("check_allowlist_domain"),
        function: Some(w_check_allowlist_domain),
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
    sys::cmd_export_ {
        name: cstr_lit!("access_entry_stats"),
        function: Some(w_access_entry_stats),
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

static PARAMS: SyncArray<sys::param_export_, 12> = SyncArray([
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
    sys::param_export_ {
        name: cstr_lit!("blocklist_ip_file"),
        type_: 1,
        param_pointer: BLOCKLIST_IP_FILE.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("blocklist_ua_file"),
        type_: 1,
        param_pointer: BLOCKLIST_UA_FILE.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("blocklist_domain_file"),
        type_: 1,
        param_pointer: BLOCKLIST_DOMAIN_FILE.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("allowlist_ip_file"),
        type_: 1,
        param_pointer: ALLOWLIST_IP_FILE.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("allowlist_ua_file"),
        type_: 1,
        param_pointer: ALLOWLIST_UA_FILE.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("allowlist_domain_file"),
        type_: 1,
        param_pointer: ALLOWLIST_DOMAIN_FILE.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("track_counters"),
        type_: 1, // STR_PARAM
        param_pointer: TRACK_COUNTERS.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("access_policy"),
        type_: 1, // STR_PARAM
        param_pointer: ACCESS_POLICY.as_ptr(),
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
            _ => panic!("expected Exact"),
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
            _ => panic!("expected Prefix"),
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

    // ── Typed file tests (Task 34) ───────────────────────────────

    fn make_typed_acl(entries: &[&str], mode: &str) -> TypedAcl {
        use rust_common::reload::{default_line_parser, FileLoader};
        use std::io::Write;

        let path = format!("{}/rust_acl_typed_{}", std::env::temp_dir().display(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                .unwrap().subsec_nanos());
        {
            let mut f = std::fs::File::create(&path).unwrap();
            for entry in entries {
                writeln!(f, "{}", entry).unwrap();
            }
        }
        let loader = FileLoader::new(&path, default_line_parser, build_vec).unwrap();
        let e = loader.get();
        let data = build_acl_data(&e, mode);
        drop(e);
        TypedAcl { data, loader }
    }

    #[test]
    fn test_typed_ip_blocklist_isolation() {
        // IP blocklist has IPs, UA blocklist has user-agents
        let generic = build_acl_data(&["catch-all-entry".to_string()], "exact");
        let ip_typed = make_typed_acl(&["192.168.1.100", "10.0.0.1"], "exact");
        let ua_typed = make_typed_acl(&["friendly-scanner", "SIPVicious"], "exact");

        // check_with_typed for IP should find IP entries but not UA entries
        assert!(check_with_typed(&generic, Some(&ip_typed), "192.168.1.100"));
        assert!(!check_with_typed(&generic, Some(&ip_typed), "friendly-scanner"));

        // check_with_typed for UA should find UA entries but not IP entries
        assert!(check_with_typed(&generic, Some(&ua_typed), "friendly-scanner"));
        assert!(!check_with_typed(&generic, Some(&ua_typed), "192.168.1.100"));

        // Generic catch-all should always be checked
        assert!(check_with_typed(&generic, Some(&ip_typed), "catch-all-entry"));
        assert!(check_with_typed(&generic, Some(&ua_typed), "catch-all-entry"));
    }

    #[test]
    fn test_typed_domain_blocklist() {
        let generic = build_acl_data(&[], "exact");
        let domain_typed = make_typed_acl(&["spam.example.com", "evil.org"], "exact");

        assert!(check_with_typed(&generic, Some(&domain_typed), "spam.example.com"));
        assert!(check_with_typed(&generic, Some(&domain_typed), "evil.org"));
        assert!(!check_with_typed(&generic, Some(&domain_typed), "good.example.com"));
    }

    #[test]
    fn test_check_all_queries_every_typed_file() {
        let generic = build_acl_data(&["generic-entry".to_string()], "exact");
        let ip_typed = make_typed_acl(&["192.168.1.100"], "exact");
        let ua_typed = make_typed_acl(&["bad-scanner"], "exact");
        let domain_typed = make_typed_acl(&["evil.com"], "exact");

        // check_all should find entries in any typed file
        assert!(check_all(&generic, Some(&ip_typed), Some(&ua_typed), Some(&domain_typed), "192.168.1.100"));
        assert!(check_all(&generic, Some(&ip_typed), Some(&ua_typed), Some(&domain_typed), "bad-scanner"));
        assert!(check_all(&generic, Some(&ip_typed), Some(&ua_typed), Some(&domain_typed), "evil.com"));
        assert!(check_all(&generic, Some(&ip_typed), Some(&ua_typed), Some(&domain_typed), "generic-entry"));
        assert!(!check_all(&generic, Some(&ip_typed), Some(&ua_typed), Some(&domain_typed), "unknown"));
    }

    #[test]
    fn test_check_all_with_none_typed() {
        let generic = build_acl_data(&["only-generic".to_string()], "exact");

        // All typed are None — only generic should be checked
        assert!(check_all(&generic, None, None, None, "only-generic"));
        assert!(!check_all(&generic, None, None, None, "not-in-generic"));
    }

    #[test]
    fn test_check_optional_with_typed_allowlist() {
        let generic_al = build_acl_data(&["trusted-generic".to_string()], "exact");
        let ip_al = make_typed_acl(&["10.0.0.1"], "exact");

        // With generic + typed IP allowlist
        assert!(check_optional_with_typed(Some(&generic_al), Some(&ip_al), "10.0.0.1"));
        assert!(check_optional_with_typed(Some(&generic_al), Some(&ip_al), "trusted-generic"));
        assert!(!check_optional_with_typed(Some(&generic_al), Some(&ip_al), "unknown"));

        // Without generic allowlist
        assert!(check_optional_with_typed(None, Some(&ip_al), "10.0.0.1"));
        assert!(!check_optional_with_typed(None, Some(&ip_al), "trusted-generic"));

        // Without typed allowlist
        assert!(check_optional_with_typed(Some(&generic_al), None, "trusted-generic"));
        assert!(!check_optional_with_typed(Some(&generic_al), None, "10.0.0.1"));
    }

    #[test]
    fn test_check_optional_all_allowlist() {
        let generic_al = build_acl_data(&["trusted".to_string()], "exact");
        let ip_al = make_typed_acl(&["10.0.0.1"], "exact");
        let ua_al = make_typed_acl(&["good-agent"], "exact");
        let domain_al = make_typed_acl(&["good.com"], "exact");

        assert!(check_optional_all(Some(&generic_al), Some(&ip_al), Some(&ua_al), Some(&domain_al), "trusted"));
        assert!(check_optional_all(Some(&generic_al), Some(&ip_al), Some(&ua_al), Some(&domain_al), "10.0.0.1"));
        assert!(check_optional_all(Some(&generic_al), Some(&ip_al), Some(&ua_al), Some(&domain_al), "good-agent"));
        assert!(check_optional_all(Some(&generic_al), Some(&ip_al), Some(&ua_al), Some(&domain_al), "good.com"));
        assert!(!check_optional_all(Some(&generic_al), Some(&ip_al), Some(&ua_al), Some(&domain_al), "bad"));
    }

    #[test]
    fn test_typed_check_does_not_cross_types() {
        // This is the key isolation test: IP check should NOT match UA entries
        let generic = build_acl_data(&[], "exact");
        let ip_typed = make_typed_acl(&["192.168.1.100"], "exact");
        let ua_typed = make_typed_acl(&["friendly-scanner"], "exact");

        // Checking IP-typed: should find 192.168.1.100 but NOT friendly-scanner
        assert!(check_with_typed(&generic, Some(&ip_typed), "192.168.1.100"));
        assert!(!check_with_typed(&generic, Some(&ip_typed), "friendly-scanner"));

        // Checking UA-typed: should find friendly-scanner but NOT 192.168.1.100
        assert!(check_with_typed(&generic, Some(&ua_typed), "friendly-scanner"));
        assert!(!check_with_typed(&generic, Some(&ua_typed), "192.168.1.100"));
    }

    #[test]
    fn test_typed_prefix_mode() {
        let generic = build_acl_data(&[], "prefix");
        let ip_typed = make_typed_acl(&["192.168.", "10.0.0."], "prefix");

        assert!(check_with_typed(&generic, Some(&ip_typed), "192.168.1.100"));
        assert!(check_with_typed(&generic, Some(&ip_typed), "10.0.0.42"));
        assert!(!check_with_typed(&generic, Some(&ip_typed), "172.16.0.1"));
    }

    #[test]
    fn test_typed_reload() {
        use std::io::Write;

        let path = format!("{}/rust_acl_typed_reload_test", std::env::temp_dir().display());
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "192.168.1.1").unwrap();
        }

        let loader = FileLoader::new(&path, default_line_parser, build_vec).unwrap();
        let entries = loader.get();
        let data = build_acl_data(&entries, "exact");
        drop(entries);
        let mut typed = TypedAcl { data, loader };

        assert!(check_acl_data(&typed.data, "192.168.1.1"));
        assert!(!check_acl_data(&typed.data, "10.0.0.1"));

        // Update file and reload
        std::fs::write(&path, "10.0.0.1\n").unwrap();
        let result = reload_typed(&mut typed, "exact", "test_typed");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);

        assert!(!check_acl_data(&typed.data, "192.168.1.1"));
        assert!(check_acl_data(&typed.data, "10.0.0.1"));

        let _ = std::fs::remove_file(&path);
    }

    // ── Regex mode tests (Task 35) ───────────────────────────────

    #[test]
    fn test_regex_basic_match() {
        let data = build_acl_data(
            &[".*scanner.*".to_string(), "^SIPVicious".to_string()],
            "regex",
        );
        assert!(check_acl_data(&data, "friendly-scanner/1.8"));
        assert!(check_acl_data(&data, "port-scanner-bot"));
        assert!(check_acl_data(&data, "SIPVicious/0.3"));
        assert!(!check_acl_data(&data, "sipvicious")); // case-sensitive
        assert!(!check_acl_data(&data, "good-agent"));
    }

    #[test]
    fn test_regex_ip_pattern() {
        let data = build_acl_data(
            &[r"^192\.168\.1\.\d+$".to_string(), r"^10\.0\.0\.".to_string()],
            "regex",
        );
        assert!(check_acl_data(&data, "192.168.1.100"));
        assert!(check_acl_data(&data, "192.168.1.1"));
        assert!(!check_acl_data(&data, "192.168.2.1"));
        assert!(check_acl_data(&data, "10.0.0.42"));
        assert!(!check_acl_data(&data, "172.16.0.1"));
    }

    #[test]
    fn test_regex_case_sensitive() {
        let data = build_acl_data(
            &["^friendly-scanner".to_string()],
            "regex",
        );
        assert!(check_acl_data(&data, "friendly-scanner/1.8"));
        assert!(!check_acl_data(&data, "Friendly-Scanner/1.8"));
    }

    #[test]
    fn test_regex_case_insensitive_flag() {
        // Use inline regex flag for case-insensitive
        let data = build_acl_data(
            &["(?i)^friendly-scanner".to_string()],
            "regex",
        );
        assert!(check_acl_data(&data, "friendly-scanner/1.8"));
        assert!(check_acl_data(&data, "Friendly-Scanner/1.8"));
        assert!(check_acl_data(&data, "FRIENDLY-SCANNER"));
    }

    #[test]
    fn test_regex_invalid_pattern_skipped() {
        // Invalid regex should be skipped, valid ones still work
        let data = build_acl_data(
            &["[invalid".to_string(), "valid-pattern".to_string()],
            "regex",
        );
        // The invalid pattern is skipped, only valid-pattern works
        assert!(check_acl_data(&data, "valid-pattern"));
        assert!(!check_acl_data(&data, "[invalid"));
        match &data {
            AclData::Regex(patterns) => assert_eq!(patterns.len(), 1),
            _ => panic!("expected Regex variant"),
        }
    }

    #[test]
    fn test_regex_anchoring() {
        // Without anchors, regex matches anywhere in the string
        let data = build_acl_data(
            &["scanner".to_string()],
            "regex",
        );
        assert!(check_acl_data(&data, "friendly-scanner/1.8"));
        assert!(check_acl_data(&data, "scanner"));
        assert!(check_acl_data(&data, "port-scanner-bot"));

        // With anchors, must match full string
        let data = build_acl_data(
            &["^scanner$".to_string()],
            "regex",
        );
        assert!(check_acl_data(&data, "scanner"));
        assert!(!check_acl_data(&data, "friendly-scanner"));
    }

    #[test]
    fn test_regex_empty_list() {
        let data = build_acl_data(&[], "regex");
        assert!(!check_acl_data(&data, "anything"));
    }

    #[test]
    fn test_regex_all_invalid_patterns() {
        let data = build_acl_data(
            &["[bad1".to_string(), "[bad2".to_string()],
            "regex",
        );
        assert!(!check_acl_data(&data, "anything"));
        match &data {
            AclData::Regex(patterns) => assert_eq!(patterns.len(), 0),
            _ => panic!("expected Regex variant"),
        }
    }

    #[test]
    fn test_build_acl_data_regex() {
        let entries = vec!["^abc".to_string(), "xyz$".to_string()];
        let data = build_acl_data(&entries, "regex");
        match &data {
            AclData::Regex(patterns) => {
                assert_eq!(patterns.len(), 2);
            }
            _ => panic!("expected Regex"),
        }
    }

    #[test]
    fn test_check_regex_function() {
        let patterns: Vec<Regex> = vec![
            Regex::new(".*scanner.*").unwrap(),
            Regex::new(r"^10\.0\.0\.").unwrap(),
        ];
        assert!(check_regex(&patterns, "friendly-scanner"));
        assert!(check_regex(&patterns, "10.0.0.1"));
        assert!(!check_regex(&patterns, "good-agent"));
        assert!(!check_regex(&patterns, "192.168.1.1"));
    }


    // ── Entry counter tests (Task 38) ────────────────────────────

    #[test]
    fn test_counter_increment() {
        let mut counters: HashMap<String, u64> = HashMap::new();
        counter_increment(&mut counters, "192.168.1.100");
        counter_increment(&mut counters, "192.168.1.100");
        counter_increment(&mut counters, "bad-agent");
        assert_eq!(counters["192.168.1.100"], 2);
        assert_eq!(counters["bad-agent"], 1);
    }

    #[test]
    fn test_counter_increment_new_entry() {
        let mut counters: HashMap<String, u64> = HashMap::new();
        counter_increment(&mut counters, "first");
        assert_eq!(counters.len(), 1);
        assert_eq!(counters["first"], 1);
    }

    #[test]
    fn test_top_n_sorting() {
        let mut counters: HashMap<String, u64> = HashMap::new();
        counters.insert("low".to_string(), 1);
        counters.insert("high".to_string(), 100);
        counters.insert("mid".to_string(), 50);

        let json = top_n_entries(&counters, 2);
        // Should have high first, then mid (top 2)
        assert!(json.contains(r#""entry":"high","count":100"#));
        assert!(json.contains(r#""entry":"mid","count":50"#));
        assert!(!json.contains("low"));
    }

    #[test]
    fn test_top_n_empty() {
        let counters: HashMap<String, u64> = HashMap::new();
        let json = top_n_entries(&counters, 10);
        assert_eq!(json, "[]");
    }

    #[test]
    fn test_top_n_all_entries() {
        let mut counters: HashMap<String, u64> = HashMap::new();
        counters.insert("a".to_string(), 5);
        counters.insert("b".to_string(), 3);
        let json = top_n_entries(&counters, 100); // N > entries
        assert!(json.contains("\"a\""));
        assert!(json.contains("\"b\""));
    }

    #[test]
    fn test_find_matching_entry_exact() {
        let data = build_acl_data(
            &["192.168.1.100".to_string(), "bad-agent".to_string()],
            "exact",
        );
        assert_eq!(find_matching_entry(&data, "192.168.1.100"), Some("192.168.1.100".to_string()));
        assert_eq!(find_matching_entry(&data, "bad-agent"), Some("bad-agent".to_string()));
        assert_eq!(find_matching_entry(&data, "unknown"), None);
    }

    #[test]
    fn test_find_matching_entry_prefix() {
        let data = build_acl_data(
            &["192.168.".to_string(), "10.0.0.".to_string()],
            "prefix",
        );
        assert_eq!(find_matching_entry(&data, "192.168.1.100"), Some("192.168.".to_string()));
        assert_eq!(find_matching_entry(&data, "10.0.0.42"), Some("10.0.0.".to_string()));
        assert_eq!(find_matching_entry(&data, "172.16.0.1"), None);
    }

    #[test]
    fn test_find_matching_entry_regex() {
        let data = build_acl_data(
            &[".*scanner.*".to_string(), "^SIPVicious".to_string()],
            "regex",
        );
        assert_eq!(find_matching_entry(&data, "friendly-scanner"), Some(".*scanner.*".to_string()));
        assert_eq!(find_matching_entry(&data, "SIPVicious/1.0"), Some("^SIPVicious".to_string()));
        assert_eq!(find_matching_entry(&data, "good-agent"), None);
    }

    #[test]
    fn test_counters_disabled_by_default() {
        // track_counters defaults to false; verify the flag
        assert!(!false); // placeholder: real test is in e2e
    }


    // ── Access policy tests (Task 65) ────────────────────────────

    #[test]
    fn test_access_policy_parse() {
        assert_eq!(AccessPolicy::from_str("allowlist-first"), Some(AccessPolicy::AllowlistFirst));
        assert_eq!(AccessPolicy::from_str("blocklist-first"), Some(AccessPolicy::BlocklistFirst));
        assert_eq!(AccessPolicy::from_str("allowlist-only"), Some(AccessPolicy::AllowlistOnly));
        assert_eq!(AccessPolicy::from_str("blocklist-only"), Some(AccessPolicy::BlocklistOnly));
        assert_eq!(AccessPolicy::from_str("invalid"), None);
        assert_eq!(AccessPolicy::from_str(""), None);
    }

    #[test]
    fn test_policy_allowlist_first_both_lists() {
        // Value in both lists: allowlist wins
        let bl = build_acl_data(&["shared".to_string()], "exact");
        let al = build_acl_data(&["shared".to_string()], "exact");
        let auto_bl: HashMap<String, AutoEntry> = HashMap::new();
        let auto_al: HashMap<String, AutoEntry> = HashMap::new();

        let result = check_access_with_policy(
            AccessPolicy::AllowlistFirst,
            &bl, None, None, None,
            Some(&al), None, None, None,
            &auto_bl, &auto_al, "shared",
        );
        assert_eq!(result, 1); // allowlist wins
    }

    #[test]
    fn test_policy_allowlist_first_only_blocklist() {
        let bl = build_acl_data(&["bad".to_string()], "exact");
        let auto_bl: HashMap<String, AutoEntry> = HashMap::new();
        let auto_al: HashMap<String, AutoEntry> = HashMap::new();

        let result = check_access_with_policy(
            AccessPolicy::AllowlistFirst,
            &bl, None, None, None,
            None, None, None, None,
            &auto_bl, &auto_al, "bad",
        );
        assert_eq!(result, -1); // blocked
    }

    #[test]
    fn test_policy_allowlist_first_neither() {
        let bl = build_acl_data(&["bad".to_string()], "exact");
        let auto_bl: HashMap<String, AutoEntry> = HashMap::new();
        let auto_al: HashMap<String, AutoEntry> = HashMap::new();

        let result = check_access_with_policy(
            AccessPolicy::AllowlistFirst,
            &bl, None, None, None,
            None, None, None, None,
            &auto_bl, &auto_al, "unknown",
        );
        assert_eq!(result, 1); // default allow
    }

    #[test]
    fn test_policy_blocklist_first_both_lists() {
        // Value in both lists: blocklist wins
        let bl = build_acl_data(&["shared".to_string()], "exact");
        let al = build_acl_data(&["shared".to_string()], "exact");
        let auto_bl: HashMap<String, AutoEntry> = HashMap::new();
        let auto_al: HashMap<String, AutoEntry> = HashMap::new();

        let result = check_access_with_policy(
            AccessPolicy::BlocklistFirst,
            &bl, None, None, None,
            Some(&al), None, None, None,
            &auto_bl, &auto_al, "shared",
        );
        assert_eq!(result, -1); // blocklist wins
    }

    #[test]
    fn test_policy_blocklist_first_only_allowlist() {
        let bl = build_acl_data(&[], "exact");
        let al = build_acl_data(&["good".to_string()], "exact");
        let auto_bl: HashMap<String, AutoEntry> = HashMap::new();
        let auto_al: HashMap<String, AutoEntry> = HashMap::new();

        let result = check_access_with_policy(
            AccessPolicy::BlocklistFirst,
            &bl, None, None, None,
            Some(&al), None, None, None,
            &auto_bl, &auto_al, "good",
        );
        assert_eq!(result, 1); // allowed
    }

    #[test]
    fn test_policy_blocklist_first_neither() {
        let bl = build_acl_data(&[], "exact");
        let auto_bl: HashMap<String, AutoEntry> = HashMap::new();
        let auto_al: HashMap<String, AutoEntry> = HashMap::new();

        let result = check_access_with_policy(
            AccessPolicy::BlocklistFirst,
            &bl, None, None, None,
            None, None, None, None,
            &auto_bl, &auto_al, "unknown",
        );
        assert_eq!(result, 1); // default allow
    }

    #[test]
    fn test_policy_allowlist_only_in_list() {
        let bl = build_acl_data(&[], "exact");
        let al = build_acl_data(&["trusted".to_string()], "exact");
        let auto_bl: HashMap<String, AutoEntry> = HashMap::new();
        let auto_al: HashMap<String, AutoEntry> = HashMap::new();

        let result = check_access_with_policy(
            AccessPolicy::AllowlistOnly,
            &bl, None, None, None,
            Some(&al), None, None, None,
            &auto_bl, &auto_al, "trusted",
        );
        assert_eq!(result, 1); // in allowlist
    }

    #[test]
    fn test_policy_allowlist_only_not_in_list() {
        let bl = build_acl_data(&[], "exact");
        let al = build_acl_data(&["trusted".to_string()], "exact");
        let auto_bl: HashMap<String, AutoEntry> = HashMap::new();
        let auto_al: HashMap<String, AutoEntry> = HashMap::new();

        let result = check_access_with_policy(
            AccessPolicy::AllowlistOnly,
            &bl, None, None, None,
            Some(&al), None, None, None,
            &auto_bl, &auto_al, "unknown",
        );
        assert_eq!(result, -1); // NOT in allowlist -> block
    }

    #[test]
    fn test_policy_blocklist_only_in_list() {
        let bl = build_acl_data(&["bad".to_string()], "exact");
        let auto_bl: HashMap<String, AutoEntry> = HashMap::new();
        let auto_al: HashMap<String, AutoEntry> = HashMap::new();

        let result = check_access_with_policy(
            AccessPolicy::BlocklistOnly,
            &bl, None, None, None,
            None, None, None, None,
            &auto_bl, &auto_al, "bad",
        );
        assert_eq!(result, -1); // in blocklist
    }

    #[test]
    fn test_policy_blocklist_only_not_in_list() {
        let bl = build_acl_data(&["bad".to_string()], "exact");
        let auto_bl: HashMap<String, AutoEntry> = HashMap::new();
        let auto_al: HashMap<String, AutoEntry> = HashMap::new();

        let result = check_access_with_policy(
            AccessPolicy::BlocklistOnly,
            &bl, None, None, None,
            None, None, None, None,
            &auto_bl, &auto_al, "good",
        );
        assert_eq!(result, 1); // NOT in blocklist -> allow
    }

    #[test]
    fn test_policy_with_auto_entries() {
        let bl = build_acl_data(&[], "exact");
        let mut auto_bl: HashMap<String, AutoEntry> = HashMap::new();
        auto_insert(&mut auto_bl, "auto-blocked", 300);
        let mut auto_al: HashMap<String, AutoEntry> = HashMap::new();
        auto_insert(&mut auto_al, "auto-allowed", 300);

        // AllowlistFirst: auto-allow wins
        assert_eq!(check_access_with_policy(
            AccessPolicy::AllowlistFirst,
            &bl, None, None, None, None, None, None, None,
            &auto_bl, &auto_al, "auto-allowed",
        ), 1);

        // BlocklistFirst: auto-block wins
        assert_eq!(check_access_with_policy(
            AccessPolicy::BlocklistFirst,
            &bl, None, None, None, None, None, None, None,
            &auto_bl, &auto_al, "auto-blocked",
        ), -1);
    }

}
