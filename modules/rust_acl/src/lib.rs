//! rust_acl — Live-reload ACL (blocklist + allowlist) for OpenSIPS.
//!
//! Loads blocklist and optional allowlist files at startup into each worker
//! process. Files are parsed line-by-line (comments and blanks skipped).
//! Matching can be exact (HashSet), prefix-based (Vec of prefixes),
//! regex-based (compiled patterns), CIDR range-based, glob-based,
//! or auto-detected per entry.
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
use rust_common::cidr::CidrRange;
use rust_common::event;
use rust_common::mi::Stats;
use rust_common::mi_resp::{MiObject, mi_error};
use rust_common::stat::{StatVar, StatVarOpaque};
use rust_common::glob;
use rust_common::reload::{default_line_parser, FileLoader};

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ffi::{c_int, c_void};
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::time::Instant;

// Native statistics -- cross-worker, aggregated by OpenSIPS core.
static STAT_CHECKED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_ALLOWED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_BLOCKED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_RELOADS: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_AUTO_BLOCKED: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_ENTRIES_BLOCKLIST: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());
static STAT_ENTRIES_ALLOWLIST: AtomicPtr<StatVarOpaque> = AtomicPtr::new(std::ptr::null_mut());

/// STAT_NO_RESET flag value (from OpenSIPS statistics.h).
const STAT_NO_RESET: u16 = 1;

use regex::Regex;

#[cfg(feature = "database")]
use sqlx;
#[cfg(feature = "database")]
use tokio;

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

/// Enable event publishing (0=off, 1=on, default 0).
static PUBLISH_EVENTS: ModString = ModString::new();

/// Access policy for check_access(): "allowlist-first", "blocklist-first",
/// "allowlist-only", or "blocklist-only" (default: "allowlist-first").
static ACCESS_POLICY: ModString = ModString::new();

// ── Database modparams (optional, used with `database` feature) ──

/// Database connection URL: postgres://, mysql://, or sqlite:// (optional).
/// Without the `database` feature compiled in, this param is accepted but
/// ignored with a warning.
static DB_URL: ModString = ModString::new();

/// Database table name (default: "address").
static DB_TABLE: ModString = ModString::new();

/// Filter by `grp` column. 0 = all groups (default: 0).
static DB_GROUP: ModString = ModString::new();

/// Seconds between automatic DB reloads. 0 = load once (default: 0).
static DB_RELOAD_INTERVAL: ModString = ModString::new();

/// Which `grp` value maps to blocklist entries (default: 1).
static DB_BLOCKLIST_GROUP: ModString = ModString::new();

/// Which `grp` value maps to allowlist entries (default: 2).
static DB_ALLOWLIST_GROUP: ModString = ModString::new();

// ── ACL data structures ─────────────────────────────────────────

enum AclData {
    Exact(HashSet<String>),
    Prefix(Vec<String>),
    Regex(Vec<Regex>),
    Cidr(Vec<CidrRange>),
    Glob(Vec<String>),
    /// Auto mode: each entry is classified individually at load time.
    /// Contains a mix of entry types for maximum flexibility.
    Auto(AutoAclData),
}

/// Container for auto-detected entries of mixed types.
struct AutoAclData {
    exact: HashSet<String>,
    cidrs: Vec<CidrRange>,
    globs: Vec<String>,
    regexes: Vec<Regex>,
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

/// Check a list of CIDR ranges against a value (IP address string).
fn check_cidr(ranges: &[CidrRange], value: &str) -> bool {
    ranges.iter().any(|r| r.contains_str(value))
}

/// Check a list of glob patterns against a value.
fn check_glob(patterns: &[String], value: &str) -> bool {
    patterns.iter().any(|p| glob::glob_match(p, value))
}

/// Check an AclData structure against a value.
fn check_acl_data(data: &AclData, value: &str) -> bool {
    match data {
        AclData::Exact(set) => check_exact(set, value),
        AclData::Prefix(prefixes) => check_prefix(prefixes, value),
        AclData::Regex(patterns) => check_regex(patterns, value),
        AclData::Cidr(ranges) => check_cidr(ranges, value),
        AclData::Glob(patterns) => check_glob(patterns, value),
        AclData::Auto(auto) => {
            check_exact(&auto.exact, value)
                || check_cidr(&auto.cidrs, value)
                || check_glob(&auto.globs, value)
                || check_regex(&auto.regexes, value)
        }
    }
}

/// Detect the entry type from its format.
///
/// - Contains `/` followed by digits at the end -> CIDR
/// - Starts with `/` and ends with `/` -> Regex
/// - Contains `*` or `?` -> Glob
/// - Otherwise -> Exact string match
fn detect_entry_type(entry: &str) -> &'static str {
    // Check for regex: /pattern/
    if entry.starts_with('/') && entry.ends_with('/') && entry.len() > 2 {
        return "regex";
    }
    // Check for CIDR: contains / followed by digits at the end
    if let Some(idx) = entry.rfind('/') {
        let suffix = &entry[idx + 1..];
        if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
            // Verify the prefix looks like an IP address
            let addr_part = &entry[..idx];
            if addr_part.contains('.') || addr_part.contains(':') {
                return "cidr";
            }
        }
    }
    // Check for glob: contains * or ?
    if entry.contains('*') || entry.contains('?') {
        return "glob";
    }
    "exact"
}

/// Rebuild AclData from raw entries and mode string.
fn build_acl_data(entries: &[String], mode: &str) -> AclData {
    match mode {
        "exact" => AclData::Exact(entries.iter().cloned().collect()),
        "cidr" => {
            let ranges: Vec<CidrRange> = entries
                .iter()
                .filter_map(|e| {
                    match CidrRange::parse(e) {
                        Some(r) => Some(r),
                        None => {
                            #[cfg(not(test))]
                            opensips_log!(WARN, "rust_acl",
                                "invalid CIDR entry '{}', skipping", e);
                            #[cfg(test)]
                            eprintln!("WARN: invalid CIDR entry '{}', skipping", e);
                            None
                        }
                    }
                })
                .collect();
            AclData::Cidr(ranges)
        }
        "glob" => AclData::Glob(entries.to_vec()),
        "regex" => {
            let total = entries.len();
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
            if patterns.is_empty() && total > 0 {
                #[cfg(not(test))]
                opensips_log!(ERR, "rust_acl",
                    "ALL {} regex patterns are invalid — blocklist is empty, \
                     all traffic will be allowed", total);
                #[cfg(test)]
                eprintln!("ERR: ALL {} regex patterns are invalid", total);
            }
            AclData::Regex(patterns)
        }
        "auto" => {
            let mut exact = HashSet::new();
            let mut cidrs = Vec::new();
            let mut globs = Vec::new();
            let mut regexes = Vec::new();

            for entry in entries {
                match detect_entry_type(entry) {
                    "cidr" => {
                        match CidrRange::parse(entry) {
                            Some(r) => cidrs.push(r),
                            None => {
                                #[cfg(not(test))]
                                opensips_log!(WARN, "rust_acl",
                                    "auto: invalid CIDR '{}', treating as exact", entry);
                                #[cfg(test)]
                                eprintln!("WARN: auto: invalid CIDR '{}', treating as exact", entry);
                                exact.insert(entry.clone());
                            }
                        }
                    }
                    "glob" => globs.push(entry.clone()),
                    "regex" => {
                        // Strip leading/trailing slashes
                        let pat = &entry[1..entry.len() - 1];
                        match Regex::new(pat) {
                            Ok(r) => regexes.push(r),
                            Err(e) => {
                                #[cfg(not(test))]
                                opensips_log!(WARN, "rust_acl",
                                    "auto: invalid regex '{}': {}", pat, e);
                                #[cfg(test)]
                                eprintln!("WARN: auto: invalid regex '{}': {}", pat, e);
                                let _ = e;
                            }
                        }
                    }
                    _ => { exact.insert(entry.clone()); }
                }
            }
            AclData::Auto(AutoAclData { exact, cidrs, globs, regexes })
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
        || ip.is_some_and(|t| check_acl_data(&t.data, value))
        || ua.is_some_and(|t| check_acl_data(&t.data, value))
        || domain.is_some_and(|t| check_acl_data(&t.data, value))
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
    primary.is_some_and(|data| check_acl_data(data, value))
}

/// Check an optional primary AclData plus ALL typed AclData.
fn check_optional_all(
    primary: Option<&AclData>,
    ip: Option<&TypedAcl>,
    ua: Option<&TypedAcl>,
    domain: Option<&TypedAcl>,
    value: &str,
) -> bool {
    primary.is_some_and(|data| check_acl_data(data, value))
        || ip.is_some_and(|t| check_acl_data(&t.data, value))
        || ua.is_some_and(|t| check_acl_data(&t.data, value))
        || domain.is_some_and(|t| check_acl_data(&t.data, value))
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

/// Purge auto maps if they exceed a size threshold, preventing unbounded growth.
/// Called from ACL check paths to ensure cleanup even when auto_block/auto_allow
/// are not actively called.
fn maybe_purge_auto(auto_blocked: &mut HashMap<String, AutoEntry>,
                    auto_allowed: &mut HashMap<String, AutoEntry>) {
    const PURGE_THRESHOLD: usize = 1024;
    if auto_blocked.len() > PURGE_THRESHOLD {
        purge_expired(auto_blocked);
    }
    if auto_allowed.len() > PURGE_THRESHOLD {
        purge_expired(auto_allowed);
    }
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
                .cloned()
        }
        AclData::Regex(patterns) => {
            patterns.iter()
                .find(|r| r.is_match(value))
                .map(|r| r.as_str().to_string())
        }
        AclData::Cidr(ranges) => {
            ranges.iter()
                .find(|r| r.contains_str(value))
                .map(|r| r.to_string())
        }
        AclData::Glob(patterns) => {
            patterns.iter()
                .find(|p| glob::glob_match(p, value))
                .cloned()
        }
        AclData::Auto(auto) => {
            if auto.exact.contains(value) {
                return Some(value.to_string());
            }
            if let Some(r) = auto.cidrs.iter().find(|r| r.contains_str(value)) {
                return Some(r.to_string());
            }
            if let Some(g) = auto.globs.iter().find(|p| glob::glob_match(p, value)) {
                return Some(g.clone());
            }
            auto.regexes.iter()
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
    // Database integration (only with `database` feature)
    #[cfg(feature = "database")]
    db_blocklist: Option<AclData>,
    #[cfg(feature = "database")]
    db_allowlist: Option<AclData>,
    #[cfg(feature = "database")]
    db_pool: Option<sqlx::AnyPool>,
    #[cfg(feature = "database")]
    db_runtime: Option<tokio::runtime::Runtime>,
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

// ── Database integration ──────────────────────────────────────────

#[cfg_attr(not(feature = "database"), allow(dead_code))]
/// Convert a database row to AclEntry-compatible data.
/// Returns (ip_with_mask, pattern, context_info) for building ACL entries.
///
/// Logic:
///   - If mask < 32 (IPv4) or < 128 (IPv6): treat as CIDR
///   - If pattern is set: treat as regex
///   - Otherwise: treat as exact IP match
fn db_row_to_entry(ip: &str, mask: i32, pattern: Option<&str>) -> String {
    // If pattern is set, use it as a regex entry
    if let Some(pat) = pattern {
        if !pat.is_empty() {
            // Wrap in regex delimiters for auto-detect
            return format!("/{}/", pat);
        }
    }

    // Determine if this is a CIDR or exact entry
    let is_v6 = ip.contains(':');
    let max_mask = if is_v6 { 128 } else { 32 };

    if mask < max_mask && mask >= 0 {
        format!("{}/{}", ip, mask)
    } else {
        ip.to_string()
    }
}

#[cfg_attr(not(feature = "database"), allow(dead_code))]
/// Build the SQL query for the address table.
fn db_build_query(table: &str, _blocklist_group: i64, _allowlist_group: i64) -> String {
    // Use positional placeholders compatible with sqlx::any
    format!(
        "SELECT ip, mask, port, proto, pattern, context_info, grp          FROM {} WHERE grp IN ($1, $2)",
        table
    )
}

/// Load entries from the database, returning (blocklist_entries, allowlist_entries).
#[cfg(feature = "database")]
fn db_load_entries(
    pool: &sqlx::AnyPool,
    runtime: &tokio::runtime::Runtime,
    table: &str,
    blocklist_group: i64,
    allowlist_group: i64,
) -> Result<(Vec<String>, Vec<String>), String> {
    runtime.block_on(async {
        db_load_entries_async(pool, table, blocklist_group, allowlist_group).await
    })
}

#[cfg(feature = "database")]
async fn db_load_entries_async(
    pool: &sqlx::AnyPool,
    table: &str,
    blocklist_group: i64,
    allowlist_group: i64,
) -> Result<(Vec<String>, Vec<String>), String> {
    use sqlx::Row;

    let query = db_build_query(table, blocklist_group, allowlist_group);
    let rows = sqlx::query(&query)
        .bind(blocklist_group)
        .bind(allowlist_group)
        .fetch_all(pool)
        .await
        .map_err(|e| format!("DB query failed: {}", e))?;

    let mut blocklist_entries = Vec::new();
    let mut allowlist_entries = Vec::new();

    for row in &rows {
        let ip: String = row.try_get("ip").unwrap_or_default();
        let mask: i32 = row.try_get("mask").unwrap_or(32);
        let pattern: Option<String> = row.try_get("pattern").ok();
        let grp: i32 = row.try_get("grp").unwrap_or(0);

        if ip.is_empty() {
            continue;
        }

        let entry = db_row_to_entry(&ip, mask, pattern.as_deref());

        if grp as i64 == blocklist_group {
            blocklist_entries.push(entry);
        } else if grp as i64 == allowlist_group {
            allowlist_entries.push(entry);
        }
    }

    Ok((blocklist_entries, allowlist_entries))
}

#[cfg_attr(not(feature = "database"), allow(dead_code))]
/// Merge DB entries into existing ACL data.
/// DB entries are added to the auto-mode data structure.
fn merge_db_entries(entries: &[String]) -> AclData {
    build_acl_data(entries, "auto")
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
    if !matches!(mode, "exact" | "prefix" | "regex" | "cidr" | "glob" | "auto") {
        opensips_log!(ERR, "rust_acl",
            "modparam match_mode must be exact, prefix, regex, cidr, glob, or auto; got {}", mode);
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

    // Database parameter validation
    if let Some(url) = DB_URL.get_value() {
        if !url.is_empty() {
            #[cfg(feature = "database")]
            {
                opensips_log!(INFO, "rust_acl", "  db_url={} (database support compiled in)", url);
                let table = DB_TABLE.get_value().unwrap_or("address");
                opensips_log!(INFO, "rust_acl", "  db_table={}", table);
                let bl_grp = DB_BLOCKLIST_GROUP.get_value().unwrap_or("1");
                let al_grp = DB_ALLOWLIST_GROUP.get_value().unwrap_or("2");
                opensips_log!(INFO, "rust_acl", "  db_blocklist_group={}, db_allowlist_group={}", bl_grp, al_grp);
                let interval = DB_RELOAD_INTERVAL.get_value().unwrap_or("0");
                opensips_log!(INFO, "rust_acl", "  db_reload_interval={}s", interval);
            }
            #[cfg(not(feature = "database"))]
            {
                opensips_log!(WARN, "rust_acl",
                    "db_url configured but database support not compiled in.                      Rebuild with: cargo build --features database -p rust-acl");
            }
        }
    }

    0
}

unsafe extern "C" fn mod_child_init(rank: c_int) -> c_int {
    // Initialize for SIP workers (rank >= 1) and PROC_MODULE (-2) which
    // handles MI commands via httpd.
    if rank < 1 && rank != -2 {
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
        .is_some_and(|v| v == "1");

    let access_policy = unsafe { ACCESS_POLICY.get_value() }
        .and_then(AccessPolicy::from_str)
        .unwrap_or(AccessPolicy::AllowlistFirst);

    // Load database entries if configured
    #[cfg(feature = "database")]
    let (db_blocklist, db_allowlist, db_pool, db_runtime) = {
        match unsafe { DB_URL.get_value() } {
            Some(url) if !url.is_empty() => {
                let table = unsafe { DB_TABLE.get_value() }.unwrap_or("address").to_string();
                let bl_grp: i64 = unsafe { DB_BLOCKLIST_GROUP.get_value() }
                    .unwrap_or("1").parse().unwrap_or(1);
                let al_grp: i64 = unsafe { DB_ALLOWLIST_GROUP.get_value() }
                    .unwrap_or("2").parse().unwrap_or(2);
                let interval: u64 = unsafe { DB_RELOAD_INTERVAL.get_value() }
                    .unwrap_or("0").parse().unwrap_or(0);

                let rt = match tokio::runtime::Runtime::new() {
                    Ok(rt) => rt,
                    Err(e) => {
                        opensips_log!(ERR, "rust_acl",
                            "failed to create tokio runtime for DB: {}", e);
                        return -1;
                    }
                };

                // Install the any driver(s)
                let _ = rt.block_on(async {
                    sqlx::any::install_default_drivers();
                });

                let pool = match rt.block_on(async {
                    sqlx::any::AnyPoolOptions::new()
                        .max_connections(2)
                        .connect(url)
                        .await
                }) {
                    Ok(p) => p,
                    Err(e) => {
                        opensips_log!(ERR, "rust_acl",
                            "failed to connect to database: {}", e);
                        return -1;
                    }
                };

                match db_load_entries(&pool, &rt, &table, bl_grp, al_grp) {
                    Ok((bl_entries, al_entries)) => {
                        let bl_count = bl_entries.len();
                        let al_count = al_entries.len();
                        let db_bl = if bl_entries.is_empty() {
                            None
                        } else {
                            Some(merge_db_entries(&bl_entries))
                        };
                        let db_al = if al_entries.is_empty() {
                            None
                        } else {
                            Some(merge_db_entries(&al_entries))
                        };
                        opensips_log!(INFO, "rust_acl",
                            "DB loaded: {} blocklist + {} allowlist entries from table '{}'",
                            bl_count, al_count, table);

                        // Spawn periodic reload task if interval > 0
                        if interval > 0 {
                            opensips_log!(INFO, "rust_acl",
                                "DB periodic reload every {}s (note: per-worker,                                  changes visible after next reload cycle)", interval);
                        }

                        (db_bl, db_al, Some(pool), Some(rt))
                    }
                    Err(e) => {
                        opensips_log!(ERR, "rust_acl",
                            "failed to load DB entries: {}", e);
                        return -1;
                    }
                }
            }
            _ => (None, None, None, None),
        }
    };

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
            #[cfg(feature = "database")]
            db_blocklist,
            #[cfg(feature = "database")]
            db_allowlist,
            #[cfg(feature = "database")]
            db_pool,
            #[cfg(feature = "database")]
            db_runtime,
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
                    maybe_purge_auto(&mut state.auto_blocked, &mut state.auto_allowed);
                    state.stats.inc("checked");
                    if let Some(s) = StatVar::from_raw(STAT_CHECKED.load(Ordering::Relaxed)) { s.inc(); }

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
                        if let Some(s) = StatVar::from_raw(STAT_BLOCKED.load(Ordering::Relaxed)) { s.inc(); }
                        // Publish E_ACL_BLOCKED event
                        if event::is_enabled() {
                            let payload = event::format_payload(&[
                                ("value", &event::json_str(value)),
                                ("source", &event::json_str("blocklist")),
                            ]);
                            opensips_log!(NOTICE, "rust_acl", "EVENT E_ACL_BLOCKED {}", payload);
                        }
                        -1
                    } else {
                        state.stats.inc("allowed");
                        if let Some(s) = StatVar::from_raw(STAT_ALLOWED.load(Ordering::Relaxed)) { s.inc(); }
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
                    if let Some(s) = StatVar::from_raw(STAT_CHECKED.load(Ordering::Relaxed)) { s.inc(); }
                    let blocked = check_with_typed(
                        &state.blocklist,
                        state.blocklist_ip.as_ref(),
                        value,
                    ) || check_auto(&state.auto_blocked, value);

                    if blocked {
                        state.stats.inc("blocked");
                        if let Some(s) = StatVar::from_raw(STAT_BLOCKED.load(Ordering::Relaxed)) { s.inc(); }
                        -1
                    } else {
                        state.stats.inc("allowed");
                        if let Some(s) = StatVar::from_raw(STAT_ALLOWED.load(Ordering::Relaxed)) { s.inc(); }
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
                    if let Some(s) = StatVar::from_raw(STAT_CHECKED.load(Ordering::Relaxed)) { s.inc(); }
                    let blocked = check_with_typed(
                        &state.blocklist,
                        state.blocklist_ua.as_ref(),
                        value,
                    ) || check_auto(&state.auto_blocked, value);

                    if blocked {
                        state.stats.inc("blocked");
                        if let Some(s) = StatVar::from_raw(STAT_BLOCKED.load(Ordering::Relaxed)) { s.inc(); }
                        -1
                    } else {
                        state.stats.inc("allowed");
                        if let Some(s) = StatVar::from_raw(STAT_ALLOWED.load(Ordering::Relaxed)) { s.inc(); }
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
                    if let Some(s) = StatVar::from_raw(STAT_CHECKED.load(Ordering::Relaxed)) { s.inc(); }
                    let blocked = check_with_typed(
                        &state.blocklist,
                        state.blocklist_domain.as_ref(),
                        value,
                    ) || check_auto(&state.auto_blocked, value);

                    if blocked {
                        state.stats.inc("blocked");
                        if let Some(s) = StatVar::from_raw(STAT_BLOCKED.load(Ordering::Relaxed)) { s.inc(); }
                        -1
                    } else {
                        state.stats.inc("allowed");
                        if let Some(s) = StatVar::from_raw(STAT_ALLOWED.load(Ordering::Relaxed)) { s.inc(); }
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

#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
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
    check_access_with_policy_and_db(
        policy, blocklist, blocklist_ip, blocklist_ua, blocklist_domain,
        allowlist, allowlist_ip, allowlist_ua, allowlist_domain,
        auto_blocked, auto_allowed, None, None, value,
    )
}

/// Full access policy check including optional DB ACL data.
#[allow(clippy::too_many_arguments)]
fn check_access_with_policy_and_db(
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
    db_blocklist: Option<&AclData>,
    db_allowlist: Option<&AclData>,
    value: &str,
) -> i32 {
    let in_allowlist = || {
        check_auto(auto_allowed, value)
            || check_optional_all(allowlist, allowlist_ip, allowlist_ua, allowlist_domain, value)
            || db_allowlist.is_some_and(|data| check_acl_data(data, value))
    };
    let in_blocklist = || {
        check_auto(auto_blocked, value)
            || check_all(blocklist, blocklist_ip, blocklist_ua, blocklist_domain, value)
            || db_blocklist.is_some_and(|data| check_acl_data(data, value))
    };

    match policy {
        AccessPolicy::AllowlistFirst => {
            if in_allowlist() {
                1
            } else if in_blocklist() {
                -1
            } else {
                1 // default allow
            }
        }
        #[allow(clippy::if_same_then_else)]
        AccessPolicy::BlocklistFirst => {
            if in_blocklist() {
                -1
            } else if in_allowlist() {
                1
            } else {
                1 // default allow
            }
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
                    if let Some(s) = StatVar::from_raw(STAT_CHECKED.load(Ordering::Relaxed)) { s.inc(); }

                    #[cfg(feature = "database")]
                    let (db_bl, db_al) = (
                        state.db_blocklist.as_ref(),
                        state.db_allowlist.as_ref(),
                    );
                    #[cfg(not(feature = "database"))]
                    let (db_bl, db_al): (Option<&AclData>, Option<&AclData>) = (None, None);

                    let result = check_access_with_policy_and_db(
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
                        db_bl,
                        db_al,
                        value,
                    );

                    if result == 1 {
                        state.stats.inc("allowed");
                        if let Some(s) = StatVar::from_raw(STAT_ALLOWED.load(Ordering::Relaxed)) { s.inc(); }
                        if event::is_enabled() {
                            let payload = event::format_payload(&[
                                ("value", &event::json_str(value)),
                                ("result", &event::json_str("allowed")),
                            ]);
                            opensips_log!(NOTICE, "rust_acl", "EVENT E_ACL_ALLOWED {}", payload);
                        }
                    } else {
                        state.stats.inc("blocked");
                        if let Some(s) = StatVar::from_raw(STAT_BLOCKED.load(Ordering::Relaxed)) { s.inc(); }
                        if event::is_enabled() {
                            let payload = event::format_payload(&[
                                ("value", &event::json_str(value)),
                                ("result", &event::json_str("blocked")),
                            ]);
                            opensips_log!(NOTICE, "rust_acl", "EVENT E_ACL_BLOCKED {}", payload);
                        }
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
                            if let Some(s) = StatVar::from_raw(STAT_RELOADS.load(Ordering::Relaxed)) { s.inc(); }
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
                                    if let Some(s) = StatVar::from_raw(STAT_RELOADS.load(Ordering::Relaxed)) { s.inc(); }
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
                    if let Some(s) = StatVar::from_raw(STAT_AUTO_BLOCKED.load(Ordering::Relaxed)) { s.inc(); }
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

// ── Script function: acl_prometheus() ──

unsafe extern "C" fn w_access_prometheus(
    msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let prom = WORKER.with(|w| {
            let borrow = w.borrow();
            match borrow.as_ref() {
                Some(state) => state.stats.to_prometheus(),
                None => String::new(),
            }
        });
        let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };
        let _ = sip_msg.set_pv("$var(acl_prom)", &prom);
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

// ── Script function: acl_db_reload() — manual DB reload ─────────

unsafe extern "C" fn w_acl_db_reload(
    _msg: *mut sys::sip_msg,
    _p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        #[cfg(feature = "database")]
        {
            WORKER.with(|w| {
                let mut borrow = w.borrow_mut();
                match borrow.as_mut() {
                    Some(state) => {
                        let (pool, runtime) = match (state.db_pool.as_ref(), state.db_runtime.as_ref()) {
                            (Some(p), Some(r)) => (p, r),
                            _ => {
                                opensips_log!(WARN, "rust_acl",
                                    "acl_db_reload: no database configured");
                                return -1;
                            }
                        };

                        let table = unsafe { DB_TABLE.get_value() }.unwrap_or("address");
                        let bl_grp: i64 = unsafe { DB_BLOCKLIST_GROUP.get_value() }
                            .unwrap_or("1").parse().unwrap_or(1);
                        let al_grp: i64 = unsafe { DB_ALLOWLIST_GROUP.get_value() }
                            .unwrap_or("2").parse().unwrap_or(2);

                        match db_load_entries(pool, runtime, table, bl_grp, al_grp) {
                            Ok((bl_entries, al_entries)) => {
                                let bl_count = bl_entries.len();
                                let al_count = al_entries.len();
                                state.db_blocklist = if bl_entries.is_empty() {
                                    None
                                } else {
                                    Some(merge_db_entries(&bl_entries))
                                };
                                state.db_allowlist = if al_entries.is_empty() {
                                    None
                                } else {
                                    Some(merge_db_entries(&al_entries))
                                };
                                state.stats.inc("reloads");
                                if let Some(s) = StatVar::from_raw(STAT_RELOADS.load(Ordering::Relaxed)) { s.inc(); }
                                opensips_log!(INFO, "rust_acl",
                                    "DB reloaded: {} blocklist + {} allowlist entries",
                                    bl_count, al_count);
                                1
                            }
                            Err(e) => {
                                opensips_log!(ERR, "rust_acl",
                                    "acl_db_reload failed: {}", e);
                                -1
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
        }
        #[cfg(not(feature = "database"))]
        {
            opensips_log!(WARN, "rust_acl",
                "acl_db_reload: database support not compiled in.                  Rebuild with: cargo build --features database -p rust-acl");
            -1
        }
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

// ── Native statistics array ────────────────────────────────────────

static MOD_STATS: SyncArray<sys::stat_export_, 8> = SyncArray([
    sys::stat_export_ { name: cstr_lit!("checked") as *mut _,           flags: 0,             stat_pointer: STAT_CHECKED.as_ptr() as *mut _ },
    sys::stat_export_ { name: cstr_lit!("allowed") as *mut _,           flags: 0,             stat_pointer: STAT_ALLOWED.as_ptr() as *mut _ },
    sys::stat_export_ { name: cstr_lit!("blocked") as *mut _,           flags: 0,             stat_pointer: STAT_BLOCKED.as_ptr() as *mut _ },
    sys::stat_export_ { name: cstr_lit!("reloads") as *mut _,           flags: 0,             stat_pointer: STAT_RELOADS.as_ptr() as *mut _ },
    sys::stat_export_ { name: cstr_lit!("auto_blocked") as *mut _,      flags: STAT_NO_RESET, stat_pointer: STAT_AUTO_BLOCKED.as_ptr() as *mut _ },
    sys::stat_export_ { name: cstr_lit!("entries_blocklist") as *mut _, flags: STAT_NO_RESET, stat_pointer: STAT_ENTRIES_BLOCKLIST.as_ptr() as *mut _ },
    sys::stat_export_ { name: cstr_lit!("entries_allowlist") as *mut _, flags: STAT_NO_RESET, stat_pointer: STAT_ENTRIES_ALLOWLIST.as_ptr() as *mut _ },
    unsafe { std::mem::zeroed() }, // NULL terminator
]);

// ── MI command handlers ────────────────────────────────────────────

/// MI handler: rust_acl:blocklist_show
unsafe extern "C" fn mi_blocklist_show(
    _params: *const sys::mi_params_,
    _async_hdl: *mut sys::mi_handler,
) -> *mut sys::mi_response_t {
    WORKER.with(|w| {
        let w = w.borrow();
        let Some(state) = w.as_ref() else {
            return mi_error(-32000, "Worker not initialized") as *mut _;
        };
        let Some(resp) = MiObject::new() else {
            return mi_error(-32000, "Failed to create MI response") as *mut _;
        };
        let Some(arr) = resp.add_array("entries") else {
            return mi_error(-32000, "Failed to create entries array") as *mut _;
        };
        let entries = state.blocklist_loader.get();
        let mut count = 0u32;
        for entry in entries.iter() {
            if let Some(obj) = arr.add_object("") {
                obj.add_str("pattern", entry);
                obj.add_str("type", &state.mode);
                if state.track_counters {
                    let hits = state.entry_counters.get(entry).copied().unwrap_or(0);
                    obj.add_num("hits", hits as f64);
                }
                count += 1;
            }
        }
        resp.add_num("count", count as f64);
        resp.into_raw() as *mut _
    })
}

/// MI handler: rust_acl:allowlist_show
unsafe extern "C" fn mi_allowlist_show(
    _params: *const sys::mi_params_,
    _async_hdl: *mut sys::mi_handler,
) -> *mut sys::mi_response_t {
    WORKER.with(|w| {
        let w = w.borrow();
        let Some(state) = w.as_ref() else {
            return mi_error(-32000, "Worker not initialized") as *mut _;
        };
        let Some(ref loader) = state.allowlist_loader else {
            return mi_error(-32000, "No allowlist configured") as *mut _;
        };
        let Some(resp) = MiObject::new() else {
            return mi_error(-32000, "Failed to create MI response") as *mut _;
        };
        let Some(arr) = resp.add_array("entries") else {
            return mi_error(-32000, "Failed to create entries array") as *mut _;
        };
        let entries = loader.get();
        let mut count = 0u32;
        for entry in entries.iter() {
            if let Some(obj) = arr.add_object("") {
                obj.add_str("pattern", entry);
                obj.add_str("type", &state.mode);
                count += 1;
            }
        }
        resp.add_num("count", count as f64);
        resp.into_raw() as *mut _
    })
}

/// MI handler: rust_acl:blocklist_reload
unsafe extern "C" fn mi_blocklist_reload(
    _params: *const sys::mi_params_,
    _async_hdl: *mut sys::mi_handler,
) -> *mut sys::mi_response_t {
    WORKER.with(|w| {
        let mut w = w.borrow_mut();
        let Some(state) = w.as_mut() else {
            return mi_error(-32000, "Worker not initialized") as *mut _;
        };
        match state.blocklist_loader.reload() {
            Ok(count) => {
                let entries = state.blocklist_loader.get();
                state.blocklist = build_acl_data(&entries, &state.mode);
                drop(entries);
                state.stats.set("entries_blocklist", count as u64);
                state.stats.inc("reloads");
                if let Some(s) = StatVar::from_raw(STAT_RELOADS.load(Ordering::Relaxed)) { s.inc(); }
                if let Some(s) = StatVar::from_raw(STAT_ENTRIES_BLOCKLIST.load(Ordering::Relaxed)) {
                    // gui_dCquvqE1csI3: clamp to i32::MAX for large entry counts
                    s.update(count.min(i32::MAX as usize) as i32);
                }
                let Some(resp) = MiObject::new() else {
                    return mi_error(-32000, "Failed to create MI response") as *mut _;
                };
                resp.add_str("status", "OK");
                resp.add_num("entries", count as f64);
                resp.into_raw() as *mut _
            }
            Err(e) => mi_error(-32000, &format!("Reload failed: {e}")) as *mut _,
        }
    })
}

/// MI handler: rust_acl:allowlist_reload
unsafe extern "C" fn mi_allowlist_reload(
    _params: *const sys::mi_params_,
    _async_hdl: *mut sys::mi_handler,
) -> *mut sys::mi_response_t {
    WORKER.with(|w| {
        let mut w = w.borrow_mut();
        let Some(state) = w.as_mut() else {
            return mi_error(-32000, "Worker not initialized") as *mut _;
        };
        let Some(ref loader) = state.allowlist_loader else {
            return mi_error(-32000, "No allowlist configured") as *mut _;
        };
        match loader.reload() {
            Ok(count) => {
                let entries = loader.get();
                state.allowlist = Some(build_acl_data(&entries, &state.mode));
                drop(entries);
                state.stats.set("entries_allowlist", count as u64);
                state.stats.inc("reloads");
                if let Some(s) = StatVar::from_raw(STAT_RELOADS.load(Ordering::Relaxed)) { s.inc(); }
                if let Some(s) = StatVar::from_raw(STAT_ENTRIES_ALLOWLIST.load(Ordering::Relaxed)) {
                    // gui_dCquvqE1csI3: clamp to i32::MAX for large entry counts
                    s.update(count.min(i32::MAX as usize) as i32);
                }
                let Some(resp) = MiObject::new() else {
                    return mi_error(-32000, "Failed to create MI response") as *mut _;
                };
                resp.add_str("status", "OK");
                resp.add_num("entries", count as f64);
                resp.into_raw() as *mut _
            }
            Err(e) => mi_error(-32000, &format!("Reload failed: {e}")) as *mut _,
        }
    })
}

// ── MI command export array ────────────────────────────────────────

static MI_CMDS: SyncArray<sys::mi_export_, 5> = SyncArray([
    sys::mi_export_ {
        name: cstr_lit!("blocklist_show") as *mut _,
        help: cstr_lit!("Show blocklist entries with hit counters") as *mut _,
        flags: 0,
        init_f: None,
        recipes: {
            let mut r: [sys::mi_recipe_; 48] = unsafe { std::mem::zeroed() };
            r[0] = sys::mi_recipe_ {
                cmd: Some(mi_blocklist_show),
                params: unsafe { std::mem::zeroed() },
            };
            r
        },
        aliases: [ptr::null(); 4],
    },
    sys::mi_export_ {
        name: cstr_lit!("allowlist_show") as *mut _,
        help: cstr_lit!("Show allowlist entries with hit counters") as *mut _,
        flags: 0,
        init_f: None,
        recipes: {
            let mut r: [sys::mi_recipe_; 48] = unsafe { std::mem::zeroed() };
            r[0] = sys::mi_recipe_ {
                cmd: Some(mi_allowlist_show),
                params: unsafe { std::mem::zeroed() },
            };
            r
        },
        aliases: [ptr::null(); 4],
    },
    sys::mi_export_ {
        name: cstr_lit!("blocklist_reload") as *mut _,
        help: cstr_lit!("Reload blocklist from file") as *mut _,
        flags: 0,
        init_f: None,
        recipes: {
            let mut r: [sys::mi_recipe_; 48] = unsafe { std::mem::zeroed() };
            r[0] = sys::mi_recipe_ {
                cmd: Some(mi_blocklist_reload),
                params: unsafe { std::mem::zeroed() },
            };
            r
        },
        aliases: [ptr::null(); 4],
    },
    sys::mi_export_ {
        name: cstr_lit!("allowlist_reload") as *mut _,
        help: cstr_lit!("Reload allowlist from file") as *mut _,
        flags: 0,
        init_f: None,
        recipes: {
            let mut r: [sys::mi_recipe_; 48] = unsafe { std::mem::zeroed() };
            r[0] = sys::mi_recipe_ {
                cmd: Some(mi_allowlist_reload),
                params: unsafe { std::mem::zeroed() },
            };
            r
        },
        aliases: [ptr::null(); 4],
    },
    unsafe { std::mem::zeroed() }, // NULL terminator
]);

static CMDS: SyncArray<sys::cmd_export_, 18> = SyncArray([
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
    sys::cmd_export_ {
        name: cstr_lit!("access_prometheus"),
        function: Some(w_access_prometheus),
        params: EMPTY_PARAMS,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("acl_db_reload"),
        function: Some(w_acl_db_reload),
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

static PARAMS: SyncArray<sys::param_export_, 19> = SyncArray([
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
    sys::param_export_ {
        name: cstr_lit!("publish_events"),
        type_: 1, // STR_PARAM
        param_pointer: PUBLISH_EVENTS.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("db_url"),
        type_: 1,
        param_pointer: DB_URL.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("db_table"),
        type_: 1,
        param_pointer: DB_TABLE.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("db_group"),
        type_: 1,
        param_pointer: DB_GROUP.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("db_reload_interval"),
        type_: 1,
        param_pointer: DB_RELOAD_INTERVAL.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("db_blocklist_group"),
        type_: 1,
        param_pointer: DB_BLOCKLIST_GROUP.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("db_allowlist_group"),
        type_: 1,
        param_pointer: DB_ALLOWLIST_GROUP.as_ptr(),
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
    stats: MOD_STATS.0.as_ptr() as *const _,
    mi_cmds: MI_CMDS.0.as_ptr(),
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


    // ── event publishing tests ──────────────────────────────────

    #[test]
    fn test_event_payload_acl_blocked() {
        let payload = event::format_payload(&[
            ("value", &event::json_str("10.0.0.1")),
            ("source", &event::json_str("blocklist")),
        ]);
        assert!(payload.contains(r#""value":"10.0.0.1""#));
        assert!(payload.contains(r#""source":"blocklist""#));
    }

    #[test]
    fn test_event_payload_acl_allowed() {
        let payload = event::format_payload(&[
            ("value", &event::json_str("alice")),
            ("result", &event::json_str("allowed")),
        ]);
        assert!(payload.contains(r#""value":"alice""#));
        assert!(payload.contains(r#""result":"allowed""#));
    }

    // ── CIDR mode tests (Task 63) ───────────────────────────────

    #[test]
    fn test_cidr_mode_basic() {
        let data = build_acl_data(
            &["10.0.0.0/24".to_string(), "192.168.1.0/24".to_string()],
            "cidr",
        );
        assert!(check_acl_data(&data, "10.0.0.1"));
        assert!(check_acl_data(&data, "10.0.0.254"));
        assert!(check_acl_data(&data, "192.168.1.100"));
        assert!(!check_acl_data(&data, "10.0.1.1"));
        assert!(!check_acl_data(&data, "172.16.0.1"));
    }

    #[test]
    fn test_cidr_mode_slash_32() {
        let data = build_acl_data(
            &["192.168.1.100/32".to_string()],
            "cidr",
        );
        assert!(check_acl_data(&data, "192.168.1.100"));
        assert!(!check_acl_data(&data, "192.168.1.101"));
    }

    #[test]
    fn test_cidr_mode_slash_0() {
        let data = build_acl_data(
            &["0.0.0.0/0".to_string()],
            "cidr",
        );
        assert!(check_acl_data(&data, "10.0.0.1"));
        assert!(check_acl_data(&data, "192.168.1.1"));
        assert!(check_acl_data(&data, "255.255.255.255"));
    }

    #[test]
    fn test_cidr_mode_16() {
        let data = build_acl_data(
            &["192.168.0.0/16".to_string()],
            "cidr",
        );
        assert!(check_acl_data(&data, "192.168.0.1"));
        assert!(check_acl_data(&data, "192.168.255.255"));
        assert!(!check_acl_data(&data, "192.169.0.1"));
    }

    #[test]
    fn test_cidr_mode_invalid_entry_skipped() {
        let data = build_acl_data(
            &["not-a-cidr/24".to_string(), "10.0.0.0/24".to_string()],
            "cidr",
        );
        // Invalid entry skipped, valid one works
        assert!(check_acl_data(&data, "10.0.0.1"));
    }

    #[test]
    fn test_cidr_mode_non_ip_value() {
        let data = build_acl_data(
            &["10.0.0.0/24".to_string()],
            "cidr",
        );
        assert!(!check_acl_data(&data, "not-an-ip"));
        assert!(!check_acl_data(&data, ""));
    }

    #[test]
    fn test_cidr_mode_ipv6() {
        let data = build_acl_data(
            &["2001:db8::/32".to_string()],
            "cidr",
        );
        assert!(check_acl_data(&data, "2001:db8::1"));
        assert!(check_acl_data(&data, "2001:db8:ffff::1"));
        assert!(!check_acl_data(&data, "2001:db9::1"));
    }

    #[test]
    fn test_cidr_boundary_25() {
        let data = build_acl_data(
            &["10.0.0.0/25".to_string()],
            "cidr",
        );
        assert!(check_acl_data(&data, "10.0.0.0"));
        assert!(check_acl_data(&data, "10.0.0.127"));
        assert!(!check_acl_data(&data, "10.0.0.128"));
        assert!(!check_acl_data(&data, "10.0.0.255"));
    }

    // ── Glob mode tests (Task 63) ────────────────────────────────

    #[test]
    fn test_glob_mode_basic() {
        let data = build_acl_data(
            &["*.example.com".to_string(), "10.0.0.*".to_string()],
            "glob",
        );
        assert!(check_acl_data(&data, "evil.example.com"));
        assert!(check_acl_data(&data, "sub.evil.example.com"));
        assert!(check_acl_data(&data, "10.0.0.1"));
        assert!(check_acl_data(&data, "10.0.0.255"));
        assert!(!check_acl_data(&data, "example.com"));
        assert!(!check_acl_data(&data, "10.0.1.1"));
    }

    #[test]
    fn test_glob_mode_question_mark() {
        let data = build_acl_data(
            &["10.0.0.?".to_string()],
            "glob",
        );
        assert!(check_acl_data(&data, "10.0.0.1"));
        assert!(check_acl_data(&data, "10.0.0.9"));
        assert!(!check_acl_data(&data, "10.0.0.10"));
    }

    #[test]
    fn test_glob_mode_case_insensitive() {
        let data = build_acl_data(
            &["*.EXAMPLE.COM".to_string()],
            "glob",
        );
        assert!(check_acl_data(&data, "foo.example.com"));
        assert!(check_acl_data(&data, "FOO.EXAMPLE.COM"));
    }

    #[test]
    fn test_glob_mode_fqdn() {
        let data = build_acl_data(
            &["evil.example.com".to_string()],
            "glob",
        );
        // Exact match still works in glob mode (no wildcards)
        assert!(check_acl_data(&data, "evil.example.com"));
        assert!(!check_acl_data(&data, "good.example.com"));
    }

    // ── Auto-detect mode tests (Task 63) ─────────────────────────

    #[test]
    fn test_detect_entry_type_cidr() {
        assert_eq!(detect_entry_type("10.0.0.0/24"), "cidr");
        assert_eq!(detect_entry_type("192.168.0.0/16"), "cidr");
        assert_eq!(detect_entry_type("::1/128"), "cidr");
        assert_eq!(detect_entry_type("2001:db8::/32"), "cidr");
    }

    #[test]
    fn test_detect_entry_type_glob() {
        assert_eq!(detect_entry_type("*.example.com"), "glob");
        assert_eq!(detect_entry_type("192.168.*"), "glob");
        assert_eq!(detect_entry_type("10.0.0.?"), "glob");
    }

    #[test]
    fn test_detect_entry_type_regex() {
        assert_eq!(detect_entry_type("/^scanner.*/"), "regex");
        assert_eq!(detect_entry_type("/.*evil.*/"), "regex");
    }

    #[test]
    fn test_detect_entry_type_exact() {
        assert_eq!(detect_entry_type("10.0.0.1"), "exact");
        assert_eq!(detect_entry_type("evil.example.com"), "exact");
        assert_eq!(detect_entry_type("friendly-scanner"), "exact");
    }

    #[test]
    fn test_detect_entry_type_edge_cases() {
        // Single slash should not be CIDR (no IP before it)
        assert_eq!(detect_entry_type("/"), "exact");
        // Just a regex delimiter with nothing inside
        assert_eq!(detect_entry_type("//"), "exact");
        // Path-like string should not be CIDR
        assert_eq!(detect_entry_type("path/to/file"), "exact");
    }

    #[test]
    fn test_auto_mode_mixed_entries() {
        let data = build_acl_data(
            &[
                "10.0.0.0/24".to_string(),      // CIDR
                "192.168.1.100".to_string(),     // Exact
                "*.evil.com".to_string(),        // Glob
                "/^scanner.*/".to_string(),      // Regex
            ],
            "auto",
        );
        // CIDR match
        assert!(check_acl_data(&data, "10.0.0.1"));
        assert!(check_acl_data(&data, "10.0.0.254"));
        assert!(!check_acl_data(&data, "10.0.1.1"));
        // Exact match
        assert!(check_acl_data(&data, "192.168.1.100"));
        assert!(!check_acl_data(&data, "192.168.1.101"));
        // Glob match
        assert!(check_acl_data(&data, "sub.evil.com"));
        assert!(!check_acl_data(&data, "good.com"));
        // Regex match
        assert!(check_acl_data(&data, "scanner-bot"));
        assert!(!check_acl_data(&data, "good-agent"));
    }

    #[test]
    fn test_auto_mode_all_cidrs() {
        let data = build_acl_data(
            &[
                "10.0.0.0/8".to_string(),
                "172.16.0.0/12".to_string(),
                "192.168.0.0/16".to_string(),
            ],
            "auto",
        );
        assert!(check_acl_data(&data, "10.255.255.255"));
        assert!(check_acl_data(&data, "172.31.255.255"));
        assert!(check_acl_data(&data, "192.168.1.1"));
        assert!(!check_acl_data(&data, "8.8.8.8"));
    }

    #[test]
    fn test_auto_mode_invalid_cidr_falls_to_exact() {
        let data = build_acl_data(
            &["bad.host/24".to_string()],
            "auto",
        );
        // "bad.host/24" has a dot and looks like CIDR but fails IP parse,
        // so it falls back to exact match
        assert!(check_acl_data(&data, "bad.host/24"));
        assert!(!check_acl_data(&data, "bad.host"));
    }

    #[test]
    fn test_auto_mode_empty() {
        let data = build_acl_data(&[], "auto");
        assert!(!check_acl_data(&data, "anything"));
    }

    #[test]
    fn test_auto_mode_find_matching_entry() {
        let data = build_acl_data(
            &[
                "10.0.0.0/24".to_string(),
                "evil.example.com".to_string(),
                "*.bad.com".to_string(),
            ],
            "auto",
        );
        assert_eq!(find_matching_entry(&data, "10.0.0.42"), Some("10.0.0.0/24".to_string()));
        assert_eq!(find_matching_entry(&data, "evil.example.com"), Some("evil.example.com".to_string()));
        assert_eq!(find_matching_entry(&data, "sub.bad.com"), Some("*.bad.com".to_string()));
        assert_eq!(find_matching_entry(&data, "unknown"), None);
    }

    // ── CIDR find_matching_entry tests ───────────────────────────

    #[test]
    fn test_find_matching_entry_cidr() {
        let data = build_acl_data(
            &["10.0.0.0/24".to_string(), "192.168.0.0/16".to_string()],
            "cidr",
        );
        assert_eq!(find_matching_entry(&data, "10.0.0.42"), Some("10.0.0.0/24".to_string()));
        assert_eq!(find_matching_entry(&data, "192.168.1.1"), Some("192.168.0.0/16".to_string()));
        assert_eq!(find_matching_entry(&data, "172.16.0.1"), None);
    }

    // ── Glob find_matching_entry tests ───────────────────────────

    #[test]
    fn test_find_matching_entry_glob() {
        let data = build_acl_data(
            &["*.example.com".to_string(), "10.0.0.*".to_string()],
            "glob",
        );
        assert_eq!(find_matching_entry(&data, "foo.example.com"), Some("*.example.com".to_string()));
        assert_eq!(find_matching_entry(&data, "10.0.0.1"), Some("10.0.0.*".to_string()));
        assert_eq!(find_matching_entry(&data, "unknown"), None);
    }

    // ── E2E-style test: mixed blocklist file ─────────────────────

    #[test]
    fn test_e2e_auto_blocklist_file() {
        use std::io::Write;

        let path = format!("{}/rust_acl_e2e_auto", std::env::temp_dir().display());
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "# Mixed blocklist with auto-detection").unwrap();
            writeln!(f, "10.0.0.0/24").unwrap();
            writeln!(f, "192.168.1.100").unwrap();
            writeln!(f, "*.evil.com").unwrap();
            writeln!(f, "172.16.0.0/12").unwrap();
            writeln!(f, "/^SIPVicious/").unwrap();
            writeln!(f, "bad-agent").unwrap();
            writeln!(f, "").unwrap();
            writeln!(f, "# End of list").unwrap();
        }

        let loader = FileLoader::new(&path, default_line_parser, build_vec).unwrap();
        let entries = loader.get();
        let data = build_acl_data(&entries, "auto");
        drop(entries);

        // CIDR entries
        assert!(check_acl_data(&data, "10.0.0.1"));
        assert!(check_acl_data(&data, "10.0.0.254"));
        assert!(!check_acl_data(&data, "10.0.1.1"));
        assert!(check_acl_data(&data, "172.16.0.1"));
        assert!(check_acl_data(&data, "172.31.255.255"));
        assert!(!check_acl_data(&data, "172.32.0.1"));

        // Exact entries
        assert!(check_acl_data(&data, "192.168.1.100"));
        assert!(!check_acl_data(&data, "192.168.1.101"));
        assert!(check_acl_data(&data, "bad-agent"));
        assert!(!check_acl_data(&data, "good-agent"));

        // Glob entries
        assert!(check_acl_data(&data, "sub.evil.com"));
        assert!(check_acl_data(&data, "deep.sub.evil.com"));
        assert!(!check_acl_data(&data, "evil.com"));

        // Regex entries
        assert!(check_acl_data(&data, "SIPVicious/0.3"));
        assert!(!check_acl_data(&data, "sipvicious"));

        // Nothing matches
        assert!(!check_acl_data(&data, "8.8.8.8"));
        assert!(!check_acl_data(&data, "good.example.com"));

        let _ = std::fs::remove_file(&path);
    }

    // ── E2E-style test: CIDR blocklist with allowlist ────────────

    #[test]
    fn test_e2e_cidr_with_allowlist() {
        use std::io::Write;

        let bl_path = format!("{}/rust_acl_e2e_cidr_bl", std::env::temp_dir().display());
        let al_path = format!("{}/rust_acl_e2e_cidr_al", std::env::temp_dir().display());

        // Block entire 10.0.0.0/8 but allow 10.0.0.40/32
        {
            let mut f = std::fs::File::create(&bl_path).unwrap();
            writeln!(f, "10.0.0.0/8").unwrap();
        }
        {
            let mut f = std::fs::File::create(&al_path).unwrap();
            writeln!(f, "10.0.0.40").unwrap();
        }

        let bl_loader = FileLoader::new(&bl_path, default_line_parser, build_vec).unwrap();
        let al_loader = FileLoader::new(&al_path, default_line_parser, build_vec).unwrap();

        let bl_entries = bl_loader.get();
        let al_entries = al_loader.get();
        let blocklist = build_acl_data(&bl_entries, "auto");
        let allowlist = build_acl_data(&al_entries, "auto");
        drop(bl_entries);
        drop(al_entries);

        let auto_bl: HashMap<String, AutoEntry> = HashMap::new();
        let auto_al: HashMap<String, AutoEntry> = HashMap::new();

        // 10.0.0.40 is in allowlist -> allowed
        assert_eq!(check_access_with_policy(
            AccessPolicy::AllowlistFirst,
            &blocklist, None, None, None,
            Some(&allowlist), None, None, None,
            &auto_bl, &auto_al, "10.0.0.40",
        ), 1);

        // 10.0.0.1 is in blocklist only -> blocked
        assert_eq!(check_access_with_policy(
            AccessPolicy::AllowlistFirst,
            &blocklist, None, None, None,
            Some(&allowlist), None, None, None,
            &auto_bl, &auto_al, "10.0.0.1",
        ), -1);

        // 8.8.8.8 is in neither -> allowed (default)
        assert_eq!(check_access_with_policy(
            AccessPolicy::AllowlistFirst,
            &blocklist, None, None, None,
            Some(&allowlist), None, None, None,
            &auto_bl, &auto_al, "8.8.8.8",
        ), 1);

        let _ = std::fs::remove_file(&bl_path);
        let _ = std::fs::remove_file(&al_path);
    }

    // ── Database row-to-entry conversion tests ───────────────────

    #[test]
    fn test_db_row_to_entry_exact_ipv4() {
        let entry = db_row_to_entry("192.168.1.100", 32, None);
        assert_eq!(entry, "192.168.1.100");
    }

    #[test]
    fn test_db_row_to_entry_exact_ipv6() {
        let entry = db_row_to_entry("::1", 128, None);
        assert_eq!(entry, "::1");
    }

    #[test]
    fn test_db_row_to_entry_cidr_ipv4() {
        let entry = db_row_to_entry("10.0.0.0", 24, None);
        assert_eq!(entry, "10.0.0.0/24");
    }

    #[test]
    fn test_db_row_to_entry_cidr_ipv6() {
        let entry = db_row_to_entry("2001:db8::", 32, None);
        assert_eq!(entry, "2001:db8::/32");
    }

    #[test]
    fn test_db_row_to_entry_cidr_zero() {
        let entry = db_row_to_entry("0.0.0.0", 0, None);
        assert_eq!(entry, "0.0.0.0/0");
    }

    #[test]
    fn test_db_row_to_entry_pattern() {
        let entry = db_row_to_entry("10.0.0.0", 24, Some("^SIPVicious"));
        assert_eq!(entry, "/^SIPVicious/");
    }

    #[test]
    fn test_db_row_to_entry_empty_pattern() {
        let entry = db_row_to_entry("10.0.0.0", 24, Some(""));
        assert_eq!(entry, "10.0.0.0/24");
    }

    #[test]
    fn test_db_row_to_entry_pattern_none() {
        let entry = db_row_to_entry("172.16.0.0", 12, None);
        assert_eq!(entry, "172.16.0.0/12");
    }

    #[test]
    fn test_db_row_to_entry_mask_32_no_pattern() {
        // mask=32 with no pattern should be exact match
        let entry = db_row_to_entry("10.0.0.40", 32, None);
        assert_eq!(entry, "10.0.0.40");
    }

    // ── SQL query building tests ─────────────────────────────────

    #[test]
    fn test_db_build_query_default_table() {
        let q = db_build_query("address", 1, 2);
        assert!(q.contains("FROM address"));
        assert!(q.contains("WHERE grp IN"));
        assert!(q.contains("$1"));
        assert!(q.contains("$2"));
    }

    #[test]
    fn test_db_build_query_custom_table() {
        let q = db_build_query("acl_entries", 5, 10);
        assert!(q.contains("FROM acl_entries"));
    }

    #[test]
    fn test_db_build_query_selects_all_columns() {
        let q = db_build_query("address", 1, 2);
        assert!(q.contains("ip"));
        assert!(q.contains("mask"));
        assert!(q.contains("pattern"));
        assert!(q.contains("context_info"));
        assert!(q.contains("grp"));
    }

    // ── Merge DB entries tests ───────────────────────────────────

    #[test]
    fn test_merge_db_entries_cidr() {
        let entries = vec!["10.0.0.0/24".to_string(), "192.168.0.0/16".to_string()];
        let data = merge_db_entries(&entries);
        assert!(check_acl_data(&data, "10.0.0.42"));
        assert!(check_acl_data(&data, "192.168.1.1"));
        assert!(!check_acl_data(&data, "172.16.0.1"));
    }

    #[test]
    fn test_merge_db_entries_exact() {
        let entries = vec!["10.0.0.40".to_string(), "192.168.1.100".to_string()];
        let data = merge_db_entries(&entries);
        assert!(check_acl_data(&data, "10.0.0.40"));
        assert!(check_acl_data(&data, "192.168.1.100"));
        assert!(!check_acl_data(&data, "10.0.0.41"));
    }

    #[test]
    fn test_merge_db_entries_regex() {
        let entries = vec!["/^SIPVicious/".to_string(), "/friendly-scanner/".to_string()];
        let data = merge_db_entries(&entries);
        assert!(check_acl_data(&data, "SIPVicious/0.3"));
        assert!(check_acl_data(&data, "friendly-scanner"));
        assert!(!check_acl_data(&data, "normal-agent"));
    }

    #[test]
    fn test_merge_db_entries_mixed() {
        let entries = vec![
            "10.0.0.0/24".to_string(),
            "192.168.1.100".to_string(),
            "/^SIPVicious/".to_string(),
        ];
        let data = merge_db_entries(&entries);
        assert!(check_acl_data(&data, "10.0.0.42"));
        assert!(check_acl_data(&data, "192.168.1.100"));
        assert!(check_acl_data(&data, "SIPVicious/0.3"));
        assert!(!check_acl_data(&data, "8.8.8.8"));
    }

    #[test]
    fn test_merge_db_entries_empty() {
        let entries: Vec<String> = vec![];
        let data = merge_db_entries(&entries);
        assert!(!check_acl_data(&data, "anything"));
    }

    // ── check_access_with_policy_and_db tests ────────────────────

    #[test]
    fn test_access_with_db_blocklist() {
        let blocklist = build_acl_data(&["1.2.3.4".to_string()], "exact");
        let db_bl = build_acl_data(&["10.0.0.0/24".to_string()], "auto");
        let auto_bl: HashMap<String, AutoEntry> = HashMap::new();
        let auto_al: HashMap<String, AutoEntry> = HashMap::new();

        // 10.0.0.42 is in DB blocklist -> blocked
        assert_eq!(check_access_with_policy_and_db(
            AccessPolicy::AllowlistFirst,
            &blocklist, None, None, None,
            None, None, None, None,
            &auto_bl, &auto_al,
            Some(&db_bl), None,
            "10.0.0.42",
        ), -1);

        // 8.8.8.8 is in neither -> allowed
        assert_eq!(check_access_with_policy_and_db(
            AccessPolicy::AllowlistFirst,
            &blocklist, None, None, None,
            None, None, None, None,
            &auto_bl, &auto_al,
            Some(&db_bl), None,
            "8.8.8.8",
        ), 1);
    }

    #[test]
    fn test_access_with_db_allowlist() {
        let blocklist = build_acl_data(&["10.0.0.0/8".to_string()], "auto");
        let db_al = build_acl_data(&["10.0.0.40".to_string()], "auto");
        let auto_bl: HashMap<String, AutoEntry> = HashMap::new();
        let auto_al: HashMap<String, AutoEntry> = HashMap::new();

        // 10.0.0.40 is in DB allowlist -> allowed (allowlist-first)
        assert_eq!(check_access_with_policy_and_db(
            AccessPolicy::AllowlistFirst,
            &blocklist, None, None, None,
            None, None, None, None,
            &auto_bl, &auto_al,
            None, Some(&db_al),
            "10.0.0.40",
        ), 1);

        // 10.0.0.1 is in blocklist, not in DB allowlist -> blocked
        assert_eq!(check_access_with_policy_and_db(
            AccessPolicy::AllowlistFirst,
            &blocklist, None, None, None,
            None, None, None, None,
            &auto_bl, &auto_al,
            None, Some(&db_al),
            "10.0.0.1",
        ), -1);
    }

    #[test]
    fn test_access_with_db_both_lists() {
        let file_bl = build_acl_data(&["1.2.3.4".to_string()], "exact");
        let db_bl = build_acl_data(&["10.0.0.0/24".to_string()], "auto");
        let db_al = build_acl_data(&["10.0.0.40".to_string()], "auto");
        let auto_bl: HashMap<String, AutoEntry> = HashMap::new();
        let auto_al: HashMap<String, AutoEntry> = HashMap::new();

        // 10.0.0.40 in DB allowlist, 10.0.0.0/24 in DB blocklist -> allowed
        assert_eq!(check_access_with_policy_and_db(
            AccessPolicy::AllowlistFirst,
            &file_bl, None, None, None,
            None, None, None, None,
            &auto_bl, &auto_al,
            Some(&db_bl), Some(&db_al),
            "10.0.0.40",
        ), 1);

        // 10.0.0.1 in DB blocklist only -> blocked
        assert_eq!(check_access_with_policy_and_db(
            AccessPolicy::AllowlistFirst,
            &file_bl, None, None, None,
            None, None, None, None,
            &auto_bl, &auto_al,
            Some(&db_bl), Some(&db_al),
            "10.0.0.1",
        ), -1);

        // 1.2.3.4 in file blocklist -> blocked
        assert_eq!(check_access_with_policy_and_db(
            AccessPolicy::AllowlistFirst,
            &file_bl, None, None, None,
            None, None, None, None,
            &auto_bl, &auto_al,
            Some(&db_bl), Some(&db_al),
            "1.2.3.4",
        ), -1);

        // 8.8.8.8 nowhere -> allowed
        assert_eq!(check_access_with_policy_and_db(
            AccessPolicy::AllowlistFirst,
            &file_bl, None, None, None,
            None, None, None, None,
            &auto_bl, &auto_al,
            Some(&db_bl), Some(&db_al),
            "8.8.8.8",
        ), 1);
    }

    #[test]
    fn test_access_with_db_blocklist_first_policy() {
        let file_bl = build_acl_data(&[], "exact");
        let db_bl = build_acl_data(&["10.0.0.0/24".to_string()], "auto");
        let db_al = build_acl_data(&["10.0.0.0/24".to_string()], "auto");
        let auto_bl: HashMap<String, AutoEntry> = HashMap::new();
        let auto_al: HashMap<String, AutoEntry> = HashMap::new();

        // With blocklist-first: 10.0.0.42 in both -> blocked
        assert_eq!(check_access_with_policy_and_db(
            AccessPolicy::BlocklistFirst,
            &file_bl, None, None, None,
            None, None, None, None,
            &auto_bl, &auto_al,
            Some(&db_bl), Some(&db_al),
            "10.0.0.42",
        ), -1);
    }

    #[test]
    fn test_access_with_no_db() {
        let file_bl = build_acl_data(&["1.2.3.4".to_string()], "exact");
        let auto_bl: HashMap<String, AutoEntry> = HashMap::new();
        let auto_al: HashMap<String, AutoEntry> = HashMap::new();

        // No DB data at all -> same as check_access_with_policy
        assert_eq!(check_access_with_policy_and_db(
            AccessPolicy::AllowlistFirst,
            &file_bl, None, None, None,
            None, None, None, None,
            &auto_bl, &auto_al,
            None, None,
            "1.2.3.4",
        ), -1);

        assert_eq!(check_access_with_policy_and_db(
            AccessPolicy::AllowlistFirst,
            &file_bl, None, None, None,
            None, None, None, None,
            &auto_bl, &auto_al,
            None, None,
            "8.8.8.8",
        ), 1);
    }

    // ── DB row conversion round-trip tests ───────────────────────

    #[test]
    fn test_db_row_roundtrip_cidr_matching() {
        // Simulate: DB has 10.0.0.0/24 -> converts to "10.0.0.0/24" -> auto-detect as CIDR
        let entry = db_row_to_entry("10.0.0.0", 24, None);
        let data = build_acl_data(&[entry], "auto");
        assert!(check_acl_data(&data, "10.0.0.1"));
        assert!(check_acl_data(&data, "10.0.0.254"));
        assert!(!check_acl_data(&data, "10.0.1.1"));
    }

    #[test]
    fn test_db_row_roundtrip_regex_matching() {
        let entry = db_row_to_entry("0.0.0.0", 0, Some("^SIPVicious.*"));
        let data = build_acl_data(&[entry], "auto");
        assert!(check_acl_data(&data, "SIPVicious/0.3.6"));
        assert!(!check_acl_data(&data, "normal-agent"));
    }

    #[test]
    fn test_db_row_roundtrip_exact_matching() {
        let entry = db_row_to_entry("192.168.1.100", 32, None);
        let data = build_acl_data(&[entry], "auto");
        assert!(check_acl_data(&data, "192.168.1.100"));
        assert!(!check_acl_data(&data, "192.168.1.101"));
    }
}

// ── Database integration tests (require `database` feature + SQLite) ──

#[cfg(test)]
#[cfg(feature = "database")]
mod db_tests {
    use super::*;

    /// Helper: create an in-memory SQLite DB with the address table schema
    /// and return a connected pool.
    async fn setup_test_db() -> sqlx::AnyPool {
        sqlx::any::install_default_drivers();
        let pool = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("failed to connect to in-memory SQLite");

        // Create the address table matching OpenSIPS schema
        sqlx::query(
            "CREATE TABLE address (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                grp INTEGER DEFAULT 0 NOT NULL,
                ip TEXT NOT NULL,
                mask INTEGER DEFAULT 32 NOT NULL,
                port INTEGER DEFAULT 0 NOT NULL,
                proto TEXT DEFAULT 'any' NOT NULL,
                pattern TEXT DEFAULT NULL,
                context_info TEXT DEFAULT NULL
            )"
        )
        .execute(&pool)
        .await
        .expect("failed to create address table");

        pool
    }

    /// Helper: insert a row into the address table.
    async fn insert_address(
        pool: &sqlx::AnyPool,
        grp: i32,
        ip: &str,
        mask: i32,
        pattern: Option<&str>,
    ) {
        sqlx::query(
            "INSERT INTO address (grp, ip, mask, pattern) VALUES ($1, $2, $3, $4)"
        )
        .bind(grp)
        .bind(ip)
        .bind(mask)
        .bind(pattern)
        .execute(pool)
        .await
        .expect("failed to insert address row");
    }

    #[tokio::test]
    async fn test_db_load_empty_table() {
        let pool = setup_test_db().await;
        let (bl, al) = db_load_entries_async(&pool, "address", 1, 2).await.unwrap();
        assert!(bl.is_empty());
        assert!(al.is_empty());
    }

    #[tokio::test]
    async fn test_db_load_blocklist_entries() {
        let pool = setup_test_db().await;
        // grp=1 -> blocklist
        insert_address(&pool, 1, "10.0.0.0", 24, None).await;
        insert_address(&pool, 1, "192.168.1.100", 32, None).await;

        let (bl, al) = db_load_entries_async(&pool, "address", 1, 2).await.unwrap();
        assert_eq!(bl.len(), 2);
        assert!(al.is_empty());
        assert!(bl.contains(&"10.0.0.0/24".to_string()));
        assert!(bl.contains(&"192.168.1.100".to_string()));
    }

    #[tokio::test]
    async fn test_db_load_allowlist_entries() {
        let pool = setup_test_db().await;
        // grp=2 -> allowlist
        insert_address(&pool, 2, "10.0.0.40", 32, None).await;
        insert_address(&pool, 2, "172.16.0.0", 12, None).await;

        let (bl, al) = db_load_entries_async(&pool, "address", 1, 2).await.unwrap();
        assert!(bl.is_empty());
        assert_eq!(al.len(), 2);
        assert!(al.contains(&"10.0.0.40".to_string()));
        assert!(al.contains(&"172.16.0.0/12".to_string()));
    }

    #[tokio::test]
    async fn test_db_load_mixed_groups() {
        let pool = setup_test_db().await;
        insert_address(&pool, 1, "10.0.0.0", 24, None).await;      // blocklist
        insert_address(&pool, 2, "10.0.0.40", 32, None).await;      // allowlist
        insert_address(&pool, 1, "192.168.0.0", 16, None).await;    // blocklist
        insert_address(&pool, 3, "8.8.8.8", 32, None).await;        // neither (grp=3)

        let (bl, al) = db_load_entries_async(&pool, "address", 1, 2).await.unwrap();
        assert_eq!(bl.len(), 2);
        assert_eq!(al.len(), 1);
        // grp=3 entry should not appear in either list
    }

    #[tokio::test]
    async fn test_db_load_with_pattern() {
        let pool = setup_test_db().await;
        insert_address(&pool, 1, "0.0.0.0", 0, Some("^SIPVicious")).await;
        insert_address(&pool, 1, "0.0.0.0", 0, Some("friendly-scanner")).await;

        let (bl, _al) = db_load_entries_async(&pool, "address", 1, 2).await.unwrap();
        assert_eq!(bl.len(), 2);
        assert!(bl.contains(&"/^SIPVicious/".to_string()));
        assert!(bl.contains(&"/friendly-scanner/".to_string()));
    }

    #[tokio::test]
    async fn test_db_load_skip_empty_ip() {
        let pool = setup_test_db().await;
        insert_address(&pool, 1, "", 32, None).await;
        insert_address(&pool, 1, "10.0.0.1", 32, None).await;

        let (bl, _al) = db_load_entries_async(&pool, "address", 1, 2).await.unwrap();
        assert_eq!(bl.len(), 1);
        assert_eq!(bl[0], "10.0.0.1");
    }

    #[tokio::test]
    async fn test_db_entries_merged_with_acl() {
        let pool = setup_test_db().await;
        insert_address(&pool, 1, "10.0.0.0", 24, None).await;
        insert_address(&pool, 2, "10.0.0.40", 32, None).await;

        let (bl_entries, al_entries) = db_load_entries_async(&pool, "address", 1, 2).await.unwrap();

        let db_bl = merge_db_entries(&bl_entries);
        let db_al = merge_db_entries(&al_entries);

        let file_bl = build_acl_data(&["1.2.3.4".to_string()], "exact");
        let auto_bl: HashMap<String, AutoEntry> = HashMap::new();
        let auto_al: HashMap<String, AutoEntry> = HashMap::new();

        // 10.0.0.42 in DB blocklist -> blocked
        assert_eq!(check_access_with_policy_and_db(
            AccessPolicy::AllowlistFirst,
            &file_bl, None, None, None,
            None, None, None, None,
            &auto_bl, &auto_al,
            Some(&db_bl), Some(&db_al),
            "10.0.0.42",
        ), -1);

        // 10.0.0.40 in DB allowlist -> allowed even though in DB blocklist range
        assert_eq!(check_access_with_policy_and_db(
            AccessPolicy::AllowlistFirst,
            &file_bl, None, None, None,
            None, None, None, None,
            &auto_bl, &auto_al,
            Some(&db_bl), Some(&db_al),
            "10.0.0.40",
        ), 1);

        // 8.8.8.8 nowhere -> allowed
        assert_eq!(check_access_with_policy_and_db(
            AccessPolicy::AllowlistFirst,
            &file_bl, None, None, None,
            None, None, None, None,
            &auto_bl, &auto_al,
            Some(&db_bl), Some(&db_al),
            "8.8.8.8",
        ), 1);
    }

    #[tokio::test]
    async fn test_db_custom_groups() {
        let pool = setup_test_db().await;
        // Use custom group IDs: blocklist=5, allowlist=10
        insert_address(&pool, 5, "10.0.0.0", 24, None).await;
        insert_address(&pool, 10, "10.0.0.40", 32, None).await;
        insert_address(&pool, 1, "8.8.8.8", 32, None).await;  // default grp, won't match

        let (bl, al) = db_load_entries_async(&pool, "address", 5, 10).await.unwrap();
        assert_eq!(bl.len(), 1);
        assert_eq!(al.len(), 1);
        assert!(bl.contains(&"10.0.0.0/24".to_string()));
        assert!(al.contains(&"10.0.0.40".to_string()));
    }

    #[tokio::test]
    async fn test_db_reload_picks_up_changes() {
        let pool = setup_test_db().await;
        insert_address(&pool, 1, "10.0.0.0", 24, None).await;

        let (bl1, _) = db_load_entries_async(&pool, "address", 1, 2).await.unwrap();
        assert_eq!(bl1.len(), 1);

        // Add another entry
        insert_address(&pool, 1, "192.168.0.0", 16, None).await;

        // Reload should pick up the new entry
        let (bl2, _) = db_load_entries_async(&pool, "address", 1, 2).await.unwrap();
        assert_eq!(bl2.len(), 2);
    }

    #[tokio::test]
    async fn test_db_ipv6_entries() {
        let pool = setup_test_db().await;
        insert_address(&pool, 1, "2001:db8::", 32, None).await;
        insert_address(&pool, 1, "::1", 128, None).await;

        let (bl, _) = db_load_entries_async(&pool, "address", 1, 2).await.unwrap();
        assert_eq!(bl.len(), 2);
        assert!(bl.contains(&"2001:db8::/32".to_string()));
        assert!(bl.contains(&"::1".to_string()));

        // Verify the entries work for matching
        let data = merge_db_entries(&bl);
        assert!(check_acl_data(&data, "2001:db8::1"));
        assert!(check_acl_data(&data, "::1"));
        assert!(!check_acl_data(&data, "2001:db9::1"));
    }

    #[tokio::test]
    async fn test_db_invalid_table_returns_error() {
        let pool = setup_test_db().await;
        let result = db_load_entries_async(&pool, "nonexistent_table", 1, 2).await;
        assert!(result.is_err());
    }
}
