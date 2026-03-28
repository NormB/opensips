//! rust_credit_check — Prepaid credit/balance checking with per-worker cache.
//!
//! Queries an external billing API for account balance, caches results
//! per-worker with configurable TTL. Computes max call duration from balance.
//!
//! # Features
//! - **Debit on call end** (Task 45): POST debit to billing API via FireAndForget.
//! - **Configurable JSON field** (Task 46): Dot-notation paths for balance extraction.
//! - **Billing failover** (Task 47): Primary + backup billing URL with timed recovery.
//! - **Rate table** (Task 48): Per-prefix rate lookup from CSV file.
//! - **Mid-call recheck** (Task 49): `credit_recheck()` for on_timeout routes.
//! - **Cache-first async** (Task 50): `credit_check_async()` with cache warmup.
//!
//! # OpenSIPS config
//!
//! ```text
//! loadmodule "rust_credit_check.so"
//! modparam("rust_credit_check", "billing_url", "http://billing:8080/balance")
//! modparam("rust_credit_check", "cache_ttl", 300)
//! modparam("rust_credit_check", "http_timeout", 2)
//! modparam("rust_credit_check", "pool_size", 4)
//! modparam("rust_credit_check", "rate_per_min", 1)
//! modparam("rust_credit_check", "on_error", "deny")
//! modparam("rust_credit_check", "balance_field", "data.account.balance")
//! modparam("rust_credit_check", "debit_url", "http://billing:8080/debit")
//! modparam("rust_credit_check", "debit_on_end", 1)
//! modparam("rust_credit_check", "billing_url_backup", "http://billing-backup:8080/balance")
//! modparam("rust_credit_check", "failover_timeout_secs", 30)
//! modparam("rust_credit_check", "rate_file", "/etc/opensips/rates.csv")
//! modparam("rust_credit_check", "recheck_interval_secs", 60)
//! modparam("rust_credit_check", "cache_warmup_url", "http://billing:8080/all_accounts")
//!
//! route {
//!     if (is_method("INVITE") && !has_totag()) {
//!         if (!credit_check("$fU")) {
//!             sl_send_reply(402, "Insufficient Credit");
//!             exit;
//!         }
//!         xlog("L_INFO", "balance=$var(credit_balance) max_dur=$var(credit_max_duration)s\n");
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
use opensips_rs::param::{Integer, ModString};
use opensips_rs::sys;
use opensips_rs::{cstr_lit, opensips_log};
use rust_common::async_dispatch::FireAndForget;
use rust_common::http::Pool;
use rust_common::event;
use rust_common::mi::Stats;

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{c_int, c_void};
use std::ptr;
use std::time::Instant;

// ── Module parameters ────────────────────────────────────────────

/// Enable event publishing (0=off, 1=on, default 0).
static PUBLISH_EVENTS: Integer = Integer::with_default(0);

/// Billing API endpoint (required). GET {url}?account={account}
static BILLING_URL: ModString = ModString::new();

/// Cache TTL in seconds (default 300).
static CACHE_TTL: Integer = Integer::with_default(300);

/// HTTP request timeout in seconds (default 2).
static HTTP_TIMEOUT: Integer = Integer::with_default(2);

/// HTTP connection pool size per worker (default 4).
static POOL_SIZE: Integer = Integer::with_default(4);

/// Cost units per minute for max duration calculation (default 1).
static RATE_PER_MIN: Integer = Integer::with_default(1);

/// Behavior on billing API error: "deny" (default) or "allow".
static ON_ERROR: ModString = ModString::new();

/// Optional TLS CA file path for billing API.
static TLS_CA_FILE: ModString = ModString::new();

// ── Task 45: Debit parameters ────────────────────────────────────

/// URL for debit POST. If not set, no debit is sent.
static DEBIT_URL: ModString = ModString::new();

/// Enable/disable debit on call end (default 0 = disabled).
static DEBIT_ON_END: Integer = Integer::with_default(0);

// ── Task 46: Configurable JSON response parsing ──────────────────

/// JSON field path for balance extraction (default "balance").
/// Supports dot notation: "data.account.balance".
static BALANCE_FIELD: ModString = ModString::new();

// ── Task 47: Billing failover parameters ─────────────────────────

/// Backup billing URL (optional).
static BILLING_URL_BACKUP: ModString = ModString::new();

/// Seconds to use backup before retrying primary (default 30).
static FAILOVER_TIMEOUT_SECS: Integer = Integer::with_default(30);

// ── Task 48: Rate table per prefix ───────────────────────────────

/// Path to CSV rate file: prefix,rate_per_min (optional).
static RATE_FILE: ModString = ModString::new();

// ── Task 49: Mid-call recheck ────────────────────────────────────

/// Re-check interval in seconds (default 0 = disabled).
static RECHECK_INTERVAL_SECS: Integer = Integer::with_default(0);

// ── Task 50: Cache warmup ────────────────────────────────────────

/// URL to pre-load cache at startup. Returns JSON array of
/// [{"account":"alice","balance":42.5}, ...].
static CACHE_WARMUP_URL: ModString = ModString::new();

// ── Pure logic (testable without FFI) ────────────────────────────

/// A cached credit balance entry.
struct CreditEntry {
    balance: f64,
    fetched: Instant,
}

/// Per-worker credit cache with TTL-based expiry.
struct CreditCache {
    entries: HashMap<String, CreditEntry>,
    ttl_secs: u64,
}

#[allow(dead_code)]
impl CreditCache {
    fn new(ttl_secs: u64) -> Self {
        CreditCache {
            entries: HashMap::new(),
            ttl_secs,
        }
    }

    /// Get cached balance if not expired. Returns None on miss or expiry.
    fn get(&self, account: &str) -> Option<f64> {
        let entry = self.entries.get(account)?;
        if entry.fetched.elapsed().as_secs() < self.ttl_secs {
            Some(entry.balance)
        } else {
            None
        }
    }

    /// Insert or update a cache entry.
    fn put(&mut self, account: &str, balance: f64) {
        self.entries.insert(account.to_string(), CreditEntry {
            balance,
            fetched: Instant::now(),
        });
    }

    /// Remove a single cache entry.
    fn clear(&mut self, account: &str) {
        self.entries.remove(account);
    }

    /// Remove all cache entries.
    fn clear_all(&mut self) {
        self.entries.clear();
    }

    /// Number of entries (including potentially expired ones).
    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if cache has a valid (non-expired) entry for account.
    fn has_valid(&self, account: &str) -> bool {
        self.get(account).is_some()
    }
}

/// Compute max call duration in seconds from balance and rate.
/// rate_per_min: cost units consumed per minute of call.
/// Returns seconds (integer).
fn compute_max_duration(balance: f64, rate_per_min: f64) -> i32 {
    if rate_per_min <= 0.0 || balance <= 0.0 {
        return 0;
    }
    ((balance / rate_per_min) * 60.0) as i32
}

/// Compute debit cost from duration and rate.
fn compute_debit_cost(duration_secs: i32, rate_per_min: f64) -> f64 {
    if rate_per_min <= 0.0 || duration_secs <= 0 {
        return 0.0;
    }
    (duration_secs as f64) * rate_per_min / 60.0
}

/// Build JSON debit payload.
fn build_debit_payload(account: &str, duration_secs: i32, cost: f64) -> String {
    format!(
        r#"{{"account":"{}","duration_secs":{},"cost":{:.2}}}"#,
        account, duration_secs, cost
    )
}

/// Parse a JSON billing response body using a configurable field path.
/// field_path is dot-separated, e.g. "balance" or "data.account.balance".
fn parse_balance_with_path(body: &str, field_path: &str) -> Option<f64> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    extract_nested_field(&v, field_path)
}

/// Extract a numeric value from a serde_json::Value using dot-notation path.
fn extract_nested_field(value: &serde_json::Value, path: &str) -> Option<f64> {
    let mut current = value;
    for segment in path.split('.') {
        let segment = segment.trim();
        if segment.is_empty() {
            return None;
        }
        current = current.get(segment)?;
    }
    current.as_f64()
}

/// Legacy: parse balance from {"balance": N} (backward compat).
#[allow(dead_code)]
fn parse_balance_response(body: &str) -> Option<f64> {
    parse_balance_with_path(body, "balance")
}

/// Decide the return value when the billing API is unreachable.
/// Returns true (allow) or false (deny).
fn on_error_allows(on_error: &str) -> bool {
    on_error.eq_ignore_ascii_case("allow")
}

// ── Task 47: Failover state ──────────────────────────────────────

/// Billing endpoint state: which URL to use.
#[derive(Debug)]
enum BillingState {
    /// Using primary URL.
    Primary,
    /// Using backup URL; switch back to primary after the Instant.
    Failover(Instant),
}

impl BillingState {
    /// Check if we should try primary again (failover period expired).
    fn should_recover(&self, timeout_secs: u64) -> bool {
        match self {
            BillingState::Primary => false,
            BillingState::Failover(since) => since.elapsed().as_secs() >= timeout_secs,
        }
    }

    /// Returns true if currently in failover state.
    fn is_failover(&self) -> bool {
        matches!(self, BillingState::Failover(_))
    }
}

// ── Task 48: Rate table ──────────────────────────────────────────

/// A sorted rate table: Vec<(prefix, rate_per_min)>, sorted by prefix length desc.
struct RateTable {
    entries: Vec<(String, f64)>,
    default_rate: f64,
}

impl RateTable {
    /// Parse a CSV string into a rate table.
    /// Format: one "prefix,rate" per line. Lines starting with '#' are comments.
    fn from_csv(csv: &str, default_rate: f64) -> Self {
        let mut entries: Vec<(String, f64)> = Vec::new();
        for line in csv.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.splitn(2, ',').collect();
            if parts.len() == 2 {
                let prefix = parts[0].trim().to_string();
                if let Ok(rate) = parts[1].trim().parse::<f64>() {
                    if !prefix.is_empty() && rate > 0.0 {
                        entries.push((prefix, rate));
                    }
                }
            }
        }
        // Sort by prefix length descending (longest match first)
        entries.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        RateTable { entries, default_rate }
    }

    /// Find the rate for a destination number using longest prefix match.
    /// Returns (matched_prefix_or_empty, rate).
    fn lookup(&self, destination: &str) -> (&str, f64) {
        for (prefix, rate) in &self.entries {
            if destination.starts_with(prefix.as_str()) {
                return (prefix, *rate);
            }
        }
        ("", self.default_rate)
    }
}

// ── Task 50: Cache warmup parsing ────────────────────────────────

/// Parse cache warmup response. Expected JSON array:
/// [{"account":"alice","balance":42.5}, ...]
/// Uses the configurable balance_field for each entry.
fn parse_warmup_response(body: &str, balance_field: &str) -> Vec<(String, f64)> {
    let mut result = Vec::new();
    if let Ok(serde_json::Value::Array(arr)) = serde_json::from_str::<serde_json::Value>(body) {
        for item in &arr {
            if let Some(account) = item.get("account").and_then(|a| a.as_str()) {
                if let Some(balance) = extract_nested_field(item, balance_field) {
                    result.push((account.to_string(), balance));
                }
            }
        }
    }
    result
}

// ── Per-worker state ─────────────────────────────────────────────

/// Call start tracking for debit calculation.
struct CallTracker {
    /// Map from key (Call-ID or account) to call start time.
    active_calls: HashMap<String, Instant>,
}

impl CallTracker {
    fn new() -> Self {
        CallTracker {
            active_calls: HashMap::new(),
        }
    }

    fn start_call(&mut self, key: &str) {
        self.active_calls.insert(key.to_string(), Instant::now());
    }

    fn end_call(&mut self, key: &str) -> Option<i32> {
        self.active_calls.remove(key).map(|start| {
            start.elapsed().as_secs() as i32
        })
    }
}

struct WorkerState {
    cache: CreditCache,
    pool: Pool,
    stats: Stats,
    billing_state: BillingState,
    call_tracker: CallTracker,
    debit_dispatcher: Option<FireAndForget>,
    rate_table: Option<RateTable>,
}

thread_local! {
    static WORKER: RefCell<Option<WorkerState>> = const { RefCell::new(None) };
}

// ── Helper: get effective billing URL (primary or backup) ────────

fn get_billing_url(state: &mut WorkerState) -> Option<String> {
    let primary = unsafe { BILLING_URL.get_value() };
    let backup = unsafe { BILLING_URL_BACKUP.get_value() };
    let failover_timeout = FAILOVER_TIMEOUT_SECS.get() as u64;

    // Check if we should recover from failover
    if state.billing_state.should_recover(failover_timeout) {
        state.billing_state = BillingState::Primary;
        opensips_log!(INFO, "rust_credit_check",
            "failover recovery: switching back to primary billing URL");
    }

    match &state.billing_state {
        BillingState::Primary => primary.map(|u| u.to_string()),
        BillingState::Failover(_) => {
            backup.map(|u| u.to_string()).or_else(|| primary.map(|u| u.to_string()))
        }
    }
}

/// Try a billing HTTP GET. On failure, handle failover.
fn billing_get(state: &mut WorkerState, account: &str) -> Result<(u16, String), String> {
    let url = get_billing_url(state).ok_or_else(|| "no billing URL configured".to_string())?;
    let full_url = format!("{url}?account={account}");

    match state.pool.get_url(&full_url) {
        Ok((status, body)) if status >= 500 || status == 0 => {
            // Server error — trigger failover if backup available
            let has_backup = unsafe { BILLING_URL_BACKUP.get_value() }.is_some();
            if has_backup && !state.billing_state.is_failover() {
                state.billing_state = BillingState::Failover(Instant::now());
                opensips_log!(WARN, "rust_credit_check",
                    "primary billing returned {}, switching to backup", status);
                // Retry on backup
                let backup_url = get_billing_url(state)
                    .ok_or_else(|| "no backup URL".to_string())?;
                let backup_full = format!("{backup_url}?account={account}");
                state.pool.get_url(&backup_full)
            } else {
                Ok((status, body))
            }
        }
        other => {
            // Success on current URL — if we were in failover and recovered, note it
            other
        }
    }
}

/// Get the balance field path, defaulting to "balance".
fn get_balance_field() -> String {
    unsafe { BALANCE_FIELD.get_value() }
        .unwrap_or("balance")
        .to_string()
}

// ── Module lifecycle ─────────────────────────────────────────────

unsafe extern "C" fn mod_init() -> c_int {
    let url = match unsafe { BILLING_URL.get_value() } {
        Some(u) if !u.is_empty() => u,
        _ => {
            opensips_log!(ERR, "rust_credit_check",
                "modparam billing_url is required but not set");
            return -1;
        }
    };

    let on_err = unsafe { ON_ERROR.get_value() }.unwrap_or("deny");

    // Validate cache_ttl
    let ttl = CACHE_TTL.get();
    if ttl < 0 {
        opensips_log!(WARN, "rust_credit_check",
            "cache_ttl={} is negative, clamping to 0 (no cache)", ttl);
    }

    // Validate http_timeout
    let timeout = HTTP_TIMEOUT.get();
    if timeout <= 0 {
        opensips_log!(WARN, "rust_credit_check",
            "http_timeout={} is invalid, clamping to default 2", timeout);
    } else if timeout > 60 {
        opensips_log!(WARN, "rust_credit_check",
            "http_timeout={} is very high (>60s), clamping to 60", timeout);
    }

    // Validate pool_size
    let pool = POOL_SIZE.get();
    if pool <= 0 {
        opensips_log!(WARN, "rust_credit_check",
            "pool_size={} is invalid, clamping to default 4", pool);
    }

    // Validate rate_per_min
    let rate = RATE_PER_MIN.get();
    if rate <= 0 {
        opensips_log!(WARN, "rust_credit_check",
            "rate_per_min={} is invalid, must be positive for duration calculation", rate);
    }

    // Validate on_error
    if on_err != "deny" && on_err != "allow"
        && !on_err.eq_ignore_ascii_case("deny")
        && !on_err.eq_ignore_ascii_case("allow")
    {
        opensips_log!(WARN, "rust_credit_check",
            "on_error='{}' is not 'deny' or 'allow', defaulting to 'deny'", on_err);
    }

    // Validate balance_field
    let bf = unsafe { BALANCE_FIELD.get_value() }.unwrap_or("balance");
    if bf.is_empty() {
        opensips_log!(WARN, "rust_credit_check",
            "balance_field is empty, using default 'balance'");
    }

    // Validate rate_file
    if let Some(rf) = unsafe { RATE_FILE.get_value() } {
        if !rf.is_empty() && std::fs::metadata(rf).is_err() {
            opensips_log!(WARN, "rust_credit_check",
                "rate_file '{}' does not exist or is not readable", rf);
        }
    }

    // Initialize event publishing
    if PUBLISH_EVENTS.get() != 0 {
        event::set_enabled(true);
        opensips_log!(INFO, "rust_credit_check", "event publishing enabled");
    }

    opensips_log!(INFO, "rust_credit_check", "module initialized");
    opensips_log!(INFO, "rust_credit_check", "  billing_url={}", url);
    opensips_log!(INFO, "rust_credit_check", "  cache_ttl={}s", CACHE_TTL.get());
    opensips_log!(INFO, "rust_credit_check", "  http_timeout={}s", HTTP_TIMEOUT.get());
    opensips_log!(INFO, "rust_credit_check", "  pool_size={}", POOL_SIZE.get());
    opensips_log!(INFO, "rust_credit_check", "  rate_per_min={}", RATE_PER_MIN.get());
    opensips_log!(INFO, "rust_credit_check", "  on_error={}", on_err);
    opensips_log!(INFO, "rust_credit_check", "  balance_field={}", bf);

    if let Some(backup) = unsafe { BILLING_URL_BACKUP.get_value() } {
        opensips_log!(INFO, "rust_credit_check", "  billing_url_backup={}", backup);
        opensips_log!(INFO, "rust_credit_check", "  failover_timeout_secs={}",
            FAILOVER_TIMEOUT_SECS.get());
    }
    if let Some(debit) = unsafe { DEBIT_URL.get_value() } {
        opensips_log!(INFO, "rust_credit_check", "  debit_url={}", debit);
        opensips_log!(INFO, "rust_credit_check", "  debit_on_end={}", DEBIT_ON_END.get());
    }
    let ri = RECHECK_INTERVAL_SECS.get();
    if ri > 0 {
        opensips_log!(INFO, "rust_credit_check", "  recheck_interval_secs={}", ri);
    }

    0
}

unsafe extern "C" fn mod_child_init(rank: c_int) -> c_int {
    if rank < 1 {
        return 0;
    }

    let pool = Pool::new();
    let ca_file = unsafe { TLS_CA_FILE.get_value() };
    pool.init(HTTP_TIMEOUT.get(), POOL_SIZE.get(), ca_file);

    let ttl = CACHE_TTL.get();
    let mut cache = CreditCache::new(if ttl > 0 { ttl as u64 } else { 300 });

    let stats = Stats::new("rust_credit_check",
        &["checked", "allowed", "denied", "errors", "cache_hits", "cache_misses",
          "debits_sent", "debits_dropped", "failovers", "rechecks"]);

    // Task 45: Initialize debit dispatcher if configured
    let debit_dispatcher = unsafe { DEBIT_URL.get_value() }
        .filter(|u| !u.is_empty())
        .map(|u| {
            FireAndForget::new(
                u.to_string(),
                256, // queue size
                HTTP_TIMEOUT.get().max(2) as u64,
                "application/json".to_string(),
            )
        });

    // Task 48: Load rate table if configured
    let rate_table = unsafe { RATE_FILE.get_value() }
        .filter(|rf| !rf.is_empty())
        .and_then(|rf| {
            match std::fs::read_to_string(rf) {
                Ok(csv) => {
                    let default_rate = RATE_PER_MIN.get().max(1) as f64;
                    let table = RateTable::from_csv(&csv, default_rate);
                    opensips_log!(INFO, "rust_credit_check",
                        "loaded {} rate table entries from {}", table.entries.len(), rf);
                    Some(table)
                }
                Err(e) => {
                    opensips_log!(ERR, "rust_credit_check",
                        "failed to read rate_file {}: {}", rf, e);
                    None
                }
            }
        });

    // Task 50: Cache warmup if configured
    if let Some(warmup_url) = unsafe { CACHE_WARMUP_URL.get_value() } {
        if !warmup_url.is_empty() {
            match pool.get_url(warmup_url) {
                Ok((200, body)) => {
                    let bf = get_balance_field();
                    let accounts = parse_warmup_response(&body, &bf);
                    let count = accounts.len();
                    for (acct, bal) in accounts {
                        cache.put(&acct, bal);
                    }
                    opensips_log!(INFO, "rust_credit_check",
                        "cache warmup: loaded {} accounts", count);
                }
                Ok((status, _)) => {
                    opensips_log!(WARN, "rust_credit_check",
                        "cache warmup URL returned status {}", status);
                }
                Err(e) => {
                    opensips_log!(WARN, "rust_credit_check",
                        "cache warmup failed: {}", e);
                }
            }
        }
    }

    WORKER.with(|w| {
        *w.borrow_mut() = Some(WorkerState {
            cache,
            pool,
            stats,
            billing_state: BillingState::Primary,
            call_tracker: CallTracker::new(),
            debit_dispatcher,
            rate_table,
        });
    });

    opensips_log!(DBG, "rust_credit_check", "worker {} initialized", rank);
    0
}

unsafe extern "C" fn mod_destroy() {
    opensips_log!(INFO, "rust_credit_check", "module destroyed");
}

// ── Shared billing query logic ──────────────────────────────────

/// Perform the billing query (cache check + HTTP fallback) and return balance.
/// Handles failover, configurable field parsing, cache updates.
fn do_credit_query(state: &mut WorkerState, account: &str, bypass_cache: bool) -> Result<f64, i32> {
    let on_err = unsafe { ON_ERROR.get_value() }.unwrap_or("deny");
    let field_path = get_balance_field();

    // 1. Check cache (unless bypassed for recheck)
    if !bypass_cache {
        if let Some(b) = state.cache.get(account) {
            state.stats.inc("cache_hits");
            opensips_log!(DBG, "rust_credit_check",
                "cache hit for {}: balance={}", account, b);
            return Ok(b);
        }
    }
    state.stats.inc("cache_misses");

    // 2. Query billing API with failover
    match billing_get(state, account) {
        Ok((status, body)) if status == 200 => {
            match parse_balance_with_path(&body, &field_path) {
                Some(b) => {
                    state.cache.put(account, b);
                    opensips_log!(DBG, "rust_credit_check",
                        "fetched balance for {}: {}", account, b);
                    Ok(b)
                }
                None => {
                    opensips_log!(ERR, "rust_credit_check",
                        "failed to parse balance from '{}' with field '{}': {}",
                        field_path, body.chars().take(200).collect::<String>(), body);
                    state.stats.inc("errors");
                    Err(if on_error_allows(on_err) { 1 } else { -2 })
                }
            }
        }
        Ok((status, body)) => {
            opensips_log!(ERR, "rust_credit_check",
                "billing API returned status {}: {}", status, body);
            state.stats.inc("errors");
            if status >= 500 {
                state.stats.inc("failovers");
            }
            Err(if on_error_allows(on_err) { 1 } else { -2 })
        }
        Err(e) => {
            opensips_log!(ERR, "rust_credit_check",
                "billing API error for {}: {}", account, e);
            state.stats.inc("errors");
            Err(if on_error_allows(on_err) { 1 } else { -2 })
        }
    }
}

// ── Script function: credit_check(account) ──────────────────

unsafe extern "C" fn w_rust_credit_check(
    msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_credit_check",
                    "credit_check: missing or invalid parameter");
                return -2;
            }
        };

        let rate = RATE_PER_MIN.get() as f64;

        WORKER.with(|w| {
            let mut borrow = w.borrow_mut();
            let state = match borrow.as_mut() {
                Some(s) => s,
                None => {
                    opensips_log!(ERR, "rust_credit_check", "worker state not initialized");
                    return -2;
                }
            };

            state.stats.inc("checked");

            let balance = match do_credit_query(state, account, false) {
                Ok(b) => b,
                Err(code) => return code,
            };

            // Set PVs
            let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };

            if balance > 0.0 {
                state.stats.inc("allowed");
                let max_dur = compute_max_duration(balance, rate);
                let balance_str = format!("{balance:.2}");
                let _ = sip_msg.set_pv("$var(credit_balance)", &balance_str);
                let _ = sip_msg.set_pv_int("$var(credit_max_duration)", max_dur);

                // Track call start if debit_on_end is enabled
                if DEBIT_ON_END.get() != 0 {
                    state.call_tracker.start_call(account);
                }

                1
            } else {
                state.stats.inc("denied");
                // Publish E_CREDIT_DENIED event
                if event::is_enabled() {
                    let payload = event::format_payload(&[
                        ("account", &event::json_str(account)),
                    ]);
                    opensips_log!(NOTICE, "rust_credit_check", "EVENT E_CREDIT_DENIED {}", payload);
                }
                let _ = sip_msg.set_pv("$var(credit_balance)", "0.00");
                let _ = sip_msg.set_pv_int("$var(credit_max_duration)", 0);
                -1
            }
        })
    })
}

// ── Script function: credit_check_dest(account, destination) ─

unsafe extern "C" fn w_rust_credit_check_dest(
    msg: *mut sys::sip_msg,
    p0: *mut c_void, p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_credit_check",
                    "credit_check_dest: missing account parameter");
                return -2;
            }
        };
        let destination = match unsafe { <&str as CommandFunctionParam>::from_raw(p1) } {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_credit_check",
                    "credit_check_dest: missing destination parameter");
                return -2;
            }
        };

        WORKER.with(|w| {
            let mut borrow = w.borrow_mut();
            let state = match borrow.as_mut() {
                Some(s) => s,
                None => {
                    opensips_log!(ERR, "rust_credit_check", "worker state not initialized");
                    return -2;
                }
            };

            state.stats.inc("checked");

            let balance = match do_credit_query(state, account, false) {
                Ok(b) => b,
                Err(code) => return code,
            };

            // Look up rate for destination
            let default_rate = RATE_PER_MIN.get() as f64;
            let (prefix, rate) = state.rate_table.as_ref()
                .map(|rt| rt.lookup(destination))
                .unwrap_or(("", default_rate));

            let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };

            if balance > 0.0 {
                state.stats.inc("allowed");
                let max_dur = compute_max_duration(balance, rate);
                let balance_str = format!("{balance:.2}");
                let _ = sip_msg.set_pv("$var(credit_balance)", &balance_str);
                let _ = sip_msg.set_pv_int("$var(credit_max_duration)", max_dur);
                let rate_str = format!("{rate:.4}");
                let _ = sip_msg.set_pv("$var(credit_rate)", &rate_str);

                if !prefix.is_empty() {
                    opensips_log!(DBG, "rust_credit_check",
                        "matched prefix '{}' rate={} for dest {}", prefix, rate, destination);
                }

                if DEBIT_ON_END.get() != 0 {
                    state.call_tracker.start_call(account);
                }
                1
            } else {
                state.stats.inc("denied");
                let _ = sip_msg.set_pv("$var(credit_balance)", "0.00");
                let _ = sip_msg.set_pv_int("$var(credit_max_duration)", 0);
                let rate_str = format!("{rate:.4}");
                let _ = sip_msg.set_pv("$var(credit_rate)", &rate_str);
                -1
            }
        })
    })
}

// ── Script function: credit_debit(account, duration_secs) ───

unsafe extern "C" fn w_rust_credit_debit(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_credit_check",
                    "credit_debit: missing account parameter");
                return -2;
            }
        };
        let duration = match unsafe { <i32 as CommandFunctionParam>::from_raw(p1) } {
            Some(d) => d,
            None => {
                opensips_log!(ERR, "rust_credit_check",
                    "credit_debit: missing duration parameter");
                return -2;
            }
        };

        let rate = RATE_PER_MIN.get() as f64;
        let cost = compute_debit_cost(duration, rate);
        let payload = build_debit_payload(account, duration, cost);

        WORKER.with(|w| {
            let mut borrow = w.borrow_mut();
            let state = match borrow.as_mut() {
                Some(s) => s,
                None => {
                    opensips_log!(ERR, "rust_credit_check", "worker state not initialized");
                    return -2;
                }
            };

            match &state.debit_dispatcher {
                Some(dispatcher) => {
                    if dispatcher.send(payload) {
                        state.stats.inc("debits_sent");
                        // Publish E_CREDIT_DEBIT event
                        if event::is_enabled() {
                            let payload = event::format_payload(&[
                                ("account", &event::json_str(account)),
                                ("amount", &format!("{:.2}", cost)),
                            ]);
                            opensips_log!(NOTICE, "rust_credit_check", "EVENT E_CREDIT_DEBIT {}", payload);
                        }
                        opensips_log!(DBG, "rust_credit_check",
                            "debit sent: account={} dur={}s cost={:.2}", account, duration, cost);
                        // Clear cache for this account since balance changed
                        state.cache.clear(account);
                        1
                    } else {
                        state.stats.inc("debits_dropped");
                        opensips_log!(ERR, "rust_credit_check",
                            "debit queue full, dropped for {}", account);
                        -2
                    }
                }
                None => {
                    opensips_log!(ERR, "rust_credit_check",
                        "credit_debit called but debit_url is not configured");
                    -2
                }
            }
        })
    })
}

// ── Script function: credit_end(account) ────────────────────
// Ends a tracked call and sends debit automatically.

unsafe extern "C" fn w_rust_credit_end(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_credit_check",
                    "credit_end: missing account parameter");
                return -2;
            }
        };

        let rate = RATE_PER_MIN.get() as f64;

        WORKER.with(|w| {
            let mut borrow = w.borrow_mut();
            let state = match borrow.as_mut() {
                Some(s) => s,
                None => {
                    opensips_log!(ERR, "rust_credit_check", "worker state not initialized");
                    return -2;
                }
            };

            let duration = match state.call_tracker.end_call(account) {
                Some(d) => d,
                None => {
                    opensips_log!(WARN, "rust_credit_check",
                        "credit_end: no active call tracked for {}", account);
                    return -1;
                }
            };

            let cost = compute_debit_cost(duration, rate);
            let payload = build_debit_payload(account, duration, cost);

            match &state.debit_dispatcher {
                Some(dispatcher) => {
                    if dispatcher.send(payload) {
                        state.stats.inc("debits_sent");
                        // Publish E_CREDIT_DEBIT event
                        if event::is_enabled() {
                            let payload = event::format_payload(&[
                                ("account", &event::json_str(account)),
                                ("amount", &format!("{:.2}", cost)),
                            ]);
                            opensips_log!(NOTICE, "rust_credit_check", "EVENT E_CREDIT_DEBIT {}", payload);
                        }
                        state.cache.clear(account);
                        opensips_log!(DBG, "rust_credit_check",
                            "call ended: {} dur={}s cost={:.2}", account, duration, cost);
                        1
                    } else {
                        state.stats.inc("debits_dropped");
                        opensips_log!(ERR, "rust_credit_check",
                            "debit queue full on call end for {}", account);
                        -2
                    }
                }
                None => {
                    opensips_log!(WARN, "rust_credit_check",
                        "call ended for {} (dur={}s) but debit_url not configured", account, duration);
                    1
                }
            }
        })
    })
}

// ── Script function: credit_recheck(account) ────────────────

unsafe extern "C" fn w_rust_credit_recheck(
    msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_credit_check",
                    "credit_recheck: missing account parameter");
                return -2;
            }
        };

        let rate = RATE_PER_MIN.get() as f64;

        WORKER.with(|w| {
            let mut borrow = w.borrow_mut();
            let state = match borrow.as_mut() {
                Some(s) => s,
                None => {
                    opensips_log!(ERR, "rust_credit_check", "worker state not initialized");
                    return -2;
                }
            };

            state.stats.inc("rechecks");

            // Bypass cache — always fresh query
            let balance = match do_credit_query(state, account, true) {
                Ok(b) => b,
                Err(code) => return code,
            };

            let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };

            if balance > 0.0 {
                let max_dur = compute_max_duration(balance, rate);
                let balance_str = format!("{balance:.2}");
                let _ = sip_msg.set_pv("$var(credit_balance)", &balance_str);
                let _ = sip_msg.set_pv_int("$var(credit_max_duration)", max_dur);
                opensips_log!(DBG, "rust_credit_check",
                    "recheck {}: balance={} new_max_dur={}s", account, balance, max_dur);
                1
            } else {
                let _ = sip_msg.set_pv("$var(credit_balance)", "0.00");
                let _ = sip_msg.set_pv_int("$var(credit_max_duration)", 0);
                -1
            }
        })
    })
}

// ── Script function: credit_check_async(account) ────────────

unsafe extern "C" fn w_rust_credit_check_async(
    msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_credit_check",
                    "credit_check_async: missing account parameter");
                return -2;
            }
        };

        let rate = RATE_PER_MIN.get() as f64;

        WORKER.with(|w| {
            let mut borrow = w.borrow_mut();
            let state = match borrow.as_mut() {
                Some(s) => s,
                None => {
                    opensips_log!(ERR, "rust_credit_check", "worker state not initialized");
                    return -2;
                }
            };

            state.stats.inc("checked");

            // Cache-first: if we have a valid cached entry, return immediately
            if let Some(balance) = state.cache.get(account) {
                state.stats.inc("cache_hits");
                let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };

                if balance > 0.0 {
                    state.stats.inc("allowed");
                    let max_dur = compute_max_duration(balance, rate);
                    let balance_str = format!("{balance:.2}");
                    let _ = sip_msg.set_pv("$var(credit_balance)", &balance_str);
                    let _ = sip_msg.set_pv_int("$var(credit_max_duration)", max_dur);

                    if DEBIT_ON_END.get() != 0 {
                        state.call_tracker.start_call(account);
                    }
                    return 1;
                } else {
                    state.stats.inc("denied");
                    let _ = sip_msg.set_pv("$var(credit_balance)", "0.00");
                    let _ = sip_msg.set_pv_int("$var(credit_max_duration)", 0);
                    return -1;
                }
            }

            // Cache miss: fall back to blocking query (same as credit_check).
            // This is the simple cache-first approach — the common case after warmup
            // is a cache hit (instant, no blocking).
            state.stats.inc("cache_misses");

            let balance = match do_credit_query(state, account, false) {
                Ok(b) => b,
                Err(code) => return code,
            };

            let mut sip_msg = unsafe { opensips_rs::SipMessage::from_raw(msg) };

            if balance > 0.0 {
                state.stats.inc("allowed");
                let max_dur = compute_max_duration(balance, rate);
                let balance_str = format!("{balance:.2}");
                let _ = sip_msg.set_pv("$var(credit_balance)", &balance_str);
                let _ = sip_msg.set_pv_int("$var(credit_max_duration)", max_dur);

                if DEBIT_ON_END.get() != 0 {
                    state.call_tracker.start_call(account);
                }
                1
            } else {
                state.stats.inc("denied");
                let _ = sip_msg.set_pv("$var(credit_balance)", "0.00");
                let _ = sip_msg.set_pv_int("$var(credit_max_duration)", 0);
                -1
            }
        })
    })
}

// ── Script function: credit_clear(account) ──────────────────

unsafe extern "C" fn w_rust_credit_clear(
    _msg: *mut sys::sip_msg,
    p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void, _p3: *mut c_void,
    _p4: *mut c_void, _p5: *mut c_void, _p6: *mut c_void, _p7: *mut c_void,
) -> c_int {
    opensips_rs::ffi::catch_unwind_ffi_mut(|| {
        let account = match unsafe { <&str as CommandFunctionParam>::from_raw(p0) } {
            Some(s) => s,
            None => {
                opensips_log!(ERR, "rust_credit_check",
                    "credit_clear: missing or invalid parameter");
                return -2;
            }
        };

        WORKER.with(|w| {
            let mut borrow = w.borrow_mut();
            match borrow.as_mut() {
                Some(state) => {
                    state.cache.clear(account);
                    opensips_log!(DBG, "rust_credit_check",
                        "cache cleared for {}", account);
                    1
                }
                None => {
                    opensips_log!(ERR, "rust_credit_check",
                        "worker state not initialized");
                    -2
                }
            }
        })
    })
}


// ── Script function: credit_stats() ─────────────────────────

unsafe extern "C" fn w_rust_credit_stats(
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
        let _ = sip_msg.set_pv("$var(credit_stats)", &json);
        1
    })
}

// ── Script function: credit_check_prometheus() ──

unsafe extern "C" fn w_rust_credit_prometheus(
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
        let _ = sip_msg.set_pv("$var(credit_prom)", &prom);
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

const STR_INT_PARAM: [sys::cmd_param; 9] = {
    let mut arr: [sys::cmd_param; 9] = unsafe { std::mem::zeroed() };
    arr[0].flags = 2; // CMD_PARAM_STR
    arr[1].flags = 4; // CMD_PARAM_INT
    arr
};

#[repr(transparent)]
struct SyncArray<T, const N: usize>([T; N]);
unsafe impl<T, const N: usize> Sync for SyncArray<T, N> {}

static CMDS: SyncArray<sys::cmd_export_, 11> = SyncArray([
    sys::cmd_export_ {
        name: cstr_lit!("credit_check"),
        function: Some(w_rust_credit_check),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4, // REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE
    },
    sys::cmd_export_ {
        name: cstr_lit!("credit_check_dest"),
        function: Some(w_rust_credit_check_dest),
        params: TWO_STR_PARAM,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("credit_check_async"),
        function: Some(w_rust_credit_check_async),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("credit_debit"),
        function: Some(w_rust_credit_debit),
        params: STR_INT_PARAM,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("credit_end"),
        function: Some(w_rust_credit_end),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("credit_recheck"),
        function: Some(w_rust_credit_recheck),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("credit_clear"),
        function: Some(w_rust_credit_clear),
        params: ONE_STR_PARAM,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("credit_stats"),
        function: Some(w_rust_credit_stats),
        params: EMPTY_PARAMS,
        flags: 1 | 2 | 4,
    },
    sys::cmd_export_ {
        name: cstr_lit!("credit_prometheus"),
        function: Some(w_rust_credit_prometheus),
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
    // Extra null for safety (ACMDS sentinel)
    sys::cmd_export_ {
        name: ptr::null(),
        function: None,
        params: EMPTY_PARAMS,
        flags: 0,
    },
]);

static ACMDS: SyncArray<sys::acmd_export_, 1> = SyncArray([
    sys::acmd_export_ {
        name: ptr::null(),
        function: None,
        params: EMPTY_PARAMS,
    },
]);

static PARAMS: SyncArray<sys::param_export_, 17> = SyncArray([
    sys::param_export_ {
        name: cstr_lit!("billing_url"),
        type_: 1, // STR_PARAM
        param_pointer: BILLING_URL.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("cache_ttl"),
        type_: 2, // INT_PARAM
        param_pointer: CACHE_TTL.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("http_timeout"),
        type_: 2,
        param_pointer: HTTP_TIMEOUT.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("pool_size"),
        type_: 2,
        param_pointer: POOL_SIZE.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("rate_per_min"),
        type_: 2,
        param_pointer: RATE_PER_MIN.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("on_error"),
        type_: 1,
        param_pointer: ON_ERROR.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("tls_ca_file"),
        type_: 1,
        param_pointer: TLS_CA_FILE.as_ptr(),
    },
    // Task 45
    sys::param_export_ {
        name: cstr_lit!("debit_url"),
        type_: 1,
        param_pointer: DEBIT_URL.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("debit_on_end"),
        type_: 2,
        param_pointer: DEBIT_ON_END.as_ptr(),
    },
    // Task 46
    sys::param_export_ {
        name: cstr_lit!("balance_field"),
        type_: 1,
        param_pointer: BALANCE_FIELD.as_ptr(),
    },
    // Task 47
    sys::param_export_ {
        name: cstr_lit!("billing_url_backup"),
        type_: 1,
        param_pointer: BILLING_URL_BACKUP.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("failover_timeout_secs"),
        type_: 2,
        param_pointer: FAILOVER_TIMEOUT_SECS.as_ptr(),
    },
    // Task 48
    sys::param_export_ {
        name: cstr_lit!("rate_file"),
        type_: 1,
        param_pointer: RATE_FILE.as_ptr(),
    },
    // Task 49
    sys::param_export_ {
        name: cstr_lit!("recheck_interval_secs"),
        type_: 2,
        param_pointer: RECHECK_INTERVAL_SECS.as_ptr(),
    },
    // Task 50
    sys::param_export_ {
        name: cstr_lit!("cache_warmup_url"),
        type_: 1,
        param_pointer: CACHE_WARMUP_URL.as_ptr(),
    },
    sys::param_export_ {
        name: cstr_lit!("publish_events"),
        type_: 2, // INT_PARAM
        param_pointer: PUBLISH_EVENTS.as_ptr(),
    },
    // Null terminator
    sys::param_export_ {
        name: ptr::null(),
        type_: 0,
        param_pointer: ptr::null_mut(),
    },
]);

static DEPS: opensips_rs::ffi::DepExportConcrete<1> = opensips_rs::ffi::DepExportConcrete {
    md: unsafe { std::mem::zeroed() },
    mpd: unsafe { std::mem::zeroed() },
};

/// The module_exports struct that OpenSIPS loads via dlsym("exports").
#[no_mangle]
pub static exports: sys::module_exports = sys::module_exports {
    name: cstr_lit!("credit_check"),
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
    use std::thread;
    use std::time::Duration;

    // ── CreditCache tests ────────────────────────────────────────

    #[test]
    fn test_cache_put_get() {
        let mut cache = CreditCache::new(300);
        cache.put("alice", 42.50);
        assert_eq!(cache.get("alice"), Some(42.50));
    }

    #[test]
    fn test_cache_miss() {
        let cache = CreditCache::new(300);
        assert_eq!(cache.get("unknown"), None);
    }

    #[test]
    fn test_cache_expired() {
        let mut cache = CreditCache::new(0); // TTL of 0 seconds
        cache.put("alice", 42.50);
        thread::sleep(Duration::from_millis(10));
        assert_eq!(cache.get("alice"), None);
    }

    #[test]
    fn test_cache_clear() {
        let mut cache = CreditCache::new(300);
        cache.put("alice", 42.50);
        cache.clear("alice");
        assert_eq!(cache.get("alice"), None);
    }

    #[test]
    fn test_cache_clear_all() {
        let mut cache = CreditCache::new(300);
        cache.put("alice", 42.50);
        cache.put("bob", 10.00);
        cache.put("charlie", 100.00);
        assert_eq!(cache.len(), 3);
        cache.clear_all();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_has_valid() {
        let mut cache = CreditCache::new(300);
        assert!(!cache.has_valid("alice"));
        cache.put("alice", 42.50);
        assert!(cache.has_valid("alice"));
    }

    // ── compute_max_duration tests ───────────────────────────────

    #[test]
    fn test_compute_max_duration() {
        assert_eq!(compute_max_duration(42.50, 1.0), 2550);
    }

    #[test]
    fn test_compute_max_duration_zero() {
        assert_eq!(compute_max_duration(0.0, 1.0), 0);
    }

    #[test]
    fn test_compute_max_duration_negative_balance() {
        assert_eq!(compute_max_duration(-5.0, 1.0), 0);
    }

    #[test]
    fn test_compute_max_duration_zero_rate() {
        assert_eq!(compute_max_duration(42.50, 0.0), 0);
    }

    #[test]
    fn test_compute_max_duration_high_rate() {
        assert_eq!(compute_max_duration(10.0, 2.0), 300);
    }

    // ── Task 45: Debit tests ─────────────────────────────────────

    #[test]
    fn test_compute_debit_cost() {
        // 180 seconds at 1.0/min = 180/60 * 1.0 = 3.0
        assert!((compute_debit_cost(180, 1.0) - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compute_debit_cost_zero_duration() {
        assert!((compute_debit_cost(0, 1.0) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compute_debit_cost_zero_rate() {
        assert!((compute_debit_cost(180, 0.0) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compute_debit_cost_negative_duration() {
        assert!((compute_debit_cost(-10, 1.0) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compute_debit_cost_high_rate() {
        // 120 seconds at 2.5/min = 120/60 * 2.5 = 5.0
        assert!((compute_debit_cost(120, 2.5) - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_build_debit_payload() {
        let p = build_debit_payload("alice", 180, 3.0);
        let v: serde_json::Value = serde_json::from_str(&p).unwrap();
        assert_eq!(v["account"], "alice");
        assert_eq!(v["duration_secs"], 180);
        assert!((v["cost"].as_f64().unwrap() - 3.0).abs() < 0.01);
    }

    #[test]
    fn test_build_debit_payload_zero() {
        let p = build_debit_payload("bob", 0, 0.0);
        let v: serde_json::Value = serde_json::from_str(&p).unwrap();
        assert_eq!(v["account"], "bob");
        assert_eq!(v["duration_secs"], 0);
        assert!((v["cost"].as_f64().unwrap() - 0.0).abs() < 0.01);
    }

    #[test]
    fn test_call_tracker_start_end() {
        let mut tracker = CallTracker::new();
        tracker.start_call("alice");
        thread::sleep(Duration::from_millis(50));
        let dur = tracker.end_call("alice");
        assert!(dur.is_some());
        // Duration should be at least 0 (could be 0 due to resolution)
        assert!(dur.unwrap() >= 0);
    }

    #[test]
    fn test_call_tracker_end_nonexistent() {
        let mut tracker = CallTracker::new();
        assert!(tracker.end_call("nobody").is_none());
    }

    #[test]
    fn test_call_tracker_overwrite() {
        let mut tracker = CallTracker::new();
        tracker.start_call("alice");
        thread::sleep(Duration::from_millis(50));
        tracker.start_call("alice"); // restart
        let dur = tracker.end_call("alice");
        assert!(dur.is_some());
    }

    // ── Task 46: Configurable JSON field path tests ──────────────

    #[test]
    fn test_parse_balance_simple() {
        assert_eq!(parse_balance_with_path(r#"{"balance": 42.50}"#, "balance"), Some(42.50));
    }

    #[test]
    fn test_parse_balance_nested() {
        let body = r#"{"data":{"account":{"balance":42.5}}}"#;
        assert_eq!(parse_balance_with_path(body, "data.account.balance"), Some(42.5));
    }

    #[test]
    fn test_parse_balance_nested_deep() {
        let body = r#"{"a":{"b":{"c":{"d":99.9}}}}"#;
        assert_eq!(parse_balance_with_path(body, "a.b.c.d"), Some(99.9));
    }

    #[test]
    fn test_parse_balance_missing_field() {
        let body = r#"{"data":{"account":{"credits":42.5}}}"#;
        assert_eq!(parse_balance_with_path(body, "data.account.balance"), None);
    }

    #[test]
    fn test_parse_balance_missing_intermediate() {
        let body = r#"{"data":{"other":42.5}}"#;
        assert_eq!(parse_balance_with_path(body, "data.account.balance"), None);
    }

    #[test]
    fn test_parse_balance_non_numeric() {
        let body = r#"{"balance":"not_a_number"}"#;
        assert_eq!(parse_balance_with_path(body, "balance"), None);
    }

    #[test]
    fn test_parse_balance_integer() {
        assert_eq!(parse_balance_with_path(r#"{"balance": 100}"#, "balance"), Some(100.0));
    }

    #[test]
    fn test_parse_balance_empty_path() {
        let body = r#"{"balance": 42.50}"#;
        assert_eq!(parse_balance_with_path(body, ""), None);
    }

    #[test]
    fn test_parse_balance_invalid_json() {
        assert_eq!(parse_balance_with_path("not json", "balance"), None);
    }

    #[test]
    fn test_extract_nested_field_single() {
        let v: serde_json::Value = serde_json::from_str(r#"{"x": 5.5}"#).unwrap();
        assert_eq!(extract_nested_field(&v, "x"), Some(5.5));
    }

    #[test]
    fn test_extract_nested_field_two_levels() {
        let v: serde_json::Value = serde_json::from_str(r#"{"a":{"b": 7.7}}"#).unwrap();
        assert_eq!(extract_nested_field(&v, "a.b"), Some(7.7));
    }

    #[test]
    fn test_parse_balance_backward_compat() {
        // Legacy function still works
        assert_eq!(parse_balance_response(r#"{"balance": 42.50}"#), Some(42.50));
    }

    #[test]
    fn test_parse_balance_extra_fields() {
        let body = r#"{"balance": 42.50, "currency": "USD", "account": "alice"}"#;
        assert_eq!(parse_balance_response(body), Some(42.50));
    }

    // ── Task 47: Failover state tests ────────────────────────────

    #[test]
    fn test_billing_state_primary() {
        let state = BillingState::Primary;
        assert!(!state.is_failover());
        assert!(!state.should_recover(30));
    }

    #[test]
    fn test_billing_state_failover() {
        let state = BillingState::Failover(Instant::now());
        assert!(state.is_failover());
        assert!(!state.should_recover(30)); // just created, not expired yet
    }

    #[test]
    fn test_billing_state_recovery() {
        let state = BillingState::Failover(Instant::now() - Duration::from_secs(60));
        assert!(state.should_recover(30)); // 60 > 30 => should recover
    }

    #[test]
    fn test_billing_state_no_early_recovery() {
        let state = BillingState::Failover(Instant::now() - Duration::from_secs(10));
        assert!(!state.should_recover(30)); // 10 < 30 => too early
    }

    #[test]
    fn test_billing_state_zero_timeout_recovery() {
        let state = BillingState::Failover(Instant::now());
        thread::sleep(Duration::from_millis(5));
        assert!(state.should_recover(0)); // 0 timeout => immediate recovery
    }

    // ── Task 48: Rate table tests ────────────────────────────────

    #[test]
    fn test_rate_table_basic() {
        let csv = "1,0.5\n44,1.0\n4420,0.8\n";
        let rt = RateTable::from_csv(csv, 1.0);
        assert_eq!(rt.entries.len(), 3);
    }

    #[test]
    fn test_rate_table_longest_match() {
        let csv = "1,0.5\n44,1.0\n4420,0.8\n";
        let rt = RateTable::from_csv(csv, 2.0);
        let (prefix, rate) = rt.lookup("44201234567");
        assert_eq!(prefix, "4420");
        assert!((rate - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn test_rate_table_shorter_match() {
        let csv = "1,0.5\n44,1.0\n4420,0.8\n";
        let rt = RateTable::from_csv(csv, 2.0);
        let (prefix, rate) = rt.lookup("4430123456");
        assert_eq!(prefix, "44");
        assert!((rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_rate_table_no_match_default() {
        let csv = "44,1.0\n4420,0.8\n";
        let rt = RateTable::from_csv(csv, 2.0);
        let (prefix, rate) = rt.lookup("33123456789");
        assert_eq!(prefix, "");
        assert!((rate - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_rate_table_empty() {
        let rt = RateTable::from_csv("", 1.5);
        assert_eq!(rt.entries.len(), 0);
        let (prefix, rate) = rt.lookup("anything");
        assert_eq!(prefix, "");
        assert!((rate - 1.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_rate_table_comments() {
        let csv = "# US rates\n1,0.5\n# UK rates\n44,1.0\n";
        let rt = RateTable::from_csv(csv, 2.0);
        assert_eq!(rt.entries.len(), 2);
    }

    #[test]
    fn test_rate_table_whitespace() {
        let csv = "  1 , 0.5 \n 44 , 1.0\n";
        let rt = RateTable::from_csv(csv, 2.0);
        assert_eq!(rt.entries.len(), 2);
        let (_, rate) = rt.lookup("12345");
        assert!((rate - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_rate_table_invalid_rate_skipped() {
        let csv = "1,abc\n44,1.0\n";
        let rt = RateTable::from_csv(csv, 2.0);
        assert_eq!(rt.entries.len(), 1);
    }

    #[test]
    fn test_rate_table_negative_rate_skipped() {
        let csv = "1,-0.5\n44,1.0\n";
        let rt = RateTable::from_csv(csv, 2.0);
        assert_eq!(rt.entries.len(), 1);
    }

    #[test]
    fn test_rate_table_zero_rate_skipped() {
        let csv = "1,0\n44,1.0\n";
        let rt = RateTable::from_csv(csv, 2.0);
        assert_eq!(rt.entries.len(), 1);
    }

    #[test]
    fn test_rate_table_sorted_by_prefix_length() {
        let csv = "1,0.5\n4420,0.8\n44,1.0\n442,0.9\n";
        let rt = RateTable::from_csv(csv, 2.0);
        // Should be sorted: 4420 (4), 442 (3), 44 (2), 1 (1)
        assert_eq!(rt.entries[0].0, "4420");
        assert_eq!(rt.entries[1].0, "442");
        assert_eq!(rt.entries[2].0, "44");
        assert_eq!(rt.entries[3].0, "1");
    }

    #[test]
    fn test_rate_table_exact_prefix_match() {
        let csv = "12345,0.1\n";
        let rt = RateTable::from_csv(csv, 2.0);
        let (prefix, rate) = rt.lookup("12345");
        assert_eq!(prefix, "12345");
        assert!((rate - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn test_rate_table_prefix_longer_than_dest() {
        let csv = "12345,0.1\n";
        let rt = RateTable::from_csv(csv, 2.0);
        let (prefix, rate) = rt.lookup("1234");
        assert_eq!(prefix, "");
        assert!((rate - 2.0).abs() < f64::EPSILON);
    }

    // ── Task 50: Cache warmup parsing tests ──────────────────────

    #[test]
    fn test_parse_warmup_response_basic() {
        let body = r#"[{"account":"alice","balance":42.5},{"account":"bob","balance":10.0}]"#;
        let result = parse_warmup_response(body, "balance");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0, "alice");
        assert!((result[0].1 - 42.5).abs() < f64::EPSILON);
        assert_eq!(result[1].0, "bob");
        assert!((result[1].1 - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_parse_warmup_response_nested_field() {
        let body = r#"[{"account":"alice","data":{"balance":42.5}}]"#;
        let result = parse_warmup_response(body, "data.balance");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "alice");
        assert!((result[0].1 - 42.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_parse_warmup_response_empty() {
        let result = parse_warmup_response("[]", "balance");
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_warmup_response_invalid_json() {
        let result = parse_warmup_response("not json", "balance");
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_warmup_response_missing_account() {
        let body = r#"[{"balance":42.5}]"#;
        let result = parse_warmup_response(body, "balance");
        assert!(result.is_empty()); // no "account" field
    }

    #[test]
    fn test_parse_warmup_response_missing_balance() {
        let body = r#"[{"account":"alice","credits":42.5}]"#;
        let result = parse_warmup_response(body, "balance");
        assert!(result.is_empty()); // wrong field name
    }

    // ── on_error_allows tests ────────────────────────────────────

    #[test]
    fn test_on_error_deny() {
        assert!(!on_error_allows("deny"));
    }

    #[test]
    fn test_on_error_allow() {
        assert!(on_error_allows("allow"));
    }

    #[test]
    fn test_on_error_allow_case_insensitive() {
        assert!(on_error_allows("Allow"));
        assert!(on_error_allows("ALLOW"));
    }

    #[test]
    fn test_on_error_unknown_defaults_deny() {
        assert!(!on_error_allows(""));
        assert!(!on_error_allows("block"));
        assert!(!on_error_allows("reject"));
    }

    // ── Cache update/overwrite tests ─────────────────────────────

    #[test]
    fn test_cache_overwrite() {
        let mut cache = CreditCache::new(300);
        cache.put("alice", 42.50);
        cache.put("alice", 10.00);
        assert_eq!(cache.get("alice"), Some(10.00));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_cache_clear_nonexistent() {
        let mut cache = CreditCache::new(300);
        cache.clear("nonexistent"); // should not panic
        assert_eq!(cache.len(), 0);
    }

    // ── Stats JSON output tests ──────────────────────────────────

    #[test]
    fn test_credit_stats_json() {
        let stats = Stats::new("rust_credit_check",
            &["checked", "allowed", "denied", "errors", "cache_hits", "cache_misses"]);
        stats.inc("checked");
        stats.inc("checked");
        stats.inc("allowed");
        stats.inc("cache_hits");
        stats.inc("cache_misses");

        let json = stats.to_json();
        assert!(json.starts_with("{"));
        assert!(json.ends_with("}"));
        assert!(json.contains(r#""checked":2"#));
        assert!(json.contains(r#""allowed":1"#));
        assert!(json.contains(r#""denied":0"#));
        assert!(json.contains(r#""cache_hits":1"#));
    }

    // ── configuration validation edge case tests ────────────────

    #[test]
    fn test_cache_ttl_zero_expires_immediately() {
        let mut cache = CreditCache::new(0);
        cache.put("alice", 42.50);
        thread::sleep(Duration::from_millis(1));
        assert_eq!(cache.get("alice"), None);
    }

    #[test]
    fn test_compute_max_duration_negative_rate() {
        assert_eq!(compute_max_duration(42.50, -1.0), 0);
    }

    #[test]
    fn test_on_error_empty_string_denies() {
        assert!(!on_error_allows(""));
    }

    #[test]
    fn test_on_error_whitespace_denies() {
        assert!(!on_error_allows(" "));
        assert!(!on_error_allows("  deny  "));
    }

    // ── event publishing tests ──────────────────────────────────

    #[test]
    fn test_event_payload_credit_denied() {
        let payload = event::format_payload(&[
            ("account", &event::json_str("alice")),
            ("balance", "0.50"),
        ]);
        assert!(payload.contains(r#""account":"alice""#));
        assert!(payload.contains(r#""balance":0.50"#));
    }

    #[test]
    fn test_event_payload_credit_debit() {
        let payload = event::format_payload(&[
            ("account", &event::json_str("bob")),
            ("amount", "2.50"),
        ]);
        assert!(payload.contains(r#""account":"bob""#));
        assert!(payload.contains(r#""amount":2.50"#));
    }
}
