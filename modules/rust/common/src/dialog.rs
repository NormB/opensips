//! Dialog lifecycle tracker.
//!
//! Pure Rust state manager for per-dialog data, generic over state type `T`.
//! Each worker process gets its own `DialogTracker<T>` (typically via
//! `thread_local!` or a per-worker static).
//!
//! The C FFI glue (`extern "C"` trampolines calling `register_dlgcb`) lives
//! in each service module — not here — because the trampolines need access
//! to the module's specific `thread_local!` state, which cannot be generic.
//!
//! This module provides:
//! - `DialogTracker<T>` — per-worker HashMap of dialog states
//! - Re-exports of dialog callback constants (`DLGCB_CREATED`, etc.)
//! - `load_dialog_api()` — safe wrapper to load the dialog module API
//! - `register_created_cb()` / `register_dlg_cb()` — safe wrappers for
//!   callback registration

use std::cell::RefCell;
use std::collections::HashMap;
use std::time::Instant;

// Re-export the FFI layer from opensips-rs
pub use opensips_rs::dlg::{
    self,
    // Callback type constants
    DLGCB_LOADED,
    DLGCB_CREATED,
    DLGCB_FAILED,
    DLGCB_CONFIRMED,
    DLGCB_REQ_WITHIN,
    DLGCB_TERMINATED,
    DLGCB_EXPIRED,
    DLGCB_EARLY,
    DLGCB_RESPONSE_FWDED,
    DLGCB_RESPONSE_WITHIN,
    DLGCB_MI_CONTEXT,
    DLGCB_DESTROY,
    DLGCB_DB_SAVED,
    DLGCB_WRITE_VP,
    DLGCB_PROCESS_VARS,
    // FFI helpers
    load_api,
    api_loaded,
};

// Re-export the callback function types for use in trampoline definitions
pub use opensips_rs::sys::{dialog_cb, param_free_cb, dlg_cell, dlg_cb_params};

// ── DialogTracker ────────────────────────────────────────────────────

/// Per-dialog state entry, stored in the tracker's HashMap.
pub struct DialogEntry<T> {
    /// User-defined per-dialog state.
    pub state: T,
    /// When this dialog was first tracked.
    pub created: Instant,
}

/// Per-worker dialog state tracker.
///
/// Generic over `T`, the per-dialog state type. Each worker process
/// maintains its own tracker instance (no cross-worker sharing needed
/// because OpenSIPS dispates each dialog's callbacks to the same worker).
///
/// # Example
///
/// ```ignore
/// use rust_common::dialog::DialogTracker;
///
/// #[derive(Default)]
/// struct CallState {
///     bytes_in: u64,
///     bytes_out: u64,
/// }
///
/// thread_local! {
///     static TRACKER: DialogTracker<CallState> = DialogTracker::new(3600);
/// }
/// ```
pub struct DialogTracker<T: Default> {
    states: RefCell<HashMap<String, DialogEntry<T>>>,
    max_age_secs: u64,
}

impl<T: Default> DialogTracker<T> {
    /// Create a new tracker with a maximum dialog age (safety-net sweep threshold).
    pub fn new(max_age_secs: u64) -> Self {
        DialogTracker {
            states: RefCell::new(HashMap::with_capacity(256)),
            max_age_secs,
        }
    }

    /// Track a new dialog. Called from the DLGCB_CREATED trampoline.
    ///
    /// Returns `&Self` for chaining.
    pub fn on_created(&self, dialog_id: &str) -> &Self {
        let mut states = self.states.borrow_mut();
        states.insert(
            dialog_id.to_string(),
            DialogEntry {
                state: T::default(),
                created: Instant::now(),
            },
        );
        self
    }

    /// Remove a terminated dialog and return its state.
    /// Called from the DLGCB_TERMINATED trampoline.
    pub fn on_terminated(&self, dialog_id: &str) -> Option<T> {
        self.states
            .borrow_mut()
            .remove(dialog_id)
            .map(|e| e.state)
    }

    /// Remove an expired dialog and return its state.
    /// Called from the DLGCB_EXPIRED trampoline.
    pub fn on_expired(&self, dialog_id: &str) -> Option<T> {
        self.on_terminated(dialog_id)
    }

    /// Access per-dialog state for reading or writing during mid-call events.
    ///
    /// Returns `None` if the dialog is not tracked (e.g., created before
    /// this module was loaded).
    pub fn with_state<R>(&self, dialog_id: &str, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        let mut states = self.states.borrow_mut();
        states.get_mut(dialog_id).map(|entry| f(&mut entry.state))
    }

    /// Read-only access to per-dialog state.
    pub fn with_state_ref<R>(&self, dialog_id: &str, f: impl FnOnce(&T) -> R) -> Option<R> {
        let states = self.states.borrow();
        states.get(dialog_id).map(|entry| f(&entry.state))
    }

    /// Number of currently tracked (active) dialogs on this worker.
    pub fn active_count(&self) -> usize {
        self.states.borrow().len()
    }

    /// Safety-net sweep: remove entries older than `max_age_secs`.
    ///
    /// Call periodically (e.g., from a timer callback) to clean up
    /// dialogs whose TERMINATED/EXPIRED callbacks were missed.
    pub fn sweep_expired(&self) -> usize {
        let max_age = std::time::Duration::from_secs(self.max_age_secs);
        let now = Instant::now();
        let mut states = self.states.borrow_mut();
        let before = states.len();
        states.retain(|_, entry| now.duration_since(entry.created) < max_age);
        before - states.len()
    }

    /// Check if a dialog is currently tracked.
    pub fn contains(&self, dialog_id: &str) -> bool {
        self.states.borrow().contains_key(dialog_id)
    }

    /// Get the age of a tracked dialog in seconds.
    pub fn age_secs(&self, dialog_id: &str) -> Option<u64> {
        self.states
            .borrow()
            .get(dialog_id)
            .map(|e| e.created.elapsed().as_secs())
    }

    /// Collect a JSON array from all active dialogs using a formatter function.
    ///
    /// The formatter receives `(dialog_id, &DialogEntry<T>)` and returns a
    /// JSON object string for that dialog. Results are joined into a JSON array.
    pub fn collect_json<F>(&self, formatter: F) -> String
    where
        F: Fn(&str, &DialogEntry<T>) -> String,
    {
        let states = self.states.borrow();
        let entries: Vec<String> = states
            .iter()
            .map(|(id, entry)| formatter(id, entry))
            .collect();
        format!("[{}]", entries.join(","))
    }

    /// Iterate over all tracked dialogs with read-only access.
    pub fn for_each_ref<F>(&self, mut f: F)
    where
        F: FnMut(&str, &DialogEntry<T>),
    {
        let states = self.states.borrow();
        for (id, entry) in states.iter() {
            f(id, entry);
        }
    }
}

// ── Convenience: extract Call-ID from callback parameters ────────────

/// Extract the Call-ID string from an opaque `dlg_cell` pointer.
///
/// This is the typical way to get the dialog identifier inside a
/// callback trampoline.
///
/// # Safety
/// `dlg` must be a valid pointer obtained from a dialog callback.
pub unsafe fn callid_from_dlg(dlg: *mut std::ffi::c_void) -> Option<String> {
    unsafe { dlg::callid(dlg).map(|s| s.to_string()) }
}

// ── Unit tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct TestState {
        value: i32,
    }

    #[test]
    fn tracker_starts_empty() {
        let tracker: DialogTracker<TestState> = DialogTracker::new(300);
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn on_created_adds_dialog() {
        let tracker: DialogTracker<TestState> = DialogTracker::new(300);
        tracker.on_created("call-1");
        assert_eq!(tracker.active_count(), 1);
        assert!(tracker.contains("call-1"));
    }

    #[test]
    fn on_terminated_removes_and_returns_state() {
        let tracker: DialogTracker<TestState> = DialogTracker::new(300);
        tracker.on_created("call-1");
        tracker.with_state("call-1", |s| s.value = 42);
        let state = tracker.on_terminated("call-1");
        assert!(state.is_some());
        assert_eq!(state.unwrap().value, 42);
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn on_terminated_unknown_returns_none() {
        let tracker: DialogTracker<TestState> = DialogTracker::new(300);
        let state = tracker.on_terminated("nonexistent");
        assert!(state.is_none());
    }

    #[test]
    fn on_expired_behaves_like_terminated() {
        let tracker: DialogTracker<TestState> = DialogTracker::new(300);
        tracker.on_created("call-1");
        let state = tracker.on_expired("call-1");
        assert!(state.is_some());
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn with_state_mutates() {
        let tracker: DialogTracker<TestState> = DialogTracker::new(300);
        tracker.on_created("call-1");
        tracker.with_state("call-1", |s| s.value = 99);
        let val = tracker.with_state("call-1", |s| s.value);
        assert_eq!(val, Some(99));
    }

    #[test]
    fn with_state_ref_reads() {
        let tracker: DialogTracker<TestState> = DialogTracker::new(300);
        tracker.on_created("call-1");
        tracker.with_state("call-1", |s| s.value = 7);
        let val = tracker.with_state_ref("call-1", |s| s.value);
        assert_eq!(val, Some(7));
    }

    #[test]
    fn with_state_unknown_returns_none() {
        let tracker: DialogTracker<TestState> = DialogTracker::new(300);
        let result = tracker.with_state("nope", |s| s.value);
        assert!(result.is_none());
    }

    #[test]
    fn multiple_dialogs() {
        let tracker: DialogTracker<TestState> = DialogTracker::new(300);
        tracker.on_created("call-1");
        tracker.on_created("call-2");
        tracker.on_created("call-3");
        assert_eq!(tracker.active_count(), 3);

        tracker.with_state("call-2", |s| s.value = 200);
        tracker.on_terminated("call-1");
        assert_eq!(tracker.active_count(), 2);
        assert!(!tracker.contains("call-1"));
        assert!(tracker.contains("call-2"));

        let val = tracker.with_state("call-2", |s| s.value);
        assert_eq!(val, Some(200));
    }

    #[test]
    fn sweep_expired_cleans_old_entries() {
        let tracker: DialogTracker<TestState> = DialogTracker::new(0);
        tracker.on_created("call-1");
        tracker.on_created("call-2");
        std::thread::sleep(std::time::Duration::from_millis(10));
        let swept = tracker.sweep_expired();
        assert_eq!(swept, 2);
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn sweep_preserves_fresh_entries() {
        let tracker: DialogTracker<TestState> = DialogTracker::new(3600);
        tracker.on_created("call-1");
        let swept = tracker.sweep_expired();
        assert_eq!(swept, 0);
        assert_eq!(tracker.active_count(), 1);
    }

    #[test]
    fn age_secs_returns_duration() {
        let tracker: DialogTracker<TestState> = DialogTracker::new(300);
        tracker.on_created("call-1");
        let age = tracker.age_secs("call-1");
        assert!(age.is_some());
        assert!(age.unwrap() < 2); // should be ~0
    }

    #[test]
    fn age_secs_unknown_returns_none() {
        let tracker: DialogTracker<TestState> = DialogTracker::new(300);
        assert!(tracker.age_secs("nope").is_none());
    }

    #[test]
    fn duplicate_created_overwrites() {
        let tracker: DialogTracker<TestState> = DialogTracker::new(300);
        tracker.on_created("call-1");
        tracker.with_state("call-1", |s| s.value = 42);
        // Second on_created resets the state
        tracker.on_created("call-1");
        let val = tracker.with_state("call-1", |s| s.value);
        assert_eq!(val, Some(0)); // Default::default()
        assert_eq!(tracker.active_count(), 1);
    }

    #[test]
    fn collect_json_empty() {
        let tracker: DialogTracker<TestState> = DialogTracker::new(300);
        let json = tracker.collect_json(|id, _entry| format!("{{\"id\":\"{}\"}}", id));
        assert_eq!(json, "[]");
    }

    #[test]
    fn collect_json_single() {
        let tracker: DialogTracker<TestState> = DialogTracker::new(300);
        tracker.on_created("call-1");
        tracker.with_state("call-1", |s| s.value = 42);
        let json = tracker.collect_json(|id, entry| {
            format!("{{\"id\":\"{}\",\"value\":{}}}", id, entry.state.value)
        });
        assert_eq!(json, r#"[{"id":"call-1","value":42}]"#);
    }

    #[test]
    fn collect_json_multiple() {
        let tracker: DialogTracker<TestState> = DialogTracker::new(300);
        tracker.on_created("a");
        tracker.on_created("b");
        tracker.with_state("a", |s| s.value = 1);
        tracker.with_state("b", |s| s.value = 2);
        let json = tracker.collect_json(|id, entry| {
            format!("{{\"id\":\"{}\",\"v\":{}}}", id, entry.state.value)
        });
        assert!(json.starts_with('['));
        assert!(json.ends_with(']'));
        assert!(json.contains(r#""id":"a""#));
        assert!(json.contains(r#""id":"b""#));
    }
}
