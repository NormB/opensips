//! Cross-module event publishing.
//!
//! Provides a simple event publishing mechanism for OpenSIPS Rust modules.
//! Events are published as NOTICE-level log messages in a structured format
//! that operators can consume via syslog, and optionally via `nats_publish`
//! if the NATS module is loaded.
//!
//! Each event has a name (e.g., "E_ACL_BLOCKED") and a JSON payload.
//!
//! The logging is done by the calling module (not this library crate) because
//! `opensips_log!` requires FFI symbols that are only available when linked
//! as a .so module. This module provides pure formatting helpers.

use std::cell::Cell;

thread_local! {
    static EVENTS_ENABLED: Cell<bool> = Cell::new(false);
}

/// Enable or disable event publishing for the current worker.
pub fn set_enabled(enabled: bool) {
    EVENTS_ENABLED.with(|e| e.set(enabled));
}

/// Check if event publishing is enabled.
pub fn is_enabled() -> bool {
    EVENTS_ENABLED.with(|e| e.get())
}

/// Format an event payload as a JSON object string.
///
/// Takes a list of key-value pairs and produces a JSON object.
/// Values are inserted as-is (caller must quote strings with `json_str`).
pub fn format_payload(pairs: &[(&str, &str)]) -> String {
    let fields: Vec<String> = pairs
        .iter()
        .map(|(k, v)| {
            let mut s = String::with_capacity(k.len() + v.len() + 4);
            s.push('"');
            s.push_str(k);
            s.push_str("\":");
            s.push_str(v);
            s
        })
        .collect();
    let mut result = String::with_capacity(fields.iter().map(|f| f.len() + 1).sum::<usize>() + 2);
    result.push('{');
    for (i, field) in fields.iter().enumerate() {
        if i > 0 {
            result.push(',');
        }
        result.push_str(field);
    }
    result.push('}');
    result
}

/// Format a string value for JSON (with quotes and escaping).
pub fn json_str(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 2);
    result.push('"');
    for ch in s.chars() {
        match ch {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            _ => result.push(ch),
        }
    }
    result.push('"');
    result
}

/// Format a NATS subject for an event name.
pub fn nats_subject(event_name: &str) -> String {
    let mut s = String::with_capacity(17 + event_name.len());
    s.push_str("opensips.events.");
    s.push_str(event_name);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_payload_empty() {
        assert_eq!(format_payload(&[]), "{}");
    }

    #[test]
    fn test_format_payload_single() {
        let result = format_payload(&[("key", "\"value\"")]);
        assert_eq!(result, r#"{"key":"value"}"#);
    }

    #[test]
    fn test_format_payload_multiple() {
        let result = format_payload(&[
            ("account", "\"alice\""),
            ("count", "5"),
            ("limit", "10"),
        ]);
        assert_eq!(result, r#"{"account":"alice","count":5,"limit":10}"#);
    }

    #[test]
    fn test_json_str_simple() {
        assert_eq!(json_str("hello"), "\"hello\"");
    }

    #[test]
    fn test_json_str_with_quotes() {
        let result = json_str("say \"hi\"");
        assert_eq!(result, "\"say \\\"hi\\\"\"");
    }

    #[test]
    fn test_json_str_with_backslash() {
        let result = json_str("path\\to");
        assert_eq!(result, "\"path\\\\to\"");
    }

    #[test]
    fn test_json_str_empty() {
        assert_eq!(json_str(""), "\"\"");
    }

    #[test]
    fn test_enabled_default_false() {
        set_enabled(false);
        assert!(!is_enabled());
    }

    #[test]
    fn test_set_enabled() {
        set_enabled(true);
        assert!(is_enabled());
        set_enabled(false);
        assert!(!is_enabled());
    }

    #[test]
    fn test_format_payload_with_json_str() {
        let account = json_str("alice");
        let result = format_payload(&[
            ("account", &account),
            ("blocked", "true"),
        ]);
        assert_eq!(result, r#"{"account":"alice","blocked":true}"#);
    }

    #[test]
    fn test_nats_subject() {
        assert_eq!(nats_subject("E_ACL_BLOCKED"), "opensips.events.E_ACL_BLOCKED");
    }

    #[test]
    fn test_format_payload_numeric() {
        let result = format_payload(&[
            ("interval", "1800"),
            ("min_se", "90"),
        ]);
        assert_eq!(result, r#"{"interval":1800,"min_se":90}"#);
    }
}
