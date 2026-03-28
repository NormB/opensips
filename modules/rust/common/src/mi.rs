//! Per-module statistics with MI command exposure.

use std::cell::Cell;

/// Simple per-worker counter set. Not cross-worker -- each worker
/// maintains its own counts. MI output shows the calling worker's stats.
pub struct Stats {
    pub name: &'static str,
    counters: Vec<(&'static str, Cell<u64>)>,
}

impl Stats {
    pub fn new(name: &'static str, counter_names: &[&'static str]) -> Self {
        let counters = counter_names.iter()
            .map(|n| (*n, Cell::new(0)))
            .collect();
        Stats { name, counters }
    }

    pub fn inc(&self, counter: &str) {
        for (name, cell) in &self.counters {
            if *name == counter {
                cell.set(cell.get() + 1);
                return;
            }
        }
    }

    pub fn set(&self, counter: &str, val: u64) {
        for (name, cell) in &self.counters {
            if *name == counter {
                cell.set(val);
                return;
            }
        }
    }

    pub fn get(&self, counter: &str) -> u64 {
        for (name, cell) in &self.counters {
            if *name == counter {
                return cell.get();
            }
        }
        0
    }

    /// Format all stats as JSON string for MI output.
    pub fn to_json(&self) -> String {
        let pairs: Vec<String> = self.counters.iter()
            .map(|(name, cell)| format!("\"{}\":{}", name, cell.get()))
            .collect();
        format!("{{{}}}", pairs.join(","))
    }

    /// Format stats as Prometheus text exposition format.
    ///
    /// Each counter is emitted with a `# HELP` comment, a `# TYPE`
    /// declaration, and the metric line.  The metric name is
    /// `{module_name}_{counter_name}`.
    ///
    /// Operators expose the output via `httpd` or a custom MI command.
    pub fn to_prometheus(&self) -> String {
        let mut out = String::with_capacity(self.counters.len() * 120);
        for (name, cell) in &self.counters {
            let metric = format!("{}_{}", self.name, name);
            out.push_str("# HELP ");
            out.push_str(&metric);
            out.push(' ');
            out.push_str(&Self::help_text(self.name, name));
            out.push('\n');
            out.push_str("# TYPE ");
            out.push_str(&metric);
            out.push(' ');
            out.push_str(Self::prom_type(name));
            out.push('\n');
            out.push_str(&metric);
            out.push(' ');
            out.push_str(&cell.get().to_string());
            out.push('\n');
        }
        out
    }

    /// Determine Prometheus metric type from counter name.
    /// Names containing "entries" or "sessions" are gauges; everything else
    /// is a counter.
    fn prom_type(name: &str) -> &'static str {
        if name.starts_with("entries")
            || name.starts_with("sessions")
            || name.starts_with("active")
            || name.starts_with("pending")
            || name.starts_with("queue")
        {
            "gauge"
        } else {
            "counter"
        }
    }

    /// Build a human-readable HELP string for a metric.
    fn help_text(module: &str, counter: &str) -> String {
        let readable = counter.replace('_', " ");
        format!("{} {}", module, readable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_new() {
        let s = Stats::new("test", &["a", "b", "c"]);
        assert_eq!(s.name, "test");
        assert_eq!(s.get("a"), 0);
        assert_eq!(s.get("b"), 0);
        assert_eq!(s.get("c"), 0);
    }

    #[test]
    fn test_stats_inc() {
        let s = Stats::new("test", &["hits"]);
        assert_eq!(s.get("hits"), 0);
        s.inc("hits");
        assert_eq!(s.get("hits"), 1);
        s.inc("hits");
        assert_eq!(s.get("hits"), 2);
    }

    #[test]
    fn test_stats_set() {
        let s = Stats::new("test", &["gauge"]);
        s.set("gauge", 42);
        assert_eq!(s.get("gauge"), 42);
        s.set("gauge", 100);
        assert_eq!(s.get("gauge"), 100);
    }

    #[test]
    fn test_stats_get_unknown() {
        let s = Stats::new("test", &["known"]);
        assert_eq!(s.get("nonexistent"), 0);
    }

    #[test]
    fn test_stats_to_json() {
        let s = Stats::new("test", &["a", "b"]);
        s.set("a", 10);
        s.set("b", 20);
        let json = s.to_json();
        assert_eq!(json, r#"{"a":10,"b":20}"#);
    }

    #[test]
    fn test_stats_multiple_counters() {
        let s = Stats::new("test", &["x", "y", "z"]);
        s.inc("x");
        s.inc("x");
        s.inc("y");
        s.set("z", 99);
        assert_eq!(s.get("x"), 2);
        assert_eq!(s.get("y"), 1);
        assert_eq!(s.get("z"), 99);
    }

    #[test]
    fn test_stats_inc_unknown_noop() {
        let s = Stats::new("test", &["a"]);
        s.inc("nonexistent"); // should not panic
        assert_eq!(s.get("a"), 0);
    }

    #[test]
    fn test_stats_to_json_empty() {
        let s = Stats::new("empty", &[]);
        assert_eq!(s.to_json(), "{}");
    }

    // ── Prometheus format tests ──────────────────────────────────

    #[test]
    fn test_stats_to_prometheus_basic() {
        let s = Stats::new("rust_test", &["sent", "dropped"]);
        s.set("sent", 100);
        s.set("dropped", 5);
        let prom = s.to_prometheus();
        assert!(prom.contains("# HELP rust_test_sent rust_test sent\n"));
        assert!(prom.contains("# TYPE rust_test_sent counter\n"));
        assert!(prom.contains("rust_test_sent 100\n"));
        assert!(prom.contains("# HELP rust_test_dropped rust_test dropped\n"));
        assert!(prom.contains("# TYPE rust_test_dropped counter\n"));
        assert!(prom.contains("rust_test_dropped 5\n"));
    }

    #[test]
    fn test_stats_to_prometheus_gauge() {
        let s = Stats::new("rust_acl", &["entries_blocklist", "entries_allowlist"]);
        s.set("entries_blocklist", 42);
        s.set("entries_allowlist", 10);
        let prom = s.to_prometheus();
        assert!(prom.contains("# TYPE rust_acl_entries_blocklist gauge\n"));
        assert!(prom.contains("rust_acl_entries_blocklist 42\n"));
        assert!(prom.contains("# TYPE rust_acl_entries_allowlist gauge\n"));
        assert!(prom.contains("rust_acl_entries_allowlist 10\n"));
    }

    #[test]
    fn test_stats_to_prometheus_empty() {
        let s = Stats::new("empty", &[]);
        assert_eq!(s.to_prometheus(), "");
    }

    #[test]
    fn test_stats_to_prometheus_zero_values() {
        let s = Stats::new("mod", &["checked"]);
        let prom = s.to_prometheus();
        assert!(prom.contains("mod_checked 0\n"));
    }

    #[test]
    fn test_stats_prom_type_counter() {
        assert_eq!(Stats::prom_type("sent"), "counter");
        assert_eq!(Stats::prom_type("dropped"), "counter");
        assert_eq!(Stats::prom_type("failed"), "counter");
        assert_eq!(Stats::prom_type("checked"), "counter");
        assert_eq!(Stats::prom_type("blocked"), "counter");
        assert_eq!(Stats::prom_type("reloads"), "counter");
    }

    #[test]
    fn test_stats_prom_type_gauge() {
        assert_eq!(Stats::prom_type("entries_blocklist"), "gauge");
        assert_eq!(Stats::prom_type("entries_allowlist"), "gauge");
        assert_eq!(Stats::prom_type("sessions_active"), "gauge");
        assert_eq!(Stats::prom_type("active_calls"), "gauge");
        assert_eq!(Stats::prom_type("pending_refers"), "gauge");
    }

    #[test]
    fn test_stats_help_text() {
        assert_eq!(
            Stats::help_text("rust_http_webhook", "sent"),
            "rust_http_webhook sent"
        );
        assert_eq!(
            Stats::help_text("rust_acl", "entries_blocklist"),
            "rust_acl entries blocklist"
        );
    }

    #[test]
    fn test_stats_to_prometheus_format_compliance() {
        // Verify each line ends with \n, and the overall format
        // matches Prometheus text exposition spec
        let s = Stats::new("test_mod", &["requests", "entries_total"]);
        s.set("requests", 42);
        s.set("entries_total", 7);
        let prom = s.to_prometheus();
        // Each metric block is 3 lines: HELP, TYPE, value
        let lines: Vec<&str> = prom.split('\n').filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 6); // 2 metrics x 3 lines each
        assert!(lines[0].starts_with("# HELP "));
        assert!(lines[1].starts_with("# TYPE "));
        // Value line should be "metric_name value"
        assert!(lines[2].starts_with("test_mod_requests "));
        assert!(lines[3].starts_with("# HELP "));
        assert!(lines[4].starts_with("# TYPE "));
        assert!(lines[5].starts_with("test_mod_entries_total "));
    }
}
