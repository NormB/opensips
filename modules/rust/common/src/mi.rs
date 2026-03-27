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
}
