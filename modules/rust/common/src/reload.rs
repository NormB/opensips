//! File loader with atomic hot reload.
//!
//! Loads a file into a per-worker data structure at startup.
//! MI reload swaps the entire data structure atomically.

use std::cell::RefCell;
use std::path::PathBuf;

/// Generic file-backed data loader.
/// T is the data structure (HashSet, HashMap, Vec, etc.).
/// Parser converts each line to an optional entry.
pub struct FileLoader<T> {
    path: PathBuf,
    data: RefCell<T>,
    parse_line: fn(&str) -> Option<String>,
    build: fn(Vec<String>) -> T,
    reload_count: std::cell::Cell<u64>,
}

impl<T> FileLoader<T> {
    /// Create a new FileLoader.
    /// path: file to load.
    /// parse_line: parse one line, return None to skip (comments, blanks).
    /// build: convert parsed entries into the target data structure.
    pub fn new(
        path: &str,
        parse_line: fn(&str) -> Option<String>,
        build: fn(Vec<String>) -> T,
    ) -> Result<Self, String> {
        let entries = Self::read_file(path, parse_line)?;
        let data = build(entries);
        Ok(FileLoader {
            path: PathBuf::from(path),
            data: RefCell::new(data),
            parse_line,
            build,
            reload_count: std::cell::Cell::new(0),
        })
    }

    /// Access the current data (borrow).
    pub fn get(&self) -> std::cell::Ref<'_, T> {
        self.data.borrow()
    }

    /// Reload from file. Atomic swap -- readers see old or new, never partial.
    pub fn reload(&self) -> Result<usize, String> {
        let entries = Self::read_file(self.path.to_str().unwrap_or(""), self.parse_line)?;
        let count = entries.len();
        let new_data = (self.build)(entries);
        *self.data.borrow_mut() = new_data;
        self.reload_count.set(self.reload_count.get() + 1);
        Ok(count)
    }

    pub fn reload_count(&self) -> u64 {
        self.reload_count.get()
    }

    fn read_file(path: &str, parse_line: fn(&str) -> Option<String>) -> Result<Vec<String>, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {}", path, e))?;
        let entries: Vec<String> = content
            .lines()
            .filter_map(parse_line)
            .collect();
        Ok(entries)
    }
}

/// Default line parser: trims whitespace, skips empty lines and # comments.
pub fn default_line_parser(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// CSV line parser: returns "key,value" pairs, skips comments.
pub fn csv_line_parser(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        None
    } else if trimmed.contains(',') {
        Some(trimmed.to_string())
    } else {
        None // skip malformed lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::io::Write;

    fn temp_file(name: &str, content: &str) -> String {
        let path = format!("{}/rust_common_test_{}", std::env::temp_dir().display(), name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
    }

    fn build_vec(entries: Vec<String>) -> Vec<String> {
        entries
    }

    fn build_hashset(entries: Vec<String>) -> HashSet<String> {
        entries.into_iter().collect()
    }

    #[test]
    fn test_file_loader_basic() {
        let path = temp_file("basic", "alpha\nbeta\ngamma\n");
        let loader = FileLoader::new(&path, default_line_parser, build_vec).unwrap();
        let data = loader.get();
        assert_eq!(data.len(), 3);
        assert_eq!(data[0], "alpha");
        assert_eq!(data[1], "beta");
        assert_eq!(data[2], "gamma");
        drop(data);
        cleanup(&path);
    }

    #[test]
    fn test_file_loader_comments() {
        let content = "# comment\nalpha\n\n# another comment\nbeta\n   \ngamma\n";
        let path = temp_file("comments", content);
        let loader = FileLoader::new(&path, default_line_parser, build_vec).unwrap();
        let data = loader.get();
        assert_eq!(data.len(), 3);
        assert_eq!(data[0], "alpha");
        assert_eq!(data[1], "beta");
        assert_eq!(data[2], "gamma");
        drop(data);
        cleanup(&path);
    }

    #[test]
    fn test_file_loader_reload() {
        let path = temp_file("reload", "one\ntwo\n");
        let loader = FileLoader::new(&path, default_line_parser, build_vec).unwrap();
        assert_eq!(loader.get().len(), 2);
        assert_eq!(loader.reload_count(), 0);

        // Overwrite file with new content
        std::fs::write(&path, "one\ntwo\nthree\nfour\n").unwrap();
        let count = loader.reload().unwrap();
        assert_eq!(count, 4);
        assert_eq!(loader.get().len(), 4);
        assert_eq!(loader.reload_count(), 1);
        cleanup(&path);
    }

    #[test]
    fn test_file_loader_missing_file() {
        let result = FileLoader::new("/tmp/rust_common_test_DOES_NOT_EXIST", default_line_parser, build_vec);
        assert!(result.is_err());
    }

    #[test]
    fn test_file_loader_empty_file() {
        let path = temp_file("empty", "");
        let loader = FileLoader::new(&path, default_line_parser, build_vec).unwrap();
        assert_eq!(loader.get().len(), 0);
        cleanup(&path);
    }

    #[test]
    fn test_csv_line_parser() {
        assert_eq!(csv_line_parser("key,value"), Some("key,value".to_string()));
        assert_eq!(csv_line_parser("# comment"), None);
        assert_eq!(csv_line_parser(""), None);
        assert_eq!(csv_line_parser("no_comma"), None);
        assert_eq!(csv_line_parser("  a,b  "), Some("a,b".to_string()));
    }

    #[test]
    fn test_default_line_parser() {
        assert_eq!(default_line_parser("hello"), Some("hello".to_string()));
        assert_eq!(default_line_parser("  hello  "), Some("hello".to_string()));
        assert_eq!(default_line_parser("# comment"), None);
        assert_eq!(default_line_parser(""), None);
        assert_eq!(default_line_parser("   "), None);
    }

    #[test]
    fn test_file_loader_as_hashset() {
        let path = temp_file("hashset", "apple\nbanana\ncherry\n");
        let loader = FileLoader::new(&path, default_line_parser, build_hashset).unwrap();
        let data = loader.get();
        assert!(data.contains("apple"));
        assert!(data.contains("banana"));
        assert!(data.contains("cherry"));
        assert!(!data.contains("durian"));
        drop(data);
        cleanup(&path);
    }

    #[test]
    fn test_file_loader_reload_count() {
        let path = temp_file("rcount", "a\n");
        let loader = FileLoader::new(&path, default_line_parser, build_vec).unwrap();
        assert_eq!(loader.reload_count(), 0);
        loader.reload().unwrap();
        assert_eq!(loader.reload_count(), 1);
        loader.reload().unwrap();
        assert_eq!(loader.reload_count(), 2);
        cleanup(&path);
    }

    #[test]
    fn test_file_loader_whitespace_trimming() {
        let path = temp_file("trim", "  spaced  \n\ttabbed\t\n");
        let loader = FileLoader::new(&path, default_line_parser, build_vec).unwrap();
        let data = loader.get();
        assert_eq!(data[0], "spaced");
        assert_eq!(data[1], "tabbed");
        drop(data);
        cleanup(&path);
    }
}
