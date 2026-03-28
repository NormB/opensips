//! Glob pattern matching for ACL and REFER target validation.
//!
//! Supports `*` (match zero or more characters) and `?` (match exactly one
//! character).  Matching is case-insensitive.

/// Check whether `text` matches the glob `pattern`.
///
/// Both strings are lowercased before comparison so matching is
/// case-insensitive.  `*` matches any sequence of characters (including
/// empty), and `?` matches exactly one character.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let text = text.to_ascii_lowercase();
    glob_match_inner(pattern.as_bytes(), text.as_bytes())
}

fn glob_match_inner(pattern: &[u8], text: &[u8]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    let mut star_pi = usize::MAX;
    let mut star_ti = 0;

    while ti < text.len() {
        if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if pi < pattern.len() && (pattern[pi] == text[ti] || pattern[pi] == b'?') {
            pi += 1;
            ti += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }

    pi == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_exact() {
        assert!(glob_match("hello", "hello"));
        assert!(!glob_match("hello", "world"));
    }

    #[test]
    fn test_glob_star() {
        assert!(glob_match("*.example.com", "foo.example.com"));
        assert!(glob_match("*.example.com", "bar.baz.example.com"));
        assert!(!glob_match("*.example.com", "example.com"));
        assert!(!glob_match("*.example.com", "foo.other.com"));
    }

    #[test]
    fn test_glob_question() {
        assert!(glob_match("10.0.0.?", "10.0.0.1"));
        assert!(glob_match("10.0.0.?", "10.0.0.9"));
        assert!(!glob_match("10.0.0.?", "10.0.0.10"));
    }

    #[test]
    fn test_glob_star_middle() {
        assert!(glob_match("192.168.*", "192.168.1.1"));
        assert!(glob_match("192.168.*", "192.168.255.255"));
        assert!(!glob_match("192.168.*", "192.169.0.1"));
    }

    #[test]
    fn test_glob_case_insensitive() {
        assert!(glob_match("*.EXAMPLE.COM", "foo.example.com"));
        assert!(glob_match("SIP:*@EXAMPLE.COM", "sip:bob@example.com"));
    }

    #[test]
    fn test_glob_star_matches_empty() {
        assert!(glob_match("*", ""));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("pre*", "pre"));
    }

    #[test]
    fn test_glob_multiple_stars() {
        assert!(glob_match("*foo*bar*", "xxxfooyyybarzzz"));
        assert!(!glob_match("*foo*bar*", "xxxfoozzz"));
    }

    #[test]
    fn test_glob_ip_patterns() {
        assert!(glob_match("10.0.0.*", "10.0.0.1"));
        assert!(glob_match("10.0.0.*", "10.0.0.255"));
        assert!(!glob_match("10.0.0.*", "10.0.1.1"));
        assert!(glob_match("192.168.?.1", "192.168.1.1"));
        assert!(glob_match("192.168.?.1", "192.168.2.1"));
        assert!(!glob_match("192.168.?.1", "192.168.10.1"));
    }

    #[test]
    fn test_glob_empty_pattern() {
        assert!(glob_match("", ""));
        assert!(!glob_match("", "nonempty"));
    }

    #[test]
    fn test_glob_only_stars() {
        assert!(glob_match("***", "anything"));
        assert!(glob_match("***", ""));
    }
}
