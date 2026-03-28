//! CIDR (Classless Inter-Domain Routing) parsing and matching.
//!
//! Supports both IPv4 and IPv6 CIDR notation (e.g. `10.0.0.0/24`,
//! `2001:db8::/32`).  No external crate dependency -- parsing is manual.

use std::net::IpAddr;

/// A parsed CIDR range: base address + prefix length.
#[derive(Debug, Clone)]
pub struct CidrRange {
    addr: IpAddr,
    prefix_len: u8,
    /// Precomputed masked address for fast comparison.
    masked: MaskedAddr,
}

#[derive(Debug, Clone)]
enum MaskedAddr {
    V4(u32),
    V6(u128),
}

impl CidrRange {
    /// Parse a CIDR string like `10.0.0.0/24` or `2001:db8::/32`.
    ///
    /// Returns `None` if the format is invalid.
    pub fn parse(s: &str) -> Option<Self> {
        let (addr_str, prefix_str) = s.rsplit_once('/')?;
        let prefix_len: u8 = prefix_str.parse().ok()?;
        let addr: IpAddr = addr_str.parse().ok()?;

        match addr {
            IpAddr::V4(v4) => {
                if prefix_len > 32 {
                    return None;
                }
                let bits = u32::from(v4);
                let mask = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
                Some(CidrRange {
                    addr,
                    prefix_len,
                    masked: MaskedAddr::V4(bits & mask),
                })
            }
            IpAddr::V6(v6) => {
                if prefix_len > 128 {
                    return None;
                }
                let bits = u128::from(v6);
                let mask = if prefix_len == 0 { 0 } else { !0u128 << (128 - prefix_len) };
                Some(CidrRange {
                    addr,
                    prefix_len,
                    masked: MaskedAddr::V6(bits & mask),
                })
            }
        }
    }

    /// Check whether the given IP address string falls within this CIDR range.
    pub fn contains_str(&self, ip_str: &str) -> bool {
        match ip_str.parse::<IpAddr>() {
            Ok(ip) => self.contains(&ip),
            Err(_) => false,
        }
    }

    /// Check whether the given `IpAddr` falls within this CIDR range.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (&self.masked, ip) {
            (MaskedAddr::V4(net), IpAddr::V4(v4)) => {
                let mask = if self.prefix_len == 0 { 0 } else { !0u32 << (32 - self.prefix_len) };
                (u32::from(*v4) & mask) == *net
            }
            (MaskedAddr::V6(net), IpAddr::V6(v6)) => {
                let mask = if self.prefix_len == 0 { 0 } else { !0u128 << (128 - self.prefix_len) };
                (u128::from(*v6) & mask) == *net
            }
            _ => false, // v4 vs v6 mismatch
        }
    }

    /// Return the prefix length.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Return the base address.
    pub fn addr(&self) -> &IpAddr {
        &self.addr
    }
}

impl std::fmt::Display for CidrRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Parsing tests ────────────────────────────────────────────

    #[test]
    fn test_parse_ipv4_cidr() {
        let cidr = CidrRange::parse("10.0.0.0/24").unwrap();
        assert_eq!(cidr.prefix_len(), 24);
        assert_eq!(cidr.to_string(), "10.0.0.0/24");
    }

    #[test]
    fn test_parse_ipv4_host() {
        let cidr = CidrRange::parse("192.168.1.1/32").unwrap();
        assert_eq!(cidr.prefix_len(), 32);
    }

    #[test]
    fn test_parse_ipv4_zero() {
        let cidr = CidrRange::parse("0.0.0.0/0").unwrap();
        assert_eq!(cidr.prefix_len(), 0);
    }

    #[test]
    fn test_parse_ipv6_cidr() {
        let cidr = CidrRange::parse("2001:db8::/32").unwrap();
        assert_eq!(cidr.prefix_len(), 32);
    }

    #[test]
    fn test_parse_ipv6_host() {
        let cidr = CidrRange::parse("::1/128").unwrap();
        assert_eq!(cidr.prefix_len(), 128);
    }

    #[test]
    fn test_parse_invalid_no_slash() {
        assert!(CidrRange::parse("10.0.0.0").is_none());
    }

    #[test]
    fn test_parse_invalid_prefix_too_large_v4() {
        assert!(CidrRange::parse("10.0.0.0/33").is_none());
    }

    #[test]
    fn test_parse_invalid_prefix_too_large_v6() {
        assert!(CidrRange::parse("::1/129").is_none());
    }

    #[test]
    fn test_parse_invalid_prefix_not_number() {
        assert!(CidrRange::parse("10.0.0.0/abc").is_none());
    }

    #[test]
    fn test_parse_invalid_addr() {
        assert!(CidrRange::parse("not.an.ip/24").is_none());
    }

    // ── IPv4 matching tests ──────────────────────────────────────

    #[test]
    fn test_ipv4_24_contains() {
        let cidr = CidrRange::parse("10.0.0.0/24").unwrap();
        assert!(cidr.contains_str("10.0.0.1"));
        assert!(cidr.contains_str("10.0.0.254"));
        assert!(cidr.contains_str("10.0.0.0"));
        assert!(cidr.contains_str("10.0.0.255"));
        assert!(!cidr.contains_str("10.0.1.0"));
        assert!(!cidr.contains_str("10.0.1.1"));
        assert!(!cidr.contains_str("192.168.0.1"));
    }

    #[test]
    fn test_ipv4_16_contains() {
        let cidr = CidrRange::parse("192.168.0.0/16").unwrap();
        assert!(cidr.contains_str("192.168.0.1"));
        assert!(cidr.contains_str("192.168.255.255"));
        assert!(!cidr.contains_str("192.169.0.1"));
        assert!(!cidr.contains_str("10.0.0.1"));
    }

    #[test]
    fn test_ipv4_32_host() {
        let cidr = CidrRange::parse("192.168.1.100/32").unwrap();
        assert!(cidr.contains_str("192.168.1.100"));
        assert!(!cidr.contains_str("192.168.1.101"));
        assert!(!cidr.contains_str("192.168.1.99"));
    }

    #[test]
    fn test_ipv4_0_matches_all() {
        let cidr = CidrRange::parse("0.0.0.0/0").unwrap();
        assert!(cidr.contains_str("10.0.0.1"));
        assert!(cidr.contains_str("192.168.1.1"));
        assert!(cidr.contains_str("255.255.255.255"));
        assert!(cidr.contains_str("0.0.0.0"));
    }

    #[test]
    fn test_ipv4_8_class_a() {
        let cidr = CidrRange::parse("10.0.0.0/8").unwrap();
        assert!(cidr.contains_str("10.255.255.255"));
        assert!(cidr.contains_str("10.0.0.1"));
        assert!(!cidr.contains_str("11.0.0.1"));
    }

    #[test]
    fn test_ipv4_boundary_25() {
        // /25 splits a /24 in half: 0-127 and 128-255
        let cidr = CidrRange::parse("10.0.0.0/25").unwrap();
        assert!(cidr.contains_str("10.0.0.0"));
        assert!(cidr.contains_str("10.0.0.127"));
        assert!(!cidr.contains_str("10.0.0.128"));
        assert!(!cidr.contains_str("10.0.0.255"));
    }

    #[test]
    fn test_ipv4_boundary_upper_half() {
        let cidr = CidrRange::parse("10.0.0.128/25").unwrap();
        assert!(!cidr.contains_str("10.0.0.0"));
        assert!(!cidr.contains_str("10.0.0.127"));
        assert!(cidr.contains_str("10.0.0.128"));
        assert!(cidr.contains_str("10.0.0.255"));
    }

    // ── IPv6 matching tests ──────────────────────────────────────

    #[test]
    fn test_ipv6_64_contains() {
        let cidr = CidrRange::parse("2001:db8::/32").unwrap();
        assert!(cidr.contains_str("2001:db8::1"));
        assert!(cidr.contains_str("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"));
        assert!(!cidr.contains_str("2001:db9::1"));
    }

    #[test]
    fn test_ipv6_128_host() {
        let cidr = CidrRange::parse("::1/128").unwrap();
        assert!(cidr.contains_str("::1"));
        assert!(!cidr.contains_str("::2"));
    }

    #[test]
    fn test_ipv6_0_matches_all() {
        let cidr = CidrRange::parse("::/0").unwrap();
        assert!(cidr.contains_str("::1"));
        assert!(cidr.contains_str("2001:db8::1"));
        assert!(cidr.contains_str("fe80::1"));
    }

    // ── Cross-family tests ───────────────────────────────────────

    #[test]
    fn test_v4_cidr_does_not_match_v6() {
        let cidr = CidrRange::parse("10.0.0.0/24").unwrap();
        assert!(!cidr.contains_str("::ffff:10.0.0.1")); // v4-mapped v6
        assert!(!cidr.contains_str("2001:db8::1"));
    }

    #[test]
    fn test_v6_cidr_does_not_match_v4() {
        let cidr = CidrRange::parse("2001:db8::/32").unwrap();
        assert!(!cidr.contains_str("10.0.0.1"));
    }

    // ── Invalid input handling ───────────────────────────────────

    #[test]
    fn test_contains_str_invalid_ip() {
        let cidr = CidrRange::parse("10.0.0.0/24").unwrap();
        assert!(!cidr.contains_str("not-an-ip"));
        assert!(!cidr.contains_str(""));
        assert!(!cidr.contains_str("10.0.0"));
    }

    #[test]
    fn test_non_aligned_network() {
        // 10.0.0.5/24 -- the host bits are masked off
        let cidr = CidrRange::parse("10.0.0.5/24").unwrap();
        assert!(cidr.contains_str("10.0.0.1"));
        assert!(cidr.contains_str("10.0.0.5"));
        assert!(cidr.contains_str("10.0.0.255"));
    }
}
