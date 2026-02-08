//! IP address utility functions for filtering and validation
//!
//! This module provides utilities for classifying IP addresses,
//! particularly for filtering out private/reserved addresses that
//! should not be queried against public internet databases like Shodan.
//!
//! # Example
//!
//! ```
//! use smap_core::ip_utils::is_global_ip;
//! use std::net::IpAddr;
//!
//! let public_ip: IpAddr = "8.8.8.8".parse().unwrap();
//! assert!(is_global_ip(&public_ip));
//!
//! let private_ip: IpAddr = "192.168.1.1".parse().unwrap();
//! assert!(!is_global_ip(&private_ip));
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Checks if an IP address is globally routable (public internet IP)
///
/// Returns `true` if the IP address is routable on the public internet,
/// `false` if it's a private, reserved, loopback, or other non-routable address.
///
/// This filters out:
/// - RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
/// - Loopback addresses (127.0.0.0/8 for IPv4, ::1 for IPv6)
/// - Link-local addresses (169.254.0.0/16 for IPv4, fe80::/10 for IPv6)
/// - Multicast addresses (224.0.0.0/4 for IPv4, ff00::/8 for IPv6)
/// - Documentation/TEST-NET ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
/// - Broadcast address (255.255.255.255)
/// - Unspecified address (0.0.0.0, ::)
/// - Other reserved ranges
///
/// # Arguments
///
/// * `ip` - The IP address to check
///
/// # Returns
///
/// `true` if the IP is globally routable, `false` otherwise
///
/// # Examples
///
/// ```
/// use smap_core::ip_utils::is_global_ip;
/// use std::net::IpAddr;
///
/// // Public IPs
/// assert!(is_global_ip(&"8.8.8.8".parse().unwrap()));
/// assert!(is_global_ip(&"1.1.1.1".parse().unwrap()));
/// assert!(is_global_ip(&"2606:4700:4700::1111".parse().unwrap()));
///
/// // Private IPs
/// assert!(!is_global_ip(&"192.168.1.1".parse().unwrap()));
/// assert!(!is_global_ip(&"10.0.0.1".parse().unwrap()));
/// assert!(!is_global_ip(&"172.16.0.1".parse().unwrap()));
///
/// // Loopback
/// assert!(!is_global_ip(&"127.0.0.1".parse().unwrap()));
/// assert!(!is_global_ip(&"::1".parse().unwrap()));
///
/// // Link-local
/// assert!(!is_global_ip(&"169.254.1.1".parse().unwrap()));
/// assert!(!is_global_ip(&"fe80::1".parse().unwrap()));
/// ```
pub fn is_global_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_global_ipv4(ipv4),
        IpAddr::V6(ipv6) => is_global_ipv6(ipv6),
    }
}

/// Checks if an IPv4 address is globally routable
fn is_global_ipv4(ip: &Ipv4Addr) -> bool {
    // Use Rust's built-in methods where available
    if ip.is_private() {
        return false; // RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    }
    if ip.is_loopback() {
        return false; // 127.0.0.0/8
    }
    if ip.is_link_local() {
        return false; // 169.254.0.0/16
    }
    if ip.is_multicast() {
        return false; // 224.0.0.0/4
    }
    if ip.is_broadcast() {
        return false; // 255.255.255.255
    }
    if ip.is_unspecified() {
        return false; // 0.0.0.0
    }
    if ip.is_documentation() {
        return false; // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
    }

    // Check for additional reserved ranges not covered by standard library
    let octets = ip.octets();

    // Shared Address Space (RFC 6598): 100.64.0.0/10
    if octets[0] == 100 && (octets[1] & 0b1100_0000) == 64 {
        return false;
    }

    // IETF Protocol Assignments (RFC 6890): 192.0.0.0/24
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return false;
    }

    // Benchmarking (RFC 2544): 198.18.0.0/15
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return false;
    }

    // Reserved (RFC 1112, Section 4): 240.0.0.0/4
    if octets[0] >= 240 && octets[0] < 255 {
        return false;
    }

    // Limited Broadcast: 255.255.255.255 (already handled by is_broadcast)

    true
}

/// Checks if an IPv6 address is globally routable
fn is_global_ipv6(ip: &Ipv6Addr) -> bool {
    // Use Rust's built-in methods where available
    if ip.is_loopback() {
        return false; // ::1
    }
    if ip.is_unspecified() {
        return false; // ::
    }
    if ip.is_multicast() {
        return false; // ff00::/8
    }

    let segments = ip.segments();

    // Unique Local Addresses (RFC 4193): fc00::/7
    if (segments[0] & 0xfe00) == 0xfc00 {
        return false;
    }

    // Link-Local Unicast (RFC 4291): fe80::/10
    if (segments[0] & 0xffc0) == 0xfe80 {
        return false;
    }

    // Documentation (RFC 3849): 2001:db8::/32
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return false;
    }

    // IPv4-mapped IPv6 addresses: ::ffff:0:0/96
    // Check if the underlying IPv4 is global
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_global_ipv4(&ipv4);
    }

    // Discard Prefix (RFC 6666): 100::/64
    if segments[0] == 0x0100 && segments[1..].iter().all(|&s| s == 0) {
        return false;
    }

    // TEREDO (RFC 4380): 2001::/32
    // Note: Some TEREDO addresses might be global, but they're tunneled
    // For our purposes, we exclude them to be conservative
    if segments[0] == 0x2001 && segments[1] == 0x0000 {
        return false;
    }

    true
}

/// Classifies the type of IP address for debugging/logging purposes
///
/// Returns a string describing the IP address type (e.g., "private", "loopback", "global")
///
/// # Arguments
///
/// * `ip` - The IP address to classify
///
/// # Returns
///
/// A string describing the IP address type
///
/// # Examples
///
/// ```
/// use smap_core::ip_utils::classify_ip;
/// use std::net::IpAddr;
///
/// assert_eq!(classify_ip(&"192.168.1.1".parse().unwrap()), "private (RFC 1918)");
/// assert_eq!(classify_ip(&"127.0.0.1".parse().unwrap()), "loopback");
/// assert_eq!(classify_ip(&"8.8.8.8".parse().unwrap()), "global");
/// ```
pub fn classify_ip(ip: &IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(ipv4) => classify_ipv4(ipv4),
        IpAddr::V6(ipv6) => classify_ipv6(ipv6),
    }
}

/// Classifies an IPv4 address type
fn classify_ipv4(ip: &Ipv4Addr) -> &'static str {
    if ip.is_private() {
        return "private (RFC 1918)";
    }
    if ip.is_loopback() {
        return "loopback";
    }
    if ip.is_link_local() {
        return "link-local";
    }
    if ip.is_multicast() {
        return "multicast";
    }
    if ip.is_broadcast() {
        return "broadcast";
    }
    if ip.is_unspecified() {
        return "unspecified";
    }
    if ip.is_documentation() {
        return "documentation/TEST-NET";
    }

    let octets = ip.octets();

    // Shared Address Space (RFC 6598): 100.64.0.0/10
    if octets[0] == 100 && (octets[1] & 0b1100_0000) == 64 {
        return "shared address space (RFC 6598)";
    }

    // IETF Protocol Assignments: 192.0.0.0/24
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return "IETF protocol assignments";
    }

    // Benchmarking: 198.18.0.0/15
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return "benchmarking (RFC 2544)";
    }

    // Reserved: 240.0.0.0/4
    if octets[0] >= 240 && octets[0] < 255 {
        return "reserved";
    }

    "global"
}

/// Classifies an IPv6 address type
fn classify_ipv6(ip: &Ipv6Addr) -> &'static str {
    if ip.is_loopback() {
        return "loopback";
    }
    if ip.is_unspecified() {
        return "unspecified";
    }
    if ip.is_multicast() {
        return "multicast";
    }

    let segments = ip.segments();

    // Unique Local Addresses: fc00::/7
    if (segments[0] & 0xfe00) == 0xfc00 {
        return "unique local (RFC 4193)";
    }

    // Link-Local: fe80::/10
    if (segments[0] & 0xffc0) == 0xfe80 {
        return "link-local";
    }

    // Documentation: 2001:db8::/32
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return "documentation (RFC 3849)";
    }

    // IPv4-mapped
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        let ipv4_type = classify_ipv4(&ipv4);
        if ipv4_type == "global" {
            return "IPv4-mapped";
        } else {
            return "IPv4-mapped (non-global)";
        }
    }

    // Discard Prefix: 100::/64
    if segments[0] == 0x0100 && segments[1..].iter().all(|&s| s == 0) {
        return "discard prefix (RFC 6666)";
    }

    // TEREDO: 2001::/32
    if segments[0] == 0x2001 && segments[1] == 0x0000 {
        return "TEREDO (RFC 4380)";
    }

    "global"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_global_ipv4_public() {
        // Well-known public DNS servers
        assert!(is_global_ip(&"8.8.8.8".parse::<IpAddr>().unwrap()));
        assert!(is_global_ip(&"1.1.1.1".parse::<IpAddr>().unwrap()));
        assert!(is_global_ip(&"208.67.222.222".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_global_ipv4_private_rfc1918() {
        // RFC 1918 private ranges
        assert!(!is_global_ip(&"10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(!is_global_ip(&"10.255.255.255".parse::<IpAddr>().unwrap()));
        assert!(!is_global_ip(&"172.16.0.1".parse::<IpAddr>().unwrap()));
        assert!(!is_global_ip(&"172.31.255.255".parse::<IpAddr>().unwrap()));
        assert!(!is_global_ip(&"192.168.0.1".parse::<IpAddr>().unwrap()));
        assert!(!is_global_ip(&"192.168.255.255".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_global_ipv4_loopback() {
        assert!(!is_global_ip(&"127.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(!is_global_ip(&"127.0.0.255".parse::<IpAddr>().unwrap()));
        assert!(!is_global_ip(&"127.255.255.255".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_global_ipv4_link_local() {
        assert!(!is_global_ip(&"169.254.0.1".parse::<IpAddr>().unwrap()));
        assert!(!is_global_ip(&"169.254.255.255".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_global_ipv4_multicast() {
        assert!(!is_global_ip(&"224.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(!is_global_ip(&"239.255.255.255".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_global_ipv4_broadcast() {
        assert!(!is_global_ip(&"255.255.255.255".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_global_ipv4_documentation() {
        // TEST-NET-1: 192.0.2.0/24
        assert!(!is_global_ip(&"192.0.2.1".parse::<IpAddr>().unwrap()));
        assert!(!is_global_ip(&"192.0.2.255".parse::<IpAddr>().unwrap()));

        // TEST-NET-2: 198.51.100.0/24
        assert!(!is_global_ip(&"198.51.100.1".parse::<IpAddr>().unwrap()));
        assert!(!is_global_ip(&"198.51.100.255".parse::<IpAddr>().unwrap()));

        // TEST-NET-3: 203.0.113.0/24
        assert!(!is_global_ip(&"203.0.113.1".parse::<IpAddr>().unwrap()));
        assert!(!is_global_ip(&"203.0.113.255".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_global_ipv4_unspecified() {
        assert!(!is_global_ip(&"0.0.0.0".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_global_ipv4_shared_address_space() {
        // RFC 6598: 100.64.0.0/10
        assert!(!is_global_ip(&"100.64.0.1".parse::<IpAddr>().unwrap()));
        assert!(!is_global_ip(&"100.127.255.255".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_global_ipv4_benchmarking() {
        // RFC 2544: 198.18.0.0/15
        assert!(!is_global_ip(&"198.18.0.1".parse::<IpAddr>().unwrap()));
        assert!(!is_global_ip(&"198.19.255.255".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_global_ipv4_reserved() {
        // Reserved: 240.0.0.0/4
        assert!(!is_global_ip(&"240.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(!is_global_ip(&"254.255.255.255".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_global_ipv6_public() {
        // Cloudflare DNS
        assert!(is_global_ip(
            &"2606:4700:4700::1111".parse::<IpAddr>().unwrap()
        ));
        // Google DNS
        assert!(is_global_ip(
            &"2001:4860:4860::8888".parse::<IpAddr>().unwrap()
        ));
    }

    #[test]
    fn test_global_ipv6_loopback() {
        assert!(!is_global_ip(&"::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_global_ipv6_unspecified() {
        assert!(!is_global_ip(&"::".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_global_ipv6_unique_local() {
        // RFC 4193: fc00::/7
        assert!(!is_global_ip(&"fc00::1".parse::<IpAddr>().unwrap()));
        assert!(!is_global_ip(&"fd00::1".parse::<IpAddr>().unwrap()));
        assert!(!is_global_ip(
            &"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
                .parse::<IpAddr>()
                .unwrap()
        ));
    }

    #[test]
    fn test_global_ipv6_link_local() {
        // RFC 4291: fe80::/10
        assert!(!is_global_ip(&"fe80::1".parse::<IpAddr>().unwrap()));
        assert!(!is_global_ip(&"fe80::dead:beef".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_global_ipv6_multicast() {
        // ff00::/8
        assert!(!is_global_ip(&"ff00::1".parse::<IpAddr>().unwrap()));
        assert!(!is_global_ip(&"ff02::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_global_ipv6_documentation() {
        // RFC 3849: 2001:db8::/32
        assert!(!is_global_ip(&"2001:db8::1".parse::<IpAddr>().unwrap()));
        assert!(!is_global_ip(
            &"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"
                .parse::<IpAddr>()
                .unwrap()
        ));
    }

    #[test]
    fn test_classify_ip_ipv4() {
        assert_eq!(classify_ip(&"8.8.8.8".parse().unwrap()), "global");
        assert_eq!(
            classify_ip(&"192.168.1.1".parse().unwrap()),
            "private (RFC 1918)"
        );
        assert_eq!(classify_ip(&"127.0.0.1".parse().unwrap()), "loopback");
        assert_eq!(classify_ip(&"169.254.1.1".parse().unwrap()), "link-local");
        assert_eq!(classify_ip(&"224.0.0.1".parse().unwrap()), "multicast");
        assert_eq!(
            classify_ip(&"255.255.255.255".parse().unwrap()),
            "broadcast"
        );
        assert_eq!(
            classify_ip(&"192.0.2.1".parse().unwrap()),
            "documentation/TEST-NET"
        );
        assert_eq!(
            classify_ip(&"100.64.0.1".parse().unwrap()),
            "shared address space (RFC 6598)"
        );
        assert_eq!(
            classify_ip(&"198.18.0.1".parse().unwrap()),
            "benchmarking (RFC 2544)"
        );
        assert_eq!(classify_ip(&"240.0.0.1".parse().unwrap()), "reserved");
    }

    #[test]
    fn test_classify_ip_ipv6() {
        assert_eq!(
            classify_ip(&"2606:4700:4700::1111".parse().unwrap()),
            "global"
        );
        assert_eq!(classify_ip(&"::1".parse().unwrap()), "loopback");
        assert_eq!(
            classify_ip(&"fc00::1".parse().unwrap()),
            "unique local (RFC 4193)"
        );
        assert_eq!(classify_ip(&"fe80::1".parse().unwrap()), "link-local");
        assert_eq!(classify_ip(&"ff00::1".parse().unwrap()), "multicast");
        assert_eq!(
            classify_ip(&"2001:db8::1".parse().unwrap()),
            "documentation (RFC 3849)"
        );
    }

    #[test]
    fn test_edge_cases() {
        // Edge of private ranges
        assert!(!is_global_ip(&"10.0.0.0".parse::<IpAddr>().unwrap()));
        assert!(is_global_ip(&"11.0.0.0".parse::<IpAddr>().unwrap()));

        assert!(!is_global_ip(&"172.16.0.0".parse::<IpAddr>().unwrap()));
        assert!(is_global_ip(&"172.15.255.255".parse::<IpAddr>().unwrap()));
        assert!(is_global_ip(&"172.32.0.0".parse::<IpAddr>().unwrap()));

        assert!(!is_global_ip(&"192.168.0.0".parse::<IpAddr>().unwrap()));
        assert!(is_global_ip(&"192.167.255.255".parse::<IpAddr>().unwrap()));
        assert!(is_global_ip(&"192.169.0.0".parse::<IpAddr>().unwrap()));
    }
}
