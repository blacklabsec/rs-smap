//! Integration tests for IP filtering functionality

use smap_core::ip_utils::{classify_ip, is_global_ip};
use std::net::IpAddr;

#[test]
fn test_filter_private_ipv4_networks() {
    // Test RFC 1918 private networks
    let private_ips = vec![
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.255.255",
    ];

    for ip_str in private_ips {
        let ip: IpAddr = ip_str.parse().unwrap();
        assert!(
            !is_global_ip(&ip),
            "{} should be filtered as private",
            ip_str
        );
        assert_eq!(classify_ip(&ip), "private (RFC 1918)");
    }
}

#[test]
fn test_filter_loopback_addresses() {
    let loopback_ips = vec!["127.0.0.1", "127.0.0.255", "::1"];

    for ip_str in loopback_ips {
        let ip: IpAddr = ip_str.parse().unwrap();
        assert!(
            !is_global_ip(&ip),
            "{} should be filtered as loopback",
            ip_str
        );
        assert_eq!(classify_ip(&ip), "loopback");
    }
}

#[test]
fn test_filter_link_local_addresses() {
    let link_local_ips = vec!["169.254.1.1", "169.254.255.255", "fe80::1"];

    for ip_str in link_local_ips {
        let ip: IpAddr = ip_str.parse().unwrap();
        assert!(
            !is_global_ip(&ip),
            "{} should be filtered as link-local",
            ip_str
        );
        assert_eq!(classify_ip(&ip), "link-local");
    }
}

#[test]
fn test_filter_multicast_addresses() {
    let multicast_ips = vec!["224.0.0.1", "239.255.255.255", "ff00::1", "ff02::1"];

    for ip_str in multicast_ips {
        let ip: IpAddr = ip_str.parse().unwrap();
        assert!(
            !is_global_ip(&ip),
            "{} should be filtered as multicast",
            ip_str
        );
        assert_eq!(classify_ip(&ip), "multicast");
    }
}

#[test]
fn test_filter_documentation_addresses() {
    let doc_ips = vec![
        "192.0.2.1",    // TEST-NET-1
        "198.51.100.1", // TEST-NET-2
        "203.0.113.1",  // TEST-NET-3
        "2001:db8::1",  // IPv6 documentation
    ];

    for ip_str in doc_ips {
        let ip: IpAddr = ip_str.parse().unwrap();
        assert!(
            !is_global_ip(&ip),
            "{} should be filtered as documentation",
            ip_str
        );
        let classification = classify_ip(&ip);
        assert!(
            classification.contains("documentation"),
            "{} should be classified as documentation, got: {}",
            ip_str,
            classification
        );
    }
}

#[test]
fn test_filter_special_addresses() {
    let special_ips = vec![
        ("0.0.0.0", "unspecified"),
        ("255.255.255.255", "broadcast"),
        ("100.64.0.1", "shared address space (RFC 6598)"),
        ("198.18.0.1", "benchmarking (RFC 2544)"),
        ("240.0.0.1", "reserved"),
    ];

    for (ip_str, expected_type) in special_ips {
        let ip: IpAddr = ip_str.parse().unwrap();
        assert!(
            !is_global_ip(&ip),
            "{} should be filtered as {}",
            ip_str,
            expected_type
        );
        assert_eq!(
            classify_ip(&ip),
            expected_type,
            "{} should be classified as {}",
            ip_str,
            expected_type
        );
    }
}

#[test]
fn test_allow_public_ipv4_addresses() {
    // Well-known public IPs that should NOT be filtered
    let public_ips = vec![
        "8.8.8.8",        // Google DNS
        "1.1.1.1",        // Cloudflare DNS
        "208.67.222.222", // OpenDNS
        "13.107.42.14",   // Microsoft
        "142.250.185.46", // Google
    ];

    for ip_str in public_ips {
        let ip: IpAddr = ip_str.parse().unwrap();
        assert!(
            is_global_ip(&ip),
            "{} should NOT be filtered (it's public)",
            ip_str
        );
        assert_eq!(classify_ip(&ip), "global");
    }
}

#[test]
fn test_allow_public_ipv6_addresses() {
    // Well-known public IPv6 addresses that should NOT be filtered
    let public_ips = vec![
        "2606:4700:4700::1111", // Cloudflare DNS
        "2001:4860:4860::8888", // Google DNS
    ];

    for ip_str in public_ips {
        let ip: IpAddr = ip_str.parse().unwrap();
        assert!(
            is_global_ip(&ip),
            "{} should NOT be filtered (it's public)",
            ip_str
        );
        assert_eq!(classify_ip(&ip), "global");
    }
}

#[test]
fn test_filter_ipv6_unique_local() {
    let unique_local_ips = vec![
        "fc00::1",
        "fd00::1",
        "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    ];

    for ip_str in unique_local_ips {
        let ip: IpAddr = ip_str.parse().unwrap();
        assert!(
            !is_global_ip(&ip),
            "{} should be filtered as unique local",
            ip_str
        );
        assert_eq!(classify_ip(&ip), "unique local (RFC 4193)");
    }
}

#[test]
fn test_boundary_cases() {
    // Test boundaries of private ranges
    let test_cases = vec![
        ("9.255.255.255", true),   // Just before 10.0.0.0/8
        ("10.0.0.0", false),       // Start of 10.0.0.0/8
        ("11.0.0.0", true),        // Just after 10.0.0.0/8
        ("172.15.255.255", true),  // Just before 172.16.0.0/12
        ("172.16.0.0", false),     // Start of 172.16.0.0/12
        ("172.32.0.0", true),      // Just after 172.31.255.255
        ("192.167.255.255", true), // Just before 192.168.0.0/16
        ("192.168.0.0", false),    // Start of 192.168.0.0/16
        ("192.169.0.0", true),     // Just after 192.168.255.255
    ];

    for (ip_str, should_be_global) in test_cases {
        let ip: IpAddr = ip_str.parse().unwrap();
        assert_eq!(
            is_global_ip(&ip),
            should_be_global,
            "{} global status mismatch (expected: {})",
            ip_str,
            should_be_global
        );
    }
}

#[test]
fn test_mixed_list_filtering() {
    // Simulate a real-world scenario with mixed public and private IPs
    let mixed_ips = vec![
        ("8.8.8.8", true),
        ("192.168.1.1", false),
        ("1.1.1.1", true),
        ("10.0.0.1", false),
        ("127.0.0.1", false),
        ("208.67.222.222", true),
        ("172.16.0.1", false),
        ("169.254.1.1", false),
    ];

    let mut global_count = 0;
    let mut private_count = 0;

    for (ip_str, should_be_global) in mixed_ips {
        let ip: IpAddr = ip_str.parse().unwrap();
        if is_global_ip(&ip) {
            global_count += 1;
            assert!(should_be_global, "{} marked as global incorrectly", ip_str);
        } else {
            private_count += 1;
            assert!(
                !should_be_global,
                "{} marked as private incorrectly",
                ip_str
            );
        }
    }

    assert_eq!(global_count, 3, "Expected 3 global IPs");
    assert_eq!(private_count, 5, "Expected 5 private IPs");
}
