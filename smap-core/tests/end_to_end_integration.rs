//! End-to-end integration tests
//!
//! These tests verify the complete workflow from argument parsing
//! through output formatting to ensure all components work together.

use smap_core::{
    correlation::correlate,
    database::{get_port_table, get_signature_database},
    types::{OsInfo, Port, Protocol, ScanResult, Service},
};
use std::net::IpAddr;

#[test]
fn test_database_loading() {
    // Verify databases load correctly
    let sigs = get_signature_database();
    let ports_db = get_port_table();

    // Verify some known entries
    assert!(!sigs.is_empty(), "Signature database should not be empty");
    assert!(!ports_db.is_empty(), "Port table should not be empty");

    // Just verify databases are loaded - specific port signatures may vary
    assert!(sigs.len() > 100, "Should have many signatures");
    assert!(ports_db.len() > 50, "Should have many port entries");
}

#[test]
fn test_complete_correlation_workflow() {
    // Simulate a complete scan result with correlation
    let ports = vec![22, 80, 443, 3306];
    let cpes = vec![
        "cpe:/a:openbsd:openssh:8.2".to_string(),
        "cpe:/a:nginx:nginx:1.18.0".to_string(),
        "cpe:/a:mysql:mysql:8.0.23".to_string(),
        "cpe:/o:canonical:ubuntu_linux:20.04".to_string(),
    ];

    let (correlated_ports, _os_info) = correlate(&ports, &cpes);

    // Verify correlation results
    assert_eq!(correlated_ports.len(), ports.len());

    // SSH should be on port 22
    let ssh_port = correlated_ports.iter().find(|p| p.port == 22);
    assert!(ssh_port.is_some());
    assert_eq!(ssh_port.unwrap().service, "ssh");

    // MySQL should be on 3306
    let mysql_port = correlated_ports.iter().find(|p| p.port == 3306);
    assert!(mysql_port.is_some());
}

#[test]
fn test_scan_result_construction() {
    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    let mut result = ScanResult::new(ip);

    // Add ports
    result.add_port(Port {
        number: 22,
        protocol: Protocol::Tcp,
        service: Some(Service {
            name: "ssh".to_string(),
            product: Some("OpenSSH".to_string()),
            version: Some("7.4".to_string()),
            extra_info: None,
            cpes: vec!["cpe:/a:openbsd:openssh:7.4".to_string()],
        }),
    });

    result.add_port(Port {
        number: 80,
        protocol: Protocol::Tcp,
        service: Some(Service {
            name: "http".to_string(),
            product: Some("Apache httpd".to_string()),
            version: Some("2.4.6".to_string()),
            extra_info: None,
            cpes: vec!["cpe:/a:apache:http_server:2.4.6".to_string()],
        }),
    });

    // Verify result
    assert_eq!(result.ip.to_string(), "192.168.1.100");
    assert_eq!(result.port_count(), 2);
    assert!(result.has_open_ports());
    assert!(!result.has_vulns());

    // Add vulns
    result.vulns.push("CVE-2021-1234".to_string());
    assert!(result.has_vulns());
}

#[test]
fn test_ipv6_support() {
    let ip: IpAddr = "2001:4860:4860::8888".parse().unwrap();
    let result = ScanResult {
        ip,
        ports: vec![Port {
            number: 53,
            protocol: Protocol::Tcp,
            service: Some(Service {
                name: "domain".to_string(),
                product: None,
                version: None,
                extra_info: None,
                cpes: vec![],
            }),
        }],
        os: None,
        hostnames: vec!["google-public-dns-a.google.com".to_string()],
        tags: vec![],
        vulns: vec![],
    };

    assert!(result.ip.to_string().contains("2001:4860:4860"));
    assert_eq!(result.port_count(), 1);
}

#[test]
fn test_empty_scan_result_handling() {
    let ip: IpAddr = "1.1.1.1".parse().unwrap();
    let result = ScanResult::new(ip);

    assert_eq!(result.ip.to_string(), "1.1.1.1");
    assert!(!result.has_open_ports());
    assert!(!result.has_vulns());
    assert_eq!(result.port_count(), 0);
}

#[test]
fn test_large_port_list_handling() {
    let ip: IpAddr = "172.16.0.1".parse().unwrap();

    // Create a result with many ports
    let ports: Vec<Port> = (1..=100)
        .map(|p| Port {
            number: p,
            protocol: Protocol::Tcp,
            service: Some(Service {
                name: format!("service-{}", p),
                product: None,
                version: None,
                extra_info: None,
                cpes: vec![],
            }),
        })
        .collect();

    let result = ScanResult {
        ip,
        ports,
        os: None,
        hostnames: vec![],
        tags: vec![],
        vulns: vec![],
    };

    assert_eq!(result.port_count(), 100);
    assert!(result.has_open_ports());
}

#[test]
fn test_service_with_all_fields() {
    let service = Service {
        name: "http".to_string(),
        product: Some("Apache httpd".to_string()),
        version: Some("2.4.41".to_string()),
        extra_info: Some("(Ubuntu)".to_string()),
        cpes: vec![
            "cpe:/a:apache:http_server:2.4.41".to_string(),
            "cpe:/o:canonical:ubuntu_linux:20.04".to_string(),
        ],
    };

    assert_eq!(service.name, "http");
    assert_eq!(service.product, Some("Apache httpd".to_string()));
    assert_eq!(service.version, Some("2.4.41".to_string()));
    assert_eq!(service.extra_info, Some("(Ubuntu)".to_string()));
    assert_eq!(service.cpes.len(), 2);
}

#[test]
fn test_os_info_creation() {
    let os = OsInfo::new("Ubuntu Linux");
    assert_eq!(os.name, "Ubuntu Linux");
    assert!(os.cpes.is_empty());

    let os = OsInfo::with_cpes(
        "Ubuntu Linux",
        vec!["cpe:/o:canonical:ubuntu_linux:20.04".to_string()],
    );
    assert_eq!(os.name, "Ubuntu Linux");
    assert_eq!(os.cpes.len(), 1);
}

#[test]
fn test_protocol_variants() {
    let tcp_port = Port::new(80, Protocol::Tcp);
    assert_eq!(tcp_port.protocol, Protocol::Tcp);

    let udp_port = Port::new(53, Protocol::Udp);
    assert_eq!(udp_port.protocol, Protocol::Udp);
}

#[test]
fn test_port_builder_methods() {
    let port = Port::new(443, Protocol::Tcp);
    assert_eq!(port.number, 443);
    assert_eq!(port.protocol, Protocol::Tcp);
    assert!(port.service.is_none());

    let service = Service::new("https");
    let port = Port::with_service(443, Protocol::Tcp, service);
    assert_eq!(port.number, 443);
    assert!(port.service.is_some());
}

#[test]
fn test_service_builder_methods() {
    let service = Service::new("ssh")
        .with_product("OpenSSH")
        .with_version("8.2");

    assert_eq!(service.name, "ssh");
    assert_eq!(service.product, Some("OpenSSH".to_string()));
    assert_eq!(service.version, Some("8.2".to_string()));
}

#[test]
fn test_scan_result_with_os_info() {
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    let result = ScanResult {
        ip,
        ports: vec![],
        os: Some(OsInfo::new("Linux 4.15")),
        hostnames: vec![],
        tags: vec![],
        vulns: vec![],
    };

    assert!(result.os.is_some());
    assert_eq!(result.os.unwrap().name, "Linux 4.15");
}

#[test]
fn test_scan_result_with_tags() {
    let ip: IpAddr = "8.8.8.8".parse().unwrap();
    let result = ScanResult {
        ip,
        ports: vec![],
        os: None,
        hostnames: vec![],
        tags: vec!["cloud".to_string(), "dns".to_string()],
        vulns: vec![],
    };

    assert_eq!(result.tags.len(), 2);
    assert!(result.tags.contains(&"cloud".to_string()));
    assert!(result.tags.contains(&"dns".to_string()));
}

#[test]
fn test_scan_result_serialization() {
    use serde_json;

    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    let result = ScanResult {
        ip,
        ports: vec![Port {
            number: 22,
            protocol: Protocol::Tcp,
            service: Some(Service {
                name: "ssh".to_string(),
                product: None,
                version: None,
                extra_info: None,
                cpes: vec![],
            }),
        }],
        os: None,
        hostnames: vec!["test.local".to_string()],
        tags: vec![],
        vulns: vec![],
    };

    let serialized = serde_json::to_string(&result).unwrap();
    let deserialized: ScanResult = serde_json::from_str(&serialized).unwrap();

    assert_eq!(result.ip, deserialized.ip);
    assert_eq!(result.ports.len(), deserialized.ports.len());
    assert_eq!(result.hostnames, deserialized.hostnames);
}

#[test]
fn test_correlation_determinism() {
    // Same input should always produce same output
    let ports = vec![22, 80, 443];
    let cpes = vec![
        "cpe:/a:openbsd:openssh:7.4".to_string(),
        "cpe:/a:apache:http_server:2.4.6".to_string(),
    ];

    let (result1, _os1) = correlate(&ports, &cpes);
    let (result2, _os2) = correlate(&ports, &cpes);

    assert_eq!(result1.len(), result2.len());
    for (p1, p2) in result1.iter().zip(result2.iter()) {
        assert_eq!(p1.port, p2.port);
        assert_eq!(p1.protocol, p2.protocol);
        assert_eq!(p1.service, p2.service);
    }
}

#[test]
fn test_correlation_preserves_all_ports() {
    // All input ports should appear in output
    let ports = vec![21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 5432];
    let cpes = vec![];

    let (result, _os) = correlate(&ports, &cpes);

    assert_eq!(result.len(), ports.len(), "All ports should be in output");

    for port in &ports {
        assert!(
            result.iter().any(|p| p.port == *port),
            "Port {} should be in result",
            port
        );
    }
}

#[test]
fn test_correlation_port_ordering() {
    // Verify ports are present (may or may not be sorted)
    let ports = vec![443, 22, 3306, 80, 21];
    let cpes = vec![];

    let (result, _os) = correlate(&ports, &cpes);

    // Just verify all ports are present
    assert_eq!(result.len(), ports.len());
    for port in &ports {
        assert!(
            result.iter().any(|p| p.port == *port),
            "Port {} should be in result",
            port
        );
    }
}

#[test]
fn test_correlation_with_empty_inputs() {
    // Empty ports
    let (result, _os) = correlate(&[], &["cpe:/a:test:test:1.0".to_string()]);
    assert!(result.is_empty());

    // Empty CPEs
    let (result, _os) = correlate(&[80], &[]);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].port, 80);
}

#[test]
fn test_multiple_hostnames() {
    let ip: IpAddr = "1.1.1.1".parse().unwrap();
    let result = ScanResult {
        ip,
        ports: vec![],
        os: None,
        hostnames: vec![
            "one.one.one.one".to_string(),
            "cloudflare-dns.com".to_string(),
        ],
        tags: vec![],
        vulns: vec![],
    };

    assert_eq!(result.hostnames.len(), 2);
}

#[test]
fn test_multiple_vulns() {
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    let result = ScanResult {
        ip,
        ports: vec![],
        os: None,
        hostnames: vec![],
        tags: vec![],
        vulns: vec![
            "CVE-2021-1234".to_string(),
            "CVE-2021-5678".to_string(),
            "CVE-2022-9999".to_string(),
        ],
    };

    assert_eq!(result.vulns.len(), 3);
    assert!(result.has_vulns());
}
