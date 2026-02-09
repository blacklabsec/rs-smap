//! Integration tests for output formatters

use smap_core::output::{
    GrepFormatter, JsonFormatter, NmapFormatter, PairFormatter, SmapFormatter, XmlFormatter,
};
use smap_core::types::{OsInfo, Port, Protocol, ScanResult, Service};
use std::net::IpAddr;
use std::time::SystemTime;

/// Create a sample scan result for testing
fn create_sample_result() -> ScanResult {
    ScanResult {
        ip: "192.168.1.100".parse::<IpAddr>().unwrap(),
        ports: vec![
            Port {
                number: 22,
                protocol: Protocol::Tcp,
                service: Some(Service {
                    name: "ssh".to_string(),
                    product: Some("OpenSSH".to_string()),
                    version: Some("7.4".to_string()),
                    extra_info: None,
                    cpes: vec!["cpe:/a:openbsd:openssh:7.4".to_string()],
                }),
            },
            Port {
                number: 80,
                protocol: Protocol::Tcp,
                service: Some(Service {
                    name: "http".to_string(),
                    product: Some("Apache httpd".to_string()),
                    version: Some("2.4.6".to_string()),
                    extra_info: None,
                    cpes: vec!["cpe:/a:apache:http_server:2.4.6".to_string()],
                }),
            },
            Port {
                number: 443,
                protocol: Protocol::Tcp,
                service: Some(Service {
                    name: "https".to_string(),
                    product: Some("Apache httpd".to_string()),
                    version: Some("2.4.6".to_string()),
                    extra_info: None,
                    cpes: vec!["cpe:/a:apache:http_server:2.4.6".to_string()],
                }),
            },
        ],        cpes: vec![],        os: Some(OsInfo::with_cpes(
            "Linux".to_string(),
            vec!["cpe:/o:linux:linux_kernel".to_string()],
        )),
        hostnames: vec!["server.example.com".to_string()],
        tags: vec!["cloud".to_string(), "self-hosted".to_string()],
        vulns: vec!["CVE-2021-1234".to_string()],
    }
}

#[test]
fn test_nmap_formatter_output() {
    let mut formatter = NmapFormatter::new(SystemTime::now());
    let result = formatter.start(&["192.168.1.100".to_string()], false);
    assert!(result.is_ok());

    let scan_result = create_sample_result();
    let result = formatter.write_result(&scan_result);
    assert!(result.is_ok());

    let result = formatter.write_service_detection();
    assert!(result.is_ok());

    let result = formatter.end(1, 1);
    assert!(result.is_ok());
}

#[test]
fn test_xml_formatter_output() {
    let mut formatter = XmlFormatter::new(SystemTime::now());
    let result = formatter.start(&["192.168.1.100".to_string()], "22,80,443", 3);
    assert!(result.is_ok());

    let scan_result = create_sample_result();
    let start = SystemTime::now();
    let end = SystemTime::now();
    let result = formatter.write_result(&scan_result, start, end);
    assert!(result.is_ok());

    let result = formatter.end(1, 1);
    assert!(result.is_ok());
}

#[test]
fn test_json_formatter_output() {
    let mut formatter = JsonFormatter::new();
    let result = formatter.start();
    assert!(result.is_ok());

    let scan_result = create_sample_result();
    let result = formatter.write_result(&scan_result);
    assert!(result.is_ok());

    let result = formatter.end();
    assert!(result.is_ok());
}

#[test]
fn test_grep_formatter_output() {
    let mut formatter = GrepFormatter::new(SystemTime::now());
    let result = formatter.start(&["192.168.1.100".to_string()]);
    assert!(result.is_ok());

    let scan_result = create_sample_result();
    let result = formatter.write_result(&scan_result);
    assert!(result.is_ok());

    let result = formatter.end(1, 1);
    assert!(result.is_ok());
}

#[test]
fn test_pair_formatter_output() {
    let mut formatter = PairFormatter::new();

    let scan_result = create_sample_result();
    let result = formatter.write_result(&scan_result);
    assert!(result.is_ok());
}

#[test]
fn test_smap_formatter_output() {
    let mut formatter = SmapFormatter::new("1.0.0");
    let result = formatter.start();
    assert!(result.is_ok());

    let scan_result = create_sample_result();
    let result = formatter.write_result(&scan_result);
    assert!(result.is_ok());
}

#[test]
fn test_nmap_formatter_empty_result() {
    let mut formatter = NmapFormatter::new(SystemTime::now());
    formatter
        .start(&["192.168.1.100".to_string()], false)
        .unwrap();

    // Result with no ports should not produce output
    let empty_result = ScanResult {
        ip: "192.168.1.100".parse::<IpAddr>().unwrap(),
        ports: vec![],
        cpes: vec![],
        os: None,
        hostnames: vec![],
        tags: vec![],
        vulns: vec![],
    };

    let result = formatter.write_result(&empty_result);
    assert!(result.is_ok());

    formatter.end(1, 0).unwrap();
}

#[test]
fn test_json_formatter_multiple_results() {
    let mut formatter = JsonFormatter::new();
    formatter.start().unwrap();

    let result1 = create_sample_result();
    formatter.write_result(&result1).unwrap();

    let result2 = ScanResult {
        ip: "192.168.1.101".parse::<IpAddr>().unwrap(),
        ports: vec![Port {
            number: 8080,
            protocol: Protocol::Tcp,
            service: Some(Service {
                name: "http-proxy".to_string(),
                product: None,
                version: None,
                extra_info: None,
                cpes: vec![],
            }),
        }],
        cpes: vec![],
        os: None,
        hostnames: vec![],
        tags: vec![],
        vulns: vec![],
    };
    formatter.write_result(&result2).unwrap();

    formatter.end().unwrap();
}

#[test]
fn test_grep_formatter_no_hostname() {
    let mut formatter = GrepFormatter::new(SystemTime::now());
    formatter.start(&["192.168.1.100".to_string()]).unwrap();

    let result = ScanResult {
        ip: "192.168.1.100".parse::<IpAddr>().unwrap(),
        ports: vec![Port {
            number: 80,
            protocol: Protocol::Tcp,
            service: Some(Service {
                name: "http".to_string(),
                product: None,
                version: None,
                extra_info: None,
                cpes: vec![],
            }),
        }],
        cpes: vec![],
        os: None,
        hostnames: vec![],
        tags: vec![],
        vulns: vec![],
    };

    formatter.write_result(&result).unwrap();
    formatter.end(1, 1).unwrap();
}

#[test]
fn test_pair_formatter_multiple_ports() {
    let mut formatter = PairFormatter::new();
    let result = create_sample_result();
    formatter.write_result(&result).unwrap();
}

#[test]
fn test_smap_formatter_with_all_fields() {
    let mut formatter = SmapFormatter::new("1.0.0");
    formatter.start().unwrap();

    let result = create_sample_result();
    formatter.write_result(&result).unwrap();
}

#[test]
fn test_xml_formatter_with_os_info() {
    let mut formatter = XmlFormatter::new(SystemTime::now());
    formatter
        .start(&["192.168.1.100".to_string()], "22", 1)
        .unwrap();

    let result = create_sample_result();
    let start = SystemTime::now();
    let end = SystemTime::now();
    formatter.write_result(&result, start, end).unwrap();

    formatter.end(1, 1).unwrap();
}
