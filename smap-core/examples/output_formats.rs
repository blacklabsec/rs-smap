//! Example: Using all output formatters
//!
//! This example demonstrates how to use each of the output formatters
//! to generate different formats of scan results.

use smap_core::output::{
    GrepFormatter, JsonFormatter, NmapFormatter, PairFormatter, SmapFormatter, XmlFormatter,
};
use smap_core::types::{OsInfo, Port, Protocol, ScanResult, Service};
use std::net::IpAddr;
use std::time::SystemTime;

fn create_sample_results() -> Vec<ScanResult> {
    vec![
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
            ],
            cpes: vec![],
            os: Some(OsInfo::with_cpes(
                "Linux".to_string(),
                vec!["cpe:/o:linux:linux_kernel".to_string()],
            )),
            hostnames: vec!["server1.example.com".to_string()],
            tags: vec!["cloud".to_string()],
            vulns: vec![],
        },
        ScanResult {
            ip: "192.168.1.101".parse::<IpAddr>().unwrap(),
            ports: vec![Port {
                number: 443,
                protocol: Protocol::Tcp,
                service: Some(Service {
                    name: "https".to_string(),
                    product: Some("nginx".to_string()),
                    version: Some("1.18.0".to_string()),
                    extra_info: None,
                    cpes: vec!["cpe:/a:nginx:nginx:1.18.0".to_string()],
                }),
            }],
            cpes: vec![],
            os: None,
            hostnames: vec!["server2.example.com".to_string()],
            tags: vec![],
            vulns: vec![],
        },
    ]
}

fn main() {
    let results = create_sample_results();
    let args = vec!["192.168.1.0/24".to_string()];
    let start_time = SystemTime::now();

    println!("=== NMAP FORMAT ===\n");
    {
        let mut formatter = NmapFormatter::new(start_time);
        formatter.start(&args, false).unwrap();
        for result in &results {
            formatter.write_result(result).unwrap();
        }
        formatter.write_service_detection().unwrap();
        formatter.end(results.len(), results.len()).unwrap();
    }

    println!("\n\n=== GREPABLE FORMAT ===\n");
    {
        let mut formatter = GrepFormatter::new(start_time);
        formatter.start(&args).unwrap();
        for result in &results {
            formatter.write_result(result).unwrap();
        }
        formatter.end(results.len(), results.len()).unwrap();
    }

    println!("\n\n=== JSON FORMAT ===\n");
    {
        let mut formatter = JsonFormatter::new();
        formatter.start().unwrap();
        for result in &results {
            formatter.write_result(result).unwrap();
        }
        formatter.end().unwrap();
    }

    println!("\n\n=== PAIR FORMAT ===\n");
    {
        let mut formatter = PairFormatter::new();
        for result in &results {
            formatter.write_result(result).unwrap();
        }
    }

    println!("\n\n=== SMAP FORMAT ===\n");
    {
        let mut formatter = SmapFormatter::new("1.0.0");
        formatter.start().unwrap();
        for result in &results {
            formatter.write_result(result).unwrap();
        }
    }

    println!("\n\n=== XML FORMAT ===\n");
    {
        let mut formatter = XmlFormatter::new(start_time);
        formatter.start(&args, "22,80,443", 3).unwrap();
        for result in &results {
            formatter
                .write_result(result, start_time, SystemTime::now())
                .unwrap();
        }
        formatter.end(results.len(), results.len()).unwrap();
    }
}
