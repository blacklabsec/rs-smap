//! Core data types for scan results and service information
//!
//! This module defines the fundamental data structures used throughout smap-core
//! for representing scan results, port information, services, and operating systems.
//!
//! # Examples
//!
//! ```
//! use smap_core::types::{ScanResult, Port, Protocol, Service};
//! use std::net::IpAddr;
//!
//! let result = ScanResult {
//!     ip: "192.168.1.1".parse().unwrap(),
//!     ports: vec![
//!         Port {
//!             number: 80,
//!             protocol: Protocol::Tcp,
//!             service: Some(Service {
//!                 name: "http".to_string(),
//!                 product: Some("nginx".to_string()),
//!                 version: Some("1.18.0".to_string()),
//!                 extra_info: None,
//!                 cpes: vec![],
//!             }),
//!         },
//!     ],
//!     os: None,
//!     hostnames: vec!["example.com".to_string()],
//!     cpes: vec![],
//!     tags: vec!["cloud".to_string()],
//!     vulns: vec![],
//! };
//! ```

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Scan result for a single host
///
/// Represents all information gathered about a single IP address,
/// including open ports, services, OS details, hostnames, tags, and vulnerabilities.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanResult {
    /// IP address of the scanned host
    pub ip: IpAddr,

    /// List of open ports with service information
    pub ports: Vec<Port>,

    /// Operating system information if detected
    pub os: Option<OsInfo>,

    /// List of hostnames associated with this IP
    pub hostnames: Vec<String>,

    /// Host-level CPEs that don't correlate to specific ports
    #[serde(default)]
    pub cpes: Vec<String>,

    /// Tags from Shodan (e.g., "cloud", "iot", "vpn")
    pub tags: Vec<String>,

    /// Vulnerabilities (CVEs) detected
    pub vulns: Vec<String>,
}

impl ScanResult {
    /// Creates a new ScanResult with the given IP address
    ///
    /// # Examples
    ///
    /// ```
    /// use smap_core::types::ScanResult;
    /// use std::net::IpAddr;
    ///
    /// let ip: IpAddr = "192.168.1.1".parse().unwrap();
    /// let result = ScanResult::new(ip);
    /// assert_eq!(result.ip.to_string(), "192.168.1.1");
    /// ```
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            ports: Vec::new(),
            os: None,
            hostnames: Vec::new(),
            cpes: Vec::new(),
            tags: Vec::new(),
            vulns: Vec::new(),
        }
    }

    /// Adds a port to the scan result
    pub fn add_port(&mut self, port: Port) {
        self.ports.push(port);
    }

    /// Returns the number of open ports
    pub fn port_count(&self) -> usize {
        self.ports.len()
    }

    /// Returns true if any vulnerabilities were detected
    pub fn has_vulns(&self) -> bool {
        !self.vulns.is_empty()
    }

    /// Returns true if the host has any open ports
    pub fn has_open_ports(&self) -> bool {
        !self.ports.is_empty()
    }
}

/// Port and service information
///
/// Represents a network port along with detected service information.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Port {
    /// Port number (1-65535)
    pub number: u16,

    /// Protocol (tcp/udp)
    pub protocol: Protocol,

    /// Service detected on this port
    pub service: Option<Service>,
}

impl Port {
    /// Creates a new Port with the given number and protocol
    ///
    /// # Examples
    ///
    /// ```
    /// use smap_core::types::{Port, Protocol};
    ///
    /// let port = Port::new(80, Protocol::Tcp);
    /// assert_eq!(port.number, 80);
    /// ```
    pub fn new(number: u16, protocol: Protocol) -> Self {
        Self {
            number,
            protocol,
            service: None,
        }
    }

    /// Creates a new Port with service information
    pub fn with_service(number: u16, protocol: Protocol, service: Service) -> Self {
        Self {
            number,
            protocol,
            service: Some(service),
        }
    }
}

/// Network protocol
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// TCP protocol
    Tcp,
    /// UDP protocol
    Udp,
}

/// Service information
///
/// Represents a network service running on a port, including name,
/// product details, version, and CPE identifiers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Service {
    /// Service name (e.g., "http", "ssh")
    pub name: String,

    /// Product name (e.g., "Apache httpd")
    pub product: Option<String>,

    /// Version information
    pub version: Option<String>,

    /// Extra information
    pub extra_info: Option<String>,

    /// CPE (Common Platform Enumeration) identifiers
    pub cpes: Vec<String>,
}

impl Service {
    /// Creates a new Service with the given name
    ///
    /// # Examples
    ///
    /// ```
    /// use smap_core::types::Service;
    ///
    /// let service = Service::new("http");
    /// assert_eq!(service.name, "http");
    /// ```
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            product: None,
            version: None,
            extra_info: None,
            cpes: Vec::new(),
        }
    }

    /// Sets the product name
    pub fn with_product(mut self, product: impl Into<String>) -> Self {
        self.product = Some(product.into());
        self
    }

    /// Sets the version
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }
}

/// Operating system information
///
/// Represents detected operating system details including name and CPE identifiers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OsInfo {
    /// OS name
    pub name: String,

    /// CPE identifiers for the OS
    pub cpes: Vec<String>,
}

impl OsInfo {
    /// Creates a new OsInfo with the given name
    ///
    /// # Examples
    ///
    /// ```
    /// use smap_core::types::OsInfo;
    ///
    /// let os = OsInfo::new("Ubuntu Linux");
    /// assert_eq!(os.name, "Ubuntu Linux");
    /// ```
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            cpes: Vec::new(),
        }
    }

    /// Creates a new OsInfo with name and CPEs
    pub fn with_cpes(name: impl Into<String>, cpes: Vec<String>) -> Self {
        Self {
            name: name.into(),
            cpes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_scan_result_serialization() {
        let result = ScanResult {
            ip: IpAddr::from_str("192.168.1.1").unwrap(),
            ports: vec![],
            os: None,
            hostnames: vec![],
            cpes: vec![],
            tags: vec![],
            vulns: vec![],
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }

    #[test]
    fn test_scan_result_with_data() {
        let result = ScanResult {
            ip: IpAddr::from_str("8.8.8.8").unwrap(),
            ports: vec![Port::new(80, Protocol::Tcp)],
            os: Some(OsInfo::new("Linux")),
            hostnames: vec!["dns.google".to_string()],
            cpes: vec![],
            tags: vec!["cloud".to_string()],
            vulns: vec!["CVE-2021-1234".to_string()],
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
        assert_eq!(deserialized.port_count(), 1);
        assert!(deserialized.has_vulns());
        assert!(deserialized.has_open_ports());
    }

    #[test]
    fn test_scan_result_new() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let result = ScanResult::new(ip);

        assert_eq!(result.ip.to_string(), "10.0.0.1");
        assert_eq!(result.port_count(), 0);
        assert!(!result.has_vulns());
        assert!(!result.has_open_ports());
    }

    #[test]
    fn test_port_creation() {
        let port = Port {
            number: 80,
            protocol: Protocol::Tcp,
            service: Some(Service {
                name: "http".to_string(),
                product: Some("nginx".to_string()),
                version: Some("1.18.0".to_string()),
                extra_info: None,
                cpes: vec![],
            }),
        };

        assert_eq!(port.number, 80);
        assert_eq!(port.protocol, Protocol::Tcp);

        let json = serde_json::to_string(&port).unwrap();
        let deserialized: Port = serde_json::from_str(&json).unwrap();
        assert_eq!(port, deserialized);
    }

    #[test]
    fn test_port_builder() {
        let port = Port::new(443, Protocol::Tcp);
        assert_eq!(port.number, 443);
        assert!(port.service.is_none());

        let service = Service::new("https")
            .with_product("nginx")
            .with_version("1.20.0");
        let port_with_service = Port::with_service(443, Protocol::Tcp, service);
        assert!(port_with_service.service.is_some());
    }

    #[test]
    fn test_service_builder() {
        let service = Service::new("ssh")
            .with_product("OpenSSH")
            .with_version("8.2p1");

        assert_eq!(service.name, "ssh");
        assert_eq!(service.product.as_deref(), Some("OpenSSH"));
        assert_eq!(service.version.as_deref(), Some("8.2p1"));
    }

    #[test]
    fn test_os_info_builder() {
        let os = OsInfo::new("Ubuntu");
        assert_eq!(os.name, "Ubuntu");
        assert!(os.cpes.is_empty());

        let os_with_cpes =
            OsInfo::with_cpes("Ubuntu", vec!["cpe:/o:canonical:ubuntu_linux".to_string()]);
        assert_eq!(os_with_cpes.name, "Ubuntu");
        assert_eq!(os_with_cpes.cpes.len(), 1);
    }

    #[test]
    fn test_protocol_serialization() {
        let tcp = Protocol::Tcp;
        let json = serde_json::to_string(&tcp).unwrap();
        assert_eq!(json, r#""tcp""#);

        let udp = Protocol::Udp;
        let json = serde_json::to_string(&udp).unwrap();
        assert_eq!(json, r#""udp""#);
    }

    #[test]
    fn test_complex_scan_result() {
        let mut result = ScanResult::new("192.168.1.100".parse().unwrap());

        result.add_port(Port::with_service(
            22,
            Protocol::Tcp,
            Service::new("ssh")
                .with_product("OpenSSH")
                .with_version("7.4"),
        ));

        result.add_port(Port::with_service(
            80,
            Protocol::Tcp,
            Service::new("http")
                .with_product("Apache")
                .with_version("2.4.6"),
        ));

        result.os = Some(OsInfo::with_cpes(
            "CentOS",
            vec!["cpe:/o:centos:centos:7".to_string()],
        ));
        result.hostnames.push("server.example.com".to_string());
        result.tags.push("self-hosted".to_string());

        assert_eq!(result.port_count(), 2);
        assert!(result.has_open_ports());
        assert!(!result.has_vulns());

        let json = serde_json::to_string_pretty(&result).unwrap();
        let deserialized: ScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }
}
