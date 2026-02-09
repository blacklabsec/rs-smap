//! Smap custom output format

use crate::output::common::OutputWriter;
use crate::types::{Protocol, ScanResult};
use std::io;

/// Smap output formatter
///
/// Produces output in a custom smap format with enhanced information.
///
/// # Examples
///
/// ```no_run
/// use smap_core::output::smap::SmapFormatter;
///
/// let mut formatter = SmapFormatter::new("1.0.0");
/// formatter.start().unwrap();
/// // Add scan results...
/// ```
pub struct SmapFormatter {
    writer: OutputWriter,
    version: String,
}

impl SmapFormatter {
    /// Create a new SmapFormatter writing to stdout
    pub fn new(version: &str) -> Self {
        Self {
            writer: OutputWriter::stdout(),
            version: version.to_string(),
        }
    }

    /// Create a new SmapFormatter writing to a file
    pub fn new_with_file(version: &str, path: &str) -> io::Result<Self> {
        Ok(Self {
            writer: OutputWriter::file(path)?,
            version: version.to_string(),
        })
    }

    /// Write the header
    pub fn start(&mut self) -> io::Result<()> {
        self.writer
            .write(&format!("\n\tSmap ({})\n", self.version))?;
        Ok(())
    }

    /// Write a scan result
    pub fn write_result(&mut self, result: &ScanResult) -> io::Result<()> {
        let mut output = String::new();

        // Hostname and IP
        if !result.hostnames.is_empty() {
            output.push_str(&format!(
                "\n+ {} ({})\n",
                result.ip,
                result.hostnames.join(", ")
            ));
        } else {
            output.push_str(&format!("{}\n", result.ip));
        }

        // OS info
        if let Some(ref os) = result.os {
            output.push_str(&format!("  - OS: {}\n", os.name));
        }

        // Tags
        if !result.tags.is_empty() {
            output.push_str(&format!("  - Tags: {}\n", result.tags.join(", ")));
        }

        // Ports
        output.push_str("  + Ports:\n");
        for port in &result.ports {
            let protocol = match port.protocol {
                Protocol::Tcp => "tcp",
                Protocol::Udp => "udp",
            };

            output.push_str(&format!("    - {} {}", port.number, protocol));

            if let Some(ref service) = port.service {
                output.push_str(&format!("/{} ", service.name));

                if !service.cpes.is_empty() {
                    output.push_str(&service.cpes.join(" "));
                }
            } else {
                output.push(' ');
            }

            output.push('\n');
        }

        // Vulnerabilities
        if !result.vulns.is_empty() {
            output.push_str(&format!("  - Vulns: {}\n", result.vulns.join(", ")));
        }

        self.writer.write(&output)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{OsInfo, Port, Protocol, Service};
    use std::net::IpAddr;

    #[test]
    fn test_smap_formatter() {
        let mut formatter = SmapFormatter::new("1.0.0");
        formatter.start().unwrap();

        let result = ScanResult {
            ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
            ports: vec![Port {
                number: 80,
                protocol: Protocol::Tcp,
                service: Some(Service {
                    name: "http".to_string(),
                    product: Some("nginx".to_string()),
                    version: Some("1.18.0".to_string()),
                    extra_info: None,
                    cpes: vec!["cpe:/a:nginx:nginx:1.18.0".to_string()],
                }),
            }],
            os: Some(OsInfo {
                name: "Linux".to_string(),
                cpes: vec!["cpe:/o:linux:linux_kernel".to_string()],
            }),
            hostnames: vec!["example.com".to_string()],
            cpes: vec![],
            tags: vec!["cloud".to_string()],
            vulns: vec!["CVE-2021-1234".to_string()],
        };

        formatter.write_result(&result).unwrap();
    }
}
