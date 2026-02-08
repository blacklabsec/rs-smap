//! IP:port pairs output format

use crate::output::common::OutputWriter;
use crate::types::ScanResult;
use std::io;

/// Pair output formatter
///
/// Produces simple IP:port pairs, one per line.
///
/// # Examples
///
/// ```no_run
/// use smap_core::output::pair::PairFormatter;
///
/// let mut formatter = PairFormatter::new();
/// // Add scan results...
/// ```
pub struct PairFormatter {
    writer: OutputWriter,
}

impl PairFormatter {
    /// Create a new PairFormatter writing to stdout
    pub fn new() -> Self {
        Self {
            writer: OutputWriter::stdout(),
        }
    }

    /// Create a new PairFormatter writing to a file
    pub fn new_with_file(path: &str) -> io::Result<Self> {
        Ok(Self {
            writer: OutputWriter::file(path)?,
        })
    }

    /// Write a scan result
    pub fn write_result(&mut self, result: &ScanResult) -> io::Result<()> {
        for port in &result.ports {
            self.writer
                .write(&format!("{}:{}\n", result.ip, port.number))?;
        }
        Ok(())
    }
}

impl Default for PairFormatter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Port, Protocol, Service};
    use std::net::IpAddr;

    #[test]
    fn test_pair_formatter() {
        let mut formatter = PairFormatter::new();

        let result = ScanResult {
            ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
            ports: vec![
                Port {
                    number: 80,
                    protocol: Protocol::Tcp,
                    service: Some(Service {
                        name: "http".to_string(),
                        product: None,
                        version: None,
                        extra_info: None,
                        cpes: vec![],
                    }),
                },
                Port {
                    number: 443,
                    protocol: Protocol::Tcp,
                    service: None,
                },
            ],
            os: None,
            hostnames: vec![],
            tags: vec![],
            vulns: vec![],
        };

        formatter.write_result(&result).unwrap();
    }
}
