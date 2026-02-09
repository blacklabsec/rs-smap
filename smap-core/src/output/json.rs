//! JSON output format

use crate::output::common::OutputWriter;
use crate::types::ScanResult;
use serde_json;
use std::io;

/// JSON output formatter
///
/// Produces a JSON array of scan results.
///
/// # Examples
///
/// ```no_run
/// use smap_core::output::json::JsonFormatter;
///
/// let mut formatter = JsonFormatter::new();
/// formatter.start().unwrap();
/// // Add scan results...
/// formatter.end().unwrap();
/// ```
pub struct JsonFormatter {
    writer: OutputWriter,
    first_done: bool,
}

impl JsonFormatter {
    /// Create a new JsonFormatter writing to stdout
    pub fn new() -> Self {
        Self {
            writer: OutputWriter::stdout(),
            first_done: false,
        }
    }

    /// Create a new JsonFormatter writing to a file
    pub fn new_with_file(path: &str) -> io::Result<Self> {
        Ok(Self {
            writer: OutputWriter::file(path)?,
            first_done: false,
        })
    }

    /// Write the opening bracket
    pub fn start(&mut self) -> io::Result<()> {
        self.writer.write("[")?;
        Ok(())
    }

    /// Write a scan result
    pub fn write_result(&mut self, result: &ScanResult) -> io::Result<()> {
        let prefix = if self.first_done { "," } else { "" };
        self.first_done = true;

        let json = serde_json::to_string(result).map_err(io::Error::other)?;

        self.writer.write(&format!("{}{}", prefix, json))?;
        Ok(())
    }

    /// Write the closing bracket
    pub fn end(&mut self) -> io::Result<()> {
        self.writer.write("]")?;
        Ok(())
    }
}

impl Default for JsonFormatter {
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
    fn test_json_formatter() {
        let mut formatter = JsonFormatter::new();
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
                    cpes: vec![],
                }),
            }],
            os: None,
            hostnames: vec!["example.com".to_string()],
            cpes: vec![],
            tags: vec![],
            vulns: vec![],
        };

        formatter.write_result(&result).unwrap();
        formatter.end().unwrap();
    }
}
