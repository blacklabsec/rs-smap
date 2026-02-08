//! Grepable output format

use crate::output::common::{format_time, get_command, OutputWriter, TimeFormat};
use crate::types::{Protocol, ScanResult};
use std::io;
use std::time::SystemTime;

/// Grepable output formatter
///
/// Produces output in a grep-friendly format similar to Nmap's -oG option.
pub struct GrepFormatter {
    writer: OutputWriter,
    start_time: SystemTime,
    end_time: Option<SystemTime>,
    args: Vec<String>,
}

impl GrepFormatter {
    /// Create a new GrepFormatter writing to stdout
    pub fn new(start_time: SystemTime) -> Self {
        Self {
            writer: OutputWriter::stdout(),
            start_time,
            end_time: None,
            args: Vec::new(),
        }
    }

    /// Create a new GrepFormatter writing to a file
    pub fn new_with_file(start_time: SystemTime, path: &str) -> io::Result<Self> {
        Ok(Self {
            writer: OutputWriter::file(path)?,
            start_time,
            end_time: None,
            args: Vec::new(),
        })
    }

    /// Write the header
    pub fn start(&mut self, args: &[String]) -> io::Result<()> {
        self.args = args.to_vec();
        let cmd = get_command(args);
        let timestr = format_time(self.start_time, TimeFormat::NmapFile);

        self.writer.write(&format!(
            "# Nmap 9.99 scan initiated {} as: {}\n",
            timestr, cmd
        ))?;
        Ok(())
    }

    /// Write a scan result
    pub fn write_result(&mut self, result: &ScanResult) -> io::Result<()> {
        let hostname = result.hostnames.first().map(|s| s.as_str()).unwrap_or("");

        let host_prefix = if hostname.is_empty() {
            format!("Host: {} ()   ", result.ip)
        } else {
            format!("Host: {} ({})", result.ip, hostname)
        };

        // Status line
        self.writer
            .write(&format!("{} Status: Up\n", host_prefix))?;

        // Ports line
        if !result.ports.is_empty() {
            let ports_str: Vec<String> = result
                .ports
                .iter()
                .map(|port| {
                    let protocol = match port.protocol {
                        Protocol::Tcp => "tcp",
                        Protocol::Udp => "udp",
                    };

                    let service = port.service.as_ref().map(|s| s.name.as_str()).unwrap_or("");

                    let product = port
                        .service
                        .as_ref()
                        .and_then(|s| s.product.as_ref())
                        .map(|p| p.as_str())
                        .unwrap_or("");

                    let version = port
                        .service
                        .as_ref()
                        .and_then(|s| s.version.as_ref())
                        .map(|v| format!(" {}/", v))
                        .unwrap_or_else(|| "/".to_string());

                    format!(
                        "{}/open/{}//{}/{}{}",
                        port.number, protocol, service, product, version
                    )
                })
                .collect();

            self.writer.write(&format!(
                "{} Ports: {}\n",
                host_prefix,
                ports_str.join(", ")
            ))?;
        }

        Ok(())
    }

    /// Write the footer
    pub fn end(&mut self, total_hosts: usize, alive_hosts: usize) -> io::Result<()> {
        self.end_time = Some(SystemTime::now());
        let elapsed = self
            .end_time
            .unwrap()
            .duration_since(self.start_time)
            .unwrap()
            .as_secs_f64();

        let timestr = format_time(self.end_time.unwrap(), TimeFormat::NmapFile);

        let es_total = if total_hosts > 1 { "es" } else { "" };
        let s_alive = if alive_hosts > 1 { "s" } else { "" };

        self.writer.write(&format!(
            "# Nmap done at {} -- {} IP address{} ({} host{} up) scanned in {:.2} seconds\n",
            timestr, total_hosts, es_total, alive_hosts, s_alive, elapsed
        ))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Port, Protocol, Service};
    use std::net::IpAddr;

    #[test]
    fn test_grep_formatter() {
        let mut formatter = GrepFormatter::new(SystemTime::now());
        formatter.start(&["192.168.1.1".to_string()]).unwrap();

        let result = ScanResult {
            ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
            ports: vec![
                Port {
                    number: 80,
                    protocol: Protocol::Tcp,
                    service: Some(Service {
                        name: "http".to_string(),
                        product: Some("nginx".to_string()),
                        version: Some("1.18.0".to_string()),
                        extra_info: None,
                        cpes: vec![],
                    }),
                },
                Port {
                    number: 443,
                    protocol: Protocol::Tcp,
                    service: Some(Service {
                        name: "https".to_string(),
                        product: None,
                        version: None,
                        extra_info: None,
                        cpes: vec![],
                    }),
                },
            ],
            os: None,
            hostnames: vec!["example.com".to_string()],
            tags: vec![],
            vulns: vec![],
        };

        formatter.write_result(&result).unwrap();
        formatter.end(1, 1).unwrap();
    }
}
