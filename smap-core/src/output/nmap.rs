//! Nmap-compatible text output format

use crate::output::common::{format_time, get_command, pad_right, OutputWriter, TimeFormat};
use crate::types::{Protocol, ScanResult};
use std::io;
use std::time::SystemTime;

/// Nmap output formatter
///
/// Produces output compatible with Nmap's normal (-oN) format.
///
/// # Examples
///
/// ```no_run
/// use smap_core::output::nmap::NmapFormatter;
/// use std::time::SystemTime;
///
/// let mut formatter = NmapFormatter::new(SystemTime::now());
/// formatter.start(&["192.168.1.1".to_string()], false).unwrap();
/// // Add scan results...
/// formatter.end(100, 50).unwrap();
/// ```
pub struct NmapFormatter {
    writer: OutputWriter,
    start_time: SystemTime,
    end_time: Option<SystemTime>,
    args: Vec<String>,
}

impl NmapFormatter {
    /// Create a new NmapFormatter writing to stdout
    pub fn new(start_time: SystemTime) -> Self {
        Self {
            writer: OutputWriter::stdout(),
            start_time,
            end_time: None,
            args: Vec::new(),
        }
    }

    /// Create a new NmapFormatter writing to a file
    pub fn new_with_file(start_time: SystemTime, path: &str) -> io::Result<Self> {
        Ok(Self {
            writer: OutputWriter::file(path)?,
            start_time,
            end_time: None,
            args: Vec::new(),
        })
    }

    /// Write the start header
    pub fn start(&mut self, args: &[String], is_file: bool) -> io::Result<()> {
        self.args = args.to_vec();
        let cmd = get_command(args);

        if is_file {
            let timestr = format_time(self.start_time, TimeFormat::NmapFile);
            self.writer.write(&format!(
                "# Starting Nmap 9.99 ( https://nmap.org ) at {} as: {}\n",
                timestr, cmd
            ))?;
        } else {
            let timestr = format_time(self.start_time, TimeFormat::NmapStdout);
            self.writer.write(&format!(
                "Starting Nmap 9.99 ( https://nmap.org ) at {}\n",
                timestr
            ))?;
        }

        Ok(())
    }

    /// Format and write a scan result
    pub fn write_result(&mut self, result: &ScanResult) -> io::Result<()> {
        if result.ports.is_empty() {
            return Ok(());
        }

        // Calculate column widths
        let mut longest_port = 5; // "PORT "
        let mut longest_service = 7; // "SERVICE"

        for port in &result.ports {
            let port_str = format!("{}/{}", port.number, protocol_to_str(port.protocol));
            if port_str.len() > longest_port {
                longest_port = port_str.len();
            }

            if let Some(ref service) = port.service {
                if service.name.len() > longest_service {
                    longest_service = service.name.len();
                }
            }
        }

        // Write header
        let mut output = String::new();

        // Hostname information
        if !result.hostnames.is_empty() {
            output.push_str(&format!(
                "Nmap scan report for {} ({})\nHost is up.\n\n",
                result.hostnames[0], result.ip
            ));
        } else {
            output.push_str(&format!(
                "Nmap scan report for {}\nHost is up.\n\n",
                result.ip
            ));
        }

        // Port table header
        output.push_str(&format!(
            "{}  STATE   {}  VERSION\n",
            pad_right("PORT", longest_port),
            pad_right("SERVICE", longest_service)
        ));

        // Service info line
        let mut service_info = String::new();

        // Port entries
        for port in &result.ports {
            let port_str = format!("{}/{}", port.number, protocol_to_str(port.protocol));
            let service_name = port.service.as_ref().map(|s| s.name.as_str()).unwrap_or("");

            let mut product_line = String::new();
            if let Some(ref service) = port.service {
                if let Some(ref product) = service.product {
                    product_line.push_str(product);
                    if let Some(ref version) = service.version {
                        product_line.push(' ');
                        product_line.push_str(version);
                    }
                }
            }

            output.push_str(&format!(
                "{}  open    {}  {}\n",
                pad_right(&port_str, longest_port),
                pad_right(service_name, longest_service),
                product_line
            ));

            // Check if OS info should be added for this port
            if let Some(ref os) = result.os {
                if port.service.is_some() {
                    // Check if any CPE matches the OS name
                    if service_info.is_empty() {
                        service_info = format!("Service Info: OS: {}", os.name);
                        for cpe in &os.cpes {
                            if cpe.to_lowercase().contains(&os.name.to_lowercase()) {
                                service_info.push_str(&format!("; CPE: {}", cpe));
                                break;
                            }
                        }
                        service_info.push('\n');
                    }
                }
            }
        }

        output.push_str(&service_info);
        output.push('\n');

        self.writer.write(&output)?;

        Ok(())
    }

    /// Write the service detection message
    pub fn write_service_detection(&mut self) -> io::Result<()> {
        self.writer.write("Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .\n")
    }

    /// Write the end footer
    pub fn end(&mut self, total_hosts: usize, alive_hosts: usize) -> io::Result<()> {
        self.end_time = Some(SystemTime::now());
        let elapsed = self
            .end_time
            .unwrap()
            .duration_since(self.start_time)
            .unwrap()
            .as_secs_f64();

        let is_file = self.writer.destination() != "-";

        let es_total = if total_hosts > 1 { "es" } else { "" };
        let s_alive = if alive_hosts > 1 { "s" } else { "" };

        if is_file {
            let timestr = format_time(self.end_time.unwrap(), TimeFormat::NmapFile);
            self.writer.write(&format!(
                "# Nmap done at {} -- {} IP address{} ({} host{} up) scanned in {:.2} seconds\n",
                timestr, total_hosts, es_total, alive_hosts, s_alive, elapsed
            ))?;
        } else {
            self.writer.write(&format!(
                "Nmap done: {} IP address{} ({} host{} up) scanned in {:.2} seconds\n",
                total_hosts, es_total, alive_hosts, s_alive, elapsed
            ))?;
        }

        Ok(())
    }
}

fn protocol_to_str(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Port, Service};
    use std::net::IpAddr;

    #[test]
    fn test_nmap_formatter() {
        let mut formatter = NmapFormatter::new(SystemTime::now());
        formatter
            .start(&["192.168.1.1".to_string()], false)
            .unwrap();

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
            hostnames: vec![],
            cpes: vec![],
            tags: vec![],
            vulns: vec![],
        };

        formatter.write_result(&result).unwrap();
        formatter.write_service_detection().unwrap();
        formatter.end(1, 1).unwrap();
    }
}
