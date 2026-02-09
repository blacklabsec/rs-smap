//! XML output format (Nmap-compatible)

use crate::output::common::{format_time, get_command, OutputWriter, TimeFormat};
use crate::types::{OsInfo, Protocol, ScanResult};
use std::io;
use std::time::SystemTime;

/// XML output formatter
///
/// Produces output compatible with Nmap's XML (-oX) format.
pub struct XmlFormatter {
    writer: OutputWriter,
    start_time: SystemTime,
    end_time: Option<SystemTime>,
    args: Vec<String>,
}

impl XmlFormatter {
    /// Create a new XmlFormatter writing to stdout
    pub fn new(start_time: SystemTime) -> Self {
        Self {
            writer: OutputWriter::stdout(),
            start_time,
            end_time: None,
            args: Vec::new(),
        }
    }

    /// Create a new XmlFormatter writing to a file
    pub fn new_with_file(start_time: SystemTime, path: &str) -> io::Result<Self> {
        Ok(Self {
            writer: OutputWriter::file(path)?,
            start_time,
            end_time: None,
            args: Vec::new(),
        })
    }

    /// Write the XML header
    pub fn start(&mut self, args: &[String], port_spec: &str, num_ports: usize) -> io::Result<()> {
        self.args = args.to_vec();
        let cmd = get_command(args);
        let timestr = format_time(self.start_time, TimeFormat::NmapFile);
        let unix_time = format_time(self.start_time, TimeFormat::Unix);

        let header = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 9.99 scan initiated {} as: {} -->
<nmaprun scanner="nmap" args="{}" start="{}" startstr="{}" version="9.99" xmloutputversion="1.04">
<scaninfo type="connect" protocol="tcp" numservices="{}" services="{}"/>
<verbose level="0"/>
<debugging level="0"/>
"#,
            timestr, cmd, cmd, unix_time, timestr, num_ports, port_spec
        );

        self.writer.write(&header)?;
        Ok(())
    }

    /// Write a scan result
    pub fn write_result(
        &mut self,
        result: &ScanResult,
        start_time: SystemTime,
        end_time: SystemTime,
    ) -> io::Result<()> {
        let start_unix = format_time(start_time, TimeFormat::Unix);
        let end_unix = format_time(end_time, TimeFormat::Unix);

        let mut output = format!(
            r#"<host starttime="{}" endtime="{}"><status state="up" reason="syn-ack" reason_ttl="0"/>
<address addr="{}" addrtype="ipv4"/>
<hostnames>
"#,
            start_unix, end_unix, result.ip
        );

        // Hostnames
        for hostname in &result.hostnames {
            output.push_str(&format!(
                r#"<hostname name="{}" type="PTR"/>
"#,
                hostname
            ));
        }

        output.push_str("</hostnames>\n<ports>");

        // Ports
        for port in &result.ports {
            output.push_str(&self.port_to_xml(port, result.os.as_ref()));
        }

        output.push_str(
            "</ports>\n<times srtt=\"247120\" rttvar=\"185695\" to=\"989900\"/>\n</host>\n",
        );

        self.writer.write(&output)?;
        Ok(())
    }

    fn port_to_xml(&self, port: &crate::types::Port, os_info: Option<&OsInfo>) -> String {
        let protocol = match port.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        };

        let mut xml = format!(
            r#"<port protocol="{}" portid="{}"><state state="open" reason="syn-ack" reason_ttl="0"/>"#,
            protocol, port.number
        );

        if let Some(ref service) = port.service {
            xml.push_str(&format!(r#"<service name="{}""#, service.name));

            if let Some(ref product) = service.product {
                xml.push_str(&format!(r#" product="{}""#, product));
            }

            if let Some(ref version) = service.version {
                xml.push_str(&format!(r#" version="{}""#, version));
            }

            // Check if OS info matches this port
            if let Some(os) = os_info {
                xml.push_str(&format!(
                    r#" ostype="{}" method="probed" conf="8">"#,
                    os.name
                ));
            } else if service.name.ends_with('?') {
                xml.push_str(r#" method="table" conf="3">"#);
            } else {
                xml.push_str(r#" method="probed" conf="8">"#);
            }

            // CPEs
            for cpe in &service.cpes {
                xml.push_str(&format!("<cpe>{}</cpe>", cpe));
            }

            xml.push_str("</service>");
        }

        xml.push_str("</port>\n");
        xml
    }

    /// Write the XML footer
    pub fn end(&mut self, total_hosts: usize, alive_hosts: usize) -> io::Result<()> {
        self.end_time = Some(SystemTime::now());
        let elapsed = self
            .end_time
            .unwrap()
            .duration_since(self.start_time)
            .unwrap()
            .as_secs_f64();

        let timestr = format_time(self.end_time.unwrap(), TimeFormat::NmapFile);
        let unix_time = format_time(self.end_time.unwrap(), TimeFormat::Unix);

        let footer = format!(
            r#"<runstats><finished time="{}" timestr="{}" elapsed="{:.2}" summary="Nmap done at {}; {} IP addresses ({} hosts up) scanned in {:.2} seconds" exit="success"/><hosts up="{}" down="{}" total="{}"/>
</runstats>
</nmaprun>
"#,
            unix_time,
            timestr,
            elapsed,
            timestr,
            total_hosts,
            alive_hosts,
            elapsed,
            alive_hosts,
            total_hosts - alive_hosts,
            total_hosts
        );

        self.writer.write(&footer)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Port, Protocol, Service};
    use std::net::IpAddr;

    #[test]
    fn test_xml_formatter() {
        let mut formatter = XmlFormatter::new(SystemTime::now());
        formatter
            .start(&["192.168.1.1".to_string()], "80", 1)
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
                    cpes: vec!["cpe:/a:nginx:nginx:1.18.0".to_string()],
                }),
            }],
            os: None,
            hostnames: vec!["example.com".to_string()],
            cpes: vec![],
            tags: vec![],
            vulns: vec![],
        };

        let start = SystemTime::now();
        let end = SystemTime::now();
        formatter.write_result(&result, start, end).unwrap();
        formatter.end(1, 1).unwrap();
    }
}
