//! Target IP and hostname parsing and expansion
//!
//! This module handles parsing various target formats including:
//! - Individual IP addresses (e.g., `192.168.1.1`)
//! - CIDR ranges (e.g., `192.168.1.0/24`)
//! - Hostnames (e.g., `example.com`)
//! - IP ranges (e.g., `192.168.1.1-254`, `192.168.1-5.1`)
//! - Files containing lists of targets
//!
//! # Example
//!
//! ```
//! use smap_core::targets::TargetParser;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let parser = TargetParser::new();
//! let targets = parser.parse("192.168.1.0/24")?;
//! assert!(!targets.is_empty());
//! # Ok(())
//! # }
//! ```

use crate::error::{Error, Result};
use cidr::IpCidr;
use publicsuffix::{List, Psl};
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::str::FromStr;

/// Handles parsing and expansion of target specifications
#[derive(Debug)]
pub struct TargetParser {
    /// Maximum number of IPs to expand from a CIDR range (safety limit)
    max_targets: usize,
    /// Public suffix list for domain validation
    psl: Option<List>,
}

impl Default for TargetParser {
    fn default() -> Self {
        Self::new()
    }
}

impl TargetParser {
    /// Creates a new target parser with default settings
    pub fn new() -> Self {
        Self {
            max_targets: 65536, // Default limit
            psl: Some(List::new()),
        }
    }

    /// Creates a parser with a custom target limit
    pub fn with_limit(max_targets: usize) -> Self {
        Self {
            max_targets,
            psl: Some(List::new()),
        }
    }

    /// Parses a target specification into a list of IP addresses
    ///
    /// # Arguments
    ///
    /// * `target` - A target specification (IP, CIDR, hostname, range)
    ///
    /// # Errors
    ///
    /// Returns an error if the target specification is invalid or exceeds limits
    pub fn parse(&self, target: &str) -> Result<Vec<IpAddr>> {
        let target = target.trim();

        // Try to parse as single IP address first
        if let Ok(ip) = IpAddr::from_str(target) {
            return Ok(vec![ip]);
        }

        // Try to parse as CIDR range
        if let Ok(cidr) = IpCidr::from_str(target) {
            return self.expand_cidr(cidr);
        }

        // Try to parse as IP range (e.g., 192.168.1.1-254)
        if let Ok(ips) = self.parse_ip_range(target) {
            return Ok(ips);
        }

        // Hostname - return as invalid for now (sync parsing)
        // Use parse_hostname_async for actual resolution
        Err(Error::InvalidInput(format!(
            "Invalid target specification or hostname (use parse_hostname_async): {}",
            target
        )))
    }

    /// Parses a hostname and resolves it asynchronously
    ///
    /// # Arguments
    ///
    /// * `hostname` - A hostname to resolve
    ///
    /// # Errors
    ///
    /// Returns an error if the hostname is invalid or cannot be resolved
    pub async fn parse_hostname_async(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        let hostname = hostname.trim();

        // Validate domain using public suffix list if available
        if let Some(ref psl) = self.psl {
            // Parse and validate the domain
            if let Ok(domain_str) = std::str::from_utf8(hostname.as_bytes()) {
                // Use the public suffix list to check if it's a valid domain
                if let Some(_suffix) = psl.suffix(domain_str.as_bytes()) {
                    // Valid domain with recognized suffix
                } else {
                    // Not a recognized domain, but we'll still try to resolve it
                    // as it might be a local hostname
                }
            }
        }

        // Perform DNS resolution
        match tokio::net::lookup_host(format!("{}:0", hostname)).await {
            Ok(addrs) => {
                let ips: Vec<IpAddr> = addrs.map(|addr| addr.ip()).collect();
                if ips.is_empty() {
                    return Err(Error::InvalidInput(format!(
                        "No IP addresses found for hostname: {}",
                        hostname
                    )));
                }
                Ok(ips)
            }
            Err(e) => Err(Error::InvalidInput(format!(
                "Failed to resolve hostname {}: {}",
                hostname, e
            ))),
        }
    }

    /// Parses targets from a file
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file containing targets (one per line)
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read
    pub fn parse_file(&self, path: impl AsRef<Path>) -> Result<Vec<String>> {
        let content = fs::read_to_string(path.as_ref())?;
        Ok(content
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(String::from)
            .collect())
    }

    /// Expands a CIDR range into individual IP addresses
    fn expand_cidr(&self, cidr: IpCidr) -> Result<Vec<IpAddr>> {
        let addresses: Vec<IpAddr> = cidr.iter().map(|ip| ip.address()).collect();

        if addresses.len() > self.max_targets {
            return Err(Error::InvalidInput(format!(
                "CIDR range too large: {} addresses (max: {})",
                addresses.len(),
                self.max_targets
            )));
        }

        Ok(addresses)
    }

    /// Parses IP ranges in various formats
    ///
    /// Supports:
    /// - `192.168.1.1-254` (last octet range)
    /// - `192.168.1-5.1` (third octet range)
    /// - `192.168.1.1-192.168.1.254` (full range)
    fn parse_ip_range(&self, target: &str) -> Result<Vec<IpAddr>> {
        if !target.contains('-') {
            return Err(Error::InvalidInput("Not a range".to_string()));
        }

        // Try to parse as full range (IP1-IP2)
        if let Some((start_str, end_str)) = target.split_once('-') {
            let start_str = start_str.trim();
            let end_str = end_str.trim();

            // Check if it's a simple last octet range (192.168.1.1-254)
            if let Ok(start_ip) = Ipv4Addr::from_str(start_str) {
                if !end_str.contains('.') {
                    // Last octet range
                    if let Ok(end_octet) = end_str.parse::<u8>() {
                        return self.expand_last_octet_range(start_ip, end_octet);
                    }
                } else if let Ok(end_ip) = Ipv4Addr::from_str(end_str) {
                    // Full IP range
                    return self.expand_full_range(start_ip, end_ip);
                }
            }

            // Check for third octet range (192.168.1-5.1)
            if let Ok(ips) = self.parse_octet_range(target) {
                return Ok(ips);
            }
        }

        Err(Error::InvalidInput(format!("Invalid IP range: {}", target)))
    }

    /// Expands a last octet range (e.g., 192.168.1.1-254)
    fn expand_last_octet_range(&self, start: Ipv4Addr, end_octet: u8) -> Result<Vec<IpAddr>> {
        let octets = start.octets();
        let start_octet = octets[3];

        if end_octet < start_octet {
            return Err(Error::InvalidInput(format!(
                "Invalid range: end ({}) < start ({})",
                end_octet, start_octet
            )));
        }

        let count = (end_octet - start_octet + 1) as usize;
        if count > self.max_targets {
            return Err(Error::InvalidInput(format!(
                "Range too large: {} addresses (max: {})",
                count, self.max_targets
            )));
        }

        let ips: Vec<IpAddr> = (start_octet..=end_octet)
            .map(|octet| IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octet)))
            .collect();

        Ok(ips)
    }

    /// Expands a full IP range (e.g., 192.168.1.1-192.168.1.254)
    fn expand_full_range(&self, start: Ipv4Addr, end: Ipv4Addr) -> Result<Vec<IpAddr>> {
        let start_num = u32::from(start);
        let end_num = u32::from(end);

        if end_num < start_num {
            return Err(Error::InvalidInput(
                "Invalid range: end IP < start IP".to_string(),
            ));
        }

        let count = (end_num - start_num + 1) as usize;
        if count > self.max_targets {
            return Err(Error::InvalidInput(format!(
                "Range too large: {} addresses (max: {})",
                count, self.max_targets
            )));
        }

        let ips: Vec<IpAddr> = (start_num..=end_num)
            .map(|num| IpAddr::V4(Ipv4Addr::from(num)))
            .collect();

        Ok(ips)
    }

    /// Parses octet range format (e.g., 192.168.1-5.1)
    fn parse_octet_range(&self, target: &str) -> Result<Vec<IpAddr>> {
        let parts: Vec<&str> = target.split('.').collect();
        if parts.len() != 4 {
            return Err(Error::InvalidInput("Not a valid octet range".to_string()));
        }

        // Find which octet has the range
        let mut range_index = None;
        let mut range_start = 0u8;
        let mut range_end = 0u8;

        for (i, part) in parts.iter().enumerate() {
            if part.contains('-') {
                if let Some((start_str, end_str)) = part.split_once('-') {
                    range_start = start_str.parse().map_err(|_| {
                        Error::InvalidInput("Invalid octet range start".to_string())
                    })?;
                    range_end = end_str
                        .parse()
                        .map_err(|_| Error::InvalidInput("Invalid octet range end".to_string()))?;
                    range_index = Some(i);
                    break;
                }
            }
        }

        let range_index = range_index.ok_or_else(|| {
            Error::InvalidInput("No range found in octet specification".to_string())
        })?;

        if range_end < range_start {
            return Err(Error::InvalidInput(format!(
                "Invalid range: {} > {}",
                range_start, range_end
            )));
        }

        let count = (range_end - range_start + 1) as usize;
        if count > self.max_targets {
            return Err(Error::InvalidInput(format!(
                "Range too large: {} addresses (max: {})",
                count, self.max_targets
            )));
        }

        // Parse fixed octets
        let mut fixed_octets = [0u8; 4];
        for (i, part) in parts.iter().enumerate() {
            if i != range_index {
                fixed_octets[i] = part
                    .parse()
                    .map_err(|_| Error::InvalidInput(format!("Invalid octet: {}", part)))?;
            }
        }

        // Generate IPs
        let mut ips = Vec::new();
        for octet_val in range_start..=range_end {
            let mut octets = fixed_octets;
            octets[range_index] = octet_val;
            ips.push(IpAddr::V4(Ipv4Addr::new(
                octets[0], octets[1], octets[2], octets[3],
            )));
        }

        Ok(ips)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_single_ipv4() {
        let parser = TargetParser::new();
        let targets = parser.parse("192.168.1.1").unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].to_string(), "192.168.1.1");
    }

    #[test]
    fn test_parse_single_ipv6() {
        let parser = TargetParser::new();
        let targets = parser.parse("::1").unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].to_string(), "::1");
    }

    #[test]
    fn test_parse_cidr_ipv4() {
        let parser = TargetParser::new();
        let targets = parser.parse("192.168.1.0/30").unwrap();
        assert_eq!(targets.len(), 4);
        assert_eq!(targets[0].to_string(), "192.168.1.0");
        assert_eq!(targets[3].to_string(), "192.168.1.3");
    }

    #[test]
    fn test_parse_cidr_ipv6() {
        let parser = TargetParser::new();
        let targets = parser.parse("2001:db8::/126").unwrap();
        assert_eq!(targets.len(), 4);
    }

    #[test]
    fn test_parse_cidr_large() {
        let parser = TargetParser::new();
        let targets = parser.parse("10.0.0.0/24").unwrap();
        assert_eq!(targets.len(), 256);
    }

    #[test]
    fn test_invalid_target() {
        let parser = TargetParser::new();
        assert!(parser.parse("not-a-valid-ip").is_err());
        assert!(parser.parse("999.999.999.999").is_err());
    }

    #[test]
    fn test_cidr_limit() {
        let parser = TargetParser::with_limit(2);
        assert!(parser.parse("192.168.1.0/30").is_err());
    }

    #[test]
    fn test_cidr_within_limit() {
        let parser = TargetParser::with_limit(10);
        let targets = parser.parse("192.168.1.0/30").unwrap();
        assert_eq!(targets.len(), 4);
    }

    #[test]
    fn test_last_octet_range() {
        let parser = TargetParser::new();
        let targets = parser.parse("192.168.1.1-5").unwrap();
        assert_eq!(targets.len(), 5);
        assert_eq!(targets[0].to_string(), "192.168.1.1");
        assert_eq!(targets[4].to_string(), "192.168.1.5");
    }

    #[test]
    fn test_last_octet_range_large() {
        let parser = TargetParser::new();
        let targets = parser.parse("192.168.1.1-254").unwrap();
        assert_eq!(targets.len(), 254);
        assert_eq!(targets[0].to_string(), "192.168.1.1");
        assert_eq!(targets[253].to_string(), "192.168.1.254");
    }

    #[test]
    fn test_full_ip_range() {
        let parser = TargetParser::new();
        let targets = parser.parse("192.168.1.1-192.168.1.5").unwrap();
        assert_eq!(targets.len(), 5);
        assert_eq!(targets[0].to_string(), "192.168.1.1");
        assert_eq!(targets[4].to_string(), "192.168.1.5");
    }

    #[test]
    fn test_third_octet_range() {
        let parser = TargetParser::new();
        let targets = parser.parse("192.168.1-3.1").unwrap();
        assert_eq!(targets.len(), 3);
        assert_eq!(targets[0].to_string(), "192.168.1.1");
        assert_eq!(targets[1].to_string(), "192.168.2.1");
        assert_eq!(targets[2].to_string(), "192.168.3.1");
    }

    #[test]
    fn test_second_octet_range() {
        let parser = TargetParser::new();
        let targets = parser.parse("192.0-2.168.1").unwrap();
        assert_eq!(targets.len(), 3);
        assert_eq!(targets[0].to_string(), "192.0.168.1");
        assert_eq!(targets[1].to_string(), "192.1.168.1");
        assert_eq!(targets[2].to_string(), "192.2.168.1");
    }

    #[test]
    fn test_invalid_range_reversed() {
        let parser = TargetParser::new();
        assert!(parser.parse("192.168.1.254-1").is_err());
        assert!(parser.parse("192.168.1.5-192.168.1.1").is_err());
    }

    #[test]
    fn test_range_too_large() {
        let parser = TargetParser::with_limit(100);
        assert!(parser.parse("192.168.1.1-254").is_err());
    }

    #[test]
    fn test_parse_file() -> Result<()> {
        let mut tmpfile = NamedTempFile::new()?;
        writeln!(tmpfile, "192.168.1.1")?;
        writeln!(tmpfile, "192.168.1.2")?;
        writeln!(tmpfile, "# This is a comment")?;
        writeln!(tmpfile)?;
        writeln!(tmpfile, "192.168.1.3")?;
        tmpfile.flush()?;

        let parser = TargetParser::new();
        let targets = parser.parse_file(tmpfile.path())?;
        assert_eq!(targets.len(), 3);
        assert_eq!(targets[0], "192.168.1.1");
        assert_eq!(targets[1], "192.168.1.2");
        assert_eq!(targets[2], "192.168.1.3");
        Ok(())
    }

    #[test]
    fn test_parse_file_empty() -> Result<()> {
        let tmpfile = NamedTempFile::new()?;
        let parser = TargetParser::new();
        let targets = parser.parse_file(tmpfile.path())?;
        assert_eq!(targets.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn test_hostname_resolution_localhost() {
        let parser = TargetParser::new();
        let result = parser.parse_hostname_async("localhost").await;
        // Localhost should resolve, but we don't assert on specific IPs
        // as it can vary by system
        assert!(result.is_ok());
        let ips = result.unwrap();
        assert!(!ips.is_empty());
    }

    #[test]
    fn test_whitespace_handling() {
        let parser = TargetParser::new();
        let targets = parser.parse("  192.168.1.1  ").unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].to_string(), "192.168.1.1");
    }

    #[test]
    fn test_cidr_slash_32() {
        let parser = TargetParser::new();
        let targets = parser.parse("192.168.1.1/32").unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].to_string(), "192.168.1.1");
    }

    #[test]
    fn test_cidr_slash_16() {
        let parser = TargetParser::with_limit(100000);
        let targets = parser.parse("192.168.0.0/16").unwrap();
        assert_eq!(targets.len(), 65536);
    }

    #[test]
    fn test_range_single_ip() {
        let parser = TargetParser::new();
        let targets = parser.parse("192.168.1.5-5").unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].to_string(), "192.168.1.5");
    }
}
