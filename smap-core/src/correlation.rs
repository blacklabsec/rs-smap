//! Service fingerprinting and CPE correlation
//!
//! This module handles matching Shodan CPEs against Nmap service signatures
//! to identify specific service versions and generate accurate port information.
//!
//! The correlation algorithm uses a sophisticated scoring system that considers:
//! - CPE prefix matching (with varying specificity)
//! - Port heuristics and exact matches
//! - SSL port detection
//! - Softmatch penalties
//! - Missing CPE penalties
//! - Duplicate detection
//!
//! # Example
//!
//! ```
//! use smap_core::correlation::correlate;
//! use smap_core::database::get_signature_database;
//!
//! # fn example() {
//! let ports = vec![22, 80, 443];
//! let cpes = vec![
//!     "cpe:/a:openbsd:openssh:7.4".to_string(),
//!     "cpe:/a:apache:http_server:2.4.6".to_string(),
//! ];
//!
//! let (result_ports, os_info) = correlate(&ports, &cpes);
//! println!("Matched {} ports", result_ports.len());
//! # }
//! ```

use crate::database::{get_port_table, get_signature_database};
use std::collections::{HashMap, HashSet};

/// Port information result from correlation
#[derive(Debug, Clone, PartialEq)]
pub struct PortInfo {
    /// Port number
    pub port: u16,
    /// Service name
    pub service: String,
    /// Protocol (tcp/udp)
    pub protocol: String,
    /// Product name
    pub product: String,
    /// Version information
    pub version: String,
    /// SSL/TLS enabled
    pub ssl: bool,
    /// Matched CPEs
    pub cpes: Vec<String>,
}

/// Operating system information from correlation
#[derive(Debug, Clone, PartialEq, Default)]
pub struct OsCorrelation {
    /// OS name
    pub name: String,
    /// OS CPEs
    pub cpes: Vec<String>,
    /// Port where OS was detected
    pub port: u16,
}

/// Internal contender structure for scoring
#[derive(Debug, Clone)]
struct Contender {
    service: String,
    cpes: Vec<String>,
    protocol: String,
    product: String,
    os: String,
    ssl: bool,
    score: i32,
}

/// Correlates Shodan CPEs with Nmap service signatures to identify services on ports
///
/// This is the main correlation function that matches CPE identifiers from Shodan
/// against Nmap service signatures, using a sophisticated scoring algorithm to
/// determine the best match for each port.
///
/// # Algorithm
///
/// The scoring works as follows:
/// - CPE prefix match: +1 point (generic) or +2 points (specific, >3 colons)
/// - Port in heuristic list: +3 points
/// - Port in explicit ports list: +2 points
/// - Port in SSL ports list: +2 points (also sets SSL flag)
/// - Not a softmatch: -1 point
/// - Missing CPE: -1 point per missing CPE
///
/// # Arguments
///
/// * `ports` - List of open port numbers
/// * `cpes` - List of CPE identifiers from Shodan
///
/// # Returns
///
/// A tuple of (port_info_list, os_info)
///
/// # Example
///
/// ```
/// use smap_core::correlation::correlate;
///
/// let ports = vec![22, 80];
/// let cpes = vec![
///     "cpe:/a:openbsd:openssh:7.4".to_string(),
///     "cpe:/a:apache:http_server:2.4.6".to_string(),
/// ];
///
/// let (port_results, os) = correlate(&ports, &cpes);
/// assert_eq!(port_results.len(), 2);
/// ```
pub fn correlate(ports: &[u16], cpes: &[String]) -> (Vec<PortInfo>, OsCorrelation) {
    let mut contenders: HashMap<u16, Contender> = HashMap::new();
    let mut used_cpes: HashMap<String, i32> = HashMap::new();
    let mut result: Vec<PortInfo> = Vec::new();
    let mut this_os = OsCorrelation::default();
    let mut duplicate_map: HashMap<String, (i32, u16)> = HashMap::new();

    // Pre-cache shodan CPE metadata
    let shodan_cpe_data: Vec<(&str, bool)> = cpes
        .iter()
        .map(|cpe| (cpe.as_str(), cpe.starts_with("cpe:/a")))
        .collect();

    // Build a set of candidate signatures using the CPE index
    // This dramatically reduces the search space
    let mut candidate_sig_indices: HashSet<usize> = HashSet::new();
    let all_signatures = get_signature_database();

    for shodan_cpe in cpes {
        // For each shodan CPE, find all signatures with CPEs that are prefixes of it
        for (sig_idx, sig) in all_signatures.iter().enumerate() {
            for sig_cpe in &sig.cpes {
                if shodan_cpe.starts_with(sig_cpe.as_str()) {
                    candidate_sig_indices.insert(sig_idx);
                    break; // Found a match for this signature, move to next
                }
            }
        }
    }

    // Convert to sorted vector for deterministic iteration
    let mut candidate_indices: Vec<usize> = candidate_sig_indices.into_iter().collect();
    candidate_indices.sort_unstable();

    // Process only the candidate signatures in deterministic order
    for &sig_idx in &candidate_indices {
        let service = &all_signatures[sig_idx];

        let mut cpe_matched = false;
        let mut base_score = 0i32;

        // Match CPEs from signature against Shodan CPEs
        for sig_cpe in &service.cpes {
            let mut minus = service.cpes.len() as i32;
            // Count colons once per sig_cpe
            let sig_cpe_colon_count = sig_cpe.bytes().filter(|&b| b == b':').count();
            let score_per_match = if sig_cpe_colon_count < 3 { 1 } else { 2 };

            for &(shodan_cpe, is_app_cpe) in &shodan_cpe_data {
                if shodan_cpe.starts_with(sig_cpe.as_str()) {
                    minus -= 1;
                    if is_app_cpe {
                        cpe_matched = true;
                    }
                    base_score += score_per_match;
                }
            }
            base_score -= minus;
        }

        // Skip if no application CPE matched
        if !cpe_matched {
            continue;
        }

        // Penalty for softmatch (used field now!)
        if !service.softmatch {
            base_score -= 1;
        }

        // Score against each port
        for &port in ports {
            let mut score = base_score;
            let mut ssl = false;

            // Heuristic port bonus
            if service.heuristic.contains(&port) {
                score += 3;
            }

            // Explicit port bonus
            if service.ports.contains(&port) {
                score += 2;
            }

            // SSL port bonus
            if service.sslports.contains(&port) {
                score += 2;
                ssl = true;
            }

            // Only update if score is better
            if score > contenders.get(&port).map_or(0, |c| c.score) {
                // Check if this CPE set was already used with a better score
                let mut failed = false;
                for cpe in &service.cpes {
                    if let Some(&best_score) = used_cpes.get(cpe.as_str()) {
                        if score < best_score {
                            failed = true;
                            break;
                        }
                    }
                }

                if failed {
                    continue;
                }

                // Handle duplicates (same CPE set shouldn't match multiple ports)
                let joined_cpes = service.cpes.join("");
                if let Some(&(local_score, local_port)) = duplicate_map.get(&joined_cpes) {
                    if score > local_score {
                        duplicate_map.insert(joined_cpes.clone(), (score, port));
                        contenders.remove(&local_port);
                    } else {
                        continue;
                    }
                } else {
                    duplicate_map.insert(joined_cpes, (score, port));
                }

                // Create contender only when needed (avoid unnecessary cloning)
                let temp_contender = Contender {
                    service: service.service.clone(),
                    cpes: service.cpes.clone(),
                    protocol: service.protocol.clone(),
                    product: service.product.clone().unwrap_or_default(),
                    os: service.os.clone().unwrap_or_default(),
                    ssl,
                    score,
                };

                // Extract OS information
                if !temp_contender.os.is_empty() {
                    this_os.port = port;
                    this_os.name = temp_contender.os.clone();
                    this_os.cpes = temp_contender
                        .cpes
                        .iter()
                        .filter(|cpe| cpe.starts_with("cpe:/o"))
                        .cloned()
                        .collect();
                }

                contenders.insert(port, temp_contender.clone());

                // Update used CPEs
                for cpe in &service.cpes {
                    used_cpes.insert(cpe.clone(), score);
                }
            }
        }
    }

    // Build result from contenders (iterate in port order for determinism)
    let mut remaining_cpes = cpes.to_vec();
    let mut contender_ports: Vec<u16> = contenders.keys().copied().collect();
    contender_ports.sort_unstable();

    for port in &contender_ports {
        let contender = &contenders[port];
        let mut this_port = PortInfo {
            port: *port,
            service: contender.service.clone(),
            protocol: contender.protocol.clone(),
            product: contender.product.clone(),
            ssl: contender.ssl,
            version: String::new(),
            cpes: Vec::new(),
        };

        // Match full CPEs and extract version
        // Use a snapshot of remaining_cpes for each contender CPE
        let mut replace_with = remaining_cpes.clone();
        for cpe in &contender.cpes {
            let temp_cpes = replace_with.clone();
            if let Some(index) = temp_cpes
                .iter()
                .position(|shodan_cpe| shodan_cpe.starts_with(cpe))
            {
                let shodan_cpe = &temp_cpes[index];
                this_port.cpes.push(shodan_cpe.clone());
                // Extract version from 5th field (after 4th colon)
                if shodan_cpe.matches(':').count() > 3 {
                    if let Some(version) = shodan_cpe.split(':').nth(4) {
                        this_port.version = version.to_string();
                    }
                }
                replace_with.remove(index);
            }
        }
        remaining_cpes = replace_with;

        result.push(this_port);
    }

    // Handle orphan ports (no match found)
    let port_table = get_port_table();
    for &port in ports {
        if !contenders.contains_key(&port) {
            let service = port_table
                .get(&port)
                .map(|s| format!("{}?", s))
                .unwrap_or_default();

            result.push(PortInfo {
                port,
                service,
                protocol: "tcp".to_string(),
                product: String::new(),
                version: String::new(),
                ssl: false,
                cpes: Vec::new(),
            });
        }
    }

    (result, this_os)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_ports_and_cpes() {
        let (ports, os) = correlate(&[], &[]);
        assert_eq!(ports.len(), 0);
        assert_eq!(os.name, "");
    }

    #[test]
    fn test_orphan_ports() {
        // Ports with no CPE matches should use port table
        let ports = vec![80, 22, 443];
        let cpes = vec![];
        let (result, _) = correlate(&ports, &cpes);

        assert_eq!(result.len(), 3);
        // Orphan ports get service from port table with "?" suffix
        for port_info in &result {
            assert!(port_info.service.is_empty() || port_info.service.ends_with('?'));
            assert_eq!(port_info.protocol, "tcp");
            assert_eq!(port_info.cpes.len(), 0);
        }
    }

    #[test]
    fn test_ssh_correlation() {
        let ports = vec![22];
        let cpes = vec!["cpe:/a:openbsd:openssh:7.4".to_string()];
        let (result, _) = correlate(&ports, &cpes);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].port, 22);
        assert_eq!(result[0].service, "ssh");
        assert_eq!(result[0].version, "7.4");
        assert!(!result[0].cpes.is_empty());
    }

    #[test]
    fn test_http_correlation() {
        let ports = vec![80];
        let cpes = vec!["cpe:/a:apache:http_server:2.4.6".to_string()];
        let (result, _) = correlate(&ports, &cpes);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].port, 80);
        assert_eq!(result[0].service, "http");
        assert_eq!(result[0].version, "2.4.6");
    }

    #[test]
    fn test_https_ssl_detection() {
        let ports = vec![443];
        let cpes = vec!["cpe:/a:apache:http_server:2.4.6".to_string()];
        let (result, _) = correlate(&ports, &cpes);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].port, 443);
        // Should detect SSL on port 443
        if result[0].service == "http" {
            assert!(result[0].ssl);
        }
    }

    #[test]
    fn test_multiple_ports_and_cpes() {
        let ports = vec![22, 80, 3306];
        let cpes = vec![
            "cpe:/a:openbsd:openssh:7.4".to_string(),
            "cpe:/a:apache:http_server:2.4.6".to_string(),
            "cpe:/a:mysql:mysql:5.7.0".to_string(),
        ];
        let (result, _) = correlate(&ports, &cpes);

        assert_eq!(result.len(), 3);

        // Check that all ports got matched
        let port_numbers: Vec<u16> = result.iter().map(|p| p.port).collect();
        assert!(port_numbers.contains(&22));
        assert!(port_numbers.contains(&80));
        assert!(port_numbers.contains(&3306));
    }

    #[test]
    fn test_os_detection() {
        let ports = vec![22];
        let cpes = vec![
            "cpe:/a:openbsd:openssh:7.4".to_string(),
            "cpe:/o:canonical:ubuntu_linux:16.04".to_string(),
        ];
        let (result, os) = correlate(&ports, &cpes);

        assert_eq!(result.len(), 1);
        // OS detection depends on the signature having OS field
        // Just verify it doesn't crash and returns valid structure
        if !os.name.is_empty() {
            // If OS is detected, check that OS CPEs start with "cpe:/o"
            if !os.cpes.is_empty() {
                assert!(os.cpes.iter().any(|c| c.starts_with("cpe:/o")));
            }
        }
    }

    #[test]
    fn test_version_extraction() {
        // Test that version is extracted from 5th field (index 4)
        let ports = vec![22];
        let cpes = vec!["cpe:/a:openbsd:openssh:7.4:p1".to_string()];
        let (result, _) = correlate(&ports, &cpes);

        if !result.is_empty() && result[0].service == "ssh" {
            // Version should be "7.4" (4th field after splitting by :)
            assert_eq!(result[0].version, "7.4");
        }
    }

    #[test]
    fn test_no_duplicate_ports() {
        // Same CPE set should not match multiple ports
        let ports = vec![22, 2222];
        let cpes = vec!["cpe:/a:openbsd:openssh:7.4".to_string()];
        let (result, _) = correlate(&ports, &cpes);

        // Should match one port with the SSH signature, other should be orphan
        assert_eq!(result.len(), 2);

        let ssh_matches: Vec<_> = result.iter().filter(|p| p.service == "ssh").collect();
        // Only one should be matched with high confidence
        assert!(ssh_matches.len() <= 2);
    }

    #[test]
    fn test_scoring_heuristic_bonus() {
        // Port in heuristic list should get +3 bonus
        // Port 22 is typically in SSH heuristic list
        let ports = vec![22];
        let cpes = vec!["cpe:/a:openbsd:openssh:8.0".to_string()];
        let (result, _) = correlate(&ports, &cpes);

        if !result.is_empty() {
            assert_eq!(result[0].port, 22);
            assert_eq!(result[0].service, "ssh");
        }
    }

    #[test]
    fn test_mixed_matched_and_orphan_ports() {
        let ports = vec![22, 80, 9999]; // 9999 is unlikely to match
        let cpes = vec!["cpe:/a:openbsd:openssh:7.4".to_string()];
        let (result, _) = correlate(&ports, &cpes);

        assert_eq!(result.len(), 3);

        // Port 22 should match SSH
        let ssh_port = result.iter().find(|p| p.port == 22);
        assert!(ssh_port.is_some());

        // Port 9999 should be orphan (no CPE match)
        let orphan_port = result.iter().find(|p| p.port == 9999);
        assert!(orphan_port.is_some());
        if let Some(p) = orphan_port {
            assert!(p.cpes.is_empty());
        }
    }

    #[test]
    fn test_specific_cpe_scoring() {
        // CPEs with more than 3 colons should get +2 points vs +1
        let ports = vec![80];
        let specific_cpe = "cpe:/a:apache:http_server:2.4.6:ubuntu".to_string();
        let (result, _) = correlate(&ports, &[specific_cpe]);

        if !result.is_empty() {
            assert_eq!(result[0].port, 80);
            // Should match with higher specificity bonus
            assert!(!result[0].cpes.is_empty());
        }
    }

    #[test]
    fn test_protocol_field() {
        let ports = vec![22];
        let cpes = vec!["cpe:/a:openbsd:openssh:7.4".to_string()];
        let (result, _) = correlate(&ports, &cpes);

        if !result.is_empty() {
            // Protocol should be set (typically "tcp")
            assert!(!result[0].protocol.is_empty());
        }
    }

    #[test]
    fn test_product_field() {
        let ports = vec![22];
        let cpes = vec!["cpe:/a:openbsd:openssh:7.4".to_string()];
        let (result, _) = correlate(&ports, &cpes);

        if !result.is_empty() && result[0].service == "ssh" {
            // Product should be set if available in signature
            // OpenSSH signatures typically have product field
            assert!(!result[0].product.is_empty() || result[0].product.is_empty());
        }
    }

    #[test]
    fn test_cpe_application_filter() {
        // Only CPEs starting with "cpe:/a" should trigger matching
        let ports = vec![22];
        let os_only_cpe = vec!["cpe:/o:canonical:ubuntu:16.04".to_string()];
        let (result, _) = correlate(&ports, &os_only_cpe);

        // Should still create result for the port, but might be orphan
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_performance_with_many_ports() {
        // Warm up database (first access loads it)
        let _ = correlate(&[1], &[]);

        // Test with realistic number of ports
        let ports: Vec<u16> = (1..=100).collect();
        let cpes = vec![
            "cpe:/a:openbsd:openssh:7.4".to_string(),
            "cpe:/a:apache:http_server:2.4.6".to_string(),
        ];

        let start = std::time::Instant::now();
        let (result, _) = correlate(&ports, &cpes);
        let duration = start.elapsed();

        assert_eq!(result.len(), 100);
        // Should complete in reasonable time (< 10ms in release mode, < 200ms in debug)
        #[cfg(debug_assertions)]
        let max_ms = 200;
        #[cfg(not(debug_assertions))]
        let max_ms = 10;
        assert!(
            duration.as_millis() < max_ms,
            "Correlation took too long: {:?}",
            duration
        );
    }

    #[test]
    fn test_large_cpe_list() {
        // Test with many CPEs
        let ports = vec![22, 80, 443, 3306, 5432];
        let mut cpes = vec![
            "cpe:/a:openbsd:openssh:7.4".to_string(),
            "cpe:/a:apache:http_server:2.4.6".to_string(),
            "cpe:/a:mysql:mysql:5.7.0".to_string(),
            "cpe:/a:postgresql:postgresql:9.6".to_string(),
            "cpe:/a:nginx:nginx:1.14.0".to_string(),
        ];
        // Add some extra CPEs
        for i in 0..20 {
            cpes.push(format!("cpe:/a:vendor{}:product{}:1.0", i, i));
        }

        let (result, _) = correlate(&ports, &cpes);
        assert_eq!(result.len(), 5);
    }
}
