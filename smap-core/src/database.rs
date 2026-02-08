//! Nmap signature database management
//!
//! This module handles loading, parsing, and managing Nmap service signature databases
//! for service fingerprinting and identification.
//!
//! The database is lazily loaded from embedded JSON files at compile time and parsed
//! on first access. This ensures minimal memory overhead and fast startup.
//!
//! # Example
//!
//! ```
//! use smap_core::database::{get_signature_database, get_port_table};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Access the global signature database (lazy loaded)
//! let db = get_signature_database();
//! println!("Loaded {} signatures", db.len());
//!
//! // Lookup service by port
//! if let Some(service) = get_port_table().get(&80) {
//!     println!("Port 80 is typically: {}", service);
//! }
//! # Ok(())
//! # }
//! ```

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Embedded Nmap service signatures JSON (~8.5MB)
const NMAP_SIGS_JSON: &str = include_str!("../data/nmap_sigs.json");

/// Embedded Nmap port-to-service table JSON (~162KB)
const NMAP_TABLE_JSON: &str = include_str!("../data/nmap_table.json");

/// A service signature entry from the Nmap database
///
/// This struct matches the JSON schema from nmap-service-probes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSignature {
    /// Service name (e.g., "http", "ssh", "mysql")
    pub service: String,

    /// Common Platform Enumeration identifiers
    #[serde(default)]
    pub cpes: Vec<String>,

    /// Protocol (typically "tcp" or "udp")
    pub protocol: String,

    /// Whether this is a soft match (less confident)
    #[serde(default)]
    pub softmatch: bool,

    /// Product name/version pattern (optional)
    #[serde(default)]
    pub product: Option<String>,

    /// Operating system (optional)
    #[serde(default)]
    pub os: Option<String>,

    /// Device type (optional, e.g., "router", "printer", "specialized")
    #[serde(default)]
    pub devicetype: Option<String>,

    /// Heuristic port numbers where this service is commonly found
    #[serde(default)]
    pub heuristic: Vec<u16>,

    /// Explicitly defined ports (optional)
    #[serde(default)]
    pub ports: Vec<u16>,

    /// SSL/TLS ports where this service may run (optional)
    #[serde(default)]
    pub sslports: Vec<u16>,
}

/// Global lazy-loaded signature database
///
/// Signatures are parsed from embedded JSON on first access.
/// Typical load time: 50-100ms for ~463K lines.
static SIGNATURES: Lazy<Vec<ServiceSignature>> = Lazy::new(|| {
    serde_json::from_str(NMAP_SIGS_JSON)
        .expect("Failed to parse embedded nmap_sigs.json - this is a build-time error")
});

/// Global lazy-loaded port-to-service mapping table
///
/// Maps port numbers (as strings in JSON) to service names.
static PORT_TABLE: Lazy<HashMap<u16, String>> = Lazy::new(|| {
    let raw: HashMap<String, String> = serde_json::from_str(NMAP_TABLE_JSON)
        .expect("Failed to parse embedded nmap_table.json - this is a build-time error");

    raw.into_iter()
        .filter_map(|(k, v)| k.parse::<u16>().ok().map(|port| (port, v)))
        .collect()
});

/// Index mapping service names to signature indices (lazy loaded)
static SERVICE_INDEX: Lazy<HashMap<String, Vec<usize>>> = Lazy::new(|| {
    let mut index: HashMap<String, Vec<usize>> = HashMap::new();

    for (i, sig) in SIGNATURES.iter().enumerate() {
        index.entry(sig.service.clone()).or_default().push(i);
    }

    index
});

/// Index mapping ports to signature indices (lazy loaded)
static PORT_INDEX: Lazy<HashMap<u16, Vec<usize>>> = Lazy::new(|| {
    let mut index: HashMap<u16, Vec<usize>> = HashMap::new();

    for (i, sig) in SIGNATURES.iter().enumerate() {
        // Index by heuristic ports
        for &port in &sig.heuristic {
            index.entry(port).or_default().push(i);
        }
        // Index by explicit ports
        for &port in &sig.ports {
            index.entry(port).or_default().push(i);
        }
        // Index by SSL ports
        for &port in &sig.sslports {
            index.entry(port).or_default().push(i);
        }
    }

    index
});

/// Index mapping CPE prefixes to signature indices (lazy loaded)
/// This allows O(1) lookup of signatures by CPE prefix
static CPE_INDEX: Lazy<HashMap<String, Vec<usize>>> = Lazy::new(|| {
    let mut index: HashMap<String, Vec<usize>> = HashMap::new();

    for (i, sig) in SIGNATURES.iter().enumerate() {
        for cpe in &sig.cpes {
            index.entry(cpe.clone()).or_default().push(i);
        }
    }

    index
});

/// Returns a reference to the global signature database
///
/// The database is lazily loaded and parsed on first call.
/// Subsequent calls return the cached reference with no overhead.
///
/// # Performance
///
/// - First call: ~50-100ms (parsing JSON)
/// - Subsequent calls: <1μs (reference lookup)
///
/// # Example
///
/// ```
/// use smap_core::database::get_signature_database;
///
/// let signatures = get_signature_database();
/// println!("Total signatures: {}", signatures.len());
/// ```
pub fn get_signature_database() -> &'static [ServiceSignature] {
    &SIGNATURES
}

/// Returns a reference to the global port table
///
/// Maps port numbers to their common service names.
///
/// # Example
///
/// ```
/// use smap_core::database::get_port_table;
///
/// let table = get_port_table();
/// if let Some(service) = table.get(&22) {
///     assert_eq!(service, "ssh");
/// }
/// ```
pub fn get_port_table() -> &'static HashMap<u16, String> {
    &PORT_TABLE
}

/// Looks up service signatures by port number
///
/// Returns all signatures that match the given port (either via
/// heuristic or explicit port definitions).
///
/// # Arguments
///
/// * `port` - The port number to look up
///
/// # Returns
///
/// A vector of references to matching signatures
///
/// # Example
///
/// ```
/// use smap_core::database::lookup_by_port;
///
/// let http_sigs = lookup_by_port(80);
/// assert!(!http_sigs.is_empty());
/// ```
pub fn lookup_by_port(port: u16) -> Vec<&'static ServiceSignature> {
    PORT_INDEX
        .get(&port)
        .map(|indices| indices.iter().map(|&i| &SIGNATURES[i]).collect())
        .unwrap_or_default()
}

/// Looks up service signatures by service name
///
/// Returns all signatures for the given service name.
///
/// # Arguments
///
/// * `service` - The service name to look up (e.g., "http", "ssh")
///
/// # Returns
///
/// A vector of references to matching signatures
///
/// # Example
///
/// ```
/// use smap_core::database::lookup_by_service;
///
/// let ssh_sigs = lookup_by_service("ssh");
/// assert!(!ssh_sigs.is_empty());
/// ```
pub fn lookup_by_service(service: &str) -> Vec<&'static ServiceSignature> {
    SERVICE_INDEX
        .get(service)
        .map(|indices| indices.iter().map(|&i| &SIGNATURES[i]).collect())
        .unwrap_or_default()
}

/// Looks up service signatures by CPE prefix
///
/// Returns all signatures that have a CPE containing the given substring.
/// For correlation, use exact CPE strings for best performance.
///
/// # Arguments
///
/// * `cpe_substring` - The CPE substring to search for (e.g., "apache", "microsoft")
///
/// # Returns
///
/// A vector of references to matching signatures
///
/// # Example
///
/// ```
/// use smap_core::database::lookup_by_cpe;
///
/// let sigs = lookup_by_cpe("apache");
/// // Returns all signatures with CPEs containing "apache"
/// ```
pub fn lookup_by_cpe(cpe_substring: &str) -> Vec<&'static ServiceSignature> {
    // First try exact lookup in index for performance
    if let Some(indices) = CPE_INDEX.get(cpe_substring) {
        return indices.iter().map(|&i| &SIGNATURES[i]).collect();
    }

    // Fall back to substring search
    SIGNATURES
        .iter()
        .filter(|sig| sig.cpes.iter().any(|c| c.contains(cpe_substring)))
        .collect()
}

/// Retrieves cached statistics about the signature database
///
/// # Example
///
/// ```
/// use smap_core::database::signature_count;
///
/// let count = signature_count();
/// assert!(count > 0);
/// ```
pub fn signature_count() -> usize {
    SIGNATURES.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signatures_load() {
        let sigs = get_signature_database();
        assert!(sigs.len() > 4000, "Should have many signatures");
        println!("Loaded {} signatures", sigs.len());
    }

    #[test]
    fn test_port_table_load() {
        let table = get_port_table();
        assert!(table.len() > 100, "Should have many port mappings");

        // Test known ports
        assert_eq!(table.get(&22), Some(&"ssh".to_string()));
        assert_eq!(table.get(&80), Some(&"http".to_string()));
        assert_eq!(table.get(&443), Some(&"https".to_string()));

        println!("Loaded {} port mappings", table.len());
    }

    #[test]
    fn test_lookup_by_port() {
        let http_sigs = lookup_by_port(80);
        assert!(!http_sigs.is_empty(), "Should find HTTP signatures");

        let ssh_sigs = lookup_by_port(22);
        assert!(!ssh_sigs.is_empty(), "Should find SSH signatures");

        println!("Port 80: {} signatures", http_sigs.len());
        println!("Port 22: {} signatures", ssh_sigs.len());
    }

    #[test]
    fn test_lookup_by_service() {
        let http_sigs = lookup_by_service("http");
        assert!(!http_sigs.is_empty(), "Should find HTTP service");

        let ssh_sigs = lookup_by_service("ssh");
        assert!(!ssh_sigs.is_empty(), "Should find SSH service");

        let ftp_sigs = lookup_by_service("ftp");
        assert!(!ftp_sigs.is_empty(), "Should find FTP service");

        println!("HTTP service: {} signatures", http_sigs.len());
        println!("SSH service: {} signatures", ssh_sigs.len());
        println!("FTP service: {} signatures", ftp_sigs.len());
    }

    #[test]
    fn test_lookup_by_cpe() {
        let apache_sigs = lookup_by_cpe("apache");
        assert!(!apache_sigs.is_empty(), "Should find Apache signatures");

        let microsoft_sigs = lookup_by_cpe("microsoft");
        assert!(
            !microsoft_sigs.is_empty(),
            "Should find Microsoft signatures"
        );

        println!("Apache CPE matches: {} signatures", apache_sigs.len());
        println!("Microsoft CPE matches: {} signatures", microsoft_sigs.len());
    }

    #[test]
    fn test_signature_count() {
        let count = signature_count();
        assert!(count > 4000, "Should have substantial signature database");
        println!("Total signature count: {}", count);
    }

    #[test]
    fn test_signature_structure() {
        let sigs = get_signature_database();

        // Find a specific signature to verify structure
        let acap_sig = sigs
            .iter()
            .find(|s| s.service == "acap")
            .expect("Should find ACAP signature");

        assert_eq!(acap_sig.service, "acap");
        assert_eq!(acap_sig.protocol, "tcp");
        assert!(!acap_sig.cpes.is_empty());
        assert!(acap_sig.product.is_some());
    }

    #[test]
    fn test_service_index() {
        // Verify the service index was built correctly
        let http_sigs = lookup_by_service("http");
        let sigs = get_signature_database();

        let manual_count = sigs.iter().filter(|s| s.service == "http").count();
        assert_eq!(
            http_sigs.len(),
            manual_count,
            "Index should match manual count"
        );
    }

    #[test]
    fn test_port_index() {
        // Verify the port index was built correctly
        let port_80_sigs = lookup_by_port(80);

        // The port index may have duplicates if a signature appears in both
        // heuristic and explicit ports, which is intentional for lookup speed
        assert!(
            port_80_sigs.len() >= 2000,
            "Should have many signatures for port 80"
        );

        // Verify we can actually find signatures
        assert!(port_80_sigs.iter().any(|s| s.service == "http"));
    }

    #[test]
    fn test_uncommon_port_lookup() {
        // Test that uncommon ports return empty results gracefully
        let sigs = lookup_by_port(65000);
        // This might be empty or have results, but shouldn't panic
        println!("Port 65000: {} signatures", sigs.len());
    }

    #[test]
    fn test_nonexistent_service_lookup() {
        let sigs = lookup_by_service("nonexistent_service_xyz");
        assert!(
            sigs.is_empty(),
            "Should return empty for nonexistent service"
        );
    }

    #[test]
    fn test_sslports_field() {
        // Find a signature with SSL ports
        let sigs = get_signature_database();
        let ssl_sig = sigs
            .iter()
            .find(|s| !s.sslports.is_empty())
            .expect("Should find at least one signature with SSL ports");

        println!(
            "Found signature '{}' with {} SSL ports",
            ssl_sig.service,
            ssl_sig.sslports.len()
        );

        // Verify SSL ports can be looked up via PORT_INDEX
        if let Some(&first_ssl_port) = ssl_sig.sslports.first() {
            let port_sigs = lookup_by_port(first_ssl_port);
            assert!(
                !port_sigs.is_empty(),
                "SSL port {} should be indexed",
                first_ssl_port
            );
        }
    }
}
