//! Shodan InternetDB API client
//!
//! This module provides an async client for querying the Shodan InternetDB API,
//! which offers free access to basic information about internet-connected devices.
//!
//! The InternetDB API provides information about:
//! - Open ports
//! - Hostnames
//! - Tags (e.g., cloud providers, self-signed certificates)
//! - CPEs (Common Platform Enumeration identifiers)
//! - Vulnerabilities (CVEs)
//!
//! # Example
//!
//! ```no_run
//! use smap_core::shodan::ShodanClient;
//! use std::net::IpAddr;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = ShodanClient::new()?;
//! let ip: IpAddr = "8.8.8.8".parse()?;
//! let result = client.query(ip).await?;
//! println!("Open ports: {:?}", result.ports);
//! println!("Hostnames: {:?}", result.hostnames);
//! # Ok(())
//! # }
//! ```

use crate::error::{Error, Result};
use crate::types::{Port, Protocol, ScanResult};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;
use tokio::time::sleep;

const INTERNETDB_API_BASE: &str = "https://internetdb.shodan.io";
const DEFAULT_TIMEOUT_SECS: u64 = 10;
const DEFAULT_RETRY_ATTEMPTS: u32 = 3;
const DEFAULT_RETRY_DELAY_MS: u64 = 1000;

/// Client for querying the Shodan InternetDB API
///
/// The client handles HTTP requests, retries on failure, and rate limiting.
#[derive(Debug, Clone)]
pub struct ShodanClient {
    client: Client,
    retry_attempts: u32,
    retry_delay: Duration,
}

/// Response from the InternetDB API for an IP address
///
/// This structure matches the JSON response from internetdb.shodan.io
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InternetDbResponse {
    /// List of open ports
    #[serde(default)]
    pub ports: Vec<u16>,

    /// List of CPEs (Common Platform Enumeration) identifiers
    #[serde(default)]
    pub cpes: Vec<String>,

    /// List of hostnames associated with the IP
    #[serde(default)]
    pub hostnames: Vec<String>,

    /// List of tags
    #[serde(default)]
    pub tags: Vec<String>,

    /// List of vulnerabilities (CVEs)
    #[serde(default)]
    pub vulns: Vec<String>,
}

/// Error response from the InternetDB API
#[derive(Debug, Deserialize)]
struct ApiErrorResponse {
    error: String,
}

impl ApiErrorResponse {
    /// Determines if this error is a rate limiting error
    fn is_rate_limit(&self) -> bool {
        let error_lower = self.error.to_lowercase();
        error_lower.contains("rate limit")
            || error_lower.contains("too many requests")
            || error_lower.contains("quota exceeded")
            || error_lower.contains("throttle")
    }
}

impl ShodanClient {
    /// Creates a new Shodan InternetDB client with default settings
    ///
    /// # Examples
    ///
    /// ```
    /// use smap_core::shodan::ShodanClient;
    ///
    /// let client = ShodanClient::new()?;
    /// # Ok::<(), smap_core::error::Error>(())
    /// ```
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .build()?;

        Ok(Self {
            client,
            retry_attempts: DEFAULT_RETRY_ATTEMPTS,
            retry_delay: Duration::from_millis(DEFAULT_RETRY_DELAY_MS),
        })
    }

    /// Creates a client with a custom timeout
    ///
    /// # Examples
    ///
    /// ```
    /// use smap_core::shodan::ShodanClient;
    /// use std::time::Duration;
    ///
    /// let client = ShodanClient::with_timeout(Duration::from_secs(5))?;
    /// # Ok::<(), smap_core::error::Error>(())
    /// ```
    pub fn with_timeout(timeout: Duration) -> Result<Self> {
        let client = Client::builder().timeout(timeout).build()?;

        Ok(Self {
            client,
            retry_attempts: DEFAULT_RETRY_ATTEMPTS,
            retry_delay: Duration::from_millis(DEFAULT_RETRY_DELAY_MS),
        })
    }

    /// Creates a client with custom retry settings
    ///
    /// # Arguments
    ///
    /// * `retry_attempts` - Number of retry attempts on failure
    /// * `retry_delay` - Initial delay between retry attempts (will use exponential backoff)
    ///
    /// # Examples
    ///
    /// ```
    /// use smap_core::shodan::ShodanClient;
    /// use std::time::Duration;
    ///
    /// let client = ShodanClient::with_retry(5, Duration::from_secs(2))?;
    /// # Ok::<(), smap_core::error::Error>(())
    /// ```
    pub fn with_retry(retry_attempts: u32, retry_delay: Duration) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .build()?;

        Ok(Self {
            client,
            retry_attempts,
            retry_delay,
        })
    }

    /// Queries the InternetDB API for information about an IP address
    ///
    /// This method handles retries on transient failures and validates
    /// the response from the API.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to query
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The API request fails after all retry attempts
    /// - The API returns an error response
    /// - The response cannot be parsed as valid JSON
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use smap_core::shodan::ShodanClient;
    /// use std::net::IpAddr;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = ShodanClient::new()?;
    /// let ip: IpAddr = "8.8.8.8".parse()?;
    /// let response = client.query(ip).await?;
    /// println!("Found {} open ports", response.ports.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn query(&self, ip: IpAddr) -> Result<InternetDbResponse> {
        let url = format!("{}/{}", INTERNETDB_API_BASE, ip);

        let mut last_error = None;
        let mut retry_after_secs: Option<u64> = None;

        for attempt in 0..self.retry_attempts {
            if attempt > 0 {
                // Use Retry-After if available, otherwise use exponential backoff
                let delay = if let Some(retry_secs) = retry_after_secs.take() {
                    // Use the Retry-After header value with a small buffer
                    Duration::from_secs(retry_secs + 1)
                } else {
                    // Exponential backoff: delay * 2^(attempt-1)
                    let backoff_multiplier = 1u32.checked_shl(attempt - 1).unwrap_or(8);
                    self.retry_delay.saturating_mul(backoff_multiplier)
                };
                sleep(delay).await;
            }

            match self.query_once(&url).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    // Check if we should store a Retry-After delay for rate limiting
                    if let Error::ShodanApiRateLimit(ref _msg, retry_secs) = e {
                        // Store retry_after for next attempt (will be used at top of loop)
                        retry_after_secs = retry_secs;
                    }
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| Error::Generic("Unknown error".into())))
    }

    /// Performs a single query attempt without retries
    async fn query_once(&self, url: &str) -> Result<InternetDbResponse> {
        let response = self.client.get(url).send().await?;

        let status = response.status();
        
        // Extract Retry-After header if present
        let retry_after_secs = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());

        // Handle different HTTP status codes
        match status {
            StatusCode::OK => {
                // Success - but still check for error in JSON body
                // First try to parse as an error response
                let body_text = response.text().await?;
                
                // Try to parse as error first
                if let Ok(error_response) = serde_json::from_str::<ApiErrorResponse>(&body_text) {
                    // Check if this is a rate limit error
                    if error_response.is_rate_limit() {
                        return Err(Error::ShodanApiRateLimit(
                            error_response.error,
                            retry_after_secs,
                        ));
                    } else {
                        return Err(Error::ShodanApi(error_response.error));
                    }
                }
                
                // Not an error, parse as normal response
                let data = serde_json::from_str::<InternetDbResponse>(&body_text)?;
                Ok(data)
            }
            StatusCode::NOT_FOUND => {
                // No information available for this IP
                Ok(InternetDbResponse {
                    ports: Vec::new(),
                    cpes: Vec::new(),
                    hostnames: Vec::new(),
                    tags: Vec::new(),
                    vulns: Vec::new(),
                })
            }
            StatusCode::TOO_MANY_REQUESTS => {
                // Rate limiting at HTTP status level
                let error_msg = retry_after_secs
                    .map(|secs| format!("Rate limit exceeded (retry after {} seconds)", secs))
                    .unwrap_or_else(|| "Rate limit exceeded".into());
                Err(Error::ShodanApiRateLimit(error_msg, retry_after_secs))
            }
            StatusCode::BAD_REQUEST => {
                // Try to parse error message
                if let Ok(error_response) = response.json::<ApiErrorResponse>().await {
                    if error_response.is_rate_limit() {
                        Err(Error::ShodanApiRateLimit(
                            error_response.error,
                            retry_after_secs,
                        ))
                    } else {
                        Err(Error::ShodanApi(error_response.error))
                    }
                } else {
                    Err(Error::ShodanApi("Bad request".into()))
                }
            }
            _ => {
                // Try to get error message from response body
                if let Ok(error_response) = response.json::<ApiErrorResponse>().await {
                    if error_response.is_rate_limit() {
                        Err(Error::ShodanApiRateLimit(
                            error_response.error,
                            retry_after_secs,
                        ))
                    } else {
                        Err(Error::ShodanApi(error_response.error))
                    }
                } else {
                    Err(Error::ShodanApi(format!(
                        "API request failed with status: {}",
                        status
                    )))
                }
            }
        }
    }

    /// Queries the InternetDB API and converts the response to a ScanResult
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to query
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use smap_core::shodan::ShodanClient;
    /// use std::net::IpAddr;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = ShodanClient::new()?;
    /// let ip: IpAddr = "8.8.8.8".parse()?;
    /// let scan_result = client.query_as_scan_result(ip).await?;
    /// println!("IP: {}", scan_result.ip);
    /// println!("Ports: {:?}", scan_result.ports);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn query_as_scan_result(&self, ip: IpAddr) -> Result<ScanResult> {
        let response = self.query(ip).await?;
        Ok(response.into_scan_result(ip))
    }
}

impl InternetDbResponse {
    /// Converts the InternetDB response to a ScanResult
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address that was queried
    ///
    /// # Examples
    ///
    /// ```
    /// use smap_core::shodan::InternetDbResponse;
    /// use std::net::IpAddr;
    ///
    /// let response = InternetDbResponse {
    ///     ports: vec![80, 443],
    ///     cpes: vec![],
    ///     hostnames: vec!["example.com".to_string()],
    ///     tags: vec![],
    ///     vulns: vec![],
    /// };
    ///
    /// let ip: IpAddr = "192.168.1.1".parse().unwrap();
    /// let scan_result = response.into_scan_result(ip);
    /// assert_eq!(scan_result.ports.len(), 2);
    /// ```
    pub fn into_scan_result(self, ip: IpAddr) -> ScanResult {
        let mut result = ScanResult::new(ip);

        // Add ports with TCP protocol (InternetDB doesn't distinguish protocols)
        for port_num in self.ports {
            result.add_port(Port::new(port_num, Protocol::Tcp));
        }

        result.hostnames = self.hostnames;
        result.tags = self.tags;
        result.vulns = self.vulns;

        result
    }
}

impl Default for ShodanClient {
    fn default() -> Self {
        // This is safe because reqwest::Client::builder().build() only fails
        // if TLS backend cannot be initialized, which is extremely rare
        Self::new().unwrap_or_else(|e| panic!("Failed to create default ShodanClient: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = ShodanClient::new();
        assert!(client.is_ok());
    }

    #[test]
    fn test_client_with_timeout() {
        let client = ShodanClient::with_timeout(Duration::from_secs(5));
        assert!(client.is_ok());
    }

    #[test]
    fn test_client_with_retry() {
        let client = ShodanClient::with_retry(5, Duration::from_millis(500)).unwrap();
        assert_eq!(client.retry_attempts, 5);
        assert_eq!(client.retry_delay, Duration::from_millis(500));
    }

    #[test]
    fn test_internetdb_response_deserialization() {
        let json = r#"{
            "ports": [80, 443, 8080],
            "cpes": ["cpe:/a:nginx:nginx"],
            "hostnames": ["example.com"],
            "tags": ["cloud"],
            "vulns": ["CVE-2021-1234"]
        }"#;

        let response: InternetDbResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.ports, vec![80, 443, 8080]);
        assert_eq!(response.cpes, vec!["cpe:/a:nginx:nginx"]);
        assert_eq!(response.hostnames, vec!["example.com"]);
        assert_eq!(response.tags, vec!["cloud"]);
        assert_eq!(response.vulns, vec!["CVE-2021-1234"]);
    }

    #[test]
    fn test_internetdb_response_with_defaults() {
        // Test that missing fields default to empty vectors
        let json = r#"{"ports": [22]}"#;
        let response: InternetDbResponse = serde_json::from_str(json).unwrap();

        assert_eq!(response.ports, vec![22]);
        assert!(response.cpes.is_empty());
        assert!(response.hostnames.is_empty());
        assert!(response.tags.is_empty());
        assert!(response.vulns.is_empty());
    }

    #[test]
    fn test_internetdb_response_empty() {
        let json = r#"{}"#;
        let response: InternetDbResponse = serde_json::from_str(json).unwrap();

        assert!(response.ports.is_empty());
        assert!(response.cpes.is_empty());
        assert!(response.hostnames.is_empty());
        assert!(response.tags.is_empty());
        assert!(response.vulns.is_empty());
    }

    #[test]
    fn test_internetdb_response_serialization() {
        let response = InternetDbResponse {
            ports: vec![80, 443],
            cpes: vec!["cpe:/a:apache:httpd".to_string()],
            hostnames: vec!["test.com".to_string()],
            tags: vec!["self-signed".to_string()],
            vulns: vec![],
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: InternetDbResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(response, deserialized);
    }

    #[test]
    fn test_into_scan_result() {
        let response = InternetDbResponse {
            ports: vec![22, 80, 443],
            cpes: vec![],
            hostnames: vec!["server.example.com".to_string()],
            tags: vec!["cloud".to_string(), "self-signed".to_string()],
            vulns: vec!["CVE-2021-1234".to_string()],
        };

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let scan_result = response.into_scan_result(ip);

        assert_eq!(scan_result.ip.to_string(), "192.168.1.1");
        assert_eq!(scan_result.ports.len(), 3);
        assert_eq!(scan_result.ports[0].number, 22);
        assert_eq!(scan_result.ports[1].number, 80);
        assert_eq!(scan_result.ports[2].number, 443);
        assert_eq!(scan_result.hostnames, vec!["server.example.com"]);
        assert_eq!(scan_result.tags.len(), 2);
        assert_eq!(scan_result.vulns, vec!["CVE-2021-1234"]);
    }

    #[test]
    fn test_into_scan_result_empty() {
        let response = InternetDbResponse {
            ports: vec![],
            cpes: vec![],
            hostnames: vec![],
            tags: vec![],
            vulns: vec![],
        };

        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let scan_result = response.into_scan_result(ip);

        assert_eq!(scan_result.ip.to_string(), "10.0.0.1");
        assert!(scan_result.ports.is_empty());
        assert!(scan_result.hostnames.is_empty());
        assert!(scan_result.tags.is_empty());
        assert!(scan_result.vulns.is_empty());
    }

    // Integration tests with mock data
    #[cfg(test)]
    mod integration {
        use super::*;

        /// Test data representing a typical Shodan response for a web server
        fn mock_web_server_response() -> InternetDbResponse {
            InternetDbResponse {
                ports: vec![80, 443],
                cpes: vec![
                    "cpe:/a:nginx:nginx:1.18.0".to_string(),
                    "cpe:/o:linux:linux_kernel".to_string(),
                ],
                hostnames: vec!["www.example.com".to_string()],
                tags: vec!["cloud".to_string()],
                vulns: vec![],
            }
        }

        /// Test data representing a server with vulnerabilities
        fn mock_vulnerable_server_response() -> InternetDbResponse {
            InternetDbResponse {
                ports: vec![22, 80, 3306],
                cpes: vec!["cpe:/a:openbsd:openssh:7.4".to_string()],
                hostnames: vec![],
                tags: vec!["database".to_string()],
                vulns: vec!["CVE-2016-10009".to_string(), "CVE-2016-10010".to_string()],
            }
        }

        #[test]
        fn test_mock_web_server_conversion() {
            let response = mock_web_server_response();
            let ip: IpAddr = "203.0.113.1".parse().unwrap();
            let result = response.into_scan_result(ip);

            assert_eq!(result.port_count(), 2);
            assert!(!result.has_vulns());
            assert!(result.has_open_ports());
            assert_eq!(result.hostnames.len(), 1);
        }

        #[test]
        fn test_mock_vulnerable_server_conversion() {
            let response = mock_vulnerable_server_response();
            let ip: IpAddr = "198.51.100.1".parse().unwrap();
            let result = response.into_scan_result(ip);

            assert_eq!(result.port_count(), 3);
            assert!(result.has_vulns());
            assert_eq!(result.vulns.len(), 2);
            assert_eq!(result.tags, vec!["database"]);
        }

        #[test]
        fn test_response_roundtrip() {
            let original = mock_web_server_response();
            let json = serde_json::to_string(&original).unwrap();
            let deserialized: InternetDbResponse = serde_json::from_str(&json).unwrap();

            assert_eq!(original, deserialized);
        }
    }
}
