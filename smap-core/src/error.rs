//! Error types for smap-core
//!
//! Provides a unified error type for all operations in the library.

use std::net::AddrParseError;

/// Result type alias for smap operations
pub type Result<T> = std::result::Result<T, Error>;

/// Error types for smap operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON parsing error
    #[error("JSON parsing failed: {0}")]
    Json(#[from] serde_json::Error),

    /// IP address parsing error
    #[error("Invalid IP address: {0}")]
    IpParse(#[from] AddrParseError),

    /// CIDR parsing error
    #[error("Invalid CIDR notation: {0}")]
    CidrParse(String),

    /// Domain validation error
    #[error("Invalid domain: {0}")]
    InvalidDomain(String),

    /// Target parsing error
    #[error("Invalid target specification: {0}")]
    InvalidTarget(String),

    /// Shodan API error
    #[error("Shodan API error: {0}")]
    ShodanApi(String),

    /// Database error
    #[error("Database error: {0}")]
    Database(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid input error
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Generic error
    #[error("{0}")]
    Generic(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::InvalidTarget("test".to_string());
        assert_eq!(err.to_string(), "Invalid target specification: test");
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = Error::from(io_err);
        assert!(err.to_string().contains("file not found"));
    }

    #[test]
    fn test_error_from_json() {
        let json_err = serde_json::from_str::<u32>("not a number").unwrap_err();
        let err = Error::from(json_err);
        assert!(err.to_string().contains("JSON parsing failed"));
    }

    #[test]
    fn test_error_from_ip_parse() {
        let ip_err = "invalid".parse::<std::net::IpAddr>().unwrap_err();
        let err = Error::from(ip_err);
        assert!(err.to_string().contains("Invalid IP address"));
    }

    #[test]
    fn test_cidr_parse_error() {
        let err = Error::CidrParse("10.0.0.0/33".to_string());
        assert_eq!(err.to_string(), "Invalid CIDR notation: 10.0.0.0/33");
    }

    #[test]
    fn test_invalid_domain_error() {
        let err = Error::InvalidDomain("..invalid".to_string());
        assert_eq!(err.to_string(), "Invalid domain: ..invalid");
    }

    #[test]
    fn test_shodan_api_error() {
        let err = Error::ShodanApi("rate limited".to_string());
        assert_eq!(err.to_string(), "Shodan API error: rate limited");
    }

    #[test]
    fn test_database_error() {
        let err = Error::Database("signature not found".to_string());
        assert_eq!(err.to_string(), "Database error: signature not found");
    }

    #[test]
    fn test_generic_error() {
        let err = Error::Generic("something went wrong".to_string());
        assert_eq!(err.to_string(), "something went wrong");
    }

    #[test]
    fn test_result_type_alias() {
        fn returns_result() -> Result<i32> {
            Ok(42)
        }
        assert_eq!(returns_result().unwrap(), 42);
    }
}
