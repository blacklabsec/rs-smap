//! Smap Core Library
//!
//! This library provides passive network scanning capabilities using the Shodan InternetDB API.
//! It implements service fingerprinting with Nmap-compatible signatures and correlation.
//!
//! # Modules
//!
//! - [`args`] - CLI argument parsing and validation
//! - [`targets`] - Target IP/hostname parsing and expansion
//! - [`shodan`] - Shodan InternetDB API client
//! - [`correlation`] - Service fingerprinting and CPE correlation
//! - [`types`] - Core data structures for scan results
//! - [`database`] - Nmap signature database management
//! - [`output`] - Output formatters (Nmap, XML, JSON, grepable, pairs, smap)
//! - [`ip_utils`] - IP address filtering and validation utilities
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
//! println!("Services: {:?}", result.ports);
//! # Ok(())
//! # }
//! ```

pub mod args;
pub mod correlation;
pub mod database;
pub mod error;
pub mod ip_utils;
pub mod output;
pub mod shodan;
pub mod targets;
pub mod types;

#[cfg(test)]
mod args_extra_tests;

pub use error::{Error, Result};
