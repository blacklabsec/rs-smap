//! Output formatting modules for scan results
//!
//! This module provides various output formats for scan results,
//! compatible with Nmap and custom formats.
//!
//! # Formats
//!
//! - **Nmap** - Nmap-compatible text output
//! - **XML** - Nmap-compatible XML output
//! - **JSON** - JSON array format
//! - **Grepable** - Grep-friendly format
//! - **Pair** - Simple IP:port pairs
//! - **Smap** - Custom smap format with enhanced information
//!
//! # Examples
//!
//! ```no_run
//! use smap_core::output::nmap::NmapFormatter;
//! use smap_core::types::ScanResult;
//! use std::time::SystemTime;
//!
//! let formatter = NmapFormatter::new(SystemTime::now());
//! // Add scan results and format output
//! ```

pub mod common;
pub mod grep;
pub mod json;
pub mod nmap;
pub mod pair;
pub mod smap;
pub mod xml;

pub use common::{OutputWriter, TimeFormat};
pub use grep::GrepFormatter;
pub use json::JsonFormatter;
pub use nmap::NmapFormatter;
pub use pair::PairFormatter;
pub use smap::SmapFormatter;
pub use xml::XmlFormatter;
