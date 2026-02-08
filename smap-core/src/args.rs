//! CLI argument parsing and validation
//!
//! This module handles parsing and validation of command-line arguments for the smap scanner.
//! It provides type-safe representation of user inputs and validates them before use.
//!
//! # Examples
//!
//! ```
//! use smap_core::args::{SmapArgs, OutputFormat};
//!
//! // Parse from iterator
//! let args = SmapArgs::from_iter_safe(["smap", "-p", "80,443", "192.168.1.1"]);
//! ```

use crate::error::{Error, Result};
use std::path::PathBuf;

/// Parsed and validated command-line arguments
///
/// This structure represents all Nmap-compatible CLI arguments supported by smap.
/// It uses a custom parsing approach to maintain exact Nmap compatibility while
/// providing type-safe access to parsed values.
#[derive(Debug, Clone, Default)]
pub struct SmapArgs {
    // ===== TARGET SPECIFICATION =====
    /// Input from list (-iL)
    pub input_list: Option<PathBuf>,
    /// Random targets (-iR)
    pub random_targets: Option<String>,
    /// Exclude hosts/networks (--exclude)
    pub exclude: Option<String>,
    /// Exclude list from file (--excludefile)
    pub exclude_file: Option<PathBuf>,

    // ===== HOST DISCOVERY =====
    /// List scan - simply list targets (-sL)
    pub list_scan: bool,
    /// Skip port scan (-sn)
    pub skip_port_scan: bool,
    /// Treat all hosts as online (-Pn)
    pub skip_host_discovery: bool,
    /// TCP SYN discovery (-PS)
    pub ps_discovery: bool,
    /// TCP ACK discovery (-PA)
    pub pa_discovery: bool,
    /// UDP discovery (-PU)
    pub pu_discovery: bool,
    /// SCTP discovery (-PY)
    pub py_discovery: bool,
    /// ICMP echo discovery (-PE)
    pub pe_discovery: bool,
    /// ICMP timestamp discovery (-PP)
    pub pp_discovery: bool,
    /// ICMP netmask discovery (-PM)
    pub pm_discovery: bool,
    /// IP protocol discovery (-PO)
    pub po_discovery: bool,

    // ===== DNS RESOLUTION =====
    /// Never do DNS resolution (-n)
    pub no_dns: bool,
    /// Always resolve DNS (-R)
    pub always_resolve: bool,
    /// Specify custom DNS servers (--dns-servers)
    pub dns_servers: Option<String>,
    /// Use system DNS resolver (--system-dns)
    pub system_dns: bool,
    /// Trace hop path to each host (--traceroute)
    pub traceroute: bool,

    // ===== SCAN TECHNIQUES =====
    /// TCP SYN scan (-sS)
    pub syn_scan: bool,
    /// TCP connect scan (-sT)
    pub connect_scan: bool,
    /// TCP ACK scan (-sA)
    pub ack_scan: bool,
    /// TCP Window scan (-sW)
    pub window_scan: bool,
    /// TCP Maimon scan (-sM)
    pub maimon_scan: bool,
    /// UDP scan (-sU)
    pub udp_scan: bool,
    /// TCP NULL scan (-sN)
    pub null_scan: bool,
    /// TCP FIN scan (-sF)
    pub fin_scan: bool,
    /// TCP Xmas scan (-sX)
    pub xmas_scan: bool,
    /// Custom TCP scan flags (--scanflags)
    pub scan_flags: Option<String>,
    /// Idle scan (-sI)
    pub idle_scan: Option<String>,
    /// SCTP INIT scan (-sY)
    pub sctp_init_scan: bool,
    /// SCTP COOKIE-ECHO scan (-sZ)
    pub cookie_echo_scan: bool,
    /// IP protocol scan (-sO)
    pub ip_protocol_scan: bool,
    /// FTP bounce scan (-b)
    pub ftp_bounce: Option<String>,

    // ===== PORT SPECIFICATION =====
    /// Port ranges to scan (-p)
    pub ports: Option<String>,
    /// Exclude ports (--exclude-ports)
    pub exclude_ports: Option<String>,
    /// Fast mode - scan fewer ports (-F)
    pub fast_scan: bool,
    /// Scan ports consecutively (-r)
    pub consecutive_scan: bool,
    /// Scan top N most common ports (--top-ports)
    pub top_ports: Option<u32>,
    /// Scan ports more common than ratio (--port-ratio)
    pub port_ratio: Option<f64>,

    // ===== SERVICE/VERSION DETECTION =====
    /// Probe open ports to determine service/version info (-sV)
    pub version_detection: bool,
    /// Set version detection intensity (--version-intensity)
    pub version_intensity: Option<u8>,
    /// Enable light mode (--version-light)
    pub version_light: bool,
    /// Try every single probe (--version-all)
    pub version_all: bool,
    /// Show detailed version scan activity (--version-trace)
    pub version_trace: bool,

    // ===== SCRIPT SCAN =====
    /// Run default NSE scripts (-sC)
    pub default_scripts: bool,
    /// Run specific scripts (--script)
    pub script: bool,
    /// Provide arguments to scripts (--script-args)
    pub script_args: bool,
    /// Load script args from file (--script-args-file)
    pub script_args_file: bool,
    /// Show all data sent and received (--script-trace)
    pub script_trace: bool,
    /// Update script database (--script-updatedb)
    pub script_updatedb: bool,
    /// Show help about scripts (--script-help)
    pub script_help: bool,

    // ===== OS DETECTION =====
    /// Enable OS detection (-O)
    pub os_detection: bool,
    /// Limit OS detection to promising targets (--osscan-limit)
    pub osscan_limit: bool,
    /// Guess OS more aggressively (--osscan-guess)
    pub osscan_guess: bool,

    // ===== TIMING AND PERFORMANCE =====
    /// Timing template (-T)
    pub timing_template: Option<String>,
    /// Parallel host scan group sizes (--min-hostgroup)
    pub min_hostgroup: Option<u32>,
    /// Parallel host scan group sizes (--max-hostgroup)
    pub max_hostgroup: Option<u32>,
    /// Probe parallelization (--min-parallelism)
    pub min_parallelism: Option<u32>,
    /// Probe parallelization (--max-parallelism)
    pub max_parallelism: Option<u32>,
    /// Adjust initial probe timeout (--min-rtt-timeout)
    pub min_rtt_timeout: Option<String>,
    /// Adjust maximum probe timeout (--max-rtt-timeout)
    pub max_rtt_timeout: Option<String>,
    /// Specify initial probe timeout (--initial-rtt-timeout)
    pub initial_rtt_timeout: Option<String>,
    /// Cap retransmission attempts (--max-retries)
    pub max_retries: Option<u32>,
    /// Give up on target after this long (--host-timeout)
    pub host_timeout: Option<String>,
    /// Adjust delay between probes (--scan-delay)
    pub scan_delay: Option<String>,
    /// Specify maximum delay between probes (--max-scan-delay)
    pub max_scan_delay: Option<String>,
    /// Send packets no slower than N per second (--min-rate)
    pub min_rate: Option<f64>,
    /// Send packets no faster than N per second (--max-rate)
    pub max_rate: Option<f64>,

    // ===== FIREWALL/IDS EVASION =====
    /// Fragment packets (-f)
    pub fragment_packets: bool,
    /// Set custom decoy addresses (-D)
    pub decoys: Option<String>,
    /// Spoof source address (-S)
    pub spoof_source: Option<String>,
    /// Use specified interface (-e)
    pub interface: Option<String>,
    /// Source port number (-g)
    pub source_port_g: Option<String>,
    /// Source port number (--source-port)
    pub source_port: Option<String>,
    /// Relay connections through HTTP/SOCKS4 proxies (--proxies)
    pub proxies: Option<String>,
    /// Append custom binary data to sent packets (--data)
    pub data: Option<String>,
    /// Append custom string to sent packets (--data-string)
    pub data_string: Option<String>,
    /// Append random data to sent packets (--data-length)
    pub data_length: Option<u32>,
    /// Send packets with specified ip options (--ip-options)
    pub ip_options: Option<String>,
    /// Set IP time-to-live field (--ttl)
    pub ttl: Option<u8>,
    /// Spoof MAC address (--spoof-mac)
    pub spoof_mac: Option<String>,
    /// Send packets with bogus TCP/UDP checksums (--badsum)
    pub badsum: bool,

    // ===== OUTPUT =====
    /// Output to normal format (-oN)
    pub output_normal: Option<PathBuf>,
    /// Output to XML format (-oX)
    pub output_xml: Option<PathBuf>,
    /// Output to s|<rIpt kIddi3 format (-oS)
    pub output_skript: Option<PathBuf>,
    /// Output to grepable format (-oG)
    pub output_grep: Option<PathBuf>,
    /// Output in all major formats (-oA)
    pub output_all: Option<String>,
    /// Output to JSON format (-oJ)
    pub output_json: Option<PathBuf>,
    /// Output to pair format (-oP)
    pub output_pair: Option<PathBuf>,

    // ===== VERBOSITY =====
    /// Increase verbosity level (-v)
    pub verbose: bool,
    /// Increase debugging level (-d)
    pub debug: bool,
    /// Display reason for state (--reason)
    pub reason: bool,
    /// Show only open ports (--open)
    pub open_only: bool,
    /// Show all packets sent/received (--packet-trace)
    pub packet_trace: bool,
    /// Print host interfaces and routes (--iflist)
    pub iflist: bool,

    // ===== MISC OUTPUT =====
    /// Append to rather than clobber output files (--append-output)
    pub append_output: bool,
    /// Resume aborted scan (--resume)
    pub resume: Option<PathBuf>,
    /// XSL stylesheet to transform XML output (--stylesheet)
    pub stylesheet: Option<PathBuf>,
    /// Reference stylesheet from Nmap.Org (--webxml)
    pub webxml: bool,
    /// Prevent associating XSL stylesheet (--no-stylesheet)
    pub no_stylesheet: bool,

    // ===== MISC =====
    /// Enable IPv6 scanning (-6)
    pub ipv6: bool,
    /// Enable OS detection, version, script, traceroute (-A)
    pub aggressive: bool,
    /// Specify custom Nmap data directory (--datadir)
    pub datadir: Option<PathBuf>,
    /// Send using raw ethernet frames (--send-eth)
    pub send_eth: bool,
    /// Send using IP packets (--send-ip)
    pub send_ip: bool,
    /// Assume user is fully privileged (--privileged)
    pub privileged: bool,
    /// Assume user lacks raw socket privileges (--unprivileged)
    pub unprivileged: bool,

    // ===== HELP/VERSION =====
    /// Print version number (-V)
    pub version: bool,
    /// Print help summary (-h)
    pub help: bool,

    // ===== TARGET LIST =====
    /// Target hosts/networks (positional arguments)
    pub targets: Vec<String>,
}

impl SmapArgs {
    /// Parse arguments from command-line iterator
    ///
    /// This method provides Nmap-compatible argument parsing, handling
    /// complex option combinations and both short/long forms.
    ///
    /// # Examples
    ///
    /// ```
    /// use smap_core::args::SmapArgs;
    ///
    /// let args = SmapArgs::from_iter_safe(vec!["smap", "-p", "80", "192.168.1.1"]);
    /// assert!(args.is_ok());
    /// ```
    pub fn from_iter_safe<I, S>(iter: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let args: Vec<String> = iter.into_iter().map(|s| s.as_ref().to_string()).collect();
        if args.is_empty() {
            return Ok(Self::default());
        }
        Self::parse_args(&args[1..]) // Skip program name
    }

    /// Internal parsing function that mimics the Go implementation
    fn parse_args(tokens: &[String]) -> Result<Self> {
        let mut args = SmapArgs::default();
        let mut i = 0;

        while i < tokens.len() {
            let token = &tokens[i];

            if token.starts_with('-') && token != "-" {
                // Handle combined short flags like -sS, -Pn, -sV, or -p80, -p-
                let cleaned = token.trim_start_matches('-');

                // Check for key=value format
                if token.contains('=') {
                    let parts: Vec<&str> = token.splitn(2, '=').collect();
                    let key = parts[0].trim_start_matches('-');
                    let value = parts[1];
                    Self::set_arg_value(&mut args, key, Some(value.to_string()))?;
                    i += 1;
                    continue;
                }

                // First, check if the whole cleaned string is a valid argument
                if Self::is_valid_arg(cleaned) {
                    // It's a known argument, parse it normally
                    match Self::parse_single_arg(&mut args, cleaned, tokens, &mut i) {
                        Ok(_) => {}
                        Err(e) => return Err(e),
                    }
                    i += 1;
                    continue;
                }

                // Check for short option with value attached (like -p80, -p-, -T4)
                // Only for single-character options
                if cleaned.len() > 1 {
                    let first_char = &cleaned[0..1];
                    if Self::is_valid_arg(first_char) && Self::arg_needs_value(first_char) {
                        // Value is attached
                        let value = cleaned[1..].to_string();
                        Self::set_arg_value(&mut args, first_char, Some(value))?;
                        i += 1;
                        continue;
                    }
                }

                // Unknown argument
                return Err(Error::InvalidInput(format!(
                    "Unknown argument: {}",
                    cleaned
                )));
            } else {
                // Positional argument (target) - includes standalone "-"
                args.targets.push(token.clone());
            }

            i += 1;
        }

        Ok(args)
    }

    /// Parse a single argument (without leading dashes)
    fn parse_single_arg(
        args: &mut SmapArgs,
        arg: &str,
        tokens: &[String],
        i: &mut usize,
    ) -> Result<()> {
        // Check if this requires a value
        let needs_value = Self::arg_needs_value(arg);

        if needs_value {
            // Look ahead for value
            if *i + 1 < tokens.len() {
                let next_token = &tokens[*i + 1];
                // Special case: allow "-" as a value for port ranges
                // Also allow values that start with "-" if they're just "-" (meaning all ports in Nmap)
                if next_token == "-" || !next_token.starts_with('-') {
                    *i += 1;
                    let value = tokens[*i].clone();
                    Self::set_arg_value(args, arg, Some(value))?;
                } else {
                    return Err(Error::InvalidInput(format!(
                        "Argument -{} requires a value",
                        arg
                    )));
                }
            } else {
                return Err(Error::InvalidInput(format!(
                    "Argument -{} requires a value",
                    arg
                )));
            }
        } else {
            Self::set_arg_value(args, arg, None)?;
        }

        Ok(())
    }

    /// Check if an argument needs a value
    fn arg_needs_value(arg: &str) -> bool {
        matches!(
            arg,
            "iL" | "iR"
                | "exclude"
                | "excludefile"
                | "dns-servers"
                | "scanflags"
                | "sI"
                | "b"
                | "p"
                | "exclude-ports"
                | "top-ports"
                | "port-ratio"
                | "version-intensity"
                | "T"
                | "min-hostgroup"
                | "max-hostgroup"
                | "min-parallelism"
                | "max-parallelism"
                | "min-rtt-timeout"
                | "max-rtt-timeout"
                | "initial-rtt-timeout"
                | "max-retries"
                | "host-timeout"
                | "scan-delay"
                | "max-scan-delay"
                | "min-rate"
                | "max-rate"
                | "D"
                | "S"
                | "e"
                | "g"
                | "source-port"
                | "proxies"
                | "data"
                | "data-string"
                | "data-length"
                | "ip-options"
                | "ttl"
                | "spoof-mac"
                | "oN"
                | "oX"
                | "oS"
                | "oG"
                | "oA"
                | "oJ"
                | "oP"
                | "resume"
                | "stylesheet"
                | "datadir"
        )
    }

    /// Check if an argument is valid (exists in our supported args)
    fn is_valid_arg(arg: &str) -> bool {
        matches!(
            arg,
            // Target specification
            "iL" | "iR" | "exclude" | "excludefile" |
            // Host discovery
            "sL" | "sn" | "Pn" | "PS" | "PA" | "PU" | "PY" | "PE" | "PP" | "PM" | "PO" |
            // DNS
            "n" | "R" | "dns-servers" | "system-dns" | "traceroute" |
            // Scan techniques
            "sS" | "sT" | "sA" | "sW" | "sM" | "sU" | "sN" | "sF" | "sX" | "scanflags" |
            "sI" | "sY" | "sZ" | "sO" | "b" |
            // Port specification
            "p" | "exclude-ports" | "F" | "r" | "top-ports" | "port-ratio" |
            // Service/version detection
            "sV" | "version-intensity" | "version-light" | "version-all" | "version-trace" |
            // Script scan
            "sC" | "script" | "script-args" | "script-args-file" | "script-trace" |
            "script-updatedb" | "script-help" |
            // OS detection
            "O" | "osscan-limit" | "osscan-guess" |
            // Timing
            "T" | "min-hostgroup" | "max-hostgroup" | "min-parallelism" | "max-parallelism" |
            "min-rtt-timeout" | "max-rtt-timeout" | "initial-rtt-timeout" | "max-retries" |
            "host-timeout" | "scan-delay" | "max-scan-delay" | "min-rate" | "max-rate" |
            // Firewall/IDS evasion
            "f" | "D" | "S" | "e" | "g" | "source-port" | "proxies" | "data" | "data-string" |
            "data-length" | "ip-options" | "ttl" | "spoof-mac" | "badsum" |
            // Output
            "oN" | "oX" | "oS" | "oG" | "oA" | "oJ" | "oP" |
            // Verbosity
            "v" | "d" | "reason" | "open" | "packet-trace" | "iflist" |
            // Misc output
            "append-output" | "resume" | "stylesheet" | "webxml" | "no-stylesheet" |
            // Misc
            "6" | "A" | "datadir" | "send-eth" | "send-ip" | "privileged" | "unprivileged" |
            // Help/version
            "V" | "h" | "help"
        )
    }

    /// Set argument value based on name
    fn set_arg_value(args: &mut SmapArgs, name: &str, value: Option<String>) -> Result<()> {
        match name {
            // Target specification
            "iL" => args.input_list = value.map(PathBuf::from),
            "iR" => args.random_targets = value,
            "exclude" => args.exclude = value,
            "excludefile" => args.exclude_file = value.map(PathBuf::from),

            // Host discovery
            "sL" => args.list_scan = true,
            "sn" => args.skip_port_scan = true,
            "Pn" => args.skip_host_discovery = true,
            "PS" => args.ps_discovery = true,
            "PA" => args.pa_discovery = true,
            "PU" => args.pu_discovery = true,
            "PY" => args.py_discovery = true,
            "PE" => args.pe_discovery = true,
            "PP" => args.pp_discovery = true,
            "PM" => args.pm_discovery = true,
            "PO" => args.po_discovery = true,

            // DNS
            "n" => args.no_dns = true,
            "R" => args.always_resolve = true,
            "dns-servers" => args.dns_servers = value,
            "system-dns" => args.system_dns = true,
            "traceroute" => args.traceroute = true,

            // Scan techniques
            "sS" => args.syn_scan = true,
            "sT" => args.connect_scan = true,
            "sA" => args.ack_scan = true,
            "sW" => args.window_scan = true,
            "sM" => args.maimon_scan = true,
            "sU" => args.udp_scan = true,
            "sN" => args.null_scan = true,
            "sF" => args.fin_scan = true,
            "sX" => args.xmas_scan = true,
            "scanflags" => args.scan_flags = value,
            "sI" => args.idle_scan = value,
            "sY" => args.sctp_init_scan = true,
            "sZ" => args.cookie_echo_scan = true,
            "sO" => args.ip_protocol_scan = true,
            "b" => args.ftp_bounce = value,

            // Port specification
            "p" => args.ports = value,
            "exclude-ports" => args.exclude_ports = value,
            "F" => args.fast_scan = true,
            "r" => args.consecutive_scan = true,
            "top-ports" => {
                if let Some(v) = value {
                    args.top_ports = Some(v.parse().map_err(|_| {
                        Error::InvalidInput(format!("Invalid top-ports value: {}", v))
                    })?);
                }
            }
            "port-ratio" => {
                if let Some(v) = value {
                    args.port_ratio = Some(v.parse().map_err(|_| {
                        Error::InvalidInput(format!("Invalid port-ratio value: {}", v))
                    })?);
                }
            }

            // Service/version detection
            "sV" => args.version_detection = true,
            "version-intensity" => {
                if let Some(v) = value {
                    args.version_intensity = Some(v.parse().map_err(|_| {
                        Error::InvalidInput(format!("Invalid version-intensity value: {}", v))
                    })?);
                }
            }
            "version-light" => args.version_light = true,
            "version-all" => args.version_all = true,
            "version-trace" => args.version_trace = true,

            // Script scan
            "sC" => args.default_scripts = true,
            "script" => args.script = true,
            "script-args" => args.script_args = true,
            "script-args-file" => args.script_args_file = true,
            "script-trace" => args.script_trace = true,
            "script-updatedb" => args.script_updatedb = true,
            "script-help" => args.script_help = true,

            // OS detection
            "O" => args.os_detection = true,
            "osscan-limit" => args.osscan_limit = true,
            "osscan-guess" => args.osscan_guess = true,

            // Timing
            "T" => args.timing_template = value,
            "min-hostgroup" => {
                if let Some(v) = value {
                    args.min_hostgroup = Some(v.parse().map_err(|_| {
                        Error::InvalidInput(format!("Invalid min-hostgroup value: {}", v))
                    })?);
                }
            }
            "max-hostgroup" => {
                if let Some(v) = value {
                    args.max_hostgroup = Some(v.parse().map_err(|_| {
                        Error::InvalidInput(format!("Invalid max-hostgroup value: {}", v))
                    })?);
                }
            }
            "min-parallelism" => {
                if let Some(v) = value {
                    args.min_parallelism = Some(v.parse().map_err(|_| {
                        Error::InvalidInput(format!("Invalid min-parallelism value: {}", v))
                    })?);
                }
            }
            "max-parallelism" => {
                if let Some(v) = value {
                    args.max_parallelism = Some(v.parse().map_err(|_| {
                        Error::InvalidInput(format!("Invalid max-parallelism value: {}", v))
                    })?);
                }
            }
            "min-rtt-timeout" => args.min_rtt_timeout = value,
            "max-rtt-timeout" => args.max_rtt_timeout = value,
            "initial-rtt-timeout" => args.initial_rtt_timeout = value,
            "max-retries" => {
                if let Some(v) = value {
                    args.max_retries = Some(v.parse().map_err(|_| {
                        Error::InvalidInput(format!("Invalid max-retries value: {}", v))
                    })?);
                }
            }
            "host-timeout" => args.host_timeout = value,
            "scan-delay" => args.scan_delay = value,
            "max-scan-delay" => args.max_scan_delay = value,
            "min-rate" => {
                if let Some(v) = value {
                    args.min_rate = Some(v.parse().map_err(|_| {
                        Error::InvalidInput(format!("Invalid min-rate value: {}", v))
                    })?);
                }
            }
            "max-rate" => {
                if let Some(v) = value {
                    args.max_rate = Some(v.parse().map_err(|_| {
                        Error::InvalidInput(format!("Invalid max-rate value: {}", v))
                    })?);
                }
            }

            // Firewall/IDS evasion
            "f" => args.fragment_packets = true,
            "D" => args.decoys = value,
            "S" => args.spoof_source = value,
            "e" => args.interface = value,
            "g" => args.source_port_g = value,
            "source-port" => args.source_port = value,
            "proxies" => args.proxies = value,
            "data" => args.data = value,
            "data-string" => args.data_string = value,
            "data-length" => {
                if let Some(v) = value {
                    args.data_length = Some(v.parse().map_err(|_| {
                        Error::InvalidInput(format!("Invalid data-length value: {}", v))
                    })?);
                }
            }
            "ip-options" => args.ip_options = value,
            "ttl" => {
                if let Some(v) = value {
                    args.ttl =
                        Some(v.parse().map_err(|_| {
                            Error::InvalidInput(format!("Invalid ttl value: {}", v))
                        })?);
                }
            }
            "spoof-mac" => args.spoof_mac = value,
            "badsum" => args.badsum = true,

            // Output
            "oN" => args.output_normal = value.map(PathBuf::from),
            "oX" => args.output_xml = value.map(PathBuf::from),
            "oS" => args.output_skript = value.map(PathBuf::from),
            "oG" => args.output_grep = value.map(PathBuf::from),
            "oA" => args.output_all = value,
            "oJ" => args.output_json = value.map(PathBuf::from),
            "oP" => args.output_pair = value.map(PathBuf::from),

            // Verbosity
            "v" => args.verbose = true,
            "d" => args.debug = true,
            "reason" => args.reason = true,
            "open" => args.open_only = true,
            "packet-trace" => args.packet_trace = true,
            "iflist" => args.iflist = true,

            // Misc output
            "append-output" => args.append_output = true,
            "resume" => args.resume = value.map(PathBuf::from),
            "stylesheet" => args.stylesheet = value.map(PathBuf::from),
            "webxml" => args.webxml = true,
            "no-stylesheet" => args.no_stylesheet = true,

            // Misc
            "6" => args.ipv6 = true,
            "A" => args.aggressive = true,
            "datadir" => args.datadir = value.map(PathBuf::from),
            "send-eth" => args.send_eth = true,
            "send-ip" => args.send_ip = true,
            "privileged" => args.privileged = true,
            "unprivileged" => args.unprivileged = true,

            // Help/version
            "V" => args.version = true,
            "h" | "help" => args.help = true,

            _ => {
                return Err(Error::InvalidInput(format!("Unknown argument: {}", name)));
            }
        }

        Ok(())
    }

    /// Validates the parsed arguments
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails (e.g., incompatible options)
    ///
    /// # Examples
    ///
    /// ```
    /// use smap_core::args::SmapArgs;
    ///
    /// let args = SmapArgs::from_iter_safe(["smap", "192.168.1.1"]).unwrap();
    /// assert!(args.validate().is_ok());
    /// ```
    pub fn validate(&self) -> Result<()> {
        // Don't require targets if showing help or version
        if self.help || self.version || self.iflist {
            return Ok(());
        }

        // Check that we have targets unless we're in list mode or resuming
        if self.targets.is_empty() && self.input_list.is_none() && self.resume.is_none() {
            return Err(Error::InvalidInput("No targets specified".to_string()));
        }

        // Validate version intensity is in range 0-9
        if let Some(intensity) = self.version_intensity {
            if intensity > 9 {
                return Err(Error::InvalidInput(
                    "version-intensity must be between 0 and 9".to_string(),
                ));
            }
        }

        // Validate timing template
        if let Some(ref template) = self.timing_template {
            if !matches!(
                template.as_str(),
                "0" | "1"
                    | "2"
                    | "3"
                    | "4"
                    | "5"
                    | "paranoid"
                    | "sneaky"
                    | "polite"
                    | "normal"
                    | "aggressive"
                    | "insane"
            ) {
                return Err(Error::InvalidInput(format!(
                    "Invalid timing template: {}",
                    template
                )));
            }
        }

        Ok(())
    }

    /// Returns the effective output format based on args
    pub fn output_format(&self) -> OutputFormat {
        if self.output_xml.is_some() {
            OutputFormat::Xml
        } else if self.output_json.is_some() {
            OutputFormat::Json
        } else if self.output_grep.is_some() {
            OutputFormat::Grep
        } else {
            OutputFormat::Standard
        }
    }
}

/// Supported output formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Standard text output
    Standard,

    /// JSON format
    Json,

    /// XML format (Nmap-compatible)
    Xml,

    /// Grep-friendly format
    Grep,
}

// For backward compatibility with existing code
pub use SmapArgs as Args;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_target() {
        let args = SmapArgs::from_iter_safe(["smap", "192.168.1.1"]).unwrap();
        assert_eq!(args.targets, vec!["192.168.1.1"]);
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_multiple_targets() {
        let args = SmapArgs::from_iter_safe(["smap", "192.168.1.1", "192.168.1.2", "example.com"])
            .unwrap();
        assert_eq!(args.targets.len(), 3);
    }

    #[test]
    fn test_port_specification() {
        let args = SmapArgs::from_iter_safe(["smap", "-p", "80,443", "192.168.1.1"]).unwrap();
        assert_eq!(args.ports, Some("80,443".to_string()));
        assert_eq!(args.targets, vec!["192.168.1.1"]);
    }

    #[test]
    fn test_port_specification_equals() {
        let args = SmapArgs::from_iter_safe(["smap", "-p=80,443", "192.168.1.1"]).unwrap();
        assert_eq!(args.ports, Some("80,443".to_string()));
    }

    #[test]
    fn test_syn_scan() {
        let args = SmapArgs::from_iter_safe(["smap", "-sS", "192.168.1.1"]).unwrap();
        assert!(args.syn_scan);
    }

    #[test]
    fn test_version_detection() {
        let args = SmapArgs::from_iter_safe(["smap", "-sV", "192.168.1.1"]).unwrap();
        assert!(args.version_detection);
    }

    #[test]
    fn test_os_detection() {
        let args = SmapArgs::from_iter_safe(["smap", "-O", "192.168.1.1"]).unwrap();
        assert!(args.os_detection);
    }

    #[test]
    fn test_aggressive_scan() {
        let args = SmapArgs::from_iter_safe(["smap", "-A", "192.168.1.1"]).unwrap();
        assert!(args.aggressive);
    }

    #[test]
    fn test_timing_template() {
        let args = SmapArgs::from_iter_safe(["smap", "-T", "4", "192.168.1.1"]).unwrap();
        assert_eq!(args.timing_template, Some("4".to_string()));
    }

    #[test]
    fn test_output_formats() {
        let args = SmapArgs::from_iter_safe(["smap", "-oX", "output.xml", "192.168.1.1"]).unwrap();
        assert_eq!(args.output_xml, Some(PathBuf::from("output.xml")));

        let args = SmapArgs::from_iter_safe(["smap", "-oN", "output.txt", "192.168.1.1"]).unwrap();
        assert_eq!(args.output_normal, Some(PathBuf::from("output.txt")));

        let args = SmapArgs::from_iter_safe(["smap", "-oG", "output.grep", "192.168.1.1"]).unwrap();
        assert_eq!(args.output_grep, Some(PathBuf::from("output.grep")));
    }

    #[test]
    fn test_verbose_and_debug() {
        let args = SmapArgs::from_iter_safe(["smap", "-v", "-d", "192.168.1.1"]).unwrap();
        assert!(args.verbose);
        assert!(args.debug);
    }

    #[test]
    fn test_ipv6() {
        let args = SmapArgs::from_iter_safe(["smap", "-6", "::1"]).unwrap();
        assert!(args.ipv6);
    }

    #[test]
    fn test_skip_host_discovery() {
        let args = SmapArgs::from_iter_safe(["smap", "-Pn", "192.168.1.1"]).unwrap();
        assert!(args.skip_host_discovery);
    }

    #[test]
    fn test_no_dns() {
        let args = SmapArgs::from_iter_safe(["smap", "-n", "192.168.1.1"]).unwrap();
        assert!(args.no_dns);
    }

    #[test]
    fn test_top_ports() {
        let args = SmapArgs::from_iter_safe(["smap", "--top-ports", "100", "192.168.1.1"]).unwrap();
        assert_eq!(args.top_ports, Some(100));
    }

    #[test]
    fn test_version_intensity() {
        let args =
            SmapArgs::from_iter_safe(["smap", "--version-intensity", "7", "192.168.1.1"]).unwrap();
        assert_eq!(args.version_intensity, Some(7));
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_version_intensity_invalid() {
        let args =
            SmapArgs::from_iter_safe(["smap", "--version-intensity", "10", "192.168.1.1"]).unwrap();
        assert!(args.validate().is_err());
    }

    #[test]
    fn test_complex_nmap_command() {
        let args = SmapArgs::from_iter_safe([
            "smap",
            "-sS",
            "-sV",
            "-O",
            "-p",
            "1-1000",
            "-T",
            "4",
            "--max-retries",
            "2",
            "-oX",
            "scan.xml",
            "-v",
            "192.168.1.0/24",
        ])
        .unwrap();

        assert!(args.syn_scan);
        assert!(args.version_detection);
        assert!(args.os_detection);
        assert_eq!(args.ports, Some("1-1000".to_string()));
        assert_eq!(args.timing_template, Some("4".to_string()));
        assert_eq!(args.max_retries, Some(2));
        assert_eq!(args.output_xml, Some(PathBuf::from("scan.xml")));
        assert!(args.verbose);
        assert_eq!(args.targets, vec!["192.168.1.0/24"]);
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_multiple_scan_types() {
        let args = SmapArgs::from_iter_safe(["smap", "-sS", "-sU", "-sV", "192.168.1.1"]).unwrap();

        assert!(args.syn_scan);
        assert!(args.udp_scan);
        assert!(args.version_detection);
    }

    #[test]
    fn test_firewall_evasion() {
        let args = SmapArgs::from_iter_safe([
            "smap",
            "-f",
            "-D",
            "RND:10",
            "--data-length",
            "100",
            "192.168.1.1",
        ])
        .unwrap();

        assert!(args.fragment_packets);
        assert_eq!(args.decoys, Some("RND:10".to_string()));
        assert_eq!(args.data_length, Some(100));
    }

    #[test]
    fn test_dns_options() {
        let args =
            SmapArgs::from_iter_safe(["smap", "--dns-servers", "8.8.8.8,1.1.1.1", "192.168.1.1"])
                .unwrap();

        assert_eq!(args.dns_servers, Some("8.8.8.8,1.1.1.1".to_string()));
    }

    #[test]
    fn test_input_list() {
        let args = SmapArgs::from_iter_safe(["smap", "-iL", "targets.txt"]).unwrap();

        assert_eq!(args.input_list, Some(PathBuf::from("targets.txt")));
        assert!(args.validate().is_ok()); // Should be OK even without targets
    }

    #[test]
    fn test_exclude_hosts() {
        let args = SmapArgs::from_iter_safe([
            "smap",
            "--exclude",
            "192.168.1.1,192.168.1.2",
            "192.168.1.0/24",
        ])
        .unwrap();

        assert_eq!(args.exclude, Some("192.168.1.1,192.168.1.2".to_string()));
    }

    #[test]
    fn test_timing_and_performance() {
        let args = SmapArgs::from_iter_safe([
            "smap",
            "--min-rate",
            "100",
            "--max-rate",
            "1000",
            "--max-retries",
            "3",
            "192.168.1.1",
        ])
        .unwrap();

        assert_eq!(args.min_rate, Some(100.0));
        assert_eq!(args.max_rate, Some(1000.0));
        assert_eq!(args.max_retries, Some(3));
    }

    #[test]
    fn test_scan_techniques_comprehensive() {
        // Test all scan technique flags
        let args = SmapArgs::from_iter_safe(["smap", "-sS", "192.168.1.1"]).unwrap();
        assert!(args.syn_scan);

        let args = SmapArgs::from_iter_safe(["smap", "-sT", "192.168.1.1"]).unwrap();
        assert!(args.connect_scan);

        let args = SmapArgs::from_iter_safe(["smap", "-sA", "192.168.1.1"]).unwrap();
        assert!(args.ack_scan);

        let args = SmapArgs::from_iter_safe(["smap", "-sW", "192.168.1.1"]).unwrap();
        assert!(args.window_scan);

        let args = SmapArgs::from_iter_safe(["smap", "-sM", "192.168.1.1"]).unwrap();
        assert!(args.maimon_scan);

        let args = SmapArgs::from_iter_safe(["smap", "-sU", "192.168.1.1"]).unwrap();
        assert!(args.udp_scan);

        let args = SmapArgs::from_iter_safe(["smap", "-sN", "192.168.1.1"]).unwrap();
        assert!(args.null_scan);

        let args = SmapArgs::from_iter_safe(["smap", "-sF", "192.168.1.1"]).unwrap();
        assert!(args.fin_scan);

        let args = SmapArgs::from_iter_safe(["smap", "-sX", "192.168.1.1"]).unwrap();
        assert!(args.xmas_scan);

        let args = SmapArgs::from_iter_safe(["smap", "-sY", "192.168.1.1"]).unwrap();
        assert!(args.sctp_init_scan);

        let args = SmapArgs::from_iter_safe(["smap", "-sZ", "192.168.1.1"]).unwrap();
        assert!(args.cookie_echo_scan);

        let args = SmapArgs::from_iter_safe(["smap", "-sO", "192.168.1.1"]).unwrap();
        assert!(args.ip_protocol_scan);
    }

    #[test]
    fn test_host_discovery_techniques() {
        let args = SmapArgs::from_iter_safe(["smap", "-PS", "192.168.1.1"]).unwrap();
        assert!(args.ps_discovery);

        let args = SmapArgs::from_iter_safe(["smap", "-PA", "192.168.1.1"]).unwrap();
        assert!(args.pa_discovery);

        let args = SmapArgs::from_iter_safe(["smap", "-PU", "192.168.1.1"]).unwrap();
        assert!(args.pu_discovery);

        let args = SmapArgs::from_iter_safe(["smap", "-PE", "192.168.1.1"]).unwrap();
        assert!(args.pe_discovery);

        let args = SmapArgs::from_iter_safe(["smap", "-PP", "192.168.1.1"]).unwrap();
        assert!(args.pp_discovery);

        let args = SmapArgs::from_iter_safe(["smap", "-PM", "192.168.1.1"]).unwrap();
        assert!(args.pm_discovery);
    }

    #[test]
    fn test_no_targets_error() {
        let args = SmapArgs::from_iter_safe(["smap"]).unwrap();
        assert!(args.validate().is_err());
    }

    #[test]
    fn test_help_no_targets_ok() {
        let args = SmapArgs::from_iter_safe(["smap", "-h"]).unwrap();
        assert!(args.help);
        assert!(args.validate().is_ok()); // Help shouldn't require targets
    }

    #[test]
    fn test_version_no_targets_ok() {
        let args = SmapArgs::from_iter_safe(["smap", "-V"]).unwrap();
        assert!(args.version);
        assert!(args.validate().is_ok()); // Version shouldn't require targets
    }

    #[test]
    fn test_invalid_argument() {
        let result = SmapArgs::from_iter_safe(["smap", "--invalid-arg", "192.168.1.1"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_required_value() {
        let result = SmapArgs::from_iter_safe(["smap", "-p", "192.168.1.1"]);
        // This should work - "192.168.1.1" becomes the port value, but then no targets
        assert!(result.is_ok());
        let args = result.unwrap();
        assert_eq!(args.ports, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_timing_template_validation() {
        let valid_templates = vec![
            "0",
            "1",
            "2",
            "3",
            "4",
            "5",
            "paranoid",
            "sneaky",
            "polite",
            "normal",
            "aggressive",
            "insane",
        ];

        for template in valid_templates {
            let args = SmapArgs::from_iter_safe(["smap", "-T", template, "192.168.1.1"]).unwrap();
            assert!(
                args.validate().is_ok(),
                "Template {} should be valid",
                template
            );
        }

        let args = SmapArgs::from_iter_safe(["smap", "-T", "invalid", "192.168.1.1"]).unwrap();
        assert!(args.validate().is_err());
    }

    #[test]
    fn test_output_format_detection() {
        let args = SmapArgs::from_iter_safe(["smap", "-oX", "out.xml", "192.168.1.1"]).unwrap();
        assert_eq!(args.output_format(), OutputFormat::Xml);

        let args = SmapArgs::from_iter_safe(["smap", "-oJ", "out.json", "192.168.1.1"]).unwrap();
        assert_eq!(args.output_format(), OutputFormat::Json);

        let args = SmapArgs::from_iter_safe(["smap", "-oG", "out.grep", "192.168.1.1"]).unwrap();
        assert_eq!(args.output_format(), OutputFormat::Grep);

        let args = SmapArgs::from_iter_safe(["smap", "192.168.1.1"]).unwrap();
        assert_eq!(args.output_format(), OutputFormat::Standard);
    }

    /// Test parsing Nmap command from real-world usage
    #[test]
    fn test_real_world_nmap_command_1() {
        let args = SmapArgs::from_iter_safe([
            "smap",
            "-sS",
            "-sV",
            "-p-",
            "-T4",
            "--max-retries",
            "1",
            "--max-scan-delay",
            "20",
            "-oA",
            "scan_output",
            "192.168.1.0/24",
        ])
        .unwrap();

        assert!(args.syn_scan);
        assert!(args.version_detection);
        assert_eq!(args.ports, Some("-".to_string()));
        assert_eq!(args.max_retries, Some(1));
        assert_eq!(args.max_scan_delay, Some("20".to_string()));
        assert_eq!(args.output_all, Some("scan_output".to_string()));
    }

    /// Test parsing command with multiple output formats
    #[test]
    fn test_multiple_output_formats() {
        let args = SmapArgs::from_iter_safe([
            "smap",
            "-oN",
            "normal.txt",
            "-oX",
            "xml.xml",
            "-oG",
            "grep.txt",
            "192.168.1.1",
        ])
        .unwrap();

        assert_eq!(args.output_normal, Some(PathBuf::from("normal.txt")));
        assert_eq!(args.output_xml, Some(PathBuf::from("xml.xml")));
        assert_eq!(args.output_grep, Some(PathBuf::from("grep.txt")));
    }
}
