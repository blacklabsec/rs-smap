//! Smap - Passive Network Scanner CLI
//!
//! A command-line interface for the smap passive network scanner.
//! Uses the Shodan InternetDB API to gather information about network targets.

use smap_core::{
    args::SmapArgs,
    correlation::correlate,
    ip_utils::{classify_ip, is_global_ip},
    output::{
        GrepFormatter, JsonFormatter, NmapFormatter, PairFormatter, SmapFormatter, XmlFormatter,
    },
    shodan::ShodanClient,
    targets::TargetParser,
    types::ScanResult,
};
use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::process;
use std::sync::atomic::{AtomicBool, AtomicUsize, AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;
use tokio::sync::mpsc;
use tokio::time::sleep;

/// Maximum concurrent scans (3 concurrent queries as per Go implementation)
const MAX_CONCURRENT_SCANS: usize = 3;

/// Rate limiting: ~200 hosts/second target
/// With 3 concurrent connections, we can space requests to achieve this
const RATE_LIMIT_DELAY_MS: u64 = 15; // ~66 requests/sec per connection = ~200/sec total

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

#[tokio::main]
async fn main() {
    // Setup Ctrl+C handler
    let running = Arc::new(AtomicUsize::new(1));
    let abort_handle = Arc::new(Mutex::new(None::<tokio::task::AbortHandle>));
    let abort_clone = Arc::clone(&abort_handle);
    let r = running.clone();
    ctrlc::set_handler(move || {
        if INTERRUPTED.swap(true, Ordering::SeqCst) {
            eprintln!("\nForce exiting...");
            process::exit(1);
        } else {
            r.store(0, Ordering::SeqCst);
            eprintln!("\nCaught interrupt signal, shutting down gracefully...");
            if let Some(handle) = abort_clone.lock().unwrap().take() {
                handle.abort();
            }
        }
    })
    .expect("Error setting Ctrl-C handler");

    if let Err(e) = run(running, abort_handle).await {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

/// Main application logic
async fn run(running: Arc<AtomicUsize>, abort_handle: Arc<Mutex<Option<tokio::task::AbortHandle>>>) -> anyhow::Result<()> {
    let scan_start_time = SystemTime::now();

    // Parse arguments using our custom Nmap-compatible parser
    let args = match SmapArgs::from_iter_safe(env::args()) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    };

    // Handle help and version flags
    if args.help {
        print_help();
        return Ok(());
    }

    if args.version {
        println!("Smap {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // Validate arguments
    args.validate()?;

    // Collect all target IPs
    let target_ips = collect_targets(&args)?;

    if target_ips.is_empty() {
        eprintln!("WARNING: No targets were specified, so 0 hosts scanned.");
        return Ok(());
    }

    // Filter out private IPs
    // Smap is passive only, so private IPs are always invalid targets for the public API
    let (filtered_ips, filtered_count) = filter_private_ips(&target_ips, args.verbose);

    if filtered_ips.is_empty() {
        if args.verbose {
            eprintln!("WARNING: All targets were filtered as private/reserved addresses.");
            eprintln!("Smap is a passive scanner using public InternetDB data; private addresses cannot be scanned.");
        }
        return Ok(());
    }

    // Print scan header
    println!(
        "Starting Smap {} at {}",
        env!("CARGO_PKG_VERSION"),
        format_time(scan_start_time)
    );
    if filtered_count > 0 {
        println!(
            "Filtered {} private/reserved IP(s), scanning {} hosts",
            filtered_count,
            filtered_ips.len()
        );
    } else {
        println!("Scanning {} hosts", filtered_ips.len());
    }

    // Parse port filter if specified
    let port_filter = if let Some(ref port_spec) = args.ports {
        Some(parse_ports(port_spec)?)
    } else {
        None
    };

    // Create Shodan client
    let client = Arc::new(ShodanClient::new()?);

    // Initialize output formatters
    let mut formatters = OutputFormatters::new(&args, scan_start_time)?;

    // Create channel for streaming results
    let (tx, mut rx) = mpsc::channel(100);

    let total_targets = filtered_ips.len();

    // Start light-weight progress/stall monitoring (used when --bar is set)
    let processed_count = Arc::new(AtomicUsize::new(0));
    let last_progress = Arc::new(AtomicU64::new(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
    ));
    let retry_deadline = Arc::new(AtomicU64::new(0u64));
    let monitor_done = Arc::new(AtomicBool::new(false));

    // Create fancy progress bar when requested
    let progress_bar = if args.bar {
        use indicatif::{ProgressBar, ProgressStyle, ProgressDrawTarget};
        let pb = ProgressBar::new(total_targets as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );
        pb.set_draw_target(ProgressDrawTarget::stdout());
        Some(Arc::new(pb))
    } else {
        None
    };

    // Spawn scanning task
    let scan_handle = tokio::spawn(scan_targets(
        filtered_ips,
        client,
        port_filter,
        args.verbose,
        running,
        tx,
        Arc::clone(&retry_deadline),
    ));

    *abort_handle.lock().unwrap() = Some(scan_handle.abort_handle());

    // Spawn monitor task that updates the progress bar message every second when --bar
    if let Some(ref pb) = progress_bar {
        let pc = Arc::clone(&processed_count);
        let lp = Arc::clone(&last_progress);
        let rd = Arc::clone(&retry_deadline);
        let done = Arc::clone(&monitor_done);
        let pb_clone = Arc::clone(pb);
        let total = total_targets;
        tokio::spawn(async move {
            const THRESH_MS: u64 = 5_000; // 5 seconds
            loop {
                if done.load(Ordering::SeqCst) {
                    break;
                }
                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                let last = lp.load(Ordering::SeqCst);
                let elapsed = now_ms.saturating_sub(last);
                let processed = pc.load(Ordering::SeqCst);

                let rd_val = rd.load(Ordering::SeqCst);
                if rd_val > now_ms {
                    // Show exact retry countdown if available
                    let secs_left = ((rd_val.saturating_sub(now_ms)) + 999) / 1000; // ceil
                    pb_clone.set_message(format!("rate-limited: retry in {}s...", secs_left));
                    pb_clone.set_position(processed as u64);
                } else if elapsed >= THRESH_MS {
                    pb_clone.set_message(format!("waiting: {}s...", elapsed / 1000));
                    pb_clone.set_position(processed as u64);
                } else {
                    pb_clone.set_message("");
                    pb_clone.set_position(processed as u64);
                }

                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }

    // Process results as they come in
    let mut total_hosts = 0;
    let mut alive_hosts = 0;

    while let Some(result) = rx.recv().await {
        total_hosts += 1;
        processed_count.fetch_add(1, Ordering::SeqCst);
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        last_progress.store(now_ms, Ordering::SeqCst);

        if result.has_open_ports() {
            alive_hosts += 1;
        }

        let result_time = SystemTime::now();
        formatters.write_result(&result, result_time)?;

        if let Some(ref pb) = progress_bar {
            pb.inc(1);
            // Clear any waiting message on new progress
            pb.set_message("");
        } else if args.bar {
            // Fallback to simple text output if for some reason pb was not created
            print!("\rProcessed: {}/{}", total_hosts, total_targets);
            let _ = std::io::stdout().flush();
        }
    }

    if args.bar {
        monitor_done.store(true, Ordering::SeqCst);
        if let Some(ref pb) = progress_bar {
            pb.finish_with_message("Done");
        } else {
            println!();
        }
    }

    // Wait for scan task to complete (should be done since channel is closed)
    match scan_handle.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!("Scan error: {}", e),
        Err(e) => eprintln!("Task join error: {}", e),
    }

    let scan_end_time = SystemTime::now();

    // Finalize output
    let args_vec: Vec<String> = env::args().collect();
    formatters.finalize(scan_end_time, total_hosts, alive_hosts, &args_vec)?;

    // Print summary if verbose
    if args.verbose {
        let duration = scan_end_time
            .duration_since(scan_start_time)
            .unwrap_or(Duration::from_secs(0));
        println!(
            "Smap done: {} IP addresses ({} hosts up) scanned in {:.2} seconds",
            total_hosts,
            alive_hosts,
            duration.as_secs_f64()
        );
    }

    Ok(())
}

/// Collect all target IPs from arguments and input files
fn collect_targets(args: &SmapArgs) -> anyhow::Result<Vec<IpAddr>> {
    let parser = TargetParser::new();
    let mut all_ips = Vec::new();

    // Process targets from command line
    for target in &args.targets {
        match parser.parse(target) {
            Ok(ips) => all_ips.extend(ips),
            Err(e) => {
                eprintln!("Failed to parse target {}: {}", target, e);
            }
        }
    }

    // Process targets from input file (-iL)
    if let Some(ref input_file) = args.input_list {
        let file_targets = if input_file.to_str() == Some("-") {
            // Read from stdin
            let stdin = std::io::stdin();
            let reader = BufReader::new(stdin);
            read_targets_from_reader(reader, &parser)?
        } else {
            // Read from file
            let file = File::open(input_file)?;
            let reader = BufReader::new(file);
            read_targets_from_reader(reader, &parser)?
        };
        all_ips.extend(file_targets);
    }

    // Remove duplicates
    let unique_ips: HashSet<_> = all_ips.into_iter().collect();
    Ok(unique_ips.into_iter().collect())
}

/// Read targets from a buffered reader
fn read_targets_from_reader<R: BufRead>(
    reader: R,
    parser: &TargetParser,
) -> anyhow::Result<Vec<IpAddr>> {
    let mut ips = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match parser.parse(trimmed) {
            Ok(parsed_ips) => ips.extend(parsed_ips),
            Err(e) => {
                eprintln!("Failed to parse target {}: {}", trimmed, e);
            }
        }
    }
    Ok(ips)
}

/// Filter out private/reserved IP addresses
///
/// Returns a tuple of (filtered IPs, count of filtered IPs)
fn filter_private_ips(ips: &[IpAddr], verbose: bool) -> (Vec<IpAddr>, usize) {
    let mut global_ips = Vec::new();
    let mut filtered_count = 0;

    for ip in ips {
        if is_global_ip(ip) {
            global_ips.push(*ip);
        } else {
            filtered_count += 1;
            if verbose {
                eprintln!(
                    "Skipping {} ({} address - not routable on public internet)",
                    ip,
                    classify_ip(ip)
                );
            }
        }
    }

    (global_ips, filtered_count)
}

/// Parse port specification (e.g., "80,443" or "1-1000")
fn parse_ports(spec: &str) -> anyhow::Result<HashSet<u16>> {
    let mut ports = HashSet::new();

    for part in spec.split(',') {
        let part = part.trim();
        if part.contains('-') {
            // Range: 1-1000
            let range_parts: Vec<&str> = part.split('-').collect();
            if range_parts.len() != 2 {
                anyhow::bail!("Invalid port range: {}", part);
            }
            let start: u16 = range_parts[0].parse()?;
            let end: u16 = range_parts[1].parse()?;
            if start > end {
                anyhow::bail!("Invalid port range: {} > {}", start, end);
            }
            for port in start..=end {
                ports.insert(port);
            }
        } else {
            // Single port
            let port: u16 = part.parse()?;
            ports.insert(port);
        }
    }

    Ok(ports)
}

/// Scan targets with rate limiting and concurrency control
async fn scan_targets(
    targets: Vec<IpAddr>,
    client: Arc<ShodanClient>,
    port_filter: Option<HashSet<u16>>,
    verbose: bool,
    running: Arc<AtomicUsize>,
    tx: mpsc::Sender<ScanResult>,
    retry_deadline: Arc<AtomicU64>,
) -> anyhow::Result<()> {
    let total = targets.len();
    let scanned = Arc::new(AtomicUsize::new(0));
    let hosts_up = Arc::new(AtomicUsize::new(0));

    // Semaphore to limit concurrent scans
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_SCANS));

    let mut tasks = Vec::new();

    for ip in targets {
        // Check if we should stop
        if running.load(Ordering::SeqCst) == 0 {
            break;
        }

        let client = Arc::clone(&client);
        let port_filter = port_filter.clone();
        let scanned = Arc::clone(&scanned);
        let hosts_up = Arc::clone(&hosts_up);
        let semaphore = Arc::clone(&semaphore);
        let running = Arc::clone(&running);
        let tx = tx.clone();
        let rd = Arc::clone(&retry_deadline);

        let task = tokio::spawn(async move {
            // Acquire semaphore permit
            let _permit = semaphore.acquire().await.ok()?;

            // Check again if we should stop
            if running.load(Ordering::SeqCst) == 0 {
                return None;
            }

            // Rate limiting delay
            sleep(Duration::from_millis(RATE_LIMIT_DELAY_MS)).await;

            // Query Shodan (notify retry_deadline so we can show countdown)
            let response = match client
                .query_with_retry_notifier(ip, Some(Arc::clone(&rd)))
                .await
            {
                Ok(resp) => resp,
                Err(e) => {
                    if verbose {
                        eprintln!("Failed to query {}: {}", ip, e);
                    }
                    // If this was a final rate-limit with a known deadline, leave the
                    // retry deadline set so the monitor can show it; otherwise clear it.
                    match e {
                        smap_core::error::Error::ShodanApiRateLimit(_, Some(_)) => {
                            // keep deadline (it should already be set by notifier)
                        }
                        _ => {
                            rd.store(0u64, Ordering::SeqCst);
                        }
                    }

                    scanned.fetch_add(1, Ordering::SeqCst);
                    // Send empty result for progress tracking
                    let empty_result = ScanResult {
                        ip,
                        ports: Vec::new(),
                        cpes: Vec::new(),
                        os: None,
                        hostnames: Vec::new(),
                        tags: Vec::new(),
                        vulns: Vec::new(),
                    };
                    let _ = tx.send(empty_result).await;
                    return None;
                }
            };

            // Create result even if no ports (for progress tracking)
            let has_ports = !response.ports.is_empty();
            if !has_ports {
                scanned.fetch_add(1, Ordering::SeqCst);
                // Send empty result for progress tracking
                let empty_result = ScanResult {
                    ip,
                    ports: Vec::new(),
                    cpes: Vec::new(),
                    os: None,
                    hostnames: Vec::new(),
                    tags: Vec::new(),
                    vulns: Vec::new(),
                };
                let _ = tx.send(empty_result).await;
                return None;
            }

            // Convert to ScanResult
            // Store CPEs before consuming the response
            let cpes = response.cpes.clone();
            let mut result = response.into_scan_result(ip);

            // Filter ports if specified
            if let Some(ref filter) = port_filter {
                result.ports.retain(|p| filter.contains(&p.number));
            }

            // Correlate services and OS using CPEs from Shodan response
            let port_numbers: Vec<u16> = result.ports.iter().map(|p| p.number).collect();

            let (port_infos, os_correlation, uncorrelated_cpes) = correlate(&port_numbers, &cpes);

            // Update ports with correlated information
            for (i, port_info) in port_infos.iter().enumerate() {
                if let Some(port) = result.ports.get_mut(i) {
                    // Create service with the correlated information
                    let service = smap_core::types::Service {
                        name: port_info.service.clone(),
                        product: if port_info.product.is_empty() {
                            None
                        } else {
                            Some(port_info.product.clone())
                        },
                        version: if port_info.version.is_empty() {
                            None
                        } else {
                            Some(port_info.version.clone())
                        },
                        extra_info: None,
                        cpes: port_info.cpes.clone(),
                    };
                    port.service = Some(service);
                }
            }

            // Store uncorrelated CPEs at the host level
            result.cpes = uncorrelated_cpes;

            // Set OS information
            if !os_correlation.name.is_empty() {
                result.os = Some(smap_core::types::OsInfo {
                    name: os_correlation.name,
                    cpes: os_correlation.cpes,
                });
            }

            scanned.fetch_add(1, Ordering::SeqCst);
            if result.has_open_ports() {
                hosts_up.fetch_add(1, Ordering::SeqCst);
            }

            // Send result - ignore send errors as they indicate receiver dropped
            // (e.g., user interrupted the scan)
            let _ = tx.send(result).await;

            Some(())
        });

        tasks.push(task);
    }

    // Drop the original sender so receiver knows when all tasks are done
    drop(tx);

    // Wait for all tasks to complete
    for task in tasks {
        let _ = task.await;
    }

    if verbose {
        let scanned_count = scanned.load(Ordering::SeqCst);
        let hosts_up_count = hosts_up.load(Ordering::SeqCst);
        eprintln!(
            "Scanned {}/{} hosts, {} hosts up",
            scanned_count, total, hosts_up_count
        );
    }

    Ok(())
}

/// Output formatters manager
struct OutputFormatters {
    nmap: Option<NmapFormatter>,
    xml: Option<XmlFormatter>,
    grep: Option<GrepFormatter>,
    json: Option<JsonFormatter>,
    pair: Option<PairFormatter>,
    smap: Option<SmapFormatter>,
    start_time: SystemTime,
}

impl OutputFormatters {
    fn new(args: &SmapArgs, start_time: SystemTime) -> anyhow::Result<Self> {
        let mut formatters = Self {
            nmap: None,
            xml: None,
            grep: None,
            json: None,
            pair: None,
            smap: None,
            start_time,
        };

        let args_vec: Vec<String> = env::args().collect();
        let port_spec = args.ports.as_deref().unwrap_or("");
        let num_ports = if let Some(ref ports) = args.ports {
            parse_ports(ports).map(|p| p.len()).unwrap_or(0)
        } else {
            0
        };

        // Handle -oA (all formats)
        if let Some(ref basename) = args.output_all {
            if basename == "-" {
                anyhow::bail!("Cannot display multiple output types to stdout.");
            }
            let mut nmap_fmt =
                NmapFormatter::new_with_file(start_time, &format!("{}.nmap", basename))?;
            nmap_fmt.start(&args_vec, true)?;
            formatters.nmap = Some(nmap_fmt);

            let mut xml_fmt =
                XmlFormatter::new_with_file(start_time, &format!("{}.xml", basename))?;
            xml_fmt.start(&args_vec, port_spec, num_ports)?;
            formatters.xml = Some(xml_fmt);

            let mut grep_fmt =
                GrepFormatter::new_with_file(start_time, &format!("{}.gnmap", basename))?;
            grep_fmt.start(&args_vec)?;
            formatters.grep = Some(grep_fmt);
        } else {
            // Individual format flags
            if let Some(ref path) = args.output_normal {
                let is_stdout = path.to_str() == Some("-");
                let mut fmt = if is_stdout {
                    NmapFormatter::new(start_time)
                } else {
                    NmapFormatter::new_with_file(start_time, path.to_str().unwrap())?
                };
                fmt.start(&args_vec, !is_stdout)?;
                formatters.nmap = Some(fmt);
            }
            if let Some(ref path) = args.output_xml {
                let mut fmt = if path.to_str() == Some("-") {
                    XmlFormatter::new(start_time)
                } else {
                    XmlFormatter::new_with_file(start_time, path.to_str().unwrap())?
                };
                fmt.start(&args_vec, port_spec, num_ports)?;
                formatters.xml = Some(fmt);
            }
            if let Some(ref path) = args.output_grep {
                let mut fmt = if path.to_str() == Some("-") {
                    GrepFormatter::new(start_time)
                } else {
                    GrepFormatter::new_with_file(start_time, path.to_str().unwrap())?
                };
                fmt.start(&args_vec)?;
                formatters.grep = Some(fmt);
            }
            if let Some(ref path) = args.output_json {
                let mut fmt = if path.to_str() == Some("-") {
                    JsonFormatter::new()
                } else {
                    JsonFormatter::new_with_file(path.to_str().unwrap())?
                };
                fmt.start()?;
                formatters.json = Some(fmt);
            }
            if let Some(ref path) = args.output_pair {
                if path.to_str() == Some("-") {
                    formatters.pair = Some(PairFormatter::new());
                } else {
                    formatters.pair = Some(PairFormatter::new_with_file(path.to_str().unwrap())?);
                }
            }
            // Note: -oS is mapped to output_skript but we use smap format
            if let Some(ref path) = args.output_skript {
                let version = env!("CARGO_PKG_VERSION");
                let mut fmt = if path.to_str() == Some("-") {
                    SmapFormatter::new(version)
                } else {
                    SmapFormatter::new_with_file(version, path.to_str().unwrap())?
                };
                fmt.start()?;
                formatters.smap = Some(fmt);
            }
        }

        // Default to Nmap format if no output specified
        if formatters.nmap.is_none()
            && formatters.xml.is_none()
            && formatters.grep.is_none()
            && formatters.json.is_none()
            && formatters.pair.is_none()
            && formatters.smap.is_none()
        {
            let mut fmt = NmapFormatter::new(start_time);
            fmt.start(&args_vec, false)?;
            formatters.nmap = Some(fmt);
        }

        Ok(formatters)
    }

    fn write_result(&mut self, result: &ScanResult, end_time: SystemTime) -> anyhow::Result<()> {
        if let Some(ref mut fmt) = self.nmap {
            fmt.write_result(result)?;
        }
        if let Some(ref mut fmt) = self.xml {
            fmt.write_result(result, self.start_time, end_time)?;
        }
        if let Some(ref mut fmt) = self.grep {
            fmt.write_result(result)?;
        }
        if let Some(ref mut fmt) = self.json {
            fmt.write_result(result)?;
        }
        if let Some(ref mut fmt) = self.pair {
            fmt.write_result(result)?;
        }
        if let Some(ref mut fmt) = self.smap {
            fmt.write_result(result)?;
        }
        Ok(())
    }

    fn finalize(
        mut self,
        _end_time: SystemTime,
        total_hosts: usize,
        alive_hosts: usize,
        _args: &[String],
    ) -> anyhow::Result<()> {
        if let Some(mut fmt) = self.nmap.take() {
            fmt.end(total_hosts, alive_hosts)?;
        }
        if let Some(mut fmt) = self.xml.take() {
            fmt.end(total_hosts, alive_hosts)?;
        }
        if let Some(mut fmt) = self.grep.take() {
            fmt.end(total_hosts, alive_hosts)?;
        }
        if let Some(mut fmt) = self.json.take() {
            fmt.end()?;
        }
        // Pair and Smap formatters don't have end methods - they flush automatically
        Ok(())
    }
}

/// Format system time for display
fn format_time(time: SystemTime) -> String {
    use std::time::UNIX_EPOCH;
    let duration = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = duration.as_secs();

    // Simple UTC time formatting
    let tm = chrono::DateTime::from_timestamp(secs as i64, 0)
        .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).unwrap());

    tm.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

/// Print help message
fn print_help() {
    println!(
        r#"Smap - Passive Network Scanner v{}

USAGE:
    smap [OPTIONS] <targets>...

TARGETS:
    Specify targets as IP addresses, hostnames, or CIDR ranges
    Examples: 192.168.1.1, example.com, 10.0.0.0/24

COMMON OPTIONS:
    -p <ports>              Port specification (e.g., 80,443 or 1-1000)
    -sS                     TCP SYN scan
    -sV                     Version detection
    -O                      Enable OS detection
    -A                      Aggressive scan (OS, version, script, traceroute)
    -T <0-5>                Timing template (0=paranoid, 5=insane)
    -v                      Verbose output
    -6                      Enable IPv6 scanning

OUTPUT:
    -oN <file>              Normal output
    -oX <file>              XML output
    -oG <file>              Grepable output
    -oJ <file>              JSON output
    -oP <file>              Pair output
    -oS <file>              Smap output
    -oA <basename>          Output in all formats

HOST DISCOVERY:
    -Pn                     Skip host discovery (treat all as online)
    -sn                     Skip port scan
    -n                      Never resolve DNS
    -R                      Always resolve DNS

INPUT:
    -iL <file>              Input from list of hosts/networks

PORT SPECIFICATION:
    -p <ports>              Port ranges (e.g., 80,443 or 1-1000)
    --top-ports <n>         Scan N most common ports
    -F                      Fast mode (scan fewer ports)

For full documentation, visit: https://github.com/s0md3v/smap
"#,
        env!("CARGO_PKG_VERSION")
    );
}
