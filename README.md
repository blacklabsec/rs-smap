

<h4 align="center">Passive Nmap like scanner built with shodan.io</h4>

<p align="center">
  <a href="https://github.com/blacklabsec/rs-smap/releases">
    <img src="https://img.shields.io/github/release/blacklabsec/rs-smap.svg?label=version">
  </a>
  <a href="https://github.com/blacklabsec/rs-smap/releases">
    <img src="https://img.shields.io/github/downloads/blacklabsec/rs-smap/total">
  </a>
  <a href="https://github.com/blacklabsec/rs-smap/issues?q=is%3Aissue+is%3Aclosed">
      <img src="https://img.shields.io/github/issues-closed-raw/blacklabsec/rs-smap?color=dark-green&label=issues%20fixed">
  </a>
</p>


---

**Note:** This is the Rust implementation of Smap, originally created by [s0md3v](https://github.com/s0md3v) as a Go tool. This Rust version is an AI driven port for use in a larger project of mine.

Smap is a port scanner built with shodan.io's free API. It takes same command line arguments as Nmap and produces the same output which makes it a drop-in replacament for Nmap.

## Features
- Scans 200 hosts per second
- Doesn't require any account/api key
- Vulnerability detection
- Supports all nmap's output formats
- Service and version fingerprinting
- Makes no contact to the targets

## Installation

### From Source (Recommended)
Clone this repository and build from source:

```bash
git clone https://github.com/blacklabsec/rs-smap.git
cd rs-smap
cargo build --release
```

The binary will be available at `target/release/smap`.

### Pre-built Binaries
You can download a pre-built binary from [here](https://github.com/blacklabsec/rs-smap/releases) and use it right away.

### Cargo
_Note: Publishing to crates.io is planned for a future release._

## Usage
Smap takes the same arguments as Nmap but options other than `-p`, `-h`, `-o*`, `-iL` are ignored. If you are unfamiliar with Nmap, here's how to use Smap.

### Specifying targets
```
smap 127.0.0.1 127.0.0.2
```
You can also use a list of targets, seperated by newlines.
```
smap -iL targets.txt
```
**Supported formats**

```
1.1.1.1         // IPv4 address
example.com     // hostname
178.23.56.0/8   // CIDR
```

### Output
Smap supports 6 output formats which can be used with the `-o* ` as follows
```
smap example.com -oX output.xml
```
If you want to print the output to terminal, use hyphen (`-`) as filename.

**Supported formats**
```
oX    // nmap's xml format
oG    // nmap's greppable format
oN    // nmap's default format
oA    // output in all 3 formats above at once
oP    // IP:PORT pairs seperated by newlines
oS    // custom smap format
oJ    // json
```

> Note: Since Nmap doesn't scan/display vulnerabilities and tags, that data is not available in nmap's formats. Use `-oS` to view that info.

### Specifying ports
Smap scans these [~4000 ports](https://api.shodan.io/shodan/ports) by default. If you want to display results for certain ports, use the `-p` option.

```
smap -p21-30,80,443 -iL targets.txt
```

## Considerations
Since Smap simply fetches existent port data from shodan.io, it is super fast but there's more to it. You should use Smap if:

#### You want
- vulnerability detection
- a super fast port scanner
- no connections to be made to the targets

#### You are okay with
- not being able to scan IPv6 addresses
- results being up to 7 days old
- a few false negatives

## Development

This project is built with Rust and uses Cargo for package management. The codebase is organized as follows:

- `smap-core/` - Core library containing the main scanning logic
- `smap-cli/` - Command-line interface implementation
- `examples/` - Example usage and debugging tools

### Building and Testing

```bash
# Build the project
cargo build

# Run tests
cargo test

# Run benchmarks
cargo bench

# Build with optimizations
cargo build --release

# Run benchmarks for a specific component
cargo bench correlation

# Check code quality
cargo clippy --all-targets --all-features

# Format code
cargo fmt --all

# Generate documentation
cargo doc --no-deps --open
```

### Testing

The project has comprehensive test coverage including:

- **Unit tests** - Located in each module with `#[cfg(test)]`
- **Integration tests** - Located in `smap-core/tests/`
  - `correlation_integration.rs` - Correlation algorithm tests
  - `output_integration.rs` - Output formatter tests
  - `end_to_end_integration.rs` - Full workflow tests
  - `property_tests.rs` - Property-based and edge case tests
- **Doc tests** - Examples in documentation comments
- **Benchmarks** - Performance benchmarks in `smap-core/benches/`

```bash
# Run tests with coverage (requires cargo-tarpaulin)
cargo install cargo-tarpaulin
cargo tarpaulin --all-features --workspace --out Html

# Run integration tests only
cargo test --test '*'

# Run benchmarks
cargo bench
```

### Architecture

```
┌─────────────┐
│   CLI Args  │
└──────┬──────┘
       │
       v
┌─────────────┐
│   Targets   │ ──> Parse IPs, CIDRs, ranges
└──────┬──────┘
       │
       v
┌─────────────┐
│   Shodan    │ ──> Query InternetDB API
└──────┬──────┘
       │
       v
┌─────────────┐
│ Correlation │ ──> Match services to ports
└──────┬──────┘
       │
       v
┌─────────────┐
│   Output    │ ──> Format results (Nmap, XML, JSON, etc.)
└─────────────┘
```

### Examples

The `examples/` directory contains several useful examples:

```bash
# Run correlation debug example
cargo run --example debug_correlation

# Run output formats example
cargo run --example output_formats

# Run performance test
cargo run --release --example perf_test

# Run memory test
cargo run --example memory_test
```

### Troubleshooting

**Build errors:**
- Ensure you have Rust 1.70+ installed: `rustc --version`
- Update dependencies: `cargo update`
- Clean build: `cargo clean && cargo build`

**Test failures:**
- Check network connectivity for Shodan API tests
- Ensure ports are available for localhost tests
- Run tests sequentially: `cargo test -- --test-threads=1`

**Performance issues:**
- Always use `--release` for production builds
- Check benchmarks: `cargo bench`
- Profile with: `cargo flamegraph`

### Contributing

Not wanting contributions at the moment. This port was made to meet a requirement for another project and as it's a component of a larger project, it's not intended to be maintained or extended. There would be no problem with you opening an issue if you flag something that is just super broken, but not looking for enhancements to this codebase at the moment.

## Original Author and License

This tool is based on the original Go implementation by [s0md3v](https://github.com/s0md3v). The Rust implementation supposedly maintains compatibility with the original while providing Rust's performance and safety benefits.

**Original Repository:** https://github.com/s0md3v/smap

**Rust Implementation:** https://github.com/blacklabsec/rs-smap

**License:** GNU Affero General Public License v3.0

**Note:** This Rust port maintains the same license as per S0md3v's original repo.
