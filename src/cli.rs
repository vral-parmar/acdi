#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use tracing::Level;

#[derive(Parser)]
#[command(
    name = "acdi",
    version,
    about = "Automated Cryptography Discovery & Inventory for PQC migration",
    long_about = "Point acdi at a directory, a binary, or a TLS endpoint — get a CycloneDX 1.7 \
                  CBOM listing every quantum-vulnerable algorithm in seconds.\n\n\
                  Single binary. No Java. No Docker. Works on airgapped boxes."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Increase verbosity (-v = debug, -vv = trace)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,
}

impl Cli {
    pub fn log_level(&self) -> Level {
        match self.verbose {
            0 => Level::WARN,
            1 => Level::DEBUG,
            _ => Level::TRACE,
        }
    }
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan a filesystem path for cryptographic assets
    Scan(ScanArgs),
    /// Probe a TLS endpoint for cryptographic posture
    Tls(TlsArgs),
    /// Compare two CBOM files and show the cryptographic delta
    Diff(DiffArgs),
}

// ── scan ──────────────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct ScanArgs {
    /// Path to scan (file or directory)
    pub path: PathBuf,

    /// Output file path (default: stdout)
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Output format
    #[arg(long, default_value = "cyclonedx-1.7", value_name = "FORMAT")]
    pub format: OutputFormat,

    /// Fail (exit 1) if any finding meets or exceeds this risk level
    #[arg(long, value_name = "LEVEL")]
    pub fail_on: Option<FailOn>,

    /// Suppress table; print only the structured output (respects --format)
    #[arg(long)]
    pub quiet: bool,

    /// Follow symlinks when walking directories
    #[arg(long)]
    pub follow_links: bool,

    /// Path to an ignore file (default: <scan-path>/.acdignore if present)
    #[arg(long, value_name = "FILE")]
    pub ignore_file: Option<PathBuf>,

    /// Do not load any .acdignore file
    #[arg(long)]
    pub no_ignore: bool,

    /// Re-scan automatically when files change; print a diff on each change
    #[arg(long)]
    pub watch: bool,
}

#[derive(ValueEnum, Clone, Debug, Default, PartialEq, Eq)]
pub enum OutputFormat {
    #[default]
    #[value(name = "cyclonedx-1.7")]
    CycloneDx17,
    #[value(name = "sarif")]
    Sarif,
    #[value(name = "html")]
    Html,
    #[value(name = "csv")]
    Csv,
}

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FailOn {
    Low,
    Medium,
    High,
    Critical,
}

// ── tls ───────────────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct TlsArgs {
    /// Host:port to probe (e.g. api.example.com:443)
    pub target: Option<String>,

    /// File containing one host:port per line
    #[arg(long, value_name = "FILE")]
    pub hosts: Option<PathBuf>,

    /// Output file for CBOM JSON
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Maximum concurrent TLS connections
    #[arg(long, default_value = "50")]
    pub concurrency: usize,

    /// Per-host timeout in seconds
    #[arg(long, default_value = "10")]
    pub timeout: u64,
}

// ── diff ──────────────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct DiffArgs {
    /// First (older) CBOM JSON file
    pub before: PathBuf,

    /// Second (newer) CBOM JSON file
    pub after: PathBuf,

    /// Output format for the diff
    #[arg(long, default_value = "text")]
    pub format: DiffFormat,
}

#[derive(ValueEnum, Clone, Debug, Default)]
pub enum DiffFormat {
    #[default]
    Text,
    Json,
}
