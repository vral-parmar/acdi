#![forbid(unsafe_code)]

use anyhow::Result;
use clap::Parser;

use acdi::cli::{Cli, Commands};
use acdi::commands::{diff, scan, tls};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(cli.log_level().into()),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    match cli.command {
        Commands::Scan(args) => scan::run(args),
        Commands::Tls(args) => tls::run(args).await,
        Commands::Diff(args) => diff::run(args),
    }
}
