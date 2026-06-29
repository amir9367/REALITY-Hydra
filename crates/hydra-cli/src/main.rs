//! The `hydra` binary: a thin clap shell over the `hydra_cli` library.
//!
//! Typical server-side use (regenerate `serverNames` for the current epoch and
//! reload Xray):
//!
//! ```text
//! hydra --config /etc/hydra/hydra.toml --format json > server-names.json
//! hydra --config /etc/hydra/hydra.toml --format xray > reality-inbound.json
//! ```

use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use hydra_cli::{OutputFormat, render, resolve_epoch, server_names};
use pool_engine::HydraConfig;

/// Derive a REALITY server's accepted `serverNames` for an epoch from hydra.toml.
#[derive(Parser, Debug)]
#[command(name = "hydra", version, about)]
struct Cli {
    /// Path to the Hydra config (TOML). See REALITY.md §11.
    #[arg(short, long, value_name = "PATH")]
    config: String,

    /// Output shape.
    #[arg(short, long, value_enum, default_value_t = Format::Lines)]
    format: Format,

    /// Evaluate at this UNIX timestamp (seconds) instead of now.
    #[arg(long, value_name = "UNIX_SECS", conflicts_with = "epoch")]
    at: Option<u64>,

    /// Pin an exact epoch number (overrides --at and the clock).
    #[arg(long, value_name = "N")]
    epoch: Option<u64>,

    /// Emit only the exact single-epoch subset, not the ±1 acceptance window.
    /// A server should normally keep the window (the default).
    #[arg(long)]
    single: bool,
}

/// CLI mirror of [`OutputFormat`] so clap owns the value parsing.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum Format {
    /// One SNI per line.
    Lines,
    /// A JSON array of SNIs (the `serverNames` value).
    Json,
    /// A paste-ready stock Xray REALITY inbound.
    Xray,
}

impl From<Format> for OutputFormat {
    fn from(f: Format) -> Self {
        match f {
            Format::Lines => OutputFormat::Lines,
            Format::Json => OutputFormat::Json,
            Format::Xray => OutputFormat::Xray,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(out) => {
            println!("{out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("hydra: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<String, hydra_cli::CliError> {
    let cfg = HydraConfig::from_file(&cli.config)?;
    let epoch = resolve_epoch(&cfg, cli.at, cli.epoch);
    let pool = server_names(&cfg, epoch, /* window = */ !cli.single);
    render(&cfg, &pool, epoch, cli.format.into())
}
