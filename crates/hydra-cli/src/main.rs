//! The `hydra` binary: a clap shell over the `hydra_cli` library.
//!
//! One tool for the whole REALITY-Hydra lifecycle:
//!
//! ```text
//! hydra keygen                                  # X25519 keypair (xray x25519)
//! hydra init -o hydra.toml                      # scaffold a full config
//! hydra server-names -c hydra.toml --format xray  # epoch serverNames (server)
//! hydra serve -c hydra.toml --listen :1080        # SOCKS5 client
//! hydra service install --role client -c hydra.toml
//! ```
//!
//! Everything that produces output lives in the library so it stays testable
//! without spawning a process.

use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use hydra_cli::init::InitArgs;
use hydra_cli::keygen::KeygenArgs;
use hydra_cli::serve::ServeArgs;
use hydra_cli::service::ServiceArgs;
use hydra_cli::{OutputFormat, render, resolve_epoch, server_names, CliError};
use pool_engine::HydraConfig;

/// REALITY-Hydra: rotating SNI-pool transport tooling.
#[derive(Parser, Debug)]
#[command(name = "hydra", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a REALITY X25519 keypair (like `xray x25519`).
    Keygen(KeygenArgs),
    /// Scaffold a complete hydra.toml with fresh secrets and keys.
    Init(InitArgs),
    /// Derive the accepted serverNames for an epoch (server side).
    #[command(name = "server-names", visible_alias = "names")]
    ServerNames(ServerNamesArgs),
    /// Run the SOCKS5 client proxy.
    Serve(ServeArgs),
    /// Install/print an OS service (systemd unit or Windows task).
    Service(ServiceArgs),
}

/// The former top-level behaviour, now a subcommand.
#[derive(clap::Args, Debug)]
struct ServerNamesArgs {
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
        Ok(Some(out)) => {
            println!("{out}");
            ExitCode::SUCCESS
        }
        Ok(None) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hydra: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Dispatch a subcommand. `Ok(Some(s))` prints `s`; `Ok(None)` prints nothing
/// (the subcommand handled its own output, e.g. `serve`).
fn run(cli: &Cli) -> Result<Option<String>, CliError> {
    match &cli.command {
        Command::Keygen(args) => Ok(Some(hydra_cli::keygen::run(args)?)),
        Command::Init(args) => Ok(Some(hydra_cli::init::run(args)?)),
        Command::ServerNames(args) => Ok(Some(server_names_output(args)?)),
        Command::Serve(args) => {
            hydra_cli::serve::run(args)?;
            Ok(None)
        }
        Command::Service(args) => Ok(Some(hydra_cli::service::run(args)?)),
    }
}

fn server_names_output(args: &ServerNamesArgs) -> Result<String, CliError> {
    let cfg = HydraConfig::from_file(&args.config)?;
    let epoch = resolve_epoch(&cfg, args.at, args.epoch);
    let pool = server_names(&cfg, epoch, /* window = */ !args.single);
    render(&cfg, &pool, epoch, args.format.into())
}
