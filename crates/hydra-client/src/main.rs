//! The `hydra-client` binary: a SOCKS5 inbound that routes app traffic through
//! the Hydra pipeline (PoolEngine → Selector → DnsWarmer → RealityTLS → CDN edge).
//!
//! ## Usage
//!
//! ```text
//! hydra-client --config crates/pool-engine/fixtures/hydra.toml --listen 127.0.0.1:1080
//! ```

use std::process::ExitCode;

use clap::Parser;
use hydra_client::{ClientError, Pipeline};
use pool_engine::HydraConfig;

/// A SOCKS5 proxy backed by the REALITY-Hydra rotating SNI pool.
#[derive(Parser, Debug)]
#[command(name = "hydra-client", version, about)]
struct Cli {
    /// Path to the Hydra config (TOML). See REALITY.md §11.
    #[arg(short, long, value_name = "PATH")]
    config: String,

    /// SOCKS5 listen address (host:port).
    #[arg(short, long, default_value = "127.0.0.1:1080")]
    listen: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hydra-client: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<(), ClientError> {
    let config = HydraConfig::from_file(&cli.config)?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(async move {
        let pipeline = Pipeline::mock(config);
        pipeline.serve(&cli.listen).await
    })
}
