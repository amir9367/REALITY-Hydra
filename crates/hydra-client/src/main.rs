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
        serve(&cli.listen, pipeline).await
    })
}

/// Accept SOCKS5 connections on `addr` and hand them to the pipeline.
async fn serve(
    addr: &str,
    pipeline: Pipeline<dns_warmer::MockResolver>,
) -> Result<(), ClientError> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| ClientError::Bind {
            addr: addr.to_string(),
            message: e.to_string(),
        })?;

    eprintln!("hydra-client: listening on {addr}");

    loop {
        let (stream, peer) = listener.accept().await?;
        eprintln!("hydra-client: connection from {peer}");

        let pipeline = pipeline.clone();
        tokio::spawn(async move {
            if let Err(e) = pipeline.handle_connection(stream).await {
                eprintln!("hydra-client: connection error: {e}");
            }
        });
    }
}
