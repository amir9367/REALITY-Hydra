//! `hydra serve` — run the SOCKS5 client proxy.
//!
//! The unified-CLI entry point to the `hydra-client` pipeline (PoolEngine →
//! Selector → DnsWarmer → RealityTLS). Equivalent to running the standalone
//! `hydra-client` binary; both call [`hydra_client::Pipeline::serve`].

use clap::Args;
use hydra_client::Pipeline;
use pool_engine::HydraConfig;

use crate::error::CliError;

#[derive(Args, Debug)]
pub struct ServeArgs {
    /// Path to the Hydra config (TOML).
    #[arg(short, long, value_name = "PATH")]
    pub config: String,

    /// SOCKS5 listen address (host:port).
    #[arg(short, long, default_value = "127.0.0.1:1080")]
    pub listen: String,
}

pub fn run(args: &ServeArgs) -> Result<(), CliError> {
    let config = HydraConfig::from_file(&args.config)?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|source| CliError::Io {
            path: "tokio runtime".to_string(),
            source,
        })?;

    rt.block_on(async move {
        let pipeline = Pipeline::mock(config);
        pipeline.serve(&args.listen).await
    })?;

    Ok(())
}
