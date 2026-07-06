//! `hydra server` — run the self-tunnel exit node (Linux VPS side).
//!
//! The counterpart to `hydra serve` (the client). This terminates the pinned TLS
//! tunnel, authenticates each CONNECT header with the shared `master_secret`, and
//! relays to the real destination. No Xray involved. See `hydra-server`.
//!
//! On first run it generates a self-signed certificate next to the config and
//! prints its SHA-256 **pin** — copy that into the client's `hydra.toml` as
//! `cert_pin` (the `hydra://` bundle does this for you). Later runs reuse the
//! stored cert so the pin stays stable.

use std::path::PathBuf;

use clap::Args;
use hydra_server::{serve, TlsMaterial};
use pool_engine::HydraConfig;
use tunnel_proto::DEFAULT_MAX_SKEW_SECS;

use crate::error::CliError;

#[derive(Args, Debug)]
pub struct ServerArgs {
    /// Path to the Hydra config (TOML) — the same file the client uses, for the
    /// shared `master_secret`.
    #[arg(short, long, value_name = "PATH")]
    pub config: String,

    /// Address to listen on (host:port). Default binds all interfaces on 443.
    #[arg(short, long, default_value = "0.0.0.0:443")]
    pub listen: String,

    /// Directory holding the exit node's `cert.der` / `key.der`. Defaults to the
    /// directory containing the config file.
    #[arg(long, value_name = "DIR")]
    pub cert_dir: Option<String>,

    /// Subject-alternative name(s) baked into a freshly generated certificate.
    /// Cosmetic only (the client pins by hash), but set it to your server's IP or
    /// domain if you like. Repeatable.
    #[arg(long = "sni", value_name = "NAME")]
    pub sni: Vec<String>,

    /// Max client/server clock skew, in seconds, before a header is rejected.
    #[arg(long, default_value_t = DEFAULT_MAX_SKEW_SECS)]
    pub max_skew: u64,
}

pub fn run(args: &ServerArgs) -> Result<(), CliError> {
    let config = HydraConfig::from_file(&args.config)?;
    let master_secret = config.master_secret().to_vec();

    // Cert dir: explicit flag, else next to the config file, else the cwd.
    let cert_dir: PathBuf = match &args.cert_dir {
        Some(d) => PathBuf::from(d),
        None => PathBuf::from(&args.config)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from(".")),
    };

    let (material, freshly_generated) = TlsMaterial::load_or_generate(&cert_dir, &args.sni)?;
    if freshly_generated {
        eprintln!("hydra-server: generated a new self-signed certificate in {}", cert_dir.display());
    }
    // Always print the pin so the operator can (re)configure clients. Flush
    // immediately: stdout is block-buffered when piped, and the server then blocks
    // forever in the accept loop, so without this the pin would never appear.
    println!("cert_pin = \"{}\"", material.pin_base64());
    use std::io::Write as _;
    let _ = std::io::stdout().flush();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|source| CliError::Io {
            path: "tokio runtime".to_string(),
            source,
        })?;

    rt.block_on(async move { serve(&args.listen, material, master_secret, args.max_skew).await })?;

    Ok(())
}
