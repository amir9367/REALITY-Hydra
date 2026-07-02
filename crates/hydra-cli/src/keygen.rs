//! `hydra keygen` — generate a REALITY X25519 keypair.
//!
//! Equivalent to `xray x25519`: prints the `privateKey` (server side) and the
//! matching `publicKey` / `pbk` (client side). Feed the private key into the
//! server's `realitySettings.privateKey` and the public key into the client's
//! `pbk` (or the `[reality] public_key` in hydra.toml).

use base64::Engine as _;
use clap::{Args, ValueEnum};
use reality_tls::auth::generate_keypair;

use crate::error::CliError;

#[derive(Args, Debug)]
pub struct KeygenArgs {
    /// Encoding for the printed keys.
    #[arg(long, value_enum, default_value_t = KeyFormat::Base64)]
    pub format: KeyFormat,

    /// Emit a JSON object instead of human-readable lines.
    #[arg(long)]
    pub json: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum KeyFormat {
    /// Standard base64 (what Xray prints).
    Base64,
    /// Lowercase hex.
    Hex,
}

/// Encode bytes in the requested format.
pub fn encode(bytes: &[u8], format: KeyFormat) -> String {
    match format {
        KeyFormat::Base64 => base64::engine::general_purpose::STANDARD.encode(bytes),
        KeyFormat::Hex => bytes.iter().map(|b| format!("{b:02x}")).collect(),
    }
}

pub fn run(args: &KeygenArgs) -> Result<String, CliError> {
    let (private, public) = generate_keypair();
    let priv_s = encode(&private, args.format);
    let pub_s = encode(&public, args.format);

    if args.json {
        let v = serde_json::json!({
            "privateKey": priv_s,
            "publicKey": pub_s,
        });
        Ok(serde_json::to_string_pretty(&v)?)
    } else {
        Ok(format!(
            "privateKey (server realitySettings.privateKey):\n  {priv_s}\n\
             publicKey  (client pbk / [reality] public_key):\n  {pub_s}"
        ))
    }
}
