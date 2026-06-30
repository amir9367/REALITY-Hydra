//! The REALITY TLS client — BoringSSL connector with Chrome fingerprint and
//! embedded X25519 auth.
//!
//! This is the data-path client (REALITY.md §7 P7): it produces a TLS
//! ClientHello that byte-matches Chrome, embeds the REALITY authentication
//! token in the `session_id` extension, and performs the standard TLS 1.3
//! handshake over a TCP connection.
//!
//! ## Feature-gated
//!
//! The entire `client` module is behind the `boring-impersonate` Cargo feature.
//! Without it the crate still exposes [`crate::auth`], [`crate::fingerprint`],
//! and [`crate::config`] — the pure-logic / data modules — so downstream crates
//! can depend on `reality-tls` for the auth and config types without needing a
//! BoringSSL toolchain. The real connector is opt-in, matching the workspace's
//! "offline by default" design philosophy.

use std::time::{SystemTime, UNIX_EPOCH};

use tokio::net::TcpStream;

use crate::auth::RealityAuth;
use crate::config::RealityConfig;
use crate::error::RealityError;
use crate::fingerprint::{CHROME_ALPN, CHROME_CIPHER_SUITES, CHROME_GROUPS, CHROME_SIG_ALGS};

/// A configured REALITY TLS client ready to open authenticated connections.
///
/// Wraps a BoringSSL `SslConnector` with the Chrome fingerprint baked in. Each
/// call to [`RealityClient::connect`] generates a fresh ephemeral X25519 keypair,
/// builds the auth token, and performs a TLS 1.3 handshake with the embedded
/// `session_id`.
pub struct RealityClient {
    config: RealityConfig,
    connector: boring::ssl::SslConnector,
}

impl RealityClient {
    /// Build a client from its configuration.
    ///
    /// Constructs a BoringSSL `SslConnector` with the Chrome fingerprint
    /// parameters and disables certificate verification (REALITY does not use
    /// standard cert verification — the server identity is proved by the X25519
    /// auth in the session ID).
    pub fn new(config: RealityConfig) -> Result<Self, RealityError> {
        let connector = build_connector(&config)?;
        Ok(Self { config, connector })
    }

    /// Open a REALITY-authenticated TLS connection to `addr` presenting `sni`.
    ///
    /// 1. Generates a fresh ephemeral X25519 keypair.
    /// 2. Builds the AES-256-GCM auth token (client_pub || timestamp || short_id).
    /// 3. Connects to `addr` over TCP.
    /// 4. Performs the TLS 1.3 handshake with the auth token in `session_id`.
    ///
    /// Returns the established `SslStream<TcpStream>`.
    pub async fn connect(
        &self,
        addr: &str,
        sni: &str,
    ) -> Result<boring::ssl::SslStream<TcpStream>, RealityError> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let short_id = self.config.pick_short_id();
        let auth = RealityAuth::build(&self.config.server_public_key, short_id, ts)?;

        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|e| RealityError::TcpConnect {
                addr: addr.to_string(),
                message: e.to_string(),
            })?;

        let mut ssl = self
            .connector
            .build()
            .map_err(|e| RealityError::BoringBuild(e.to_string()))?;

        ssl.set_connect_state()
            .map_err(|e| RealityError::BoringConfig(e.to_string()))?;

        ssl.set_session_id(&auth.session_id)
            .map_err(|e| RealityError::BoringConfig(format!("set_session_id: {e}")))?;

        let stream = ssl.connect(sni, tcp).map_err(|e| RealityError::Handshake {
            addr: addr.to_string(),
            sni: sni.to_string(),
            message: e.to_string(),
        })?;

        Ok(stream)
    }

    pub fn config(&self) -> &RealityConfig {
        &self.config
    }
}

/// Format a list of `u16` values as a colon-separated hex string prefixed with
/// `0x` for BoringSSL's list-style APIs (`set_cipher_list`, `set_curves_list`,
/// `set_sigalgs_list`).
fn hex_list(values: &[u16]) -> String {
    values
        .iter()
        .map(|v| format!("0x{v:04x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Build a BoringSSL `SslConnector` with the Chrome fingerprint baked in.
///
/// Cipher suite order, key-share groups, signature algorithms, ALPN, GREASE,
/// and certificate verification are all configured to match Chrome 120+.
fn build_connector(_config: &RealityConfig) -> Result<boring::ssl::SslConnector, RealityError> {
    let mut builder = boring::ssl::SslConnectorBuilder::new(boring::ssl::SslMethod::tls())
        .map_err(|e| RealityError::BoringBuild(e.to_string()))?;

    builder
        .set_min_proto_version(Some(boring::ssl::SslVersion::TLS1_2))
        .map_err(|e| RealityError::BoringBuild(e.to_string()))?;
    builder
        .set_max_proto_version(Some(boring::ssl::SslVersion::TLS1_3))
        .map_err(|e| RealityError::BoringBuild(e.to_string()))?;

    let cipher_str = hex_list(CHROME_CIPHER_SUITES);
    builder
        .set_cipher_list(&cipher_str)
        .map_err(|e| RealityError::BoringBuild(e.to_string()))?;

    let curves_str = hex_list(CHROME_GROUPS);
    builder
        .set_curves_list(&curves_str)
        .map_err(|e| RealityError::BoringBuild(e.to_string()))?;

    let sigalgs_str = hex_list(CHROME_SIG_ALGS);
    builder
        .set_sigalgs_list(&sigalgs_str)
        .map_err(|e| RealityError::BoringBuild(e.to_string()))?;

    let mut alpn = Vec::new();
    for proto in CHROME_ALPN {
        alpn.push(proto.len() as u8);
        alpn.extend_from_slice(proto);
    }
    builder
        .set_alpn_protos(&alpn)
        .map_err(|e| RealityError::BoringBuild(e.to_string()))?;

    builder.set_verify_callback(boring::ssl::SslVerifyMode::NONE, |_ok, _ctx| true);

    builder.set_options(boring::ssl::SslOptions::NO_COMPRESSION);

    Ok(builder.build())
}
