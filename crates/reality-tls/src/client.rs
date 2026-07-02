//! The REALITY TLS client — a Chrome-fingerprinted BoringSSL connector plus the
//! seam where REALITY's X25519 auth is injected into the ClientHello.
//!
//! ## What this module can and cannot do (read this)
//!
//! REALITY seals its auth token into the ClientHello `session_id` field, and that
//! sealed value must be part of the TLS transcript — so it has to be written
//! **before** the ClientHello is serialized, and its AEAD binds to the exact
//! serialized bytes plus the X25519 `key_share`. Stock BoringSSL (and therefore
//! the `boring` crate, verified against 4.22) exposes **no hook** to set the
//! ClientHello `session_id` or to override the handshake's ephemeral key_share.
//! Real REALITY is implemented as a *patched* TLS stack (uTLS) for exactly this
//! reason (REALITY.md §7 P7).
//!
//! This module therefore provides:
//!
//! * [`build_connector`] / [`RealityClient::new`] — a correct, compile-checked
//!   `boring` connector whose ClientHello matches Chrome as far as stock APIs
//!   allow (cipher order, curves, sigalgs, ALPN, GREASE, extension permutation,
//!   TLS 1.2–1.3, no cert verification).
//! * [`RealityInjector`] — the seam a REALITY-patched TLS stack plugs into to
//!   actually seal and install the `session_id` (via [`crate::auth::RealityAuth`]).
//!   The only bundled implementation, [`UnsupportedInjector`], returns
//!   [`RealityError::SessionIdInjectionUnsupported`], so an un-patched build fails
//!   loudly instead of silently sending an unauthenticated handshake.
//!
//! Residual JA4 gaps versus a real Chrome capture with stock `boring`:
//! `application_settings` (ALPS) and `compress_certificate` have no setters here.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use boring::ssl::{SslConnector, SslMethod, SslRef, SslVerifyMode, SslVersion};
use tokio::net::TcpStream;

use crate::config::RealityConfig;
use crate::error::RealityError;
use crate::fingerprint::{CHROME_ALPN, CHROME_CIPHER_SUITES, CHROME_GROUPS, CHROME_SIG_ALGS};

/// The seam where REALITY's X25519 auth is written into the ClientHello.
///
/// A faithful implementation, backed by a REALITY-patched TLS stack, must:
/// 1. install a fresh ephemeral X25519 keypair as the ClientHello `key_share`,
/// 2. call [`crate::auth::RealityAuth::seal_with_ephemeral`] with that private
///    key, the *actual* 32-byte ClientHello random, and the serialized
///    ClientHello bytes as AAD,
/// 3. write the resulting 32-byte `session_id` into the ClientHello.
///
/// All three require pre-serialization access that stock `boring` does not offer,
/// which is why the bundled [`UnsupportedInjector`] refuses. Downstream code that
/// links a patched stack supplies its own implementation via
/// [`RealityClient::with_injector`].
pub trait RealityInjector: Send + Sync {
    /// Install REALITY auth into `ssl` before the handshake starts.
    fn install(
        &self,
        ssl: &mut SslRef,
        config: &RealityConfig,
        timestamp: u32,
    ) -> Result<(), RealityError>;
}

/// The default injector: refuses, because stock BoringSSL cannot do the job.
///
/// This keeps [`RealityClient`] honest — without a patched TLS stack, a connect
/// attempt errors at the auth step rather than completing an unauthenticated
/// (and therefore instantly-detectable) handshake.
pub struct UnsupportedInjector;

impl RealityInjector for UnsupportedInjector {
    fn install(
        &self,
        _ssl: &mut SslRef,
        _config: &RealityConfig,
        _timestamp: u32,
    ) -> Result<(), RealityError> {
        Err(RealityError::SessionIdInjectionUnsupported(
            "stock BoringSSL cannot set the ClientHello session_id or override the \
             key_share before serialization; supply a RealityInjector backed by a \
             REALITY-patched TLS stack (uTLS-equivalent)"
                .to_string(),
        ))
    }
}

/// A configured REALITY TLS client.
///
/// Wraps a BoringSSL `SslConnector` with the Chrome fingerprint baked in and a
/// [`RealityInjector`] responsible for the REALITY auth step. Each
/// [`RealityClient::connect`] builds a fresh handshake.
pub struct RealityClient {
    config: RealityConfig,
    connector: SslConnector,
    injector: Arc<dyn RealityInjector>,
}

impl RealityClient {
    /// Build a client from its configuration, using [`UnsupportedInjector`].
    ///
    /// The resulting client produces a Chrome-fingerprinted ClientHello but will
    /// error on [`connect`](RealityClient::connect) at the auth step unless you
    /// swap in a real injector via [`RealityClient::with_injector`].
    pub fn new(config: RealityConfig) -> Result<Self, RealityError> {
        Self::with_injector(config, Arc::new(UnsupportedInjector))
    }

    /// Build a client with a caller-supplied [`RealityInjector`] (a patched TLS
    /// stack), enabling a genuine REALITY data-path.
    pub fn with_injector(
        config: RealityConfig,
        injector: Arc<dyn RealityInjector>,
    ) -> Result<Self, RealityError> {
        let connector = build_connector(&config)?;
        Ok(Self {
            config,
            connector,
            injector,
        })
    }

    /// Open a REALITY-authenticated TLS connection to `addr` presenting `sni`.
    ///
    /// 1. Connects to `addr` over TCP.
    /// 2. Configures a Chrome-fingerprinted ClientHello with SNI = `sni` and no
    ///    certificate/hostname verification (REALITY proves server identity via
    ///    the X25519 auth, not the borrowed cert).
    /// 3. Runs the [`RealityInjector`] to seal and install the auth token.
    /// 4. Performs the TLS 1.3 handshake.
    pub async fn connect(
        &self,
        addr: &str,
        sni: &str,
    ) -> Result<tokio_boring::SslStream<TcpStream>, RealityError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|e| RealityError::TcpConnect {
                addr: addr.to_string(),
                message: e.to_string(),
            })?;

        let mut config = self
            .connector
            .configure()
            .map_err(|e| RealityError::BoringConfig(e.to_string()))?;
        // REALITY borrows someone else's certificate; standard verification is
        // meaningless and would fail. Identity is proved by the sealed auth.
        config.set_verify_hostname(false);
        config.set_use_server_name_indication(true);

        // The REALITY auth step. Errors here (the default) before any bytes go
        // out. `ConnectConfiguration` derefs to `SslRef`, so `&mut config`
        // coerces to the `&mut SslRef` the injector expects.
        self.injector
            .install(&mut config, &self.config, timestamp)?;

        tokio_boring::connect(config, sni, tcp)
            .await
            .map_err(|e| RealityError::Handshake {
                addr: addr.to_string(),
                sni: sni.to_string(),
                message: e.to_string(),
            })
    }

    pub fn config(&self) -> &RealityConfig {
        &self.config
    }
}

/// Format a list of `u16` values as a colon-separated `0x`-prefixed hex string
/// for BoringSSL's list-style setters.
fn hex_list(values: &[u16]) -> String {
    values
        .iter()
        .map(|v| format!("0x{v:04x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Build a BoringSSL `SslConnector` with the Chrome fingerprint baked in.
///
/// Configures cipher order, key-share groups, signature algorithms, ALPN, GREASE,
/// extension permutation, and TLS 1.2–1.3, and disables certificate verification
/// (REALITY does not use standard cert verification).
pub fn build_connector(_config: &RealityConfig) -> Result<SslConnector, RealityError> {
    let mut builder = SslConnector::builder(SslMethod::tls())
        .map_err(|e| RealityError::BoringBuild(e.to_string()))?;

    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|e| RealityError::BoringBuild(e.to_string()))?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|e| RealityError::BoringBuild(e.to_string()))?;

    builder
        .set_cipher_list(&hex_list(CHROME_CIPHER_SUITES))
        .map_err(|e| RealityError::BoringBuild(e.to_string()))?;
    builder
        .set_curves_list(&hex_list(CHROME_GROUPS))
        .map_err(|e| RealityError::BoringBuild(e.to_string()))?;
    builder
        .set_sigalgs_list(&hex_list(CHROME_SIG_ALGS))
        .map_err(|e| RealityError::BoringBuild(e.to_string()))?;

    let mut alpn = Vec::new();
    for proto in CHROME_ALPN {
        alpn.push(proto.len() as u8);
        alpn.extend_from_slice(proto);
    }
    builder
        .set_alpn_protos(&alpn)
        .map_err(|e| RealityError::BoringBuild(e.to_string()))?;

    // Chrome-shaped ClientHello: GREASE values and permuted extension order.
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);

    // REALITY borrows a real cert; do not verify it.
    builder.set_verify(SslVerifyMode::NONE);

    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::Fingerprint;

    fn test_config() -> RealityConfig {
        RealityConfig::new([0xAB; 32], vec![vec![0x01, 0x02]], Fingerprint::Chrome).unwrap()
    }

    #[test]
    fn hex_list_formats_lowercase_prefixed() {
        assert_eq!(hex_list(&[0x1301, 0xc02b]), "0x1301:0xc02b");
    }

    #[test]
    fn connector_builds_with_chrome_fingerprint() {
        assert!(build_connector(&test_config()).is_ok());
    }

    #[test]
    fn default_injector_refuses() {
        let cfg = test_config();
        let connector = build_connector(&cfg).unwrap();
        let mut ssl = boring::ssl::Ssl::new(connector.context()).unwrap();
        let err = UnsupportedInjector
            .install(&mut ssl, &cfg, 0)
            .expect_err("stock stack must refuse");
        assert!(matches!(
            err,
            RealityError::SessionIdInjectionUnsupported(_)
        ));
    }
}
