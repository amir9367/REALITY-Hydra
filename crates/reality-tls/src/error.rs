//! Error type for the REALITY TLS client.

use thiserror::Error;

/// Anything that can go wrong building or using the REALITY TLS layer.
#[derive(Debug, Error)]
pub enum RealityError {
    /// The server public key is not exactly 32 bytes.
    #[error("server public key must be 32 bytes, got {0}")]
    BadServerKey(usize),

    /// A short_id entry is longer than 32 bytes (REALITY protocol limit).
    #[error("short_id too long ({0} bytes, max 32)")]
    ShortIdTooLong(usize),

    /// AES-256-GCM encryption of the auth payload failed.
    #[error("auth encryption failed: {0}")]
    AuthEncrypt(String),

    /// The BoringSSL connector could not be built.
    #[error("boring connector build failed: {0}")]
    BoringBuild(String),

    /// The TLS handshake failed.
    #[error("tls handshake to {addr} (sni={sni}) failed: {message}")]
    Handshake {
        addr: String,
        sni: String,
        message: String,
    },

    /// The TCP connection to the destination failed.
    #[error("tcp connect to {addr} failed: {message}")]
    TcpConnect { addr: String, message: String },

    /// A BoringSSL configuration step failed.
    #[error("boring config error: {0}")]
    BoringConfig(String),
}
