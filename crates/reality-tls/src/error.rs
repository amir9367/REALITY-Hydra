//! Error type for the REALITY TLS layer.

use thiserror::Error;

/// Anything that can go wrong building or using the REALITY TLS layer.
#[derive(Debug, Error)]
pub enum RealityError {
    /// The server public key is not exactly 32 bytes.
    #[error("server public key must be 32 bytes, got {0}")]
    BadServerKey(usize),

    /// The ClientHello random was not exactly 32 bytes. REALITY derives the
    /// auth-key HKDF salt from `random[0..20]` and the AES-GCM nonce from
    /// `random[20..32]`, so a short random cannot be sealed.
    #[error("client random must be 32 bytes, got {0}")]
    BadClientRandom(usize),

    /// A `short_id` entry is longer than 32 bytes (REALITY protocol limit). Note
    /// that only the first 8 bytes ever travel on the wire (the `session_id`
    /// short-id field is 8 bytes); longer values are accepted at config time but
    /// truncated when sealed.
    #[error("short_id too long ({0} bytes, max 32)")]
    ShortIdTooLong(usize),

    /// AES-256-GCM sealing of the REALITY auth plaintext failed.
    #[error("auth seal failed: {0}")]
    AuthSeal(String),

    /// AES-256-GCM opening (server-side verification) failed — wrong key,
    /// tampered ClientHello (AAD mismatch), or a forged `session_id`.
    #[error("auth open failed: {0}")]
    AuthOpen(String),

    /// The active TLS stack cannot inject a caller-chosen `session_id` into the
    /// ClientHello *before* serialization, which REALITY requires (the sealed
    /// value must be part of the TLS transcript). Stock BoringSSL / `boring`
    /// exposes no such hook — a REALITY-patched TLS stack (uTLS-equivalent) must
    /// provide a [`crate::client::RealityInjector`] to cross this boundary.
    #[error("session_id injection is unsupported by this TLS stack: {0}")]
    SessionIdInjectionUnsupported(String),

    /// The BoringSSL connector could not be built.
    #[error("boring connector build failed: {0}")]
    BoringBuild(String),

    /// A BoringSSL configuration step failed.
    #[error("boring config error: {0}")]
    BoringConfig(String),

    /// The TCP connection to the destination failed.
    #[error("tcp connect to {addr} failed: {message}")]
    TcpConnect { addr: String, message: String },

    /// The TLS handshake failed.
    #[error("tls handshake to {addr} (sni={sni}) failed: {message}")]
    Handshake {
        addr: String,
        sni: String,
        message: String,
    },
}
