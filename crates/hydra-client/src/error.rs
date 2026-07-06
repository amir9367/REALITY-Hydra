//! Error type for the Hydra client integration layer.

use thiserror::Error;

/// Anything that can go wrong in the Hydra client pipeline.
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("pool engine: {0}")]
    Pool(#[from] pool_engine::PoolError),

    #[error("DNS resolution failed for {sni:?}: {message}")]
    Dns { sni: String, message: String },

    #[error("reality-tls: {0}")]
    Reality(#[from] reality_tls::RealityError),

    #[error("TCP bind failed on {addr}: {message}")]
    Bind { addr: String, message: String },

    #[error("no exit-node address configured: set `server_addr` (or `dest`) in hydra.toml")]
    NoServerAddr,

    #[error("could not reach exit node {addr}: {source}")]
    TunnelConnect {
        addr: String,
        source: std::io::Error,
    },

    #[error("TLS handshake with exit node {addr} failed: {source}")]
    TunnelTls {
        addr: String,
        source: std::io::Error,
    },

    #[error("exit node refused the tunnel: {reason}")]
    TunnelRejected { reason: String },

    #[error("client TLS setup failed: {0}")]
    Tls(String),

    #[error("SOCKS5 handshake failed: {0}")]
    Socks5(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
