//! Error type for the exit-node server.

use thiserror::Error;

/// Anything that can go wrong standing up or running the exit node.
#[derive(Debug, Error)]
pub enum ServerError {
    #[error("TCP bind failed on {addr}: {source}")]
    Bind {
        addr: String,
        source: std::io::Error,
    },

    #[error("accept failed: {0}")]
    Accept(std::io::Error),

    #[error("generating self-signed certificate failed: {0}")]
    CertGen(String),

    #[error("reading certificate material from {path}: {source}")]
    CertRead {
        path: String,
        source: std::io::Error,
    },

    #[error("certificate material in {path} is malformed: {reason}")]
    CertParse { path: String, reason: String },

    #[error("building the rustls server config failed: {0}")]
    Tls(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
