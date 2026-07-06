//! Error type for the pool engine.

use thiserror::Error;

/// Anything that can go wrong building or loading a pool.
#[derive(Debug, Error)]
pub enum PoolError {
    #[error("master list is empty")]
    EmptyMasterList,

    #[error("entry {index} has an empty SNI")]
    EmptySni { index: usize },

    #[error("entry {index} has invalid weight {weight} (weights must be finite and > 0)")]
    InvalidWeight { index: usize, weight: f64 },

    #[error("duplicate SNI {sni:?} in master list")]
    DuplicateSni { sni: String },

    #[error("active size k must be >= 1")]
    ZeroK,

    #[error("master_secret must be {expected} bytes, got {actual}")]
    BadSecretLen { expected: usize, actual: usize },

    #[error("server_salt must be {expected} bytes, got {actual}")]
    BadSaltLen { expected: usize, actual: usize },

    #[error("invalid base64 in {field}: {source}")]
    Base64 {
        field: &'static str,
        source: base64::DecodeError,
    },

    #[error("unsupported pool_format {found:?}; this build understands {expected:?}")]
    UnsupportedFormat {
        found: String,
        expected: &'static str,
    },

    #[error("invalid epoch_len {0:?}: expected an integer followed by h, m, or s (e.g. \"6h\")")]
    BadDuration(String),

    #[error("failed to read config file {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },

    #[error("failed to parse TOML: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("reality key {field} must be {expected} bytes, got {actual}")]
    BadRealityKeyLen {
        field: &'static str,
        expected: usize,
        actual: usize,
    },

    #[error("invalid hex in reality short_id {index}: {reason}")]
    BadShortIdHex { index: usize, reason: String },

    #[error("reality short_id {index} is {actual} bytes; the REALITY limit is 32")]
    ShortIdTooLong { index: usize, actual: usize },

    #[error("cert_pin must be {expected} bytes (SHA-256), got {actual}")]
    BadCertPinLen { expected: usize, actual: usize },
}
