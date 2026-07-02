//! Error type for the CLI layer.

use thiserror::Error;

/// Anything that can go wrong loading config or rendering output.
#[derive(Debug, Error)]
pub enum CliError {
    /// The underlying pool engine failed (config parse/validation, etc.).
    #[error(transparent)]
    Pool(#[from] pool_engine::PoolError),

    /// Serializing the JSON / Xray output failed (should be unreachable for the
    /// values we build, but surfaced rather than panicked on).
    #[error("failed to serialize output: {0}")]
    Serialize(#[from] serde_json::Error),

    /// A filesystem operation failed (reading/writing config or unit files).
    #[error("{path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },

    /// `init` refused to overwrite an existing file without `--force`.
    #[error("{0} already exists (use --force to overwrite)")]
    AlreadyExists(String),

    /// The SOCKS5 client returned an error while serving.
    #[error(transparent)]
    Client(#[from] hydra_client::ClientError),

    /// Service (systemd / scheduled task) management failed.
    #[error("service: {0}")]
    Service(String),
}
