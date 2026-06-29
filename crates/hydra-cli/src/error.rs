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
}
