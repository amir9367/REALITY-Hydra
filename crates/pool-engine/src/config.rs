//! Loading the engine's configuration (and master list) from TOML.
//!
//! Mirrors the `hydra.toml` sketch in REALITY.md §11. Phase 1 only needs the
//! keying material, epoch parameters, and the pool; network-layer fields
//! (`dest`, `coherence_cidrs`) are accepted and preserved for later phases so the
//! same file works unchanged.

use std::path::Path;
use std::time::Duration;

use base64::Engine as _;
use secrecy::{ExposeSecret, SecretBox};
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use crate::entry::{MasterList, PoolEntry};
use crate::error::PoolError;
use crate::kdf::{DOMAIN_TAG, SALT_LEN, SECRET_LEN};

/// Fully-parsed, validated engine configuration.
///
/// The master secret is wrapped in a [`SecretBox`], which keeps it out of
/// `Debug` output and zeroizes it on drop. Read it only through
/// [`HydraConfig::master_secret`], and keep the borrow short-lived.
pub struct HydraConfig {
    master_secret: SecretBox<[u8; SECRET_LEN]>,
    pub server_salt: [u8; SALT_LEN],
    pub epoch_len: Duration,
    pub active_k: usize,
    pub master_list: MasterList,
    /// Network fields for later phases (unused in Phase 1).
    pub dest: Option<String>,
    pub coherence_cidrs: Vec<String>,
}

impl HydraConfig {
    /// Borrow the master-secret bytes for seed derivation. Never log or clone it.
    pub fn master_secret(&self) -> &[u8; SECRET_LEN] {
        self.master_secret.expose_secret()
    }

    /// Parse and validate config from a TOML string.
    pub fn from_toml_str(s: &str) -> Result<Self, PoolError> {
        let raw: RawConfig = toml::from_str(s)?;
        raw.into_config()
    }

    /// Read, parse, and validate config from a TOML file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, PoolError> {
        let path = path.as_ref();
        let s = std::fs::read_to_string(path).map_err(|source| PoolError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_toml_str(&s)
    }
}

/// The on-disk shape, before validation. Unknown fields are ignored by serde, so
/// future config keys won't break older clients.
#[derive(Deserialize)]
struct RawConfig {
    master_secret: String,
    server_salt: String,
    #[serde(default = "default_format")]
    pool_format: String,
    #[serde(default = "default_epoch_len")]
    epoch_len: String,
    active_k: usize,
    #[serde(default)]
    dest: Option<String>,
    #[serde(default)]
    coherence_cidrs: Vec<String>,
    #[serde(default)]
    pool: Vec<PoolEntry>,
}

fn default_format() -> String {
    expected_format().to_string()
}

fn default_epoch_len() -> String {
    "6h".to_string()
}

/// The pool format this build understands, as a string.
fn expected_format() -> &'static str {
    // DOMAIN_TAG is a fixed ASCII byte string, so this never fails.
    std::str::from_utf8(DOMAIN_TAG).expect("DOMAIN_TAG is valid ASCII")
}

impl RawConfig {
    fn into_config(self) -> Result<HydraConfig, PoolError> {
        // Version/format gate (REALITY.md P9 — the master list is versioned data).
        let expected = expected_format();
        if self.pool_format != expected {
            return Err(PoolError::UnsupportedFormat {
                found: self.pool_format,
                expected,
            });
        }

        // Master secret: decode, copy into a fixed array, box it as a secret, and
        // scrub every intermediate copy.
        let secret_bytes = Zeroizing::new(decode_b64("master_secret", &self.master_secret)?);
        if secret_bytes.len() != SECRET_LEN {
            return Err(PoolError::BadSecretLen {
                expected: SECRET_LEN,
                actual: secret_bytes.len(),
            });
        }
        let mut secret = [0u8; SECRET_LEN];
        secret.copy_from_slice(&secret_bytes);
        let master_secret = SecretBox::new(Box::new(secret));
        secret.zeroize(); // scrub the stack copy left behind by Box::new

        // Salt is not secret.
        let salt_bytes = decode_b64("server_salt", &self.server_salt)?;
        let server_salt: [u8; SALT_LEN] =
            salt_bytes
                .as_slice()
                .try_into()
                .map_err(|_| PoolError::BadSaltLen {
                    expected: SALT_LEN,
                    actual: salt_bytes.len(),
                })?;

        if self.active_k == 0 {
            return Err(PoolError::ZeroK);
        }

        let epoch_len = parse_duration(&self.epoch_len)?;
        let master_list = MasterList::new(self.pool)?;

        Ok(HydraConfig {
            master_secret,
            server_salt,
            epoch_len,
            active_k: self.active_k,
            master_list,
            dest: self.dest,
            coherence_cidrs: self.coherence_cidrs,
        })
    }
}

/// Decode a base64 value that may carry an optional `base64:` prefix (as written
/// in the REALITY.md config sketch).
fn decode_b64(field: &'static str, value: &str) -> Result<Vec<u8>, PoolError> {
    let body = value.strip_prefix("base64:").unwrap_or(value);
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|source| PoolError::Base64 { field, source })
}

/// Parse a tiny duration string: an integer followed by `h`, `m`, or `s`.
fn parse_duration(s: &str) -> Result<Duration, PoolError> {
    let s = s.trim();
    let bad = || PoolError::BadDuration(s.to_string());
    let (num, unit) = s.split_at(s.len().checked_sub(1).ok_or_else(bad)?);
    let n: u64 = num.parse().map_err(|_| bad())?;
    let secs = match unit {
        "h" => n.checked_mul(3600),
        "m" => n.checked_mul(60),
        "s" => Some(n),
        _ => return Err(bad()),
    };
    Ok(Duration::from_secs(secs.ok_or_else(bad)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_units() {
        assert_eq!(parse_duration("6h").unwrap(), Duration::from_secs(6 * 3600));
        assert_eq!(parse_duration("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_duration("45s").unwrap(), Duration::from_secs(45));
        assert!(parse_duration("6").is_err());
        assert!(parse_duration("6d").is_err());
        assert!(parse_duration("").is_err());
    }
}
