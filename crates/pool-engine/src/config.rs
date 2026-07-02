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

/// The X25519 key length used by REALITY (`pbk` / `privateKey`).
pub const REALITY_KEY_LEN: usize = 32;
/// The REALITY protocol `short_id` byte limit.
const MAX_SHORT_ID_LEN: usize = 32;

/// REALITY handshake keys, parsed from the optional `[reality]` table.
///
/// A server config carries `private_key` (kept secret) plus `public_key`; a
/// client config needs only `public_key` (the `pbk`) and `short_ids`. This is the
/// bridge between the pool engine and the `reality-tls` layer — `hydra init`
/// generates it, `hydra server-names --format xray` renders it, and the client
/// pipeline consumes it.
pub struct RealitySettings {
    /// Server X25519 private key (32 B). Present on servers, absent on clients.
    private_key: Option<SecretBox<[u8; REALITY_KEY_LEN]>>,
    /// Server X25519 public key / client `pbk` (32 B).
    pub public_key: [u8; REALITY_KEY_LEN],
    /// Accepted short IDs (hex-decoded, 0–32 B each). Empty means the empty `""`.
    pub short_ids: Vec<Vec<u8>>,
    /// uTLS fingerprint to impersonate (e.g. `"chrome"`).
    pub fingerprint: String,
}

impl RealitySettings {
    /// Borrow the server private key, if this config carries one. Never log it.
    pub fn private_key(&self) -> Option<&[u8; REALITY_KEY_LEN]> {
        self.private_key.as_ref().map(|s| s.expose_secret())
    }
}

impl std::fmt::Debug for RealitySettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealitySettings")
            .field("public_key", &self.public_key)
            .field("short_ids", &self.short_ids)
            .field("fingerprint", &self.fingerprint)
            .field("has_private_key", &self.private_key.is_some())
            .finish()
    }
}

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
    /// REALITY handshake keys (optional `[reality]` table).
    pub reality: Option<RealitySettings>,
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
    #[serde(default)]
    reality: Option<RawReality>,
}

/// On-disk shape of the optional `[reality]` table.
#[derive(Deserialize)]
struct RawReality {
    #[serde(default)]
    private_key: Option<String>,
    public_key: String,
    #[serde(default)]
    short_ids: Vec<String>,
    #[serde(default = "default_fingerprint")]
    fingerprint: String,
}

fn default_fingerprint() -> String {
    "chrome".to_string()
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

        let reality = self.reality.map(RawReality::into_settings).transpose()?;

        Ok(HydraConfig {
            master_secret,
            server_salt,
            epoch_len,
            active_k: self.active_k,
            master_list,
            dest: self.dest,
            coherence_cidrs: self.coherence_cidrs,
            reality,
        })
    }
}

impl RawReality {
    fn into_settings(self) -> Result<RealitySettings, PoolError> {
        let public_key = decode_key("public_key", &self.public_key)?;

        let private_key = match self.private_key {
            Some(ref pk) => {
                let bytes = decode_key("private_key", pk)?;
                let secret = SecretBox::new(Box::new(bytes));
                Some(secret)
            }
            None => None,
        };

        let mut short_ids = Vec::with_capacity(self.short_ids.len());
        for (index, hex) in self.short_ids.iter().enumerate() {
            let bytes = decode_hex(hex).map_err(|reason| PoolError::BadShortIdHex { index, reason })?;
            if bytes.len() > MAX_SHORT_ID_LEN {
                return Err(PoolError::ShortIdTooLong {
                    index,
                    actual: bytes.len(),
                });
            }
            short_ids.push(bytes);
        }

        Ok(RealitySettings {
            private_key,
            public_key,
            short_ids,
            fingerprint: self.fingerprint,
        })
    }
}

/// Decode a base64 X25519 key and require exactly [`REALITY_KEY_LEN`] bytes.
fn decode_key(field: &'static str, value: &str) -> Result<[u8; REALITY_KEY_LEN], PoolError> {
    let bytes = decode_b64(field, value)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| PoolError::BadRealityKeyLen {
            field,
            expected: REALITY_KEY_LEN,
            actual: bytes.len(),
        })
}

/// Decode a hex string (even length, `0-9a-fA-F`) into bytes.
fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(format!("odd length ({} chars)", s.len()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let nibble = |c: u8| -> Result<u8, String> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            other => Err(format!("invalid hex char {:?}", other as char)),
        }
    };
    for pair in bytes.chunks_exact(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Ok(out)
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
