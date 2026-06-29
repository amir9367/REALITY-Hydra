//! Keyed seed derivation.
//!
//! ```text
//! seed = HMAC-SHA256(key = master_secret,
//!                    msg = DOMAIN_TAG || server_salt || LE64(epoch))
//! ```
//!
//! - **`DOMAIN_TAG`** versions the scheme and ensures this key is reused for
//!   nothing else (domain separation).
//! - **`server_salt`** makes two deployments with the *same* master list derive
//!   *different* pools, so there is no cross-deployment correlation.
//! - The trailing fields are fixed-width (`server_salt` is 16 B, the epoch is a
//!   little-endian `u64`), so the concatenation is unambiguous.
//!
//! Security note (REALITY.md §5.4): there is **no forward secrecy** — leaking
//! `master_secret` exposes every past and future epoch pool. Keep it separate
//! from REALITY's `privateKey` and make it rotatable.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::epoch::Epoch;

type HmacSha256 = Hmac<Sha256>;

/// Domain-separation / version tag. Bump when the derivation format changes.
pub const DOMAIN_TAG: &[u8] = b"hydra-pool-v1";

/// Length of the per-deployment salt, in bytes.
pub const SALT_LEN: usize = 16;

/// Required master-secret length, in bytes. (HMAC itself accepts any key
/// length; the config layer enforces 32 for consistency.)
pub const SECRET_LEN: usize = 32;

/// Derive the 32-byte ChaCha20 seed for `epoch`.
pub fn derive_seed(master_secret: &[u8], server_salt: &[u8; SALT_LEN], epoch: Epoch) -> [u8; 32] {
    // HMAC accepts a key of any length, so this construction never fails.
    let mut mac =
        HmacSha256::new_from_slice(master_secret).expect("HMAC accepts keys of any length");
    mac.update(DOMAIN_TAG);
    mac.update(server_salt);
    mac.update(&epoch.to_le_bytes());

    let out = mac.finalize().into_bytes();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&out); // SHA-256 output is exactly 32 bytes
    seed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let s = derive_seed(b"secret", &[0u8; SALT_LEN], 1);
        let s2 = derive_seed(b"secret", &[0u8; SALT_LEN], 1);
        assert_eq!(s, s2);
    }

    #[test]
    fn changes_with_each_input() {
        let base = derive_seed(b"secret", &[0u8; SALT_LEN], 1);
        assert_ne!(base, derive_seed(b"secreT", &[0u8; SALT_LEN], 1)); // key
        assert_ne!(base, derive_seed(b"secret", &[1u8; SALT_LEN], 1)); // salt
        assert_ne!(base, derive_seed(b"secret", &[0u8; SALT_LEN], 2)); // epoch
    }
}
