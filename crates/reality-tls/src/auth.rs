//! REALITY authentication: X25519 key exchange + AES-256-GCM auth payload.
//!
//! The REALITY protocol embeds an authentication token in the TLS session ID
//! field of the ClientHello (REALITY.md §1). Only the real server — holding the
//! corresponding X25519 private key — can decrypt and verify it.
//!
//! ## Protocol
//!
//! ```text
//! 1. Client generates ephemeral X25519 keypair (client_pub, client_priv).
//! 2. shared_secret = X25519(client_priv, server_pub).
//! 3. auth_payload  = client_pub (32B) || timestamp (8B LE) || short_id (0–32B).
//! 4. nonce         = HKDF-SHA256("hydra-reality-nonce" || len(payload), shared_secret)[0..12].
//! 5. ciphertext    = AES-256-GCM(key = shared_secret, nonce, auth_payload).
//! 6. The session_id extension in the ClientHello carries the ciphertext.
//! ```

use aes_gcm::aead::Aead;
use aes_gcm::aead::OsRng;
use aes_gcm::{Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::error::RealityError;

const NONCE_INFO: &[u8] = b"hydra-reality-nonce";
const NONCE_LEN: usize = 12;
#[allow(dead_code)]
const TAG_LEN: usize = 16;
const PUBKEY_LEN: usize = 32;
const TIMESTAMP_LEN: usize = 8;
const MAX_SHORT_ID_LEN: usize = 32;

/// The result of building a REALITY auth token: the ephemeral client public key
/// and the encrypted session_id to embed in the ClientHello.
#[derive(Clone, Debug)]
pub struct RealityAuth {
    pub client_public: [u8; PUBKEY_LEN],
    pub session_id: Vec<u8>,
}

impl RealityAuth {
    /// Build a fresh auth token for this connection.
    ///
    /// * `server_public_key` — the server's 32-byte X25519 public key (`pbk`).
    /// * `short_id` — one of the server's accepted `shortIds` (0–32 bytes).
    /// * `timestamp` — UNIX seconds (passed in so the caller controls the clock).
    pub fn build(
        server_public_key: &[u8; PUBKEY_LEN],
        short_id: &[u8],
        timestamp: u64,
    ) -> Result<Self, RealityError> {
        if short_id.len() > MAX_SHORT_ID_LEN {
            return Err(RealityError::ShortIdTooLong(short_id.len()));
        }

        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_secret);

        let server_pub = PublicKey::from(*server_public_key);
        let shared = client_secret.diffie_hellman(&server_pub);

        let mut payload = Vec::with_capacity(PUBKEY_LEN + TIMESTAMP_LEN + short_id.len());
        payload.extend_from_slice(client_public.as_bytes());
        payload.extend_from_slice(&timestamp.to_le_bytes());
        payload.extend_from_slice(short_id);

        let nonce = derive_nonce(shared.as_bytes(), payload.len());

        let cipher = Aes256Gcm::new_from_slice(shared.as_bytes())
            .map_err(|e| RealityError::AuthEncrypt(e.to_string()))?;
        let ciphertext = cipher
            .encrypt(&nonce.into(), payload.as_ref())
            .map_err(|e| RealityError::AuthEncrypt(e.to_string()))?;

        let mut client_pub_bytes = [0u8; PUBKEY_LEN];
        client_pub_bytes.copy_from_slice(client_public.as_bytes());

        Ok(Self {
            client_public: client_pub_bytes,
            session_id: ciphertext,
        })
    }
}

/// Derive a 12-byte AES-GCM nonce from the shared secret using HKDF-SHA256.
fn derive_nonce(shared_secret: &[u8], payload_len: usize) -> [u8; NONCE_LEN] {
    let mut info = Vec::with_capacity(NONCE_INFO.len() + 8);
    info.extend_from_slice(NONCE_INFO);
    info.extend_from_slice(&(payload_len as u64).to_le_bytes());

    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut nonce = [0u8; NONCE_LEN];
    hk.expand(&info, &mut nonce)
        .expect("HKDF-SHA256 expand for 12 bytes cannot fail");
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_id_too_long_is_rejected() {
        let server_key = [0u8; 32];
        let too_long = vec![0u8; 33];
        assert!(RealityAuth::build(&server_key, &too_long, 0).is_err());
    }

    #[test]
    fn empty_short_id_is_valid() {
        let server_key = [0xAAu8; 32];
        let auth = RealityAuth::build(&server_key, &[], 12345).unwrap();
        assert_eq!(auth.session_id.len(), 32 + 8 + TAG_LEN);
    }

    #[test]
    fn eight_byte_short_id_gives_correct_length() {
        let server_key = [0xBBu8; 32];
        let short_id = [0x01u8; 8];
        let auth = RealityAuth::build(&server_key, &short_id, 0).unwrap();
        assert_eq!(auth.session_id.len(), 32 + 8 + 8 + TAG_LEN);
    }

    #[test]
    fn fresh_keypairs_are_unique() {
        let server_key = [0xCCu8; 32];
        let auths: Vec<_> = (0..10)
            .map(|_| RealityAuth::build(&server_key, &[], 0).unwrap())
            .collect();
        let mut keys: Vec<_> = auths.iter().map(|a| a.client_public).collect();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), 10);
    }

    #[test]
    fn different_timestamps_produce_different_ciphertexts() {
        let server_key = [0xDDu8; 32];
        let a = RealityAuth::build(&server_key, &[], 100).unwrap();
        let b = RealityAuth::build(&server_key, &[], 200).unwrap();
        assert_ne!(a.session_id, b.session_id);
    }

    #[test]
    fn different_short_ids_produce_different_ciphertexts() {
        let server_key = [0xEEu8; 32];
        let a = RealityAuth::build(&server_key, &[0x01], 0).unwrap();
        let b = RealityAuth::build(&server_key, &[0x02], 0).unwrap();
        assert_ne!(a.session_id, b.session_id);
    }
}
