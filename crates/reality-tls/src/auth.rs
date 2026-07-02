//! REALITY authentication — the exact wire format Xray-core's REALITY uses.
//!
//! REALITY hides a proof-of-knowledge of the server's X25519 key inside the TLS
//! ClientHello `session_id` field (REALITY.md §1). Only the real server, holding
//! the matching `privateKey`, can decrypt and verify it; everyone else forwards
//! the connection to the genuine `dest` and sees a real website.
//!
//! This module is a faithful, offline-testable re-implementation of the sealing
//! performed by Xray-core (`transport/internet/reality/reality.go`). The exact
//! construction is:
//!
//! ```text
//!  eph_priv, eph_pub = X25519 keypair          // eph_pub IS the TLS key_share
//!  shared            = X25519(eph_priv, server_pub)
//!  auth_key          = HKDF-SHA256(ikm=shared, salt=client_random[0..20], info="REALITY")[0..32]
//!  plaintext[16]     = version[0..3] || 0x00 || BE32(unix_secs) || short_id[0..8]
//!  nonce             = client_random[20..32]    // 12 bytes
//!  session_id[32]    = AES-256-GCM(key=auth_key, nonce, aad=client_hello_raw, msg=plaintext)
//!                      //  = 16-byte ciphertext || 16-byte tag = exactly 32 bytes
//! ```
//!
//! Two facts make this different from a naive scheme and are the reason the old
//! implementation could never talk to a real server:
//!
//! 1. **The ephemeral public key is the ClientHello's X25519 `key_share`.** The
//!    server recovers it straight from the handshake; it is *not* carried inside
//!    the encrypted blob. [`RealityAuth`] therefore exposes both halves of the
//!    keypair so the TLS layer can install them as the real key_share.
//! 2. **The whole ClientHello is the AEAD's associated data.** The seal binds the
//!    auth token to the exact bytes on the wire, so it cannot be lifted into a
//!    different (e.g. non-Chrome) handshake.
//!
//! [`RealityAuth::seal`] is the client role; [`RealityAuth::open`] is the server
//! role, included so the crate can prove round-trip correctness in tests without
//! a live Xray server.

use aes_gcm::aead::{Aead, OsRng, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::RealityError;

/// HKDF `info` string REALITY derives the auth key with. Must match Xray-core.
pub const REALITY_HKDF_INFO: &[u8] = b"REALITY";
/// X25519 public/private key length.
pub const KEY_LEN: usize = 32;
/// AES-256-GCM key length (also the HKDF output length).
pub const AUTH_KEY_LEN: usize = 32;
/// The ClientHello random length; REALITY slices it into HKDF salt + GCM nonce.
pub const CLIENT_RANDOM_LEN: usize = 32;
/// AES-GCM nonce length (`client_random[20..32]`).
pub const NONCE_LEN: usize = 12;
/// AES-GCM tag length.
pub const TAG_LEN: usize = 16;
/// The fixed REALITY plaintext length: `version(3) + reserved(1) + ts(4) + sid(8)`.
pub const PLAINTEXT_LEN: usize = 16;
/// The resulting `session_id` length: `ciphertext(16) + tag(16)`. Exactly the
/// TLS legacy-session-id limit (RFC 8446), which is why it fits the field.
pub const SESSION_ID_LEN: usize = 32;
/// The number of `short_id` bytes that travel on the wire (`plaintext[8..16]`).
pub const SHORT_ID_FIELD_LEN: usize = 8;
/// Upper bound accepted at the API boundary; only the first 8 bytes are sealed.
const MAX_SHORT_ID_LEN: usize = 32;

/// The version triple written into `plaintext[0..3]`. Informational on the wire
/// (a real Xray client sends its own version); configurable via [`RealityAuth`]
/// callers. The reserved fourth byte is always zero.
pub const DEFAULT_VERSION: [u8; 3] = [1, 8, 4];

/// A built REALITY auth token.
///
/// `client_public` is the ephemeral X25519 key_share the TLS layer must place in
/// the ClientHello; `client_private` is its secret half, exposed so a REALITY-
/// patched TLS stack can install the same keypair as the handshake key_share
/// (stock stacks generate their own and give no way to override it — see
/// [`crate::client`]). `session_id` is the 32-byte sealed blob.
#[derive(Clone)]
pub struct RealityAuth {
    pub client_public: [u8; KEY_LEN],
    pub client_private: [u8; KEY_LEN],
    pub session_id: [u8; SESSION_ID_LEN],
}

impl core::fmt::Debug for RealityAuth {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print the private key.
        f.debug_struct("RealityAuth")
            .field("client_public", &self.client_public)
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

/// The plaintext recovered by the server after opening a `session_id`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthPayload {
    pub version: [u8; 3],
    pub timestamp: u32,
    pub short_id: [u8; SHORT_ID_FIELD_LEN],
}

impl RealityAuth {
    /// Build a token with a fresh ephemeral keypair (client role).
    ///
    /// * `server_public_key` — the server's 32-byte X25519 public key (`pbk`).
    /// * `short_id` — one of the server's accepted `shortIds` (0–32 bytes; only
    ///   the first 8 are sealed).
    /// * `version` — the version triple for `plaintext[0..3]` (see [`DEFAULT_VERSION`]).
    /// * `timestamp` — UNIX seconds (caller controls the clock; the server checks
    ///   it against `maxTimeDiff`).
    /// * `client_random` — the 32-byte ClientHello random the TLS layer will send;
    ///   REALITY derives the HKDF salt and GCM nonce from it, so it must be the
    ///   *actual* random on the wire.
    /// * `client_hello_raw` — the serialized ClientHello, used verbatim as the
    ///   AEAD associated data.
    pub fn seal(
        server_public_key: &[u8; KEY_LEN],
        short_id: &[u8],
        version: [u8; 3],
        timestamp: u32,
        client_random: &[u8; CLIENT_RANDOM_LEN],
        client_hello_raw: &[u8],
    ) -> Result<Self, RealityError> {
        let ephemeral = StaticSecret::random_from_rng(OsRng);
        Self::seal_with_ephemeral(
            ephemeral.to_bytes(),
            server_public_key,
            short_id,
            version,
            timestamp,
            client_random,
            client_hello_raw,
        )
    }

    /// Like [`RealityAuth::seal`] but with a caller-supplied ephemeral private
    /// key. Used when the TLS stack owns the key_share (so both sides seal with
    /// the same key) and for deterministic tests.
    pub fn seal_with_ephemeral(
        client_private: [u8; KEY_LEN],
        server_public_key: &[u8; KEY_LEN],
        short_id: &[u8],
        version: [u8; 3],
        timestamp: u32,
        client_random: &[u8; CLIENT_RANDOM_LEN],
        client_hello_raw: &[u8],
    ) -> Result<Self, RealityError> {
        if short_id.len() > MAX_SHORT_ID_LEN {
            return Err(RealityError::ShortIdTooLong(short_id.len()));
        }

        let secret = StaticSecret::from(client_private);
        let client_public = PublicKey::from(&secret);
        let server_pub = PublicKey::from(*server_public_key);
        let shared = secret.diffie_hellman(&server_pub);

        let auth_key = derive_auth_key(shared.as_bytes(), client_random);
        let plaintext = build_plaintext(version, timestamp, short_id);

        let cipher = Aes256Gcm::new_from_slice(&auth_key)
            .map_err(|e| RealityError::AuthSeal(e.to_string()))?;
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&client_random[20..32]);
        let sealed = cipher
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: &plaintext,
                    aad: client_hello_raw,
                },
            )
            .map_err(|e| RealityError::AuthSeal(e.to_string()))?;

        // ciphertext(16) + tag(16) is exactly the 32-byte session_id.
        debug_assert_eq!(sealed.len(), SESSION_ID_LEN);
        let mut session_id = [0u8; SESSION_ID_LEN];
        session_id.copy_from_slice(&sealed);

        Ok(Self {
            client_public: client_public.to_bytes(),
            client_private,
            session_id,
        })
    }

    /// Verify and decrypt a `session_id` (server role).
    ///
    /// * `server_private_key` — the server's 32-byte X25519 private key.
    /// * `client_public_key` — the ephemeral key_share taken from the ClientHello.
    /// * `session_id` — the 32-byte value from the ClientHello session_id field.
    /// * `client_random` / `client_hello_raw` — the same handshake bytes the
    ///   client sealed against.
    ///
    /// Returns the [`AuthPayload`] on success, or [`RealityError::AuthOpen`] if
    /// the key is wrong, the ClientHello was tampered with (AAD mismatch), or the
    /// token was forged.
    pub fn open(
        server_private_key: &[u8; KEY_LEN],
        client_public_key: &[u8; KEY_LEN],
        session_id: &[u8; SESSION_ID_LEN],
        client_random: &[u8; CLIENT_RANDOM_LEN],
        client_hello_raw: &[u8],
    ) -> Result<AuthPayload, RealityError> {
        let secret = StaticSecret::from(*server_private_key);
        let client_pub = PublicKey::from(*client_public_key);
        let shared = secret.diffie_hellman(&client_pub);

        let auth_key = derive_auth_key(shared.as_bytes(), client_random);

        let cipher = Aes256Gcm::new_from_slice(&auth_key)
            .map_err(|e| RealityError::AuthOpen(e.to_string()))?;
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&client_random[20..32]);
        let plaintext = cipher
            .decrypt(
                &nonce.into(),
                Payload {
                    msg: session_id.as_slice(),
                    aad: client_hello_raw,
                },
            )
            .map_err(|e| RealityError::AuthOpen(e.to_string()))?;

        parse_plaintext(&plaintext)
    }
}

/// Derive the X25519 public key from a private key — the `xray x25519`
/// operation. Useful for turning a server `privateKey` into the `pbk` clients
/// need, and for deriving the key_share public from an ephemeral private.
pub fn public_from_private(private: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    PublicKey::from(&StaticSecret::from(*private)).to_bytes()
}

/// Generate a fresh X25519 keypair as `(private, public)` — the REALITY
/// `privateKey` / `publicKey` (`pbk`) pair, equivalent to `xray x25519`.
pub fn generate_keypair() -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

/// `auth_key = HKDF-SHA256(ikm = shared_secret, salt = client_random[0..20], info = "REALITY")`.
fn derive_auth_key(
    shared_secret: &[u8],
    client_random: &[u8; CLIENT_RANDOM_LEN],
) -> [u8; AUTH_KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(&client_random[..20]), shared_secret);
    let mut auth_key = [0u8; AUTH_KEY_LEN];
    hk.expand(REALITY_HKDF_INFO, &mut auth_key)
        .expect("HKDF-SHA256 expand for 32 bytes cannot fail");
    auth_key
}

/// Build the 16-byte REALITY plaintext: `version || 0x00 || BE32(ts) || short_id[0..8]`.
fn build_plaintext(version: [u8; 3], timestamp: u32, short_id: &[u8]) -> [u8; PLAINTEXT_LEN] {
    let mut pt = [0u8; PLAINTEXT_LEN];
    pt[0..3].copy_from_slice(&version);
    pt[3] = 0; // reserved
    pt[4..8].copy_from_slice(&timestamp.to_be_bytes());
    let n = short_id.len().min(SHORT_ID_FIELD_LEN);
    pt[8..8 + n].copy_from_slice(&short_id[..n]);
    pt
}

/// Parse the 16-byte plaintext recovered by [`RealityAuth::open`].
fn parse_plaintext(plaintext: &[u8]) -> Result<AuthPayload, RealityError> {
    if plaintext.len() != PLAINTEXT_LEN {
        return Err(RealityError::AuthOpen(format!(
            "plaintext length {} != {PLAINTEXT_LEN}",
            plaintext.len()
        )));
    }
    let mut version = [0u8; 3];
    version.copy_from_slice(&plaintext[0..3]);
    let timestamp = u32::from_be_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);
    let mut short_id = [0u8; SHORT_ID_FIELD_LEN];
    short_id.copy_from_slice(&plaintext[8..16]);
    Ok(AuthPayload {
        version,
        timestamp,
        short_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic (server_priv, server_pub) pair for tests.
    fn server_keypair() -> ([u8; 32], [u8; 32]) {
        let priv_bytes = [7u8; 32];
        let secret = StaticSecret::from(priv_bytes);
        let public = PublicKey::from(&secret);
        (priv_bytes, public.to_bytes())
    }

    fn sample_random() -> [u8; 32] {
        let mut r = [0u8; 32];
        for (i, b) in r.iter_mut().enumerate() {
            *b = i as u8;
        }
        r
    }

    #[test]
    fn session_id_is_exactly_32_bytes() {
        let (_, server_pub) = server_keypair();
        let auth = RealityAuth::seal(
            &server_pub,
            &[0x01, 0x02, 0x03, 0x04],
            DEFAULT_VERSION,
            1_700_000_000,
            &sample_random(),
            b"client-hello-bytes",
        )
        .unwrap();
        assert_eq!(auth.session_id.len(), 32);
        assert_eq!(auth.client_public.len(), 32);
    }

    #[test]
    fn seal_open_round_trip() {
        let (server_priv, server_pub) = server_keypair();
        let random = sample_random();
        let hello = b"the-exact-client-hello";
        let short_id = [0xAA, 0xBB, 0xCC];

        let auth = RealityAuth::seal(
            &server_pub,
            &short_id,
            DEFAULT_VERSION,
            1_700_000_000,
            &random,
            hello,
        )
        .unwrap();

        let payload = RealityAuth::open(
            &server_priv,
            &auth.client_public,
            &auth.session_id,
            &random,
            hello,
        )
        .unwrap();

        assert_eq!(payload.version, DEFAULT_VERSION);
        assert_eq!(payload.timestamp, 1_700_000_000);
        assert_eq!(&payload.short_id[..3], &short_id);
        assert_eq!(&payload.short_id[3..], &[0, 0, 0, 0, 0]);
    }

    #[test]
    fn wrong_server_key_fails_to_open() {
        let (_, server_pub) = server_keypair();
        let wrong_priv = [9u8; 32];
        let random = sample_random();
        let hello = b"hello";
        let auth = RealityAuth::seal(&server_pub, &[], DEFAULT_VERSION, 1, &random, hello).unwrap();
        assert!(
            RealityAuth::open(
                &wrong_priv,
                &auth.client_public,
                &auth.session_id,
                &random,
                hello
            )
            .is_err()
        );
    }

    #[test]
    fn tampered_client_hello_fails_to_open() {
        let (server_priv, server_pub) = server_keypair();
        let random = sample_random();
        let auth = RealityAuth::seal(
            &server_pub,
            &[0x01],
            DEFAULT_VERSION,
            42,
            &random,
            b"original-hello",
        )
        .unwrap();
        // AAD differs → authentication tag mismatch.
        assert!(
            RealityAuth::open(
                &server_priv,
                &auth.client_public,
                &auth.session_id,
                &random,
                b"tampered-hello!"
            )
            .is_err()
        );
    }

    #[test]
    fn deterministic_given_ephemeral_and_random() {
        let (_, server_pub) = server_keypair();
        let eph = [3u8; 32];
        let random = sample_random();
        let hello = b"fixed";
        let a = RealityAuth::seal_with_ephemeral(
            eph,
            &server_pub,
            &[0x11],
            DEFAULT_VERSION,
            100,
            &random,
            hello,
        )
        .unwrap();
        let b = RealityAuth::seal_with_ephemeral(
            eph,
            &server_pub,
            &[0x11],
            DEFAULT_VERSION,
            100,
            &random,
            hello,
        )
        .unwrap();
        assert_eq!(a.session_id, b.session_id);
        assert_eq!(a.client_public, b.client_public);
    }

    #[test]
    fn returned_public_key_matches_ephemeral() {
        let (_, server_pub) = server_keypair();
        let eph = [5u8; 32];
        let expected = PublicKey::from(&StaticSecret::from(eph)).to_bytes();
        let auth = RealityAuth::seal_with_ephemeral(
            eph,
            &server_pub,
            &[],
            DEFAULT_VERSION,
            0,
            &sample_random(),
            b"h",
        )
        .unwrap();
        assert_eq!(auth.client_public, expected);
    }

    #[test]
    fn fresh_keypairs_are_unique() {
        let (_, server_pub) = server_keypair();
        let random = sample_random();
        let auths: Vec<_> = (0..10)
            .map(|_| {
                RealityAuth::seal(&server_pub, &[], DEFAULT_VERSION, 0, &random, b"h").unwrap()
            })
            .collect();
        let mut keys: Vec<_> = auths.iter().map(|a| a.client_public).collect();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), 10);
    }

    #[test]
    fn short_id_over_32_bytes_is_rejected() {
        let (_, server_pub) = server_keypair();
        let too_long = vec![0u8; 33];
        assert!(
            RealityAuth::seal(
                &server_pub,
                &too_long,
                DEFAULT_VERSION,
                0,
                &sample_random(),
                b"h"
            )
            .is_err()
        );
    }

    #[test]
    fn short_id_longer_than_8_bytes_is_truncated_on_wire() {
        let (server_priv, server_pub) = server_keypair();
        let random = sample_random();
        let hello = b"h";
        let short_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]; // 10 bytes
        let auth =
            RealityAuth::seal(&server_pub, &short_id, DEFAULT_VERSION, 0, &random, hello).unwrap();
        let payload = RealityAuth::open(
            &server_priv,
            &auth.client_public,
            &auth.session_id,
            &random,
            hello,
        )
        .unwrap();
        assert_eq!(payload.short_id, [1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
