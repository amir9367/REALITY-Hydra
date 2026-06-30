//! # reality-tls — REALITY-Hydra Phase 4
//!
//! The camouflaged TLS client: produces a ClientHello that byte-matches a real
//! browser (Chrome 120+) and embeds the REALITY X25519 authentication proof in
//! the TLS `session_id` extension (REALITY.md §7 P7).
//!
//! ## What this crate does
//!
//! 1. **BoringSSL impersonation** (feature `boring-impersonate`) — builds a
//!    `SslConnector` whose ClientHello matches Chrome's cipher order, extension
//!    layout, key-share groups, signature algorithms, ALPN, ALPS, GREASE, and
//!    compress_certificate. The goal is JA3/JA4 equivalence with a real Chrome
//!    capture.
//!
//! 2. **REALITY auth embedding** — generates an ephemeral X25519 keypair,
//!    computes the shared secret with the server's public key, encrypts
//!    `(client_pub || timestamp || short_id)` with AES-256-GCM, and places the
//!    ciphertext in the `session_id` field of the ClientHello. Only the real
//!    server (holding the matching `privateKey`) can decrypt and verify it.
//!
//! 3. **`xtls-rprx-vision` flow** — the Vision flow (REALITY.md §1/P10) is
//!    configured at the Xray protocol layer, not the TLS layer, so it is
//!    orthogonal to this crate. A production client would pair this TLS layer
//!    with a Vision-aware framing layer.
//!
//! ## Offline by default
//!
//! The `auth`, `fingerprint`, `config`, and `error` modules are pure logic and
//! compile without a BoringSSL toolchain. The `client` module (the real
//! connector) is behind the `boring-impersonate` feature, matching the
//! workspace's "offline by default" design (REALITY.md §7 P7).
//!
//! ## Quick tour (auth only, no BoringSSL needed)
//!
//! ```
//! use reality_tls::{RealityAuth, RealityConfig};
//! use reality_tls::fingerprint::Fingerprint;
//!
//! let config = RealityConfig::new(
//!     [0xAB; 32],            // server public key (pbk)
//!     vec![vec![0x01, 0x02]], // short_ids (sid)
//!     Fingerprint::Chrome,
//! )
//! .unwrap();
//!
//! // Build the auth token (fresh ephemeral keypair + AES-GCM encryption).
//! let auth = RealityAuth::build(
//!     &config.server_public_key,
//!     config.pick_short_id(),
//!     1_700_000_000, // UNIX timestamp
//! )
//! .unwrap();
//!
//! assert_eq!(auth.client_public.len(), 32);
//! assert!(!auth.session_id.is_empty());
//! ```

pub mod auth;
pub mod config;
pub mod error;
pub mod fingerprint;

#[cfg(feature = "boring-impersonate")]
pub mod client;

pub use auth::RealityAuth;
pub use config::RealityConfig;
pub use error::RealityError;
pub use fingerprint::Fingerprint;

#[cfg(feature = "boring-impersonate")]
pub use client::RealityClient;
