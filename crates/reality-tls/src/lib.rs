//! # reality-tls — REALITY-Hydra Phase 4
//!
//! The camouflaged TLS client layer: a ClientHello that byte-matches a real
//! browser (Chrome 120+) plus the REALITY X25519 authentication proof sealed
//! into the TLS `session_id` field (REALITY.md §1, §7 P7).
//!
//! ## What this crate provides
//!
//! 1. **Wire-accurate REALITY auth** ([`auth`]) — [`RealityAuth::seal`] builds the
//!    exact 32-byte `session_id` Xray-core's REALITY expects: the ephemeral X25519
//!    public key is the TLS `key_share`, the AEAD key is
//!    `HKDF-SHA256(shared, salt=client_random[0..20], info="REALITY")`, the nonce
//!    is `client_random[20..32]`, and the whole ClientHello is the AEAD associated
//!    data. [`RealityAuth::open`] is the matching server-side verification, so the
//!    round-trip is provable offline without a live server.
//!
//! 2. **Chrome fingerprint data** ([`fingerprint`]) — cipher order, key-share
//!    groups, signature algorithms, and ALPN targeting Chrome 120+ JA3/JA4.
//!
//! 3. **A `boring` connector + injection seam** ([`client`], feature
//!    `boring-impersonate`) — a compile-checked Chrome-fingerprinted connector and
//!    the [`client::RealityInjector`] trait where a REALITY-patched TLS stack
//!    installs the sealed `session_id`. See that module for why stock BoringSSL
//!    cannot do this step itself.
//!
//! ## Offline by default
//!
//! The [`auth`], [`fingerprint`], [`config`], and [`error`] modules are pure logic
//! and compile without a BoringSSL toolchain. The [`client`] module is behind the
//! `boring-impersonate` feature (REALITY.md §7 P7).
//!
//! ## Quick tour (auth only, no BoringSSL needed)
//!
//! ```
//! use reality_tls::auth::{RealityAuth, DEFAULT_VERSION};
//! use reality_tls::{RealityConfig};
//! use reality_tls::fingerprint::Fingerprint;
//!
//! let config = RealityConfig::new(
//!     [0xAB; 32],             // server public key (pbk)
//!     vec![vec![0x01, 0x02]], // short_ids (sid)
//!     Fingerprint::Chrome,
//! )
//! .unwrap();
//!
//! // In a real client these come from the TLS stack's actual ClientHello.
//! let client_random = [0u8; 32];
//! let client_hello_raw = b"...serialized ClientHello...";
//!
//! let auth = RealityAuth::seal(
//!     &config.server_public_key,
//!     config.pick_short_id(),
//!     config.version,
//!     1_700_000_000, // UNIX timestamp
//!     &client_random,
//!     client_hello_raw,
//! )
//! .unwrap();
//!
//! assert_eq!(auth.client_public.len(), 32);   // this is the TLS key_share
//! assert_eq!(auth.session_id.len(), 32);      // exactly the TLS session_id limit
//! ```

pub mod auth;
pub mod config;
pub mod error;
pub mod fingerprint;

#[cfg(feature = "boring-impersonate")]
pub mod client;

pub use auth::{AuthPayload, RealityAuth};
pub use config::RealityConfig;
pub use error::RealityError;
pub use fingerprint::Fingerprint;

#[cfg(feature = "boring-impersonate")]
pub use client::{RealityClient, RealityInjector, UnsupportedInjector};
