//! Client-side REALITY configuration.
//!
//! Holds the deployment-specific values a client needs to connect to a REALITY
//! server: the server's public key, the accepted short IDs, the version triple,
//! and the TLS fingerprint to impersonate. This is the *client-side* counterpart
//! of the server config the `hydra-cli` renders (REALITY.md §11).
//!
//! The master secret and server salt are **not** here — those are pool-engine
//! concerns (Phase 1). This crate only cares about the REALITY handshake
//! parameters.

use crate::auth::{DEFAULT_VERSION, KEY_LEN};
use crate::error::RealityError;
use crate::fingerprint::Fingerprint;

/// Maximum short_id byte length accepted at the API boundary. Only the first 8
/// bytes are sealed into the `session_id` (see [`crate::auth::SHORT_ID_FIELD_LEN`]).
const MAX_SHORT_ID_LEN: usize = 32;

/// Client-side REALITY configuration.
///
/// Parsed from (or matching) the client-side fields of the Xray VLESS+REALITY
/// JSON config — `pbk`, `sid`, `fp`, and the `realitySettings` envelope.
#[derive(Clone, Debug)]
pub struct RealityConfig {
    /// The server's 32-byte X25519 public key (`pbk`).
    pub server_public_key: [u8; KEY_LEN],
    /// One or more accepted short IDs (`sid`); the client picks one per
    /// connection. An empty list means the server allows `""` (empty short ID).
    pub short_ids: Vec<Vec<u8>>,
    /// Which browser fingerprint to impersonate.
    pub fingerprint: Fingerprint,
    /// The version triple written into the REALITY auth plaintext. Informational
    /// on the wire; defaults to [`DEFAULT_VERSION`].
    pub version: [u8; 3],
    /// The `dest` / `target` the server relays probe traffic to — used for the
    /// TLS handshake SNI when not rotating. Stored here for reference; the pool
    /// engine supplies the actual per-connection SNI.
    pub dest: Option<String>,
}

impl RealityConfig {
    /// Build from the raw Xray client fields, using [`DEFAULT_VERSION`].
    ///
    /// `server_public_key` is the 32-byte `pbk` (base64-decoded).
    /// `short_ids` are the hex-decoded `sid` values.
    pub fn new(
        server_public_key: [u8; KEY_LEN],
        short_ids: Vec<Vec<u8>>,
        fingerprint: Fingerprint,
    ) -> Result<Self, RealityError> {
        Self::with_version(server_public_key, short_ids, fingerprint, DEFAULT_VERSION)
    }

    /// Build with an explicit version triple.
    pub fn with_version(
        server_public_key: [u8; KEY_LEN],
        short_ids: Vec<Vec<u8>>,
        fingerprint: Fingerprint,
        version: [u8; 3],
    ) -> Result<Self, RealityError> {
        for sid in &short_ids {
            if sid.len() > MAX_SHORT_ID_LEN {
                return Err(RealityError::ShortIdTooLong(sid.len()));
            }
        }
        Ok(Self {
            server_public_key,
            short_ids,
            fingerprint,
            version,
            dest: None,
        })
    }

    /// Set the reference `dest` (builder-style).
    pub fn with_dest(mut self, dest: impl Into<String>) -> Self {
        self.dest = Some(dest.into());
        self
    }

    /// Pick a short_id for this connection. If the list is non-empty, returns the
    /// first entry (a real client might randomize); if empty, returns `&[]`.
    pub fn pick_short_id(&self) -> &[u8] {
        self.short_ids.first().map_or(&[], |v| v.as_slice())
    }
}
