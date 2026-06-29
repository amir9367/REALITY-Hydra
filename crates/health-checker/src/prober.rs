//! The TLS-inspection seam.
//!
//! Axes (b)/(c)/(d) of a health check need facts that only a real handshake to
//! the `dest` reveals: which TLS version was negotiated, which ALPN protocol was
//! selected, what dNSName SANs the leaf certificate carries, and how long the
//! round trip took. [`TlsInspector`] is the one-method async seam that produces
//! those facts, mirroring `dns-warmer`'s `Resolver`:
//!
//! * offline tests drive a [`MockInspector`] with canned observations, and
//! * the real [`crate::RustlsInspector`] (feature `live-tls`) performs a plain
//!   validation handshake and reads them off the connection.
//!
//! The checker never opens a socket itself — it asks an inspector — so the whole
//! crate and its tests build and run with no network and no TLS provider.

use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

use crate::error::HealthError;

/// The observable result of one validation handshake to `dest` with a given SNI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsObservation {
    /// `true` if the negotiated protocol was TLS 1.3.
    pub is_tls13: bool,
    /// The selected ALPN protocol, if any (e.g. `b"h2"`).
    pub alpn: Option<Vec<u8>>,
    /// The dNSName SAN entries read from the leaf certificate.
    pub leaf_san_dns_names: Vec<String>,
    /// Wall-clock round trip of the handshake.
    pub rtt: Duration,
}

impl TlsObservation {
    /// Convenience: was `h2` the negotiated ALPN protocol?
    pub fn alpn_is_h2(&self) -> bool {
        self.alpn.as_deref() == Some(b"h2")
    }
}

/// Performs a validation handshake to `dest` presenting `sni`, returning the
/// observable facts about the connection.
///
/// The returned future is `Send` so checks can run concurrently on a
/// multi-threaded runtime; implementors are `Send + Sync`.
pub trait TlsInspector: Send + Sync {
    fn inspect(
        &self,
        dest: &str,
        sni: &str,
    ) -> impl Future<Output = Result<TlsObservation, HealthError>> + Send;
}

/// An in-memory [`TlsInspector`] for tests and offline runs.
///
/// Maps an SNI to a canned [`TlsObservation`]; an unknown SNI yields
/// [`HealthError::Probe`], standing in for a failed connect/handshake.
#[derive(Clone, Debug, Default)]
pub struct MockInspector {
    table: HashMap<String, TlsObservation>,
}

impl MockInspector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register the observation `inspect` should return for `sni`.
    pub fn with(mut self, sni: impl Into<String>, observation: TlsObservation) -> Self {
        self.table.insert(sni.into(), observation);
        self
    }
}

impl TlsInspector for MockInspector {
    async fn inspect(&self, dest: &str, sni: &str) -> Result<TlsObservation, HealthError> {
        match self.table.get(sni) {
            Some(obs) => Ok(obs.clone()),
            None => Err(HealthError::Probe {
                dest: dest.to_string(),
                sni: sni.to_string(),
                message: "SNI not in MockInspector table".to_string(),
            }),
        }
    }
}
