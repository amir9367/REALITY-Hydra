//! Error type for DNS warming.

use thiserror::Error;

/// Anything that can go wrong resolving a hostname.
///
/// The `Backend` variant carries a flattened `String` rather than the underlying
/// resolver error so that the public API stays identical whether or not the
/// `live-dns` feature (and its `hickory-resolver` types) is compiled in.
#[derive(Debug, Error)]
pub enum ResolveError {
    /// The lookup succeeded at the protocol level but yielded no A/AAAA records.
    #[error("no addresses returned for {host:?}")]
    NoAddresses { host: String },

    /// The resolver backend itself failed (timeout, SERVFAIL, no network, …).
    #[error("resolver backend failed for {host:?}: {message}")]
    Backend { host: String, message: String },
}
