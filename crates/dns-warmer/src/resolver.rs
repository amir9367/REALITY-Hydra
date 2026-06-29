//! The `Resolver` trait and an offline `MockResolver`.
//!
//! Everything the warmer needs from "DNS" is captured by one async method,
//! [`Resolver::resolve`]. The trait keeps the warmer's caching logic independent
//! of *how* names are resolved, so:
//!
//! * offline tests drive a [`MockResolver`] with a fixed table (no network), and
//! * the real [`crate::HickoryResolver`] (behind the `live-dns` feature) is just
//!   another implementor.
//!
//! See REALITY.md §7 P5: *when* and *how* we resolve is itself a side channel, so
//! the resolver is an injection point — a future implementor could route lookups
//! over the same DoH path the camouflaged browser uses.

use std::future::Future;
use std::net::IpAddr;
use std::time::Duration;

use crate::error::ResolveError;

/// The outcome of one successful resolution: the addresses plus the record TTL
/// the authoritative server advertised.
///
/// The TTL matters for Trap 1 (REALITY.md §4): to look like a real client we
/// must refresh on roughly the same cadence the real records do, not on some
/// rotation timer of our own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    /// One or more A/AAAA addresses, in the order the resolver returned them.
    pub addrs: Vec<IpAddr>,
    /// The smallest TTL across the answer records (the record set is only valid
    /// until its shortest-lived member expires).
    pub ttl: Duration,
}

/// Resolves a hostname to IP addresses.
///
/// The returned future is `Send` so the warmer can be shared across Tokio worker
/// threads. Implementors are `Send + Sync` for the same reason.
pub trait Resolver: Send + Sync {
    /// Resolve `host` to its current A/AAAA records.
    fn resolve(&self, host: &str) -> impl Future<Output = Result<Resolved, ResolveError>> + Send;
}

/// An in-memory resolver for tests and offline builds.
///
/// Holds a fixed `host -> Resolved` table; unknown hosts return
/// [`ResolveError::Backend`], mimicking an `NXDOMAIN`/SERVFAIL. No network, no
/// async runtime requirement beyond the caller's own.
#[derive(Clone, Debug, Default)]
pub struct MockResolver {
    table: std::collections::HashMap<String, Resolved>,
}

impl MockResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `host` to resolve to `addrs` with the given `ttl`.
    ///
    /// Builder-style so tests can chain a few entries:
    /// `MockResolver::new().with("a", &[ip], ttl).with("b", &[ip2], ttl)`.
    pub fn with(mut self, host: impl Into<String>, addrs: &[IpAddr], ttl: Duration) -> Self {
        self.table.insert(
            host.into(),
            Resolved {
                addrs: addrs.to_vec(),
                ttl,
            },
        );
        self
    }
}

impl Resolver for MockResolver {
    async fn resolve(&self, host: &str) -> Result<Resolved, ResolveError> {
        match self.table.get(host) {
            Some(r) => Ok(r.clone()),
            None => Err(ResolveError::Backend {
                host: host.to_string(),
                message: "host not in MockResolver table".to_string(),
            }),
        }
    }
}
