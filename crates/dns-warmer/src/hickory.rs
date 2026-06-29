//! Real async resolver backed by `hickory-resolver` (the `live-dns` feature).
//!
//! Compiled only when `live-dns` is on; the trait and [`MockResolver`] above
//! cover every offline path, so the default build (and CI) needs no network
//! stack — REALITY.md §7 P5.
//!
//! [`MockResolver`]: crate::MockResolver

use std::net::IpAddr;

use hickory_resolver::TokioResolver;

use crate::error::ResolveError;
use crate::resolver::{Resolved, Resolver};

/// A [`Resolver`] backed by a real Tokio-driven `hickory-resolver`.
#[derive(Clone)]
pub struct HickoryResolver {
    inner: TokioResolver,
}

impl HickoryResolver {
    /// Build a resolver from the host system's DNS configuration
    /// (`/etc/resolv.conf`, the Windows registry, etc.).
    pub fn from_system() -> Result<Self, ResolveError> {
        // hickory-resolver 0.26 split this into a fallible builder *and* a
        // fallible `build()`; map both into our backend error.
        let inner = TokioResolver::builder_tokio()
            .map_err(|e| ResolveError::Backend {
                host: "<system-config>".to_string(),
                message: e.to_string(),
            })?
            .build()
            .map_err(|e| ResolveError::Backend {
                host: "<system-config>".to_string(),
                message: e.to_string(),
            })?;
        Ok(Self { inner })
    }
}

impl std::fmt::Debug for HickoryResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HickoryResolver").finish_non_exhaustive()
    }
}

impl Resolver for HickoryResolver {
    async fn resolve(&self, host: &str) -> Result<Resolved, ResolveError> {
        let lookup = self
            .inner
            .lookup_ip(host)
            .await
            .map_err(|e| ResolveError::Backend {
                host: host.to_string(),
                message: e.to_string(),
            })?;

        let addrs: Vec<IpAddr> = lookup.iter().collect();
        if addrs.is_empty() {
            return Err(ResolveError::NoAddresses {
                host: host.to_string(),
            });
        }

        // The record set is valid only until its shortest-lived member expires,
        // so take the minimum TTL across the answers. `as_lookup().answers()`
        // exposes the underlying records; in hickory-proto 0.26 `ttl` is a public
        // field (seconds), not a method.
        let ttl_secs = lookup
            .as_lookup()
            .answers()
            .iter()
            .map(|r| r.ttl)
            .min()
            .unwrap_or(0);

        Ok(Resolved {
            addrs,
            ttl: std::time::Duration::from_secs(u64::from(ttl_secs)),
        })
    }
}
