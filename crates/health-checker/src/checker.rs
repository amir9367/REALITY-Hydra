//! The orchestrator: turn a pool entry into a four-axis [`Health`] verdict.
//!
//! [`HealthChecker`] composes the seams — a `dns-warmer` [`Resolver`] for axis
//! (a) and a [`TlsInspector`] for axes (b)/(c)/(d) — with the pure coherence,
//! SAN, latency, and pruning logic. It holds no sockets of its own; swapping in
//! the mock seams makes every path here exercisable offline.

use dns_warmer::Resolver;
use pool_engine::{MasterList, PoolEntry};

use crate::coherence::CoherenceAllowlist;
use crate::error::HealthError;
use crate::prober::TlsInspector;
use crate::report::{Health, LatencyBand};
use crate::san;

/// Validates pool entries against a single `dest` and a coherence allowlist.
pub struct HealthChecker<R: Resolver, I: TlsInspector> {
    resolver: R,
    inspector: I,
    allowlist: CoherenceAllowlist,
    latency: LatencyBand,
    /// The one upstream every probe connects to (a CDN edge that serves a valid
    /// cert for every pool SNI — REALITY.md §5.1, single-`dest` reality).
    dest: String,
}

impl<R: Resolver, I: TlsInspector> HealthChecker<R, I> {
    /// Assemble a checker from its seams and policy.
    pub fn new(
        resolver: R,
        inspector: I,
        allowlist: CoherenceAllowlist,
        latency: LatencyBand,
        dest: impl Into<String>,
    ) -> Self {
        Self {
            resolver,
            inspector,
            allowlist,
            latency,
            dest: dest.into(),
        }
    }

    /// Run all four checks for one entry and return its verdict.
    ///
    /// A [`HealthError`] is returned only when a step could not run (resolver or
    /// probe failure); a *completed* check that simply failed an axis comes back
    /// as a [`Health`] with that axis `false`.
    pub async fn check(&self, entry: &PoolEntry) -> Result<Health, HealthError> {
        let sni = entry.sni.as_str();

        // (a) Coherence: the SNI's real DNS answer must land in the allowlist.
        let resolved = self
            .resolver
            .resolve(sni)
            .await
            .map_err(|e| HealthError::Resolve {
                sni: sni.to_string(),
                message: e.to_string(),
            })?;
        let coherent = self.allowlist.contains_all(&resolved.addrs);

        // (b)/(c)/(d) Inspect the validation handshake to the single dest.
        let obs = self.inspector.inspect(&self.dest, sni).await?;

        Ok(Health {
            sni: sni.to_string(),
            coherent,
            san_match: san::sni_matches_any(sni, &obs.leaf_san_dns_names),
            alpn_h2: obs.alpn_is_h2(),
            tls13: obs.is_tls13,
            latency_ok: self.latency.contains(obs.rtt),
        })
    }

    /// Check every entry in a master list, collecting one verdict per entry.
    ///
    /// Entries are checked sequentially for simplicity; a per-entry error is
    /// propagated (the caller can decide to skip vs. abort). To prune the pool,
    /// pass the returned verdicts to [`crate::prune`].
    pub async fn check_all(&self, master: &MasterList) -> Result<Vec<Health>, HealthError> {
        let mut reports = Vec::with_capacity(master.len());
        for entry in master.entries() {
            reports.push(self.check(entry).await?);
        }
        Ok(reports)
    }
}
