//! Per-entry verdict, latency band, and pool pruning — the pure decision layer.
//!
//! A health check produces a [`Health`] verdict per pool entry from four
//! independent observations (REALITY.md §7 P1/P8). All of this is pure data
//! reduction: the network-touching parts (DNS, the TLS inspection probe) live
//! behind traits and feed their observations in. That keeps the "is this entry
//! acceptable?" policy fully unit-testable with no network.

use std::time::Duration;

use pool_engine::{ActivePool, MasterList, PoolEntry};

use crate::error::HealthError;

/// An acceptable round-trip latency window for the validation probe.
///
/// Both an unusually slow *and* an unusually fast result are suspicious for a
/// real CDN edge, so the band is two-sided.
#[derive(Clone, Copy, Debug)]
pub struct LatencyBand {
    pub min: Duration,
    pub max: Duration,
}

impl LatencyBand {
    /// A band `[min, max]`; rejects an inverted band.
    pub fn new(min: Duration, max: Duration) -> Result<Self, HealthError> {
        if min > max {
            return Err(HealthError::InvertedLatencyBand {
                min_ms: min.as_millis() as u64,
                max_ms: max.as_millis() as u64,
            });
        }
        Ok(Self { min, max })
    }

    /// Whether `rtt` is inside the band (inclusive).
    pub fn contains(&self, rtt: Duration) -> bool {
        self.min <= rtt && rtt <= self.max
    }
}

impl Default for LatencyBand {
    /// `[0ms, 2000ms]` — generous defaults; tune per deployment.
    fn default() -> Self {
        Self {
            min: Duration::ZERO,
            max: Duration::from_millis(2000),
        }
    }
}

/// The four-axis verdict for one pool entry (REALITY.md §5.3 / §7 P1/P8).
///
/// Each field is the result of one independent check; [`Health::is_healthy`] is
/// their conjunction. Keeping them separate (rather than a single bool) makes the
/// *reason* an entry was pruned visible to logs and tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Health {
    pub sni: String,
    /// (a) Every resolved IP fell inside the coherence allowlist.
    pub coherent: bool,
    /// (b) The leaf cert's SAN set covers this SNI.
    pub san_match: bool,
    /// (c) The negotiated ALPN advertised `h2`.
    pub alpn_h2: bool,
    /// (b) The negotiated protocol was TLS 1.3.
    pub tls13: bool,
    /// (d) The probe round-trip was inside the configured latency band.
    pub latency_ok: bool,
}

impl Health {
    /// An entry is healthy only if **every** axis passed.
    pub fn is_healthy(&self) -> bool {
        self.coherent && self.san_match && self.alpn_h2 && self.tls13 && self.latency_ok
    }
}

/// Reduce a set of verdicts to the SNIs that passed every axis.
pub fn healthy_snis(reports: &[Health]) -> Vec<String> {
    reports
        .iter()
        .filter(|h| h.is_healthy())
        .map(|h| h.sni.clone())
        .collect()
}

/// Prune a [`MasterList`] down to the entries whose verdict is healthy.
///
/// The surviving entries keep their original weights. The result is an
/// [`ActivePool`] of exactly the verified-good camouflage identities — the
/// "pruned `ActivePool`" Phase 2 is specified to emit. Returns an empty pool if
/// nothing passed (the caller decides whether that is fatal).
pub fn prune(master: &MasterList, reports: &[Health]) -> ActivePool {
    let healthy: std::collections::HashSet<&str> = reports
        .iter()
        .filter(|h| h.is_healthy())
        .map(|h| h.sni.as_str())
        .collect();

    let kept: Vec<PoolEntry> = master
        .entries()
        .iter()
        .filter(|e| healthy.contains(e.sni.as_str()))
        .cloned()
        .collect();

    ActivePool::from_entries(kept)
}
