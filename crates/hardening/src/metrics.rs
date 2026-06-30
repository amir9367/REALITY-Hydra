//! Lightweight metrics collection for runtime monitoring.
//!
//! Provides simple counter-based metrics that can be tracked during operation to
//! detect anomalies (REALITY.md §12 monitoring: pool entry failures, probe
//! traffic spikes, handshake drops). The counters are plain `AtomicU64` values —
//! no external metrics library dependency, no async, no network.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// A named set of atomic counters for tracking runtime metrics.
///
/// Pre-defined counter names are provided as associated constants; callers can
/// also add free-form counters.
pub struct CounterSet {
    counters: HashMap<&'static str, AtomicU64>,
}

impl CounterSet {
    /// Create an empty counter set.
    pub fn new() -> Self {
        Self {
            counters: HashMap::new(),
        }
    }

    /// Increment the named counter by 1.
    pub fn inc(&self, name: &'static str) {
        self.counters
            .get(name)
            .unwrap_or_else(|| panic!("unknown counter: {name}"))
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the named counter by `n`.
    pub fn add(&self, name: &'static str, n: u64) {
        self.counters
            .get(name)
            .unwrap_or_else(|| panic!("unknown counter: {name}"))
            .fetch_add(n, Ordering::Relaxed);
    }

    /// Read the current value of a counter.
    pub fn get(&self, name: &'static str) -> u64 {
        self.counters
            .get(name)
            .unwrap_or_else(|| panic!("unknown counter: {name}"))
            .load(Ordering::Relaxed)
    }
}

impl Default for CounterSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Pre-defined metric names used across the Hydra components.
pub struct Metrics;

impl Metrics {
    // --- Pool engine ---
    /// Number of epoch transitions observed.
    pub const EPOCH_TRANSITIONS: &'static str = "epoch_transitions";
    /// Number of SNI selections made.
    pub const SELECTIONS: &'static str = "selections";
    /// Number of sticky cache hits.
    pub const STICKY_HITS: &'static str = "sticky_hits";

    // --- DNS warmer ---
    /// Number of real DNS resolutions performed.
    pub const DNS_RESOLUTIONS: &'static str = "dns_resolutions";
    /// Number of DNS cache hits (avoided a real lookup).
    pub const DNS_CACHE_HITS: &'static str = "dns_cache_hits";
    /// Number of DNS resolution failures.
    pub const DNS_FAILURES: &'static str = "dns_failures";

    // --- Health checker ---
    /// Number of health checks performed.
    pub const HEALTH_CHECKS: &'static str = "health_checks";
    /// Number of entries that passed all health axes.
    pub const HEALTHY_ENTRIES: &'static str = "healthy_entries";
    /// Number of entries that failed one or more axes.
    pub const UNHEALTHY_ENTRIES: &'static str = "unhealthy_entries";

    // --- Reality TLS ---
    /// Number of TLS handshakes attempted.
    pub const TLS_HANDSHAKES: &'static str = "tls_handshakes";
    /// Number of TLS handshake failures.
    pub const TLS_FAILURES: &'static str = "tls_failures";
    /// Number of REALITY auth tokens built.
    pub const AUTH_BUILT: &'static str = "auth_built";

    /// All standard counter names, for validation.
    pub const ALL_NAMES: &[&'static str] = &[
        Self::EPOCH_TRANSITIONS,
        Self::SELECTIONS,
        Self::STICKY_HITS,
        Self::DNS_RESOLUTIONS,
        Self::DNS_CACHE_HITS,
        Self::DNS_FAILURES,
        Self::HEALTH_CHECKS,
        Self::HEALTHY_ENTRIES,
        Self::UNHEALTHY_ENTRIES,
        Self::TLS_HANDSHAKES,
        Self::TLS_FAILURES,
        Self::AUTH_BUILT,
    ];

    /// Create a [`CounterSet`] pre-populated with all standard counters at 0.
    pub fn counter_set() -> CounterSet {
        let mut counters = HashMap::new();
        for &name in Self::ALL_NAMES {
            counters.insert(name, AtomicU64::new(0));
        }
        CounterSet { counters }
    }
}

/// A snapshot of all counters at a point in time (for logging / comparison).
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub counters: Vec<(&'static str, u64)>,
}

impl Snapshot {
    /// Take a snapshot of the given counter set.
    pub fn take(set: &CounterSet) -> Self {
        let counters = Metrics::ALL_NAMES
            .iter()
            .map(|&name| (name, set.get(name)))
            .collect();
        Self { counters }
    }

    /// Compute the delta between two snapshots (self - earlier).
    pub fn delta(&self, earlier: &Snapshot) -> Vec<(&'static str, u64)> {
        let earlier_map: HashMap<_, _> = earlier.counters.iter().cloned().collect();
        self.counters
            .iter()
            .map(|&(name, val)| {
                let prev = earlier_map.get(name).copied().unwrap_or(0);
                (name, val.saturating_sub(prev))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_set_inc_and_get() {
        let set = Metrics::counter_set();
        assert_eq!(set.get(Metrics::SELECTIONS), 0);
        set.inc(Metrics::SELECTIONS);
        set.inc(Metrics::SELECTIONS);
        assert_eq!(set.get(Metrics::SELECTIONS), 2);
    }

    #[test]
    fn counter_set_add() {
        let set = Metrics::counter_set();
        set.add(Metrics::DNS_RESOLUTIONS, 5);
        assert_eq!(set.get(Metrics::DNS_RESOLUTIONS), 5);
    }

    #[test]
    fn snapshot_delta() {
        let set = Metrics::counter_set();
        set.inc(Metrics::SELECTIONS);
        let s1 = Snapshot::take(&set);
        set.add(Metrics::SELECTIONS, 7);
        set.inc(Metrics::TLS_HANDSHAKES);
        let s2 = Snapshot::take(&set);

        let delta = s2.delta(&s1);
        let delta_map: HashMap<_, _> = delta.into_iter().collect();
        assert_eq!(delta_map[Metrics::SELECTIONS], 7);
        assert_eq!(delta_map[Metrics::TLS_HANDSHAKES], 1);
        assert_eq!(delta_map[Metrics::DNS_RESOLUTIONS], 0);
    }
}
