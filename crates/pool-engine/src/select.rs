//! Per-connection SNI selection with browser-like "sticky" reuse.
//!
//! For each outbound connection the client picks an SNI from the *active* pool by
//! weighted-random choice. But a real browser does not flip the SNI it uses for a
//! given site on every request, so we cache the choice per real destination for a
//! short TTL, mimicking connection reuse (REALITY.md §5.2, and P3: a rotation
//! *pattern* is itself a fingerprint — so we rotate per connection, not on a
//! timer, and keep choices sticky).
//!
//! Time is passed in as `now_ms` (milliseconds, monotonic) rather than read from
//! a clock, so the cache logic is deterministic and unit-testable.

use std::collections::HashMap;

use rand::RngExt;

use crate::entry::ActivePool;

/// Selects SNIs from an active pool, keeping a sticky choice per destination.
#[derive(Debug)]
pub struct Selector {
    sticky_ttl_ms: u64,
    cache: HashMap<String, Sticky>,
}

#[derive(Debug, Clone)]
struct Sticky {
    sni: String,
    expires_at_ms: u64,
}

impl Selector {
    /// Create a selector whose per-destination choice stays fixed for
    /// `sticky_ttl_ms` milliseconds. A TTL of `0` re-picks on every call.
    pub fn new(sticky_ttl_ms: u64) -> Self {
        Self {
            sticky_ttl_ms,
            cache: HashMap::new(),
        }
    }

    /// Pick an SNI for `dest` at time `now_ms`, drawing from the injected `rng`.
    ///
    /// Returns the cached SNI if one is still fresh for `dest` *and* still in the
    /// pool (the epoch may have rolled and evicted it); otherwise draws a new
    /// weighted-random SNI, caches it, and returns it. Returns `None` only if the
    /// pool is empty.
    ///
    /// `rng` is injected so tests can drive it deterministically; production code
    /// can call [`Selector::pick`] instead, which uses the thread RNG.
    pub fn select(
        &mut self,
        pool: &ActivePool,
        dest: &str,
        now_ms: u64,
        rng: &mut impl RngExt,
    ) -> Option<String> {
        if pool.is_empty() {
            return None;
        }

        if let Some(s) = self.cache.get(dest)
            && now_ms < s.expires_at_ms
            && pool.contains(&s.sni)
        {
            return Some(s.sni.clone());
        }

        let sni = weighted_pick(pool, rng);
        self.cache.insert(
            dest.to_string(),
            Sticky {
                sni: sni.clone(),
                expires_at_ms: now_ms.saturating_add(self.sticky_ttl_ms),
            },
        );
        Some(sni)
    }

    /// Convenience wrapper over [`Selector::select`] using the thread-local RNG.
    pub fn pick(&mut self, pool: &ActivePool, dest: &str, now_ms: u64) -> Option<String> {
        let mut rng = rand::rng();
        self.select(pool, dest, now_ms, &mut rng)
    }

    /// Drop expired cache entries (optional housekeeping).
    pub fn evict_expired(&mut self, now_ms: u64) {
        self.cache.retain(|_, s| now_ms < s.expires_at_ms);
    }
}

/// Weighted-random pick of one SNI, by `weight`.
fn weighted_pick(pool: &ActivePool, rng: &mut impl RngExt) -> String {
    let entries = pool.entries();
    let total: f64 = entries.iter().map(|e| e.weight).sum();

    // Walk the cumulative weights until we cross a uniform point in [0, total).
    let mut r = rng.random::<f64>() * total;
    for e in entries {
        r -= e.weight;
        if r < 0.0 {
            return e.sni.clone();
        }
    }
    // Floating-point round-off could let the loop fall through; return the last.
    entries[entries.len() - 1].sni.clone()
}
