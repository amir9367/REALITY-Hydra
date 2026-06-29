//! The TTL-aware DNS cache — `DnsWarmer`.
//!
//! This is Hydra's answer to **Trap 1** (REALITY.md §4): a DPI engine flags an
//! SNI the client never looked up (`NDPI_UNRESOLVED_HOSTNAME`). So before the
//! client may present `SNI=X`, [`DnsWarmer::warm`] must have performed a *real*
//! resolution of `X`. We cache each result for the record's advertised TTL
//! (clamped, see [`WarmerConfig`]) and re-resolve only when it lapses, so the
//! lookup cadence tracks what a real client's would (P5).
//!
//! ## Concurrency
//!
//! The warmer is shared (`&self`, behind an `Arc`) across many connections, so
//! the cache lives behind a [`std::sync::Mutex`]. The lock is **never held across
//! an `.await`**: we lock to read, drop the guard, do the network resolve, then
//! lock again to write. Two connections racing on a cold name may both resolve
//! it once — harmless, and simpler than single-flight de-duplication (a possible
//! later refinement).
//!
//! ## Time
//!
//! Like the pool engine's `Selector`, expiry is computed against an injected
//! `now_ms` (monotonic milliseconds) so the cache is deterministic and testable;
//! the wall clock never leaks into the logic.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use crate::error::ResolveError;
use crate::resolver::{Resolved, Resolver};

/// Tuning for the warmer's cache.
#[derive(Clone, Copy, Debug)]
pub struct WarmerConfig {
    /// Floor for a cached entry's lifetime. A record advertising a 0–few second
    /// TTL would otherwise make us re-resolve almost every connection — itself
    /// an anomaly — so we hold it at least this long.
    pub min_ttl: Duration,
    /// Ceiling for a cached entry's lifetime. Caps absurd TTLs so a stale record
    /// can't pin us to an address the CDN has since rotated away.
    pub max_ttl: Duration,
}

impl Default for WarmerConfig {
    /// 30 s floor, 1 h ceiling — sane defaults for CDN edge records.
    fn default() -> Self {
        Self {
            min_ttl: Duration::from_secs(30),
            max_ttl: Duration::from_secs(3600),
        }
    }
}

impl WarmerConfig {
    /// Clamp a record's advertised TTL into `[min_ttl, max_ttl]`.
    fn clamp(&self, ttl: Duration) -> Duration {
        ttl.clamp(self.min_ttl, self.max_ttl)
    }
}

/// One cached resolution and the instant (in `now_ms` units) it goes stale.
#[derive(Clone, Debug)]
struct CacheEntry {
    resolved: Resolved,
    expires_at_ms: u64,
}

/// A resolve-on-first-use, TTL-aware DNS cache over any [`Resolver`].
#[derive(Debug)]
pub struct DnsWarmer<R: Resolver> {
    resolver: R,
    config: WarmerConfig,
    cache: Mutex<HashMap<String, CacheEntry>>,
}

impl<R: Resolver> DnsWarmer<R> {
    /// Build a warmer with the [default config](WarmerConfig::default).
    pub fn new(resolver: R) -> Self {
        Self::with_config(resolver, WarmerConfig::default())
    }

    /// Build a warmer with an explicit [`WarmerConfig`].
    pub fn with_config(resolver: R, config: WarmerConfig) -> Self {
        Self {
            resolver,
            config,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Ensure `host` has a fresh, real resolution at time `now_ms`, returning it.
    ///
    /// Returns the cached [`Resolved`] if the entry is still within its (clamped)
    /// TTL; otherwise performs a real lookup, caches it, and returns it. Calling
    /// this and *then* connecting with `SNI=host` is what defeats Trap 1 — the
    /// resolution provably happened first.
    pub async fn warm(&self, host: &str, now_ms: u64) -> Result<Resolved, ResolveError> {
        // Fast path: a fresh cache hit. Scope the guard so it drops before any
        // `.await` below — a std Mutex guard is not Send and must not cross one.
        {
            let cache = self.cache.lock().expect("dns cache mutex poisoned");
            if let Some(entry) = cache.get(host)
                && now_ms < entry.expires_at_ms
            {
                return Ok(entry.resolved.clone());
            }
        }

        // Slow path: resolve for real with no lock held.
        let resolved = self.resolver.resolve(host).await?;
        let ttl = self.config.clamp(resolved.ttl);
        let expires_at_ms = now_ms.saturating_add(ttl.as_millis() as u64);

        let mut cache = self.cache.lock().expect("dns cache mutex poisoned");
        cache.insert(
            host.to_string(),
            CacheEntry {
                resolved: resolved.clone(),
                expires_at_ms,
            },
        );
        Ok(resolved)
    }

    /// Whether `host` currently has a fresh cached resolution at `now_ms`.
    ///
    /// A connection path can assert this is `true` before presenting `SNI=host`,
    /// turning "we resolved first" into a checkable invariant rather than a hope.
    pub fn is_warm(&self, host: &str, now_ms: u64) -> bool {
        let cache = self.cache.lock().expect("dns cache mutex poisoned");
        cache.get(host).is_some_and(|e| now_ms < e.expires_at_ms)
    }

    /// The cached resolution for `host` if it is still fresh — never resolves.
    ///
    /// Useful for the coherence check (Trap 3): the health-checker compares the
    /// IP we *resolved* against the IP we *connect* to, and reads it from here.
    pub fn peek(&self, host: &str, now_ms: u64) -> Option<Resolved> {
        let cache = self.cache.lock().expect("dns cache mutex poisoned");
        cache
            .get(host)
            .filter(|e| now_ms < e.expires_at_ms)
            .map(|e| e.resolved.clone())
    }

    /// Drop entries that have gone stale by `now_ms` (optional housekeeping).
    pub fn evict_expired(&self, now_ms: u64) {
        let mut cache = self.cache.lock().expect("dns cache mutex poisoned");
        cache.retain(|_, e| now_ms < e.expires_at_ms);
    }
}
