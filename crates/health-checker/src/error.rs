//! Error type for the health checker.

use thiserror::Error;

/// Why a single health check could not produce a verdict.
///
/// Note the distinction from a *failed* verdict ([`crate::Health`]): a `HealthError`
/// means the check itself could not run to completion (bad config, the resolver
/// or TLS backend errored), whereas an unhealthy verdict is a *successful* check
/// that found the entry wanting. Config errors surface here; per-entry rejections
/// surface as [`crate::Health::is_healthy`] being `false`.
#[derive(Debug, Error)]
pub enum HealthError {
    /// A `coherence_cidrs` entry was not parseable as an IPv4/IPv6 CIDR.
    #[error("invalid coherence CIDR {cidr:?}: {message}")]
    BadCidr { cidr: String, message: String },

    /// The coherence allowlist was empty — every resolved IP would be rejected,
    /// which is never the intent, so we reject the config instead.
    #[error("coherence allowlist is empty; at least one CIDR is required")]
    EmptyAllowlist,

    /// The configured latency band is inverted (`min > max`).
    #[error("latency band is inverted: min {min_ms}ms > max {max_ms}ms")]
    InvertedLatencyBand { min_ms: u64, max_ms: u64 },

    /// The DNS resolution step failed (propagated from `dns-warmer`).
    #[error("DNS resolution failed for {sni:?}: {message}")]
    Resolve { sni: String, message: String },

    /// The TLS validation probe could not complete (connect/handshake error).
    #[error("TLS probe to {dest:?} for SNI {sni:?} failed: {message}")]
    Probe {
        dest: String,
        sni: String,
        message: String,
    },
}
