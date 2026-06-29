//! # health-checker — REALITY-Hydra Phase 2
//!
//! Validates candidate pool SNIs and emits a pruned pool of the ones that pass.
//! For each entry it checks four independent axes (REALITY.md §7 P1/P8):
//!
//! 1. **Coherence (a)** — the SNI's real DNS answer lands inside the configured
//!    `coherence_cidrs` allowlist (the CDN edge ranges your server is fronted by).
//!    Defeats Traps 2 & 3 (REALITY.md §4).
//! 2. **Certificate (b)** — the leaf cert returned for that SNI carries a SAN
//!    that matches it, over a TLS 1.3 connection.
//! 3. **ALPN (c)** — the edge negotiates `h2`.
//! 4. **Latency (d)** — the handshake round-trip is inside a sane band.
//!
//! Only entries that pass *every* axis survive into the pruned [`ActivePool`].
//!
//! [`ActivePool`]: pool_engine::ActivePool
//!
//! ## Shape (mirrors `dns-warmer`)
//!
//! The decision logic is pure and fully offline-testable. The two network-facing
//! steps are seams:
//!
//! * DNS resolution reuses `dns-warmer`'s [`Resolver`] (with [`MockResolver`] for
//!   tests), and
//! * the TLS facts come from a [`TlsInspector`] ([`MockInspector`] for tests;
//!   [`RustlsInspector`] under the `live-tls` feature for real connections).
//!
//! So the default build and the whole test suite need no network and no TLS
//! provider.
//!
//! [`Resolver`]: dns_warmer::Resolver
//! [`MockResolver`]: dns_warmer::MockResolver
//!
//! ## Quick tour (offline, with mock seams)
//!
//! ```
//! use std::time::Duration;
//! use dns_warmer::MockResolver;
//! use pool_engine::{MasterList, PoolEntry};
//! use health_checker::{
//!     CoherenceAllowlist, HealthChecker, LatencyBand, MockInspector, TlsObservation, prune,
//! };
//!
//! let master = MasterList::new(vec![PoolEntry::new("a.cdn.example", 1.0)]).unwrap();
//!
//! // The SNI resolves into the allowed CDN range...
//! let resolver = MockResolver::new()
//!     .with("a.cdn.example", &["104.16.0.5".parse().unwrap()], Duration::from_secs(300));
//! let allowlist = CoherenceAllowlist::parse(["104.16.0.0/13"]).unwrap();
//!
//! // ...and the edge serves a matching cert over TLS 1.3 + h2, quickly.
//! let inspector = MockInspector::new().with("a.cdn.example", TlsObservation {
//!     is_tls13: true,
//!     alpn: Some(b"h2".to_vec()),
//!     leaf_san_dns_names: vec!["*.cdn.example".to_string()],
//!     rtt: Duration::from_millis(40),
//! });
//!
//! let checker = HealthChecker::new(
//!     resolver, inspector, allowlist, LatencyBand::default(), "cdn-edge.example:443",
//! );
//!
//! let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
//! let reports = rt.block_on(checker.check_all(&master)).unwrap();
//! assert!(reports[0].is_healthy());
//!
//! let pruned = prune(&master, &reports);
//! assert!(pruned.contains("a.cdn.example"));
//! ```

mod checker;
mod coherence;
mod error;
mod prober;
mod report;
mod san;

#[cfg(feature = "live-tls")]
mod rustls_inspector;

pub use checker::HealthChecker;
pub use coherence::CoherenceAllowlist;
pub use error::HealthError;
pub use prober::{MockInspector, TlsInspector, TlsObservation};
pub use report::{Health, LatencyBand, healthy_snis, prune};
pub use san::sni_matches_any;

#[cfg(feature = "live-tls")]
pub use rustls_inspector::RustlsInspector;
