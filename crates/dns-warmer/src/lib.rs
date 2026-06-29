//! # dns-warmer — REALITY-Hydra Phase 3
//!
//! Real, resolve-on-first-use DNS warming with a TTL-aware cache. This is the
//! crate that defeats **Trap 1** (REALITY.md §4): a DPI engine raises
//! `NDPI_UNRESOLVED_HOSTNAME` when a client sends an SNI it never looked up, so
//! before Hydra presents `SNI=X` it must have performed a *genuine* DNS lookup
//! for `X`. The [`DnsWarmer`] does exactly that and caches the answer for the
//! record's TTL, so the lookup cadence tracks a real client's (P5) instead of
//! firing a tell-tale burst of queries for the whole pool at startup.
//!
//! ## Shape
//!
//! * [`Resolver`] — the one-method async seam over "DNS". [`MockResolver`] is an
//!   offline table; [`HickoryResolver`] (feature `live-dns`) is the real thing.
//! * [`DnsWarmer`] — a `Resolver` wrapped in a TTL-aware, concurrency-safe cache.
//!
//! It does **not** check coherence (resolved-IP ∈ CDN range, Traps 2 & 3) or
//! validate TLS — that is the `health-checker` crate (Phase 2). This crate only
//! guarantees *a real resolution happened*.
//!
//! ## Quick tour
//!
//! ```
//! use dns_warmer::{DnsWarmer, MockResolver};
//! use std::time::Duration;
//!
//! let ip = "203.0.113.10".parse().unwrap();
//! let resolver = MockResolver::new().with("a.cdn.example", &[ip], Duration::from_secs(300));
//! let warmer = DnsWarmer::new(resolver);
//!
//! // A tiny current-thread runtime just to drive the async `warm` call.
//! let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
//!
//! // Cold: a real resolution happens and is cached.
//! let resolved = rt.block_on(warmer.warm("a.cdn.example", /* now_ms */ 0)).unwrap();
//! assert_eq!(resolved.addrs, vec![ip]);
//!
//! // Now it is safe to present SNI=a.cdn.example — the lookup provably happened.
//! assert!(warmer.is_warm("a.cdn.example", 0));
//! ```

mod error;
mod resolver;
mod warmer;

#[cfg(feature = "live-dns")]
mod hickory;

pub use error::ResolveError;
pub use resolver::{MockResolver, Resolved, Resolver};
pub use warmer::{DnsWarmer, WarmerConfig};

#[cfg(feature = "live-dns")]
pub use hickory::HickoryResolver;
