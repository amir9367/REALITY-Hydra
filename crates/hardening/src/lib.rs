//! # hardening — REALITY-Hydra Phase 7
//!
//! Hardening checklist, distribution validation, and metrics for the Hydra
//! components (REALITY.md §10 Phase 7, §13, §7 P1–P13).
//!
//! This crate provides:
//!
//! 1. **Correctness checklist** — automated validation of the invariants from
//!    §13: pool determinism, sampler unbiasedness, epoch window superset, sticky
//!    cache behavior, and config validation.
//!
//! 2. **Distribution validation** — checks that a long run of weighted-random
//!    selections produces a frequency distribution that closely matches the
//!    configured weights (χ² test). This ensures the pool doesn't produce a
//!    uniform distribution when Tranco-shaped weights are configured (P3/P4).
//!
//! 3. **Metrics collection** — lightweight counters for tracking selection
//!    frequency, epoch transitions, cache hit rates, and health-check outcomes
//!    at runtime.
//!
//! ## Quick tour
//!
//! ```
//! use hardening::{chi_square, distribution_matches_weights, SampleEntry, Metrics};
//! use std::collections::HashMap;
//!
//! // 1. Distribution validation: check that observed counts match weights.
//! let weights = vec![
//!     SampleEntry { label: "a".into(), weight: 3.0 },
//!     SampleEntry { label: "b".into(), weight: 2.0 },
//! ];
//! let mut counts = HashMap::new();
//! counts.insert("a".into(), 300);
//! counts.insert("b".into(), 200);
//! assert!(distribution_matches_weights(&counts, &weights));
//!
//! // 2. Metrics: track counters.
//! let metrics = Metrics::counter_set();
//! metrics.inc(Metrics::SELECTIONS);
//! assert_eq!(metrics.get(Metrics::SELECTIONS), 1);
//! ```

mod checklist;
mod distribution;
mod metrics;

pub use checklist::{CheckResult, ChecklistReport, run_checklist};
pub use distribution::{SampleEntry, chi_square, distribution_matches_weights};
pub use metrics::{CounterSet, Metrics};
