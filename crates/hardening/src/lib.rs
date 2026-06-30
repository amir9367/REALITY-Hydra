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
//! use hardening::{check_pool_determinism, check_epoch_window};
//! use pool_engine::{MasterList, PoolEntry};
//!
//! let master = MasterList::new(vec![
//!     PoolEntry::new("a.cdn.example", 3.0),
//!     PoolEntry::new("b.cdn.example", 2.0),
//!     PoolEntry::new("c.cdn.example", 1.0),
//! ])
//! .unwrap();
//!
//! let secret = b"a-32-byte-or-so shared master secret";
//! let salt = [0u8; pool_engine::SALT_LEN];
//!
//! // Check that both "sides" derive the same pool.
//! let ok = check_pool_determinism(secret, &salt, &master, 42, 2);
//! assert!(ok);
//!
//! // Check that the ±1 window is a superset of the single-epoch pool.
//! let ok = check_epoch_window(secret, &salt, &master, 42, 2);
//! assert!(ok);
//! ```

mod checklist;
mod distribution;
mod metrics;

pub use checklist::{CheckResult, ChecklistReport, run_checklist};
pub use distribution::{chi_square, distribution_matches_weights, SampleEntry};
pub use metrics::{CounterSet, Metrics};
