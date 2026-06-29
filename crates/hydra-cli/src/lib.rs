//! # hydra-cli — REALITY-Hydra Phase 6 (server-side epoch automation)
//!
//! A small sidecar that turns the keyed epoch pool (Phase 1, `pool-engine`) into
//! the concrete thing a REALITY server needs: the set of SNIs it should accept
//! *this epoch*, ready to drop into `serverNames` (REALITY.md §10 Phase 6, §11).
//!
//! Because Hydra's auth is SNI-independent and both sides derive the same pool
//! from the shared `master_secret` + `server_salt`, the server doesn't negotiate
//! anything — it just recomputes its accepted set as the clock advances. Run this
//! on the server each epoch (e.g. from cron) and reload Xray with the output.
//!
//! ## Library vs binary
//!
//! The `hydra` binary ([`main`]) is a thin clap shell over this library. Everything
//! that produces output lives here so it is unit-testable without a process:
//!
//! * [`resolve_epoch`] / [`server_names`] — pick the epoch and derive its
//!   accepted pool (the ±1 union by default).
//! * [`render`] / [`OutputFormat`] — emit it as lines, a JSON `serverNames`
//!   array, or a paste-ready stock Xray REALITY inbound.
//!
//! ## Quick tour
//!
//! ```
//! use hydra_cli::{server_names, render, OutputFormat};
//! use pool_engine::HydraConfig;
//!
//! let cfg = HydraConfig::from_toml_str(include_str!(
//!     "../../pool-engine/fixtures/hydra.toml"
//! ))
//! .unwrap();
//!
//! // The SNIs the server should accept for epoch 100 (±1 window).
//! let pool = server_names(&cfg, 100, true);
//! let json = render(&cfg, &pool, 100, OutputFormat::Json).unwrap();
//! assert!(json.starts_with('['));
//! ```

mod epoch;
mod error;
mod render;

pub use epoch::{resolve_epoch, server_names};
pub use error::CliError;
pub use render::{OutputFormat, render, render_json, render_lines, render_xray};
