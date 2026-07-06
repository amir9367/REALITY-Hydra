//! # hydra-client — REALITY-Hydra Phase 5
//!
//! The integration crate that wires all Hydra components into a working client:
//!
//! ```text
//! app traffic  ──SOCKS5──▶  Pipeline
//!                            ├─ PoolEngine     (keyed epoch subset)
//!                            ├─ Selector       (weighted-random + sticky cache)
//!                            ├─ DnsWarmer      (resolve-on-first-use, TTL-aware)
//!                            └─ RealityTLS     (Chrome fingerprint + X25519 auth)
//!                                         ──▶ CDN edge ──▶ Xray server
//! ```
//!
//! ## Architecture
//!
//! - **`Pipeline`** — the core orchestrator. Loads `hydra.toml`, derives the
//!   active epoch pool, and for each inbound connection: selects an SNI, warms
//!   DNS, opens a REALITY-authenticated TLS connection, and relays bytes.
//! - **`socks5`** — a minimal SOCKS5 inbound (RFC 1928) that accepts app
//!   traffic and hands it to the pipeline.
//!
//! ## Feature gates
//!
//! - `live-dns` — real DNS resolution via hickory (off by default).
//! - `boring-impersonate` — Chrome-fingerprinted TLS via BoringSSL (off by
//!   default). Without it, the pipeline connects with plain TCP for testing.
//! - `full` — enables both live-dns and boring-impersonate.
//!
//! ## Quick tour (offline, with mock seams)
//!
//! ```
//! use hydra_client::Pipeline;
//! use pool_engine::HydraConfig;
//!
//! let cfg = HydraConfig::from_toml_str(include_str!(
//!     "../../pool-engine/fixtures/hydra.toml"
//! ))
//! .unwrap();
//!
//! let pipeline = Pipeline::mock(cfg);
//! // In production: pipeline.serve("127.0.0.1:1080").await.unwrap();
//! ```

mod error;
mod pipeline;
pub mod server_setup;
mod socks5;
mod tunnel;

pub use error::ClientError;
pub use pipeline::Pipeline;
pub use socks5::Socks5Addr;
pub use tunnel::TunnelClient;
