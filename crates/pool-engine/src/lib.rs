//! # pool-engine — REALITY-Hydra Phase 1
//!
//! The keyed, time-evolving SNI pool: the novel, self-contained core of
//! REALITY-Hydra (see `REALITY.md` §5.4). It is pure logic — no network, no
//! async — and is the "perfect Rust onramp" the design doc calls for.
//!
//! Both the client and the server derive the **same** active subset of SNIs for
//! a given time epoch from a shared `master_secret` + `server_salt`, with no
//! coordination channel:
//!
//! ```text
//! epoch  = floor(unix_time / EPOCH_LEN)
//! seed   = HMAC-SHA256(master_secret, "hydra-pool-v1" || server_salt || LE64(epoch))
//! active = weighted_reservoir(MasterList, ChaCha20(seed), k)   // A-Res, unbiased
//! ```
//!
//! ## What this crate does (and does not) do
//!
//! It chooses *which borrowed SNIs are live this epoch* and *which one a given
//! connection uses*. It does **not** perform DNS, TLS, health-checking, or any
//! IP-layer work — those are later phases. See the threat model in `REALITY.md`
//! §2/§6: Hydra targets passive SNI readers and active probers; it does nothing
//! against TLS-in-TLS or IP blocking.
//!
//! ## Quick tour
//!
//! ```
//! use pool_engine::{MasterList, PoolEntry, keyed_epoch_subset, Selector};
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
//! // Client and server independently derive the identical epoch pool:
//! let pool = keyed_epoch_subset(secret, &salt, &master, /* epoch */ 12_345, /* k */ 2);
//! assert_eq!(pool.len(), 2);
//!
//! // The client picks one SNI per connection, sticky per destination:
//! let mut selector = Selector::new(30_000 /* ms */);
//! let sni = selector.pick(&pool, "chat.example", /* now_ms */ 0).unwrap();
//! assert!(pool.contains(&sni));
//! ```

mod config;
mod entry;
mod epoch;
mod error;
mod kdf;
mod sampler;
mod select;

pub use config::HydraConfig;
pub use entry::{ActivePool, MasterList, PoolEntry};
pub use epoch::{Epoch, current_epoch, epoch_at, epoch_window};
pub use error::PoolError;
pub use kdf::{DOMAIN_TAG, SALT_LEN, SECRET_LEN, derive_seed};
pub use sampler::{keyed_epoch_subset, subset_from_seed};
pub use select::Selector;

use std::collections::BTreeMap;

/// The server-side accepted pool: the union of the active subsets for
/// `epoch - 1`, `epoch`, and `epoch + 1`.
///
/// A server publishes these SNIs as REALITY `serverNames` so that a client whose
/// clock is up to one epoch off — e.g. sitting right on a boundary — still
/// presents an SNI the server accepts (REALITY.md §5.4). This `±1` window is
/// Hydra's clock-skew tolerance and is *separate* from REALITY's own
/// `maxTimeDiff` anti-replay window.
pub fn accepted_pool_window(
    master_secret: &[u8],
    server_salt: &[u8; SALT_LEN],
    master: &MasterList,
    epoch: Epoch,
    k: usize,
) -> ActivePool {
    // Union by SNI across the three epochs (a BTreeMap also keeps it ordered).
    let mut union: BTreeMap<String, PoolEntry> = BTreeMap::new();
    for e in epoch_window(epoch) {
        for entry in keyed_epoch_subset(master_secret, server_salt, master, e, k).entries() {
            union
                .entry(entry.sni.clone())
                .or_insert_with(|| entry.clone());
        }
    }
    ActivePool::from_unsorted(union.into_values().collect())
}
