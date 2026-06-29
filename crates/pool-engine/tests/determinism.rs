//! The load-bearing property: client and server derive the *same* epoch pool
//! from the same inputs, with no coordination (REALITY.md §5.4, §13).

use pool_engine::{MasterList, PoolEntry, keyed_epoch_subset};
use std::collections::HashSet;

const SECRET: &[u8] = b"reality-hydra determinism test secret";
const SALT: [u8; 16] = *b"0123456789abcdef";

fn master() -> MasterList {
    let entries = (0..12)
        .map(|i| PoolEntry::new(format!("d{i:02}.cdn.example"), 1.0 + (i % 5) as f64))
        .collect();
    MasterList::new(entries).unwrap()
}

#[test]
fn same_inputs_same_subset() {
    let m = master();
    // Two independent "sides" deriving the pool for the same epoch.
    let client = keyed_epoch_subset(SECRET, &SALT, &m, 100, 5);
    let server = keyed_epoch_subset(SECRET, &SALT, &m, 100, 5);
    assert_eq!(client, server);
    assert_eq!(client.len(), 5);
}

#[test]
fn k_is_clamped_to_master_len() {
    let m = master();
    let all = keyed_epoch_subset(SECRET, &SALT, &m, 1, 999);
    assert_eq!(all.len(), m.len());
}

#[test]
fn salt_changes_the_pool() {
    // Different deployments (different salt) must derive different pools, so
    // there is no shared cross-deployment SNI signature.
    let m = master();
    let salt2: [u8; 16] = *b"fedcba9876543210";
    let a = keyed_epoch_subset(SECRET, &SALT, &m, 100, 5);
    let b = keyed_epoch_subset(SECRET, &salt2, &m, 100, 5);
    assert_ne!(a, b);
}

#[test]
fn pool_evolves_across_epochs() {
    let m = master();
    let mut distinct = HashSet::new();
    for epoch in 0..32 {
        let pool = keyed_epoch_subset(SECRET, &SALT, &m, epoch, 5);
        distinct.insert(pool.snis().collect::<Vec<_>>().join(","));
    }
    // The active set should drift over time, not stay constant.
    assert!(distinct.len() > 1, "pool never changed across 32 epochs");
}
