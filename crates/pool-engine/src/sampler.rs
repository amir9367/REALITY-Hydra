//! Weighted, unbiased subset selection — A-Res (Efraimidis–Spirakis).
//!
//! Given the master list, a per-epoch seed, and a target size `k`, pick `k`
//! distinct entries *without replacement*, each included with probability shaped
//! by its `weight`. Selection is fully determined by the seed, so the client and
//! server compute the identical subset for the same epoch with no coordination.
//!
//! **The algorithm.** A-Res assigns entry *i* the key `u_i^(1/w_i)` where
//! `u_i ~ Uniform(0,1]`, then keeps the `k` entries with the largest keys. We
//! use the order-equivalent, numerically stable form `ln(u_i) / w_i` (a
//! monotonic transform of the key) and take the top `k`.
//!
//! Why not `seed % N`? Modulo is biased and, worse, produces a pattern that is
//! itself fingerprintable across epochs (REALITY.md §5.4). A-Res is unbiased:
//! for `k = 1` the inclusion probability is exactly `w_i / Σw`.

use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::entry::{ActivePool, MasterList, PoolEntry};
use crate::epoch::Epoch;
use crate::kdf::{SALT_LEN, derive_seed};

/// Select the active subset from a raw 32-byte seed.
///
/// `k` is clamped to the master-list size (you cannot pick more than you have).
pub fn subset_from_seed(master: &MasterList, seed: [u8; 32], k: usize) -> ActivePool {
    let entries = master.entries();
    let k = k.min(entries.len());

    let mut rng = ChaCha20Rng::from_seed(seed);

    // Draw one A-Res key per entry, in the master list's canonical (sorted)
    // order, so both sides produce identical keys for the same seed.
    let mut keyed: Vec<(f64, &PoolEntry)> = entries
        .iter()
        .map(|e| {
            // `1.0 - random()` lands in (0, 1], so ln(u) is finite (never -inf).
            let u: f64 = 1.0 - rng.random::<f64>();
            let key = u.ln() / e.weight;
            (key, e)
        })
        .collect();

    // Largest keys win. `total_cmp` is a total order over f64; ties break by SNI
    // so the result stays deterministic even if two keys were ever equal.
    keyed.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.sni.cmp(&b.1.sni)));

    let chosen = keyed.into_iter().take(k).map(|(_, e)| e.clone()).collect();
    ActivePool::from_unsorted(chosen)
}

/// Select the active subset for `epoch` from the keyed inputs.
///
/// This is the headline function: client and server call it with the same
/// `(master_secret, server_salt, master, epoch, k)` and get the identical pool.
pub fn keyed_epoch_subset(
    master_secret: &[u8],
    server_salt: &[u8; SALT_LEN],
    master: &MasterList,
    epoch: Epoch,
    k: usize,
) -> ActivePool {
    let seed = derive_seed(master_secret, server_salt, epoch);
    subset_from_seed(master, seed, k)
}
