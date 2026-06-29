//! Unbiasedness of the weighted sampler (REALITY.md §5.4, §13): selection
//! frequency must track the configured weights, and selection must be without
//! replacement.
//!
//! These sweep a fixed `(secret, salt)` across many epochs, so they are fully
//! deterministic — stable regression bounds, not flaky statistical tests.

use pool_engine::{MasterList, PoolEntry, keyed_epoch_subset};
use std::collections::HashMap;

#[test]
fn k1_selection_matches_weights_chi_square() {
    // For k = 1, A-Res includes entry i with probability exactly w_i / Σw.
    let entries = vec![
        PoolEntry::new("w1.example", 1.0),
        PoolEntry::new("w2.example", 2.0),
        PoolEntry::new("w3.example", 3.0),
        PoolEntry::new("w4.example", 4.0),
    ];
    let m = MasterList::new(entries.clone()).unwrap();
    let total: f64 = entries.iter().map(|e| e.weight).sum();

    let secret = b"chi-square unbiasedness secret";
    let salt = [7u8; 16];
    let n = 60_000u64;

    let mut counts: HashMap<String, u64> = HashMap::new();
    for epoch in 0..n {
        let pool = keyed_epoch_subset(secret, &salt, &m, epoch, 1);
        let sni = pool.snis().next().unwrap().to_owned();
        *counts.entry(sni).or_default() += 1;
    }

    // Pearson chi-square against expected = N * w_i / Σw.
    let mut chi2 = 0.0;
    for e in &entries {
        let observed = *counts.get(&e.sni).unwrap_or(&0) as f64;
        let expected = n as f64 * (e.weight / total);
        chi2 += (observed - expected).powi(2) / expected;
    }
    // df = 3; chi-square critical value at p = 0.001 is ~16.27.
    assert!(
        chi2 < 16.27,
        "chi^2 = {chi2:.3} — selection not weight-proportional"
    );
}

#[test]
fn selection_is_without_replacement() {
    let m = MasterList::new(
        (0..20)
            .map(|i| PoolEntry::new(format!("d{i}.example"), 1.0 + i as f64))
            .collect(),
    )
    .unwrap();

    for epoch in 0..50 {
        let pool = keyed_epoch_subset(b"distinct", &[3u8; 16], &m, epoch, 8);
        let mut snis: Vec<&str> = pool.snis().collect();
        let before = snis.len();
        snis.sort_unstable();
        snis.dedup();
        assert_eq!(
            snis.len(),
            before,
            "duplicate SNI in active pool at epoch {epoch}"
        );
        assert_eq!(before, 8);
    }
}

#[test]
fn heavier_weights_selected_more_often() {
    // Monotonicity for k > 1: the marginal inclusion probability is no longer
    // exactly w/Σw, but heavier entries must still appear more frequently.
    let entries = vec![
        PoolEntry::new("light.example", 1.0),
        PoolEntry::new("heavy.example", 25.0),
        PoolEntry::new("a.example", 2.0),
        PoolEntry::new("b.example", 2.0),
        PoolEntry::new("c.example", 2.0),
        PoolEntry::new("d.example", 2.0),
    ];
    let m = MasterList::new(entries).unwrap();

    let (mut light, mut heavy) = (0u64, 0u64);
    let n = 20_000u64;
    for epoch in 0..n {
        let pool = keyed_epoch_subset(b"monotone", &[1u8; 16], &m, epoch, 2);
        if pool.contains("light.example") {
            light += 1;
        }
        if pool.contains("heavy.example") {
            heavy += 1;
        }
    }
    assert!(
        heavy > light,
        "heavy ({heavy}) should be selected more than light ({light})"
    );
}
