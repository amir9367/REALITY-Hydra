//! Property tests: for arbitrary inputs the sampler is deterministic and always
//! returns a well-formed subset (right size, distinct, drawn from the master).

use pool_engine::{MasterList, PoolEntry, keyed_epoch_subset};
use proptest::prelude::*;

fn list(n: usize) -> MasterList {
    let entries = (0..n)
        .map(|i| PoolEntry::new(format!("d{i}.example"), 1.0 + i as f64))
        .collect();
    MasterList::new(entries).unwrap()
}

proptest! {
    #[test]
    fn deterministic_and_well_formed(
        secret in proptest::collection::vec(any::<u8>(), 1..40),
        salt_seed in any::<u128>(),
        epoch in any::<u64>(),
        k in 1usize..15,
        n in 1usize..30,
    ) {
        let salt = salt_seed.to_le_bytes(); // u128 is exactly 16 bytes
        let m = list(n);

        let a = keyed_epoch_subset(&secret, &salt, &m, epoch, k);
        let b = keyed_epoch_subset(&secret, &salt, &m, epoch, k);

        prop_assert_eq!(&a, &b);              // determinism
        prop_assert_eq!(a.len(), k.min(n));   // size == min(k, n)

        // No replacement: all SNIs distinct.
        let mut snis: Vec<&str> = a.snis().collect();
        let before = snis.len();
        snis.sort_unstable();
        snis.dedup();
        prop_assert_eq!(snis.len(), before);

        // Every chosen SNI belongs to the master list.
        for s in a.snis() {
            prop_assert!(m.entries().iter().any(|e| e.sni == s));
        }
    }
}
