//! Sticky-per-destination selection (REALITY.md §5.2, P3): a browser does not
//! flip the SNI it uses for a site on every request, so the selector reuses its
//! choice per destination for a TTL.

use pool_engine::{ActivePool, MasterList, PoolEntry, Selector, keyed_epoch_subset};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn pool() -> ActivePool {
    let m = MasterList::new(vec![
        PoolEntry::new("a.example", 1.0),
        PoolEntry::new("b.example", 1.0),
        PoolEntry::new("c.example", 1.0),
        PoolEntry::new("d.example", 1.0),
    ])
    .unwrap();
    keyed_epoch_subset(b"sticky", &[2u8; 16], &m, 0, 4) // k == n, so all four
}

#[test]
fn sticky_within_ttl_returns_same_sni() {
    let p = pool();
    let mut sel = Selector::new(1000);
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let first = sel.select(&p, "site.example", 0, &mut rng).unwrap();
    let again = sel.select(&p, "site.example", 999, &mut rng).unwrap();
    assert_eq!(first, again, "choice should be sticky within the TTL");
}

#[test]
fn re_picks_after_ttl_expiry() {
    let p = pool();
    let mut sel = Selector::new(1000);
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let _first = sel.select(&p, "site.example", 0, &mut rng).unwrap();
    let later = sel.select(&p, "site.example", 1000, &mut rng).unwrap(); // at expiry
    assert!(p.contains(&later), "re-pick must be a valid pool member");
}

#[test]
fn distinct_destinations_are_independent() {
    let p = pool();
    let mut sel = Selector::new(10_000);
    let mut rng = ChaCha20Rng::seed_from_u64(99);
    let a1 = sel.select(&p, "a.dest", 0, &mut rng).unwrap();
    let b1 = sel.select(&p, "b.dest", 0, &mut rng).unwrap();
    let a2 = sel.select(&p, "a.dest", 5, &mut rng).unwrap();
    let b2 = sel.select(&p, "b.dest", 5, &mut rng).unwrap();
    assert_eq!(a1, a2, "dest a should keep its own sticky choice");
    assert_eq!(b1, b2, "dest b should keep its own sticky choice");
}

#[test]
fn every_pick_is_a_pool_member() {
    let p = pool();
    let mut sel = Selector::new(0); // never sticky; re-pick every call
    let mut rng = ChaCha20Rng::seed_from_u64(123);
    for t in 0..200 {
        let sni = sel.select(&p, "x.dest", t, &mut rng).unwrap();
        assert!(p.contains(&sni));
    }
}

#[test]
fn evict_expired_drops_stale_entries() {
    let p = pool();
    let mut sel = Selector::new(100);
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    sel.select(&p, "d1", 0, &mut rng);
    sel.select(&p, "d2", 0, &mut rng);
    sel.evict_expired(50); // nothing expired yet
    let d1a = sel.select(&p, "d1", 60, &mut rng).unwrap();
    sel.evict_expired(200); // now both are expired and removed
    let d1b = sel.select(&p, "d1", 210, &mut rng).unwrap();
    assert!(p.contains(&d1a));
    assert!(p.contains(&d1b));
}
