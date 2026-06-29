//! Criterion benchmarks for the hot paths: per-epoch subset derivation and
//! per-connection selection. Run with `cargo bench`.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use pool_engine::{MasterList, PoolEntry, Selector, keyed_epoch_subset};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn master(n: usize) -> MasterList {
    let entries = (0..n)
        .map(|i| PoolEntry::new(format!("d{i}.cdn.example"), 1.0 + (i % 100) as f64))
        .collect();
    MasterList::new(entries).unwrap()
}

fn bench_subset(c: &mut Criterion) {
    let m = master(500);
    let secret = b"benchmark-master-secret-bytes!!!";
    let salt = [9u8; 16];
    let mut epoch = 0u64;
    c.bench_function("keyed_epoch_subset n=500 k=12", |b| {
        b.iter(|| {
            epoch += 1;
            black_box(keyed_epoch_subset(secret, &salt, &m, epoch, 12))
        })
    });
}

fn bench_select(c: &mut Criterion) {
    let m = master(50);
    let pool = keyed_epoch_subset(b"bench", &[9u8; 16], &m, 0, 12);
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    // TTL 0 => never sticky, so every call exercises the weighted pick.
    let mut selector = Selector::new(0);
    let mut t = 0u64;
    c.bench_function("selector.select ttl=0", |b| {
        b.iter(|| {
            t += 1;
            black_box(selector.select(&pool, "dest.example", t, &mut rng))
        })
    });
}

criterion_group!(benches, bench_subset, bench_select);
criterion_main!(benches);
