//! Integration tests for the hardening checklist and distribution validation.

use hardening::{
    chi_square, distribution_matches_weights, run_checklist, SampleEntry,
};
use pool_engine::{HydraConfig, MasterList, PoolEntry};
use std::collections::HashMap;

fn cfg() -> HydraConfig {
    HydraConfig::from_toml_str(include_str!("../../pool-engine/fixtures/hydra.toml")).unwrap()
}

// ---- Checklist --------------------------------------------------------------

#[test]
fn full_checklist_passes_with_fixture_config() {
    let report = run_checklist(&cfg());
    assert!(
        report.all_passed(),
        "checklist failed: {:?}",
        report.failures()
    );
    assert_eq!(report.fail_count(), 0);
}

#[test]
fn checklist_report_has_all_items() {
    let report = run_checklist(&cfg());
    assert!(report.results.len() >= 8);
    let names: Vec<&str> = report.results.iter().map(|r| r.name).collect();
    assert!(names.contains(&"pool_determinism"));
    assert!(names.contains(&"epoch_window_superset"));
    assert!(names.contains(&"salt_isolation"));
    assert!(names.contains(&"epoch_evolution"));
}

// ---- Distribution validation ------------------------------------------------

#[test]
fn perfectly_proportional_counts_pass() {
    let entries = vec![
        SampleEntry { label: "a".into(), weight: 5.0 },
        SampleEntry { label: "b".into(), weight: 3.0 },
        SampleEntry { label: "c".into(), weight: 2.0 },
    ];
    let mut counts = HashMap::new();
    counts.insert("a".into(), 500);
    counts.insert("b".into(), 300);
    counts.insert("c".into(), 200);
    assert!(distribution_matches_weights(&counts, &entries));
}

#[test]
fn heavily_biased_counts_fail() {
    let entries = vec![
        SampleEntry { label: "a".into(), weight: 5.0 },
        SampleEntry { label: "b".into(), weight: 3.0 },
        SampleEntry { label: "c".into(), weight: 2.0 },
    ];
    let mut counts = HashMap::new();
    counts.insert("a".into(), 50);
    counts.insert("b".into(), 50);
    counts.insert("c".into(), 900);
    assert!(!distribution_matches_weights(&counts, &entries));
}

#[test]
fn chi2_statistic_increases_with_mismatch() {
    let entries = vec![
        SampleEntry { label: "a".into(), weight: 1.0 },
        SampleEntry { label: "b".into(), weight: 1.0 },
    ];

    // Perfect 50:50 split.
    let mut c1 = HashMap::new();
    c1.insert("a".into(), 500);
    c1.insert("b".into(), 500);
    let (chi1, _) = chi_square(&c1, &entries);

    // Slightly off 60:40 split.
    let mut c2 = HashMap::new();
    c2.insert("a".into(), 600);
    c2.insert("b".into(), 400);
    let (chi2, _) = chi_square(&c2, &entries);

    // Heavily off 90:10 split.
    let mut c3 = HashMap::new();
    c3.insert("a".into(), 900);
    c3.insert("b".into(), 100);
    let (chi3, _) = chi_square(&c3, &entries);

    assert!(chi1 < chi2);
    assert!(chi2 < chi3);
}

// ---- Edge cases -------------------------------------------------------------

#[test]
fn checklist_with_single_entry() {
    let master = MasterList::new(vec![PoolEntry::new("only.cdn.example", 1.0)]).unwrap();
    let secret = b"a-32-byte-or-so shared master secret";
    let salt = [0u8; pool_engine::SALT_LEN];
    let pool = pool_engine::keyed_epoch_subset(secret, &salt, &master, 42, 1);
    assert_eq!(pool.len(), 1);
    assert!(pool.contains("only.cdn.example"));
}

#[test]
fn checklist_with_large_k() {
    let master = MasterList::new(vec![
        PoolEntry::new("a.cdn.example", 1.0),
        PoolEntry::new("b.cdn.example", 2.0),
    ])
    .unwrap();
    let secret = b"a-32-byte-or-so shared master secret";
    let salt = [0u8; pool_engine::SALT_LEN];
    // k > N should be clamped.
    let pool = pool_engine::keyed_epoch_subset(secret, &salt, &master, 42, 100);
    assert_eq!(pool.len(), 2);
}
