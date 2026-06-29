//! Integration tests for the Phase 6 sidecar, driven through the public library
//! API exactly as the `hydra` binary drives it.

use hydra_cli::{OutputFormat, render, resolve_epoch, server_names};
use pool_engine::HydraConfig;
use serde_json::Value;

fn cfg() -> HydraConfig {
    HydraConfig::from_toml_str(include_str!("../../pool-engine/fixtures/hydra.toml")).unwrap()
}

/// The whole point of Phase 6: a server deriving its accepted set must match
/// what a correctly-synced client would draw — with no coordination. We can't
/// run two processes here, but we can assert the derivation is deterministic and
/// the ±1 window contains the exact single epoch (the boundary-skew guarantee).
#[test]
fn derivation_is_deterministic_and_window_contains_single() {
    let cfg = cfg();
    let epoch = resolve_epoch(&cfg, Some(50_000), None);

    let a = server_names(&cfg, epoch, true);
    let b = server_names(&cfg, epoch, true);
    assert_eq!(a, b, "same inputs must yield the same accepted pool");

    let single = server_names(&cfg, epoch, false);
    for sni in single.snis() {
        assert!(
            a.contains(sni),
            "±1 window must accept the exact epoch's {sni}"
        );
    }
}

/// `--epoch` pins exactly; `--at` maps through `epoch_len`; neither just reads
/// the clock. (6h epoch_len in the fixture ⇒ 21600s per epoch.)
#[test]
fn epoch_selection_flags_resolve_as_documented() {
    let cfg = cfg();
    assert_eq!(resolve_epoch(&cfg, None, Some(123)), 123);
    assert_eq!(resolve_epoch(&cfg, Some(0), None), 0);
    assert_eq!(resolve_epoch(&cfg, Some(21_599), None), 0);
    assert_eq!(resolve_epoch(&cfg, Some(21_600), None), 1);
}

/// All three renderers agree on the SNI set for a given pool.
#[test]
fn renderers_agree_on_the_sni_set() {
    let cfg = cfg();
    let epoch = 12;
    let pool = server_names(&cfg, epoch, true);
    let expected: Vec<&str> = pool.snis().collect();

    let lines: Vec<String> = render(&cfg, &pool, epoch, OutputFormat::Lines)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    assert_eq!(lines, expected);

    let json: Value =
        serde_json::from_str(&render(&cfg, &pool, epoch, OutputFormat::Json).unwrap()).unwrap();
    let from_json: Vec<&str> = json
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(from_json, expected);

    let xray: Value =
        serde_json::from_str(&render(&cfg, &pool, epoch, OutputFormat::Xray).unwrap()).unwrap();
    let from_xray: Vec<&str> = xray["streamSettings"]["realitySettings"]["serverNames"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(from_xray, expected);
}
