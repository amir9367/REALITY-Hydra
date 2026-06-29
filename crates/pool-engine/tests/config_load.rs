//! Loading and validating the TOML config + master list (REALITY.md §11).

use pool_engine::{HydraConfig, keyed_epoch_subset};
use std::time::Duration;

#[test]
fn loads_fixture_and_drives_engine() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/hydra.toml");
    let cfg = HydraConfig::from_file(path).expect("fixture should load");

    assert_eq!(cfg.epoch_len, Duration::from_secs(6 * 3600));
    assert_eq!(cfg.active_k, 4);
    assert_eq!(cfg.server_salt.len(), 16);
    assert_eq!(cfg.master_secret().len(), 32);
    assert!(cfg.master_list.len() >= cfg.active_k);
    assert_eq!(cfg.dest.as_deref(), Some("cdn-edge.example:443"));

    // The loaded config actually produces a pool of the configured size.
    let pool = keyed_epoch_subset(
        cfg.master_secret(),
        &cfg.server_salt,
        &cfg.master_list,
        1,
        cfg.active_k,
    );
    assert_eq!(pool.len(), cfg.active_k);
}

#[test]
fn rejects_unknown_pool_format() {
    let toml = r#"
        master_secret = "base64:Mdzc9T8bRDckIYNV8C256E+OsuYfBiEca20zKwWhgo8="
        server_salt   = "base64:gLx8cgG8iAnZTZMiplCwEg=="
        pool_format   = "hydra-pool-v999"
        active_k      = 1
        [[pool]]
        sni = "a.example"
        weight = 1.0
    "#;
    assert!(HydraConfig::from_toml_str(toml).is_err());
}

#[test]
fn rejects_bad_secret_length() {
    let toml = r#"
        master_secret = "base64:AAAA"
        server_salt   = "base64:gLx8cgG8iAnZTZMiplCwEg=="
        active_k      = 1
        [[pool]]
        sni = "a.example"
        weight = 1.0
    "#;
    assert!(HydraConfig::from_toml_str(toml).is_err());
}

#[test]
fn rejects_invalid_weight() {
    let toml = r#"
        master_secret = "base64:Mdzc9T8bRDckIYNV8C256E+OsuYfBiEca20zKwWhgo8="
        server_salt   = "base64:gLx8cgG8iAnZTZMiplCwEg=="
        active_k      = 1
        [[pool]]
        sni = "a.example"
        weight = 0.0
    "#;
    assert!(HydraConfig::from_toml_str(toml).is_err());
}
