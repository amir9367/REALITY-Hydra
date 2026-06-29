//! Epoch resolution and the accepted-`serverNames` derivation.
//!
//! This is the whole point of Phase 6 (REALITY.md §10): a server-side sidecar
//! computes *which SNIs it should accept right now* straight from the shared
//! `master_secret` + `server_salt`, with no coordination channel. The result is
//! published as REALITY `serverNames`.
//!
//! The functions take the epoch explicitly so they stay pure and testable;
//! [`resolve_epoch`] is the one place that may read the wall clock.

use pool_engine::{
    ActivePool, Epoch, HydraConfig, accepted_pool_window, current_epoch, epoch_at,
    keyed_epoch_subset,
};

/// How the target epoch was chosen, in precedence order.
///
/// `--epoch` wins over `--at`, which wins over the wall clock — so an operator
/// can pin an exact epoch for testing, evaluate a specific wall-clock instant, or
/// (the common case) just ask for "now".
pub fn resolve_epoch(cfg: &HydraConfig, at_unix_secs: Option<u64>, epoch: Option<Epoch>) -> Epoch {
    match (epoch, at_unix_secs) {
        (Some(e), _) => e,
        (None, Some(secs)) => epoch_at(secs, cfg.epoch_len),
        (None, None) => current_epoch(cfg.epoch_len),
    }
}

/// Derive the SNIs the server should accept for `epoch`.
///
/// With `window = true` (the default for a server) this is the ±1 epoch union
/// from [`accepted_pool_window`], so a client whose clock sits right on an epoch
/// boundary still presents an accepted SNI. With `window = false` it is the exact
/// single-epoch subset a correctly-synced client would draw from — useful for
/// inspecting or diffing one epoch.
pub fn server_names(cfg: &HydraConfig, epoch: Epoch, window: bool) -> ActivePool {
    if window {
        accepted_pool_window(
            cfg.master_secret(),
            &cfg.server_salt,
            &cfg.master_list,
            epoch,
            cfg.active_k,
        )
    } else {
        keyed_epoch_subset(
            cfg.master_secret(),
            &cfg.server_salt,
            &cfg.master_list,
            epoch,
            cfg.active_k,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn cfg() -> HydraConfig {
        HydraConfig::from_toml_str(include_str!("../../pool-engine/fixtures/hydra.toml")).unwrap()
    }

    #[test]
    fn epoch_precedence_is_explicit_over_at_over_clock() {
        let cfg = cfg();
        // --epoch wins regardless of --at.
        assert_eq!(resolve_epoch(&cfg, Some(999_999), Some(42)), 42);
        // --at maps through epoch_len (6h = 21600s) when no explicit epoch.
        assert_eq!(
            resolve_epoch(&cfg, Some(21_600), None),
            epoch_at(21_600, Duration::from_secs(21_600))
        );
        assert_eq!(resolve_epoch(&cfg, Some(21_600), None), 1);
        assert_eq!(resolve_epoch(&cfg, Some(43_199), None), 1);
        assert_eq!(resolve_epoch(&cfg, Some(43_200), None), 2);
    }

    #[test]
    fn window_is_a_superset_of_the_single_epoch() {
        let cfg = cfg();
        let single = server_names(&cfg, 1000, false);
        let windowed = server_names(&cfg, 1000, true);
        // Every SNI live for the exact epoch is also accepted by the ±1 window.
        for sni in single.snis() {
            assert!(windowed.contains(sni), "window dropped {sni}");
        }
        assert!(windowed.len() >= single.len());
    }
}
