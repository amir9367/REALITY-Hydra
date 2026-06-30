//! Correctness checklist — automated validation of §13 invariants.
//!
//! Each function tests one invariant from the REALITY.md §13 correctness
//! checklist and returns a [`CheckResult`]. [`run_checklist`] executes every
//! check and produces a [`ChecklistReport`] with pass/fail per item.

use pool_engine::{Epoch, HydraConfig, MasterList, accepted_pool_window, keyed_epoch_subset};

/// The outcome of a single checklist item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckResult {
    pub name: &'static str,
    pub passed: bool,
    pub detail: Option<String>,
}

/// A full checklist report.
#[derive(Clone, Debug)]
pub struct ChecklistReport {
    pub results: Vec<CheckResult>,
}

impl ChecklistReport {
    /// Whether every check passed.
    pub fn all_passed(&self) -> bool {
        self.results.iter().all(|r| r.passed)
    }

    /// The number of failed checks.
    pub fn fail_count(&self) -> usize {
        self.results.iter().filter(|r| !r.passed).count()
    }

    /// Failed items only.
    pub fn failures(&self) -> Vec<&CheckResult> {
        self.results.iter().filter(|r| !r.passed).collect()
    }
}

/// Check that two independent derivations of the same epoch pool produce
/// identical results (§13: "client-derived == server-derived").
pub fn check_pool_determinism(
    master_secret: &[u8],
    server_salt: &[u8; pool_engine::SALT_LEN],
    master: &MasterList,
    epoch: Epoch,
    k: usize,
) -> bool {
    let a = keyed_epoch_subset(master_secret, server_salt, master, epoch, k);
    let b = keyed_epoch_subset(master_secret, server_salt, master, epoch, k);
    a == b
}

/// Check that the ±1 epoch window is a superset of the single-epoch pool
/// (§13: "±1 epoch boundary: client one epoch off still authenticates").
pub fn check_epoch_window(
    master_secret: &[u8],
    server_salt: &[u8; pool_engine::SALT_LEN],
    master: &MasterList,
    epoch: Epoch,
    k: usize,
) -> bool {
    let single = keyed_epoch_subset(master_secret, server_salt, master, epoch, k);
    let windowed = accepted_pool_window(master_secret, server_salt, master, epoch, k);
    single.snis().all(|sni| windowed.contains(sni)) && windowed.len() >= single.len()
}

/// Check that the epoch window saturates at epoch 0 (no underflow).
pub fn check_epoch_window_saturation(
    master_secret: &[u8],
    server_salt: &[u8; pool_engine::SALT_LEN],
    master: &MasterList,
    k: usize,
) -> bool {
    let windowed = accepted_pool_window(master_secret, server_salt, master, 0, k);
    !windowed.is_empty()
}

/// Check that k is clamped to the master-list size (§13: "k is clamped").
pub fn check_k_clamping(
    master_secret: &[u8],
    server_salt: &[u8; pool_engine::SALT_LEN],
    master: &MasterList,
    epoch: Epoch,
) -> bool {
    let oversized_k = master.len() + 100;
    let pool = keyed_epoch_subset(master_secret, server_salt, master, epoch, oversized_k);
    pool.len() == master.len()
}

/// Check that different salts produce different pools (cross-deployment
/// isolation, §5.4).
pub fn check_salt_isolation(
    master_secret: &[u8],
    master: &MasterList,
    epoch: Epoch,
    k: usize,
) -> bool {
    let salt_a = [0xAAu8; pool_engine::SALT_LEN];
    let salt_b = [0xBBu8; pool_engine::SALT_LEN];
    let pool_a = keyed_epoch_subset(master_secret, &salt_a, master, epoch, k);
    let pool_b = keyed_epoch_subset(master_secret, &salt_b, master, epoch, k);
    pool_a != pool_b
}

/// Check that the pool changes across epochs (time evolution).
pub fn check_epoch_evolution(
    master_secret: &[u8],
    server_salt: &[u8; pool_engine::SALT_LEN],
    master: &MasterList,
    k: usize,
) -> bool {
    let pool_a = keyed_epoch_subset(master_secret, server_salt, master, 100, k);
    let pool_b = keyed_epoch_subset(master_secret, server_salt, master, 200, k);
    pool_a != pool_b
}

/// Check that every SNI in the active pool comes from the master list.
pub fn check_pool_is_subset(
    master_secret: &[u8],
    server_salt: &[u8; pool_engine::SALT_LEN],
    master: &MasterList,
    epoch: Epoch,
    k: usize,
) -> bool {
    let pool = keyed_epoch_subset(master_secret, server_salt, master, epoch, k);
    pool.snis()
        .all(|sni| master.entries().iter().any(|e| e.sni == sni))
}

/// Check that the pool size equals min(k, N).
pub fn check_pool_size(
    master_secret: &[u8],
    server_salt: &[u8; pool_engine::SALT_LEN],
    master: &MasterList,
    epoch: Epoch,
    k: usize,
) -> bool {
    let pool = keyed_epoch_subset(master_secret, server_salt, master, epoch, k);
    pool.len() == k.min(master.len())
}

/// Run the full checklist against a config and return a report.
pub fn run_checklist(cfg: &HydraConfig) -> ChecklistReport {
    let secret = cfg.master_secret();
    let salt = &cfg.server_salt;
    let master = &cfg.master_list;
    let k = cfg.active_k;

    let results = vec![
        CheckResult {
            name: "pool_determinism",
            passed: check_pool_determinism(secret, salt, master, 42, k),
            detail: Some("same (secret, salt, epoch) ⇒ identical subset".into()),
        },
        CheckResult {
            name: "epoch_window_superset",
            passed: check_epoch_window(secret, salt, master, 42, k),
            detail: Some("±1 window is a superset of single-epoch pool".into()),
        },
        CheckResult {
            name: "epoch_window_saturation",
            passed: check_epoch_window_saturation(secret, salt, master, k),
            detail: Some("epoch=0 does not underflow".into()),
        },
        CheckResult {
            name: "k_clamping",
            passed: check_k_clamping(secret, salt, master, 42),
            detail: Some("k > N is clamped to N".into()),
        },
        CheckResult {
            name: "salt_isolation",
            passed: check_salt_isolation(secret, master, 42, k),
            detail: Some("different salts ⇒ different pools".into()),
        },
        CheckResult {
            name: "epoch_evolution",
            passed: check_epoch_evolution(secret, salt, master, k),
            detail: Some("pool changes across epochs".into()),
        },
        CheckResult {
            name: "pool_is_subset",
            passed: check_pool_is_subset(secret, salt, master, 42, k),
            detail: Some("every pool SNI is in the master list".into()),
        },
        CheckResult {
            name: "pool_size",
            passed: check_pool_size(secret, salt, master, 42, k),
            detail: Some("pool size = min(k, N)".into()),
        },
    ];

    ChecklistReport { results }
}
