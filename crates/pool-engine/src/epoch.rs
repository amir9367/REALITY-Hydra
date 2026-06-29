//! Epoch math.
//!
//! The keyed pool is constant within an *epoch*, defined as
//! `floor(unix_time / EPOCH_LEN)`. This is Hydra's own clock and is distinct
//! from REALITY's `maxTimeDiff` anti-replay window (REALITY.md §5.4 / P6).
//!
//! Core functions take an explicit timestamp so they stay pure and testable;
//! [`current_epoch`] is the only one that reads the wall clock.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A monotonically increasing epoch counter.
pub type Epoch = u64;

/// The epoch a given UNIX timestamp (seconds) falls into.
pub fn epoch_at(unix_secs: u64, epoch_len: Duration) -> Epoch {
    // `max(1)` guards against a zero-length epoch (division by zero).
    let len = epoch_len.as_secs().max(1);
    unix_secs / len
}

/// The current epoch, read from the system clock.
///
/// Pure callers (and all tests) should prefer [`epoch_at`] with an explicit
/// timestamp.
pub fn current_epoch(epoch_len: Duration) -> Epoch {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    epoch_at(now, epoch_len)
}

/// The `±1` epoch acceptance window: `[epoch-1, epoch, epoch+1]`.
///
/// A server unions the active pools across this window into its `serverNames`
/// so a client whose clock is up to one epoch off — e.g. right at a boundary —
/// still presents an accepted SNI. At `epoch == 0` the lower bound saturates to
/// `0`; the caller is expected to deduplicate (the engine does).
pub fn epoch_window(epoch: Epoch) -> [Epoch; 3] {
    [epoch.saturating_sub(1), epoch, epoch.saturating_add(1)]
}
