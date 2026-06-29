//! Core data types: one pool entry, the validated master list, and the
//! per-epoch active pool.

use serde::{Deserialize, Serialize};

use crate::error::PoolError;

/// One candidate camouflage identity.
///
/// `sni` must be a real domain genuinely served by the CDN your REALITY server
/// is fronted by (see REALITY.md §4 — the three traps). `weight` shapes how
/// often the client picks it, ideally proportional to real-world popularity
/// (e.g. a Tranco rank) so the SNI distribution looks like a real CDN edge.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PoolEntry {
    pub sni: String,
    pub weight: f64,
}

impl PoolEntry {
    pub fn new(sni: impl Into<String>, weight: f64) -> Self {
        Self {
            sni: sni.into(),
            weight,
        }
    }
}

/// The full, curated set of candidate SNIs, validated and in canonical order.
///
/// Entries are sorted by SNI at construction so that the client and server — who
/// ship the *same* list — always iterate in the identical order. The keyed
/// sampler depends on this: it draws one RNG value per entry in order, so a
/// different order would yield a different subset for the same epoch.
#[derive(Clone, Debug, PartialEq)]
pub struct MasterList {
    entries: Vec<PoolEntry>,
}

impl MasterList {
    /// Validate and canonicalize a set of entries.
    ///
    /// Rejects an empty list, empty SNIs, non-finite or non-positive weights,
    /// and duplicate SNIs.
    pub fn new(mut entries: Vec<PoolEntry>) -> Result<Self, PoolError> {
        if entries.is_empty() {
            return Err(PoolError::EmptyMasterList);
        }
        for (index, e) in entries.iter().enumerate() {
            if e.sni.is_empty() {
                return Err(PoolError::EmptySni { index });
            }
            if !e.weight.is_finite() || e.weight <= 0.0 {
                return Err(PoolError::InvalidWeight {
                    index,
                    weight: e.weight,
                });
            }
        }

        // Canonical order so both sides iterate identically.
        entries.sort_by(|a, b| a.sni.cmp(&b.sni));

        // Duplicates are adjacent after sorting.
        for pair in entries.windows(2) {
            if pair[0].sni == pair[1].sni {
                return Err(PoolError::DuplicateSni {
                    sni: pair[0].sni.clone(),
                });
            }
        }

        Ok(Self { entries })
    }

    /// The entries, sorted by SNI.
    pub fn entries(&self) -> &[PoolEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Always `false` (a `MasterList` cannot be empty), but provided so callers
    /// and lints can pair it with [`MasterList::len`].
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The subset of the master list that is "live" for a single epoch.
///
/// Construction is crate-internal: an `ActivePool` only ever comes out of the
/// keyed sampler (or the server-side epoch-window union), guaranteeing every
/// entry really belongs to the master list. Entries are sorted by SNI so two
/// independently-derived pools compare equal with `==`.
#[derive(Clone, Debug, PartialEq)]
pub struct ActivePool {
    entries: Vec<PoolEntry>,
}

impl ActivePool {
    pub(crate) fn from_unsorted(mut entries: Vec<PoolEntry>) -> Self {
        entries.sort_by(|a, b| a.sni.cmp(&b.sni));
        Self { entries }
    }

    /// Build a pool from an already-vetted subset of master-list entries.
    ///
    /// Unlike the keyed sampler, this does not derive the set — the caller is
    /// responsible for the entries being a real subset of the master list. It is
    /// used by the health checker to emit a *pruned* pool (the entries that
    /// passed validation), keeping their original weights. Entries are sorted by
    /// SNI so the result compares equal regardless of input order.
    pub fn from_entries(entries: Vec<PoolEntry>) -> Self {
        Self::from_unsorted(entries)
    }

    pub fn entries(&self) -> &[PoolEntry] {
        &self.entries
    }

    /// Iterate the SNIs (e.g. to publish as a server's `serverNames`).
    pub fn snis(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|e| e.sni.as_str())
    }

    pub fn contains(&self, sni: &str) -> bool {
        self.entries.iter().any(|e| e.sni == sni)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
