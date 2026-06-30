//! Distribution validation — χ² test for weighted selection fairness.
//!
//! A real CDN edge sees a popularity-shaped SNI distribution, not a uniform one
//! (REALITY.md §7 P3/P4). If the sampler produces a flat distribution despite
//! Tranco-shaped weights, the *pattern itself* becomes a fingerprint. This
//! module provides the χ² goodness-of-fit test to verify that long-run
//! selection frequency matches the configured weights.
//!
//! ## Usage
//!
//! ```
//! use hardening::{chi_square, distribution_matches_weights, SampleEntry};
//! use std::collections::HashMap;
//!
//! // Configure 3 SNIs with weights 3:2:1.
//! let weights = vec![
//!     SampleEntry { label: "a".into(), weight: 3.0 },
//!     SampleEntry { label: "b".into(), weight: 2.0 },
//!     SampleEntry { label: "c".into(), weight: 1.0 },
//! ];
//!
//! // Simulate 6000 selections split exactly 300:200:100.
//! let mut counts = HashMap::new();
//! counts.insert("a".into(), 300);
//! counts.insert("b".into(), 200);
//! counts.insert("c".into(), 100);
//!
//! let (chi_sq, dof) = chi_square(&counts, &weights);
//! assert!(distribution_matches_weights(&counts, &weights));
//! ```

use std::collections::HashMap;

/// One entry in a distribution specification: a label and its expected weight.
#[derive(Clone, Debug)]
pub struct SampleEntry {
    pub label: String,
    pub weight: f64,
}

/// Compute the χ² (chi-squared) statistic for observed counts vs expected
/// frequencies derived from the weights.
///
/// `counts` maps each label to its observed count. `entries` defines the
/// labels and their weights. The expected count for each label is
/// `total_observations * (weight_i / total_weight)`.
///
/// Returns `(chi_sq, degrees_of_freedom)`. A χ² value much larger than the
/// degrees of freedom indicates the observed distribution does NOT match the
/// expected distribution.
pub fn chi_square(counts: &HashMap<String, u64>, entries: &[SampleEntry]) -> (f64, usize) {
    let total_weight: f64 = entries.iter().map(|e| e.weight).sum();
    let total_obs: u64 = entries
        .iter()
        .map(|e| counts.get(&e.label).copied().unwrap_or(0))
        .sum();

    if total_obs == 0 || total_weight <= 0.0 {
        return (0.0, 0);
    }

    let total_obs_f = total_obs as f64;
    let mut chi_sq = 0.0;

    for entry in entries {
        let observed = counts.get(&entry.label).copied().unwrap_or(0) as f64;
        let expected = total_obs_f * (entry.weight / total_weight);
        if expected > 0.0 {
            chi_sq += (observed - expected).powi(2) / expected;
        }
    }

    let dof = entries.len().saturating_sub(1);
    (chi_sq, dof)
}

/// Check whether the observed distribution matches the expected weights within
/// a reasonable χ² threshold.
///
/// For a "good fit" at the 0.01 significance level, the χ² statistic should be
/// below the critical value for the given degrees of freedom. We use a
/// pre-computed table for common dof values (1–20) and fall back to a rough
/// approximation for larger dof.
///
/// Returns `true` if the distribution is a plausible match for the weights.
pub fn distribution_matches_weights(
    counts: &HashMap<String, u64>,
    entries: &[SampleEntry],
) -> bool {
    let (chi_sq, dof) = chi_square(counts, entries);
    if dof == 0 {
        return true; // single entry — no variance to test.
    }
    chi_sq <= critical_value_001(dof)
}

/// χ² critical values at significance level α = 0.01 for dof 1–20.
///
/// Source: standard χ² distribution tables. Values above 20 are approximated
/// as `dof + 4 * sqrt(2 * dof)` (Wilson-Hilferty approximation), which is
/// conservative for large dof.
fn critical_value_001(dof: usize) -> f64 {
    match dof {
        1 => 6.635,
        2 => 9.210,
        3 => 11.345,
        4 => 13.277,
        5 => 15.086,
        6 => 16.812,
        7 => 18.475,
        8 => 20.090,
        9 => 21.666,
        10 => 23.209,
        11 => 24.725,
        12 => 26.217,
        13 => 27.688,
        14 => 29.141,
        15 => 30.578,
        16 => 32.000,
        17 => 33.409,
        18 => 34.805,
        19 => 36.191,
        20 => 37.566,
        _ => (dof as f64) + 4.0 * ((2.0 * dof as f64).sqrt()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perfect_distribution_passes_chi2() {
        // 3:2:1 weight, 600 observations split exactly 300:200:100.
        let entries = vec![
            SampleEntry {
                label: "a".into(),
                weight: 3.0,
            },
            SampleEntry {
                label: "b".into(),
                weight: 2.0,
            },
            SampleEntry {
                label: "c".into(),
                weight: 1.0,
            },
        ];
        let mut counts = HashMap::new();
        counts.insert("a".into(), 300);
        counts.insert("b".into(), 200);
        counts.insert("c".into(), 100);

        let (chi_sq, dof) = chi_square(&counts, &entries);
        assert!((chi_sq - 0.0).abs() < 0.001);
        assert_eq!(dof, 2);
        assert!(distribution_matches_weights(&counts, &entries));
    }

    #[test]
    fn skewed_distribution_fails_chi2() {
        // 3:2:1 weight but observed is 100:100:400 (heavily skewed toward "c").
        let entries = vec![
            SampleEntry {
                label: "a".into(),
                weight: 3.0,
            },
            SampleEntry {
                label: "b".into(),
                weight: 2.0,
            },
            SampleEntry {
                label: "c".into(),
                weight: 1.0,
            },
        ];
        let mut counts = HashMap::new();
        counts.insert("a".into(), 100);
        counts.insert("b".into(), 100);
        counts.insert("c".into(), 400);

        let (chi_sq, _) = chi_square(&counts, &entries);
        // The χ² should be very large for this mismatch.
        assert!(chi_sq > 50.0);
        assert!(!distribution_matches_weights(&counts, &entries));
    }

    #[test]
    fn single_entry_has_zero_dof() {
        let entries = vec![SampleEntry {
            label: "only".into(),
            weight: 1.0,
        }];
        let mut counts = HashMap::new();
        counts.insert("only".into(), 1000);

        let (chi_sq, dof) = chi_square(&counts, &entries);
        assert_eq!(chi_sq, 0.0);
        assert_eq!(dof, 0);
        assert!(distribution_matches_weights(&counts, &entries));
    }

    #[test]
    fn empty_counts_gives_zero_chi2() {
        let entries = vec![
            SampleEntry {
                label: "a".into(),
                weight: 1.0,
            },
            SampleEntry {
                label: "b".into(),
                weight: 1.0,
            },
        ];
        let counts = HashMap::new();
        let (chi_sq, dof) = chi_square(&counts, &entries);
        assert_eq!(chi_sq, 0.0);
        assert_eq!(dof, 0); // no observations → no degrees of freedom
    }
}
