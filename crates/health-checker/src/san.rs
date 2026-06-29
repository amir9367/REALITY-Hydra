//! Certificate SAN matching — part of axis (b) (REALITY.md P1).
//!
//! A prober that connects to the `dest` (a CDN edge) with `SNI=X` must get back a
//! leaf certificate whose Subject Alternative Names actually cover `X`; otherwise
//! the genuine-site fallback produces a cert mismatch — an instant tell. So the
//! checker reads the leaf's dNSName SANs and asks: *does any of them match this
//! SNI?* That match — including wildcard rules — is the pure logic here.
//!
//! We implement the dNSName rules from RFC 6125 / RFC 9525:
//! * matching is case-insensitive on ASCII;
//! * a wildcard is allowed only in the **leftmost** label (`*.example.com`);
//! * `*` matches exactly **one** label, and never an empty label;
//! * so `*.example.com` matches `a.example.com` but **not** `example.com` and
//!   **not** `a.b.example.com`.

/// Whether `sni` is covered by any of the certificate's dNSName SANs.
pub fn sni_matches_any(sni: &str, san_dns_names: &[String]) -> bool {
    san_dns_names.iter().any(|san| dns_name_matches(sni, san))
}

/// Whether a single SAN dNSName `pattern` matches `sni` (with wildcard rules).
fn dns_name_matches(sni: &str, pattern: &str) -> bool {
    // Normalize a trailing root dot and case; DNS names are case-insensitive.
    let sni = sni.trim_end_matches('.').to_ascii_lowercase();
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();

    if sni.is_empty() || pattern.is_empty() {
        return false;
    }

    // Exact (non-wildcard) match is the common case.
    if !pattern.starts_with("*.") {
        return sni == pattern;
    }

    // Wildcard: `*.rest` matches `<one-label>.rest`.
    let rest = &pattern[2..];
    // The wildcard must not be the only thing (`*.` alone) and `rest` must itself
    // be a real multi-label suffix — a bare `*.com` is too broad to honor.
    if rest.is_empty() || !rest.contains('.') {
        return false;
    }

    // Split off the SNI's first label; the remainder must equal `rest`, and the
    // first label must be exactly one non-empty label (no embedded dot).
    match sni.split_once('.') {
        Some((first, suffix)) => !first.is_empty() && suffix == rest,
        None => false,
    }
}
