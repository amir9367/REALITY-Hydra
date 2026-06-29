//! Offline behavioural tests for the health checker, driven by the mock seams.
//! No network and no `live-tls` feature required.

use std::time::Duration;

use dns_warmer::MockResolver;
use health_checker::{
    CoherenceAllowlist, Health, HealthChecker, LatencyBand, MockInspector, TlsObservation,
    healthy_snis, prune, sni_matches_any,
};
use pool_engine::{MasterList, PoolEntry};

const DEST: &str = "cdn-edge.example:443";

fn ip(s: &str) -> std::net::IpAddr {
    s.parse().expect("valid IP literal")
}

/// A healthy observation: TLS 1.3, h2, a matching wildcard SAN, fast.
fn good_obs(san: &str) -> TlsObservation {
    TlsObservation {
        is_tls13: true,
        alpn: Some(b"h2".to_vec()),
        leaf_san_dns_names: vec![san.to_string()],
        rtt: Duration::from_millis(40),
    }
}

// ---- pure SAN matching (RFC 6125 dNSName rules) ----------------------------

#[test]
fn san_exact_and_case_insensitive() {
    assert!(sni_matches_any("a.example.com", &["a.example.com".into()]));
    assert!(sni_matches_any("A.Example.CoM", &["a.example.com".into()]));
    assert!(!sni_matches_any("b.example.com", &["a.example.com".into()]));
}

#[test]
fn san_wildcard_matches_one_label_only() {
    let san = vec!["*.example.com".to_string()];
    assert!(sni_matches_any("a.example.com", &san)); // one label: ok
    assert!(!sni_matches_any("example.com", &san)); // no label: no
    assert!(!sni_matches_any("a.b.example.com", &san)); // two labels: no
}

#[test]
fn san_wildcard_must_be_leftmost_and_not_too_broad() {
    // A bare `*.com` is too broad to honor.
    assert!(!sni_matches_any("anything.com", &["*.com".into()]));
    // Trailing-dot forms normalize equal.
    assert!(sni_matches_any("a.example.com.", &["*.example.com".into()]));
}

#[test]
fn san_any_of_several_matches() {
    let sans = vec!["other.example".into(), "*.cdn.example".into()];
    assert!(sni_matches_any("img.cdn.example", &sans));
}

// ---- coherence allowlist ----------------------------------------------------

#[test]
fn coherence_membership_v4_and_v6() {
    let allow = CoherenceAllowlist::parse(["104.16.0.0/13", "2606:4700::/32"]).unwrap();
    assert!(allow.contains(ip("104.16.0.5")));
    assert!(allow.contains(ip("2606:4700::1")));
    assert!(!allow.contains(ip("8.8.8.8")));
}

#[test]
fn coherence_requires_all_addrs_in_range_and_nonempty() {
    let allow = CoherenceAllowlist::parse(["104.16.0.0/13"]).unwrap();
    assert!(allow.contains_all(&[ip("104.16.0.1"), ip("104.16.9.9")]));
    // One stray out-of-range address fails the whole set (Trap 3).
    assert!(!allow.contains_all(&[ip("104.16.0.1"), ip("8.8.8.8")]));
    // An empty answer is not coherent.
    assert!(!allow.contains_all(&[]));
}

#[test]
fn coherence_rejects_empty_and_bad_config() {
    assert!(CoherenceAllowlist::parse(Vec::<String>::new()).is_err());
    assert!(CoherenceAllowlist::parse(["not-a-cidr"]).is_err());
}

// ---- latency band -----------------------------------------------------------

#[test]
fn latency_band_two_sided_and_validated() {
    let band = LatencyBand::new(Duration::from_millis(10), Duration::from_millis(500)).unwrap();
    assert!(!band.contains(Duration::from_millis(5))); // too fast
    assert!(band.contains(Duration::from_millis(250)));
    assert!(!band.contains(Duration::from_millis(900))); // too slow
    // Inverted band is rejected.
    assert!(LatencyBand::new(Duration::from_millis(500), Duration::from_millis(10)).is_err());
}

// ---- end-to-end verdicts via the checker -----------------------------------

fn checker(
    resolver: MockResolver,
    inspector: MockInspector,
) -> HealthChecker<MockResolver, MockInspector> {
    let allow = CoherenceAllowlist::parse(["104.16.0.0/13"]).unwrap();
    let band = LatencyBand::new(Duration::ZERO, Duration::from_millis(500)).unwrap();
    HealthChecker::new(resolver, inspector, allow, band, DEST)
}

#[tokio::test]
async fn healthy_entry_passes_every_axis() {
    let resolver = MockResolver::new().with(
        "a.cdn.example",
        &[ip("104.16.0.10")],
        Duration::from_secs(300),
    );
    let inspector = MockInspector::new().with("a.cdn.example", good_obs("*.cdn.example"));
    let h = checker(resolver, inspector)
        .check(&PoolEntry::new("a.cdn.example", 1.0))
        .await
        .unwrap();
    assert_eq!(
        h,
        Health {
            sni: "a.cdn.example".to_string(),
            coherent: true,
            san_match: true,
            alpn_h2: true,
            tls13: true,
            latency_ok: true,
        }
    );
    assert!(h.is_healthy());
}

#[tokio::test]
async fn out_of_range_dns_fails_coherence_only() {
    let resolver =
        MockResolver::new().with("a.cdn.example", &[ip("8.8.8.8")], Duration::from_secs(300));
    let inspector = MockInspector::new().with("a.cdn.example", good_obs("*.cdn.example"));
    let h = checker(resolver, inspector)
        .check(&PoolEntry::new("a.cdn.example", 1.0))
        .await
        .unwrap();
    assert!(!h.coherent);
    assert!(h.san_match && h.alpn_h2 && h.tls13 && h.latency_ok);
    assert!(!h.is_healthy());
}

#[tokio::test]
async fn cert_san_mismatch_fails() {
    let resolver = MockResolver::new().with(
        "a.cdn.example",
        &[ip("104.16.0.10")],
        Duration::from_secs(300),
    );
    // Cert is for a different domain entirely.
    let inspector = MockInspector::new().with("a.cdn.example", good_obs("*.other.example"));
    let h = checker(resolver, inspector)
        .check(&PoolEntry::new("a.cdn.example", 1.0))
        .await
        .unwrap();
    assert!(!h.san_match);
    assert!(!h.is_healthy());
}

#[tokio::test]
async fn non_h2_or_non_tls13_or_slow_each_fail() {
    let resolver = MockResolver::new().with(
        "a.cdn.example",
        &[ip("104.16.0.10")],
        Duration::from_secs(300),
    );
    let bad = TlsObservation {
        is_tls13: false,                  // TLS 1.2 — fails tls13
        alpn: Some(b"http/1.1".to_vec()), // fails h2
        leaf_san_dns_names: vec!["*.cdn.example".to_string()],
        rtt: Duration::from_millis(900), // outside [0,500] — fails latency
    };
    let inspector = MockInspector::new().with("a.cdn.example", bad);
    let h = checker(resolver, inspector)
        .check(&PoolEntry::new("a.cdn.example", 1.0))
        .await
        .unwrap();
    assert!(h.coherent && h.san_match);
    assert!(!h.tls13 && !h.alpn_h2 && !h.latency_ok);
    assert!(!h.is_healthy());
}

#[tokio::test]
async fn resolver_failure_is_an_error_not_a_verdict() {
    // SNI absent from the resolver table -> the check can't run.
    let resolver = MockResolver::new();
    let inspector = MockInspector::new().with("a.cdn.example", good_obs("*.cdn.example"));
    let res = checker(resolver, inspector)
        .check(&PoolEntry::new("a.cdn.example", 1.0))
        .await;
    assert!(matches!(res, Err(health_checker::HealthError::Resolve { .. })));
}

#[tokio::test]
async fn check_all_then_prune_keeps_only_healthy_with_weights() {
    let master = MasterList::new(vec![
        PoolEntry::new("good.cdn.example", 3.0),
        PoolEntry::new("badip.cdn.example", 2.0),
        PoolEntry::new("badcert.cdn.example", 1.0),
    ])
    .unwrap();

    let resolver = MockResolver::new()
        .with(
            "good.cdn.example",
            &[ip("104.16.0.1")],
            Duration::from_secs(300),
        )
        .with(
            "badip.cdn.example",
            &[ip("8.8.8.8")],
            Duration::from_secs(300),
        ) // out of range
        .with(
            "badcert.cdn.example",
            &[ip("104.16.0.2")],
            Duration::from_secs(300),
        );

    let inspector = MockInspector::new()
        .with("good.cdn.example", good_obs("*.cdn.example"))
        .with("badip.cdn.example", good_obs("*.cdn.example"))
        .with("badcert.cdn.example", good_obs("*.elsewhere.example")); // SAN mismatch

    let reports = checker(resolver, inspector)
        .check_all(&master)
        .await
        .unwrap();

    assert_eq!(healthy_snis(&reports), vec!["good.cdn.example".to_string()]);

    let pruned = prune(&master, &reports);
    assert_eq!(pruned.len(), 1);
    assert!(pruned.contains("good.cdn.example"));
    // Surviving entry keeps its original weight.
    assert_eq!(pruned.entries()[0].weight, 3.0);
}
