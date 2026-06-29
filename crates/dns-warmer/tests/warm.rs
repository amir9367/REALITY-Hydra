//! Offline behavioural tests for the TTL-aware warmer, driven by `MockResolver`.
//! No network and no `live-dns` feature required.

use std::net::IpAddr;
use std::time::Duration;

use dns_warmer::{DnsWarmer, MockResolver, ResolveError, WarmerConfig};

fn ip(s: &str) -> IpAddr {
    s.parse().expect("valid IP literal")
}

/// Default config so a 60 s record TTL passes through unclamped (30 s ≤ 60 s ≤ 1 h).
fn warmer_60s() -> DnsWarmer<MockResolver> {
    let resolver = MockResolver::new().with(
        "a.cdn.example",
        &[ip("203.0.113.10")],
        Duration::from_secs(60),
    );
    DnsWarmer::new(resolver)
}

#[tokio::test]
async fn cold_resolve_populates_cache() {
    let warmer = warmer_60s();
    assert!(!warmer.is_warm("a.cdn.example", 0));

    let resolved = warmer.warm("a.cdn.example", 0).await.unwrap();
    assert_eq!(resolved.addrs, vec![ip("203.0.113.10")]);
    assert_eq!(resolved.ttl, Duration::from_secs(60));
    assert!(warmer.is_warm("a.cdn.example", 0));
}

#[tokio::test]
async fn hit_within_ttl_then_reresolve_after_expiry() {
    let warmer = warmer_60s();

    warmer.warm("a.cdn.example", 0).await.unwrap();
    // 59 s in: still fresh (TTL 60 s → expires at 60_000 ms).
    assert!(warmer.is_warm("a.cdn.example", 59_000));
    assert!(warmer.peek("a.cdn.example", 59_000).is_some());

    // At 60 s exactly the entry is stale (expiry is exclusive).
    assert!(!warmer.is_warm("a.cdn.example", 60_000));
    assert!(warmer.peek("a.cdn.example", 60_000).is_none());

    // warm() at/after expiry re-resolves and re-arms the cache.
    warmer.warm("a.cdn.example", 60_000).await.unwrap();
    assert!(warmer.is_warm("a.cdn.example", 119_000));
}

#[tokio::test]
async fn unknown_host_is_backend_error() {
    let warmer = warmer_60s();
    let err = warmer.warm("not.in.table", 0).await.unwrap_err();
    assert!(matches!(err, ResolveError::Backend { .. }));
    assert!(!warmer.is_warm("not.in.table", 0));
}

#[tokio::test]
async fn tiny_ttl_is_clamped_up_to_min() {
    // Record advertises 1 s; default min_ttl is 30 s, so the entry must survive
    // well past 1 s — otherwise we'd re-resolve almost every connection (anomaly).
    let resolver = MockResolver::new().with(
        "b.cdn.example",
        &[ip("203.0.113.20")],
        Duration::from_secs(1),
    );
    let warmer = DnsWarmer::new(resolver);

    warmer.warm("b.cdn.example", 0).await.unwrap();
    assert!(warmer.is_warm("b.cdn.example", 29_000)); // < 30 s floor
    assert!(!warmer.is_warm("b.cdn.example", 30_000)); // at the floor it lapses
}

#[tokio::test]
async fn huge_ttl_is_clamped_down_to_max() {
    // Record advertises 1 day; default max_ttl is 1 h, so it must lapse by 1 h.
    let resolver = MockResolver::new().with(
        "c.cdn.example",
        &[ip("203.0.113.30")],
        Duration::from_secs(86_400),
    );
    let warmer = DnsWarmer::new(resolver);

    warmer.warm("c.cdn.example", 0).await.unwrap();
    assert!(warmer.is_warm("c.cdn.example", 3_599_000)); // < 1 h
    assert!(!warmer.is_warm("c.cdn.example", 3_600_000)); // at 1 h it lapses
}

#[tokio::test]
async fn custom_config_bounds_are_honored() {
    let config = WarmerConfig {
        min_ttl: Duration::from_secs(10),
        max_ttl: Duration::from_secs(20),
    };
    let resolver = MockResolver::new().with(
        "d.cdn.example",
        &[ip("203.0.113.40")],
        Duration::from_secs(300),
    );
    let warmer = DnsWarmer::with_config(resolver, config);

    warmer.warm("d.cdn.example", 0).await.unwrap();
    assert!(warmer.is_warm("d.cdn.example", 19_000)); // capped to 20 s
    assert!(!warmer.is_warm("d.cdn.example", 20_000));
}

#[tokio::test]
async fn evict_expired_drops_only_stale_entries() {
    let resolver = MockResolver::new()
        .with(
            "short.example",
            &[ip("203.0.113.50")],
            Duration::from_secs(60),
        )
        .with(
            "long.example",
            &[ip("203.0.113.51")],
            Duration::from_secs(3000),
        );
    let warmer = DnsWarmer::new(resolver);

    warmer.warm("short.example", 0).await.unwrap();
    warmer.warm("long.example", 0).await.unwrap();

    // At 90 s the 60 s entry is stale, the 3000 s one is not.
    warmer.evict_expired(90_000);
    assert!(!warmer.is_warm("short.example", 90_000));
    assert!(warmer.is_warm("long.example", 90_000));
}

#[tokio::test]
async fn multiple_addresses_are_preserved_in_order() {
    let addrs = [ip("203.0.113.1"), ip("2001:db8::1"), ip("203.0.113.2")];
    let resolver = MockResolver::new().with("multi.example", &addrs, Duration::from_secs(120));
    let warmer = DnsWarmer::new(resolver);

    let resolved = warmer.warm("multi.example", 0).await.unwrap();
    assert_eq!(resolved.addrs, addrs.to_vec());
}
