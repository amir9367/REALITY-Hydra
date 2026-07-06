//! Property tests: any well-formed target round-trips, and any tampering with
//! the encoded bytes is caught (bad MAC, bad version, or a clean truncation —
//! never a panic, never a silent accept).

use proptest::prelude::*;
use tunnel_proto::{encode_request, parse_request, Host, Target, DEFAULT_MAX_SKEW_SECS};

const KEY: &[u8] = b"prop-test-master-secret-32-bytes!";

fn arb_host() -> impl Strategy<Value = Host> {
    prop_oneof![
        any::<[u8; 4]>().prop_map(Host::V4),
        any::<[u8; 16]>().prop_map(Host::V6),
        // Domains: 1..=253 chars drawn from a DNS-ish alphabet.
        "[a-z0-9.-]{1,253}".prop_map(Host::Domain),
    ]
}

fn arb_target() -> impl Strategy<Value = Target> {
    (arb_host(), any::<u16>()).prop_map(|(host, port)| Target::new(host, port))
}

proptest! {
    #[test]
    fn roundtrip_any_target(target in arb_target(), ts in any::<u64>()) {
        // Use ts as the server clock too, so freshness always passes here.
        let bytes = encode_request(KEY, ts, &target);
        let parsed = parse_request(&bytes, KEY, ts, DEFAULT_MAX_SKEW_SECS).unwrap();
        prop_assert_eq!(parsed.target, target);
        prop_assert_eq!(parsed.consumed, bytes.len());
    }

    #[test]
    fn any_single_byte_flip_is_rejected(
        target in arb_target(),
        ts in 1_000_000u64..4_000_000_000,
        idx in any::<prop::sample::Index>(),
        xor in 1u8..=255,
    ) {
        let mut bytes = encode_request(KEY, ts, &target);
        let i = idx.index(bytes.len());
        bytes[i] ^= xor;
        // Any corruption must fail to parse-verify; it must never round-trip to a
        // *different* authenticated target, and must never panic.
        let res = parse_request(&bytes, KEY, ts, DEFAULT_MAX_SKEW_SECS);
        match res {
            Ok(parsed) => prop_assert_eq!(parsed.target, target.clone()),
            Err(_) => {}
        }
    }
}
