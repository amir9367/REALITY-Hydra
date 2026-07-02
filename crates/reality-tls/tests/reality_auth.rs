//! Offline behavioural tests for the REALITY auth, config, and fingerprint
//! modules. No BoringSSL toolchain required — pure-logic modules only.
//!
//! The auth tests exercise the real Xray-compatible wire format: a 32-byte
//! `session_id`, the ephemeral public key doubling as the TLS key_share, and a
//! full seal → open round-trip standing in for a live server.

use reality_tls::auth::{AuthPayload, DEFAULT_VERSION, SESSION_ID_LEN, public_from_private};
use reality_tls::fingerprint::{
    CHROME_ALPN, CHROME_CIPHER_SUITES, CHROME_GROUPS, CHROME_SIG_ALGS, Fingerprint,
};
use reality_tls::{RealityAuth, RealityConfig};

/// Deterministic server keypair for round-trip tests.
fn server_keypair() -> ([u8; 32], [u8; 32]) {
    let priv_bytes = [0x42u8; 32];
    (priv_bytes, public_from_private(&priv_bytes))
}

fn random32() -> [u8; 32] {
    let mut r = [0u8; 32];
    for (i, b) in r.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7);
    }
    r
}

#[test]
fn config_rejects_short_id_over_32_bytes() {
    let too_long = vec![0u8; 33];
    assert!(RealityConfig::new([0u8; 32], vec![too_long], Fingerprint::Chrome).is_err());
}

#[test]
fn config_accepts_empty_short_ids() {
    let cfg = RealityConfig::new([0u8; 32], vec![], Fingerprint::Chrome).unwrap();
    assert_eq!(cfg.pick_short_id(), &[] as &[u8]);
    assert_eq!(cfg.version, DEFAULT_VERSION);
}

#[test]
fn config_picks_first_short_id() {
    let cfg = RealityConfig::new(
        [0u8; 32],
        vec![vec![0xAA, 0xBB], vec![0xCC]],
        Fingerprint::Chrome,
    )
    .unwrap();
    assert_eq!(cfg.pick_short_id(), &[0xAA, 0xBB]);
}

#[test]
fn config_with_dest_builder() {
    let cfg = RealityConfig::new([0u8; 32], vec![], Fingerprint::Chrome)
        .unwrap()
        .with_dest("cdn-edge.example:443");
    assert_eq!(cfg.dest.as_deref(), Some("cdn-edge.example:443"));
}

#[test]
fn auth_session_id_is_32_bytes() {
    let (_, server_pub) = server_keypair();
    let auth = RealityAuth::seal(
        &server_pub,
        &[0x01, 0x02, 0x03, 0x04],
        DEFAULT_VERSION,
        1_700_000_000,
        &random32(),
        b"client-hello",
    )
    .unwrap();
    assert_eq!(auth.client_public.len(), 32);
    assert_eq!(auth.session_id.len(), SESSION_ID_LEN);
}

#[test]
fn auth_seal_open_round_trip_recovers_payload() {
    let (server_priv, server_pub) = server_keypair();
    let random = random32();
    let hello = b"the-exact-client-hello-bytes";
    let short_id = vec![0x10, 0x20, 0x30];

    let auth = RealityAuth::seal(
        &server_pub,
        &short_id,
        DEFAULT_VERSION,
        1_700_000_000,
        &random,
        hello,
    )
    .unwrap();

    let payload: AuthPayload = RealityAuth::open(
        &server_priv,
        &auth.client_public, // recovered from the ClientHello key_share on a real server
        &auth.session_id,
        &random,
        hello,
    )
    .unwrap();

    assert_eq!(payload.version, DEFAULT_VERSION);
    assert_eq!(payload.timestamp, 1_700_000_000);
    assert_eq!(&payload.short_id[..3], &short_id[..]);
}

#[test]
fn auth_open_rejects_wrong_server_key() {
    let (_, server_pub) = server_keypair();
    let random = random32();
    let auth = RealityAuth::seal(&server_pub, &[0x01], DEFAULT_VERSION, 1, &random, b"h").unwrap();
    assert!(
        RealityAuth::open(
            &[0xFFu8; 32],
            &auth.client_public,
            &auth.session_id,
            &random,
            b"h"
        )
        .is_err()
    );
}

#[test]
fn auth_open_rejects_tampered_client_hello() {
    let (server_priv, server_pub) = server_keypair();
    let random = random32();
    let auth =
        RealityAuth::seal(&server_pub, &[], DEFAULT_VERSION, 1, &random, b"original").unwrap();
    assert!(
        RealityAuth::open(
            &server_priv,
            &auth.client_public,
            &auth.session_id,
            &random,
            b"tampered!"
        )
        .is_err()
    );
}

#[test]
fn auth_fresh_keypairs_are_unique() {
    let (_, server_pub) = server_keypair();
    let random = random32();
    let auths: Vec<_> = (0..10)
        .map(|_| RealityAuth::seal(&server_pub, &[], DEFAULT_VERSION, 0, &random, b"h").unwrap())
        .collect();
    let mut keys: Vec<_> = auths.iter().map(|a| a.client_public).collect();
    keys.sort();
    keys.dedup();
    assert_eq!(keys.len(), 10);
}

#[test]
fn chrome_cipher_suites_start_with_tls13() {
    assert_eq!(CHROME_CIPHER_SUITES[0], 0x1301);
    assert_eq!(CHROME_CIPHER_SUITES[1], 0x1302);
    assert_eq!(CHROME_CIPHER_SUITES[2], 0x1303);
}

#[test]
fn chrome_groups_contain_x25519() {
    assert!(CHROME_GROUPS.contains(&0x001d));
}

#[test]
fn chrome_sig_algs_contain_ecdsa_p256() {
    assert!(CHROME_SIG_ALGS.contains(&0x0403));
}

#[test]
fn chrome_alpn_starts_with_h2() {
    assert_eq!(CHROME_ALPN[0], b"h2");
}

#[test]
fn fingerprint_target_is_chrome() {
    assert_eq!(Fingerprint::default().target_browser(), "Chrome 120+");
}

#[test]
fn full_auth_round_trip_via_config() {
    let (server_priv, server_pub) = server_keypair();
    let cfg = RealityConfig::new(
        server_pub,
        vec![vec![0x10, 0x20, 0x30]],
        Fingerprint::Chrome,
    )
    .unwrap();
    let random = random32();
    let hello = b"client-hello";

    let auth = RealityAuth::seal(
        &cfg.server_public_key,
        cfg.pick_short_id(),
        cfg.version,
        1_700_000_000,
        &random,
        hello,
    )
    .unwrap();

    let payload = RealityAuth::open(
        &server_priv,
        &auth.client_public,
        &auth.session_id,
        &random,
        hello,
    )
    .unwrap();
    assert_eq!(&payload.short_id[..3], &[0x10, 0x20, 0x30]);
}
