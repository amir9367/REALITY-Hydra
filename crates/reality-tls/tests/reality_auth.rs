//! Offline behavioural tests for the REALITY auth and config modules.
//! No BoringSSL toolchain required — tests the pure-logic modules only.

use reality_tls::fingerprint::Fingerprint;
use reality_tls::fingerprint::{CHROME_ALPN, CHROME_CIPHER_SUITES, CHROME_GROUPS, CHROME_SIG_ALGS};
use reality_tls::{RealityAuth, RealityConfig};

#[test]
fn config_rejects_short_id_over_32_bytes() {
    let too_long = vec![0u8; 33];
    assert!(RealityConfig::new([0u8; 32], vec![too_long], Fingerprint::Chrome).is_err());
}

#[test]
fn config_accepts_empty_short_ids() {
    let cfg = RealityConfig::new([0u8; 32], vec![], Fingerprint::Chrome).unwrap();
    assert_eq!(cfg.pick_short_id(), &[] as &[u8]);
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
fn auth_builds_valid_session_id() {
    let server_key = [0x11u8; 32];
    let short_id = vec![0x01, 0x02, 0x03, 0x04];
    let auth = RealityAuth::build(&server_key, &short_id, 1_700_000_000).unwrap();

    assert_eq!(auth.client_public.len(), 32);
    // 32 (pub) + 8 (ts) + 4 (sid) + 16 (tag) = 60
    assert_eq!(auth.session_id.len(), 60);
}

#[test]
fn auth_fresh_keypairs_are_unique() {
    let server_key = [0x22u8; 32];
    let auths: Vec<_> = (0..10)
        .map(|_| RealityAuth::build(&server_key, &[], 0).unwrap())
        .collect();
    let mut keys: Vec<_> = auths.iter().map(|a| a.client_public).collect();
    keys.sort();
    keys.dedup();
    assert_eq!(keys.len(), 10);
}

#[test]
fn auth_ciphertext_differs_from_plaintext() {
    let server_key = [0x33u8; 32];
    let auth = RealityAuth::build(&server_key, &[0xAA], 12345).unwrap();
    assert_ne!(&auth.session_id[..32], &auth.client_public[..]);
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
fn full_auth_round_trip() {
    let cfg = RealityConfig::new(
        [0xDE; 32],
        vec![vec![0x10, 0x20, 0x30]],
        Fingerprint::Chrome,
    )
    .unwrap();
    let auth =
        RealityAuth::build(&cfg.server_public_key, cfg.pick_short_id(), 1_700_000_000).unwrap();
    // 32 + 8 + 3 + 16 = 59
    assert_eq!(auth.session_id.len(), 59);
    assert!(auth.client_public.iter().any(|&b| b != 0));
}
