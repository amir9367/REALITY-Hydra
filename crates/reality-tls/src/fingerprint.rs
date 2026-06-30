//! Chrome TLS fingerprint profile for BoringSSL impersonation.
//!
//! A real Chrome browser has a specific TLS ClientHello shape — cipher suite
//! order, extension order, key-share groups, signature algorithms, ALPN — that
//! produces a unique JA3/JA4 hash. The censor's tier-C classifier compares the
//! ClientHello against known browser fingerprints, so a mismatch undoes all the
//! SNI camouflage work (REALITY.md §7 P7).
//!
//! This module holds the **data** (the parameter lists); the actual BoringSSL
//! configuration lives in [`crate::client`] and is feature-gated behind
//! `boring-impersonate` because it requires a native TLS toolchain.

/// Supported cipher suites in Chrome 120+ order.
///
/// TLS 1.3 suites come first, followed by TLS 1.2 ECDHE suites for CDN
/// compatibility. REALITY only works against TLS 1.3 + h2 targets (§7 P8).
pub const CHROME_CIPHER_SUITES: &[u16] = &[
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
    0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
];

/// Supported groups (key-share groups) in Chrome 120+ order.
///
/// BoringSSL prepends GREASE automatically when the cipher list contains a
/// GREASE value; we do not include it here.
pub const CHROME_GROUPS: &[u16] = &[
    0x001d, // x25519
    0x0017, // secp256r1 (P-256)
    0x0018, // secp384r1 (P-384)
    0x0019, // secp521r1 (P-521)
];

/// Signature algorithms in Chrome 120+ order.
pub const CHROME_SIG_ALGS: &[u16] = &[
    0x0403, // ecdsa_secp256r1_sha256
    0x0804, // rsa_pss_rsae_sha256
    0x0401, // rsa_pkcs1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0805, // rsa_pss_rsae_sha384
    0x0501, // rsa_pkcs1_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0601, // rsa_pkcs1_sha512
];

/// ALPN protocols in Chrome order: `h2` first, then `http/1.1`.
pub const CHROME_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];

/// A high-level fingerprint selector. In the future this can grow to include
/// Firefox/Safari profiles; for now Chrome is the only realistic target.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Fingerprint {
    /// Chrome 120+ (the default and only production target).
    #[default]
    Chrome,
}

impl Fingerprint {
    /// The JA3/JA4 target this profile aims to match.
    pub fn target_browser(&self) -> &'static str {
        match self {
            Fingerprint::Chrome => "Chrome 120+",
        }
    }
}
