//! The REALITY-Hydra self-tunnel wire format.
//!
//! When the Windows client (a SOCKS5 inbound) wants to reach some destination —
//! say `149.154.167.51:443` for Telegram — it opens a TLS connection to the exit
//! node and, as the very first bytes inside that TLS session, sends a single
//! **authenticated CONNECT header** describing where it wants to go. The exit
//! node verifies the header, dials that destination itself, and then the two
//! sides relay raw bytes. This crate is *only* that header: its byte layout, the
//! HMAC that authenticates it, and the freshness check that bounds replay.
//!
//! It is deliberately pure logic (no sockets, no async) so both the client and
//! the server link the exact same encode/verify code and so the format is unit-
//! and property-testable without standing up a network. The async socket reads
//! live in `hydra-server`; this crate hands it the pieces.
//!
//! ## Header layout
//!
//! ```text
//! ┌─────────┬──────────────┬──────┬────────────┬──────────┬───────────────┐
//! │ version │  timestamp   │ atyp │  address   │   port   │      mac      │
//! │  1 B    │  8 B (LE u64)│ 1 B  │  variable  │ 2 B (BE) │     32 B      │
//! └─────────┴──────────────┴──────┴────────────┴──────────┴───────────────┘
//!                                                          └── HMAC-SHA256 ──┘
//! ```
//!
//! * `version` — [`VERSION`]; lets the format evolve without silent misreads.
//! * `timestamp` — client's UNIX seconds. The server rejects headers whose time
//!   differs from its own clock by more than [`DEFAULT_MAX_SKEW_SECS`], so a
//!   captured header cannot be replayed indefinitely (cf. REALITY's `maxTimeDiff`).
//! * `atyp`/`address`/`port` — the destination, using the same address-type tags
//!   as SOCKS5 (`0x01` IPv4, `0x03` domain, `0x04` IPv6).
//! * `mac` — `HMAC-SHA256(master_secret, all preceding bytes)`. The same
//!   `master_secret` already shared via the `hydra://` bundle authenticates the
//!   tunnel; an attacker without it cannot forge a header, and the exit node
//!   answers unauthenticated bytes by simply hanging up.
//!
//! ## Security notes
//!
//! * There is **no forward secrecy** and no per-request key ratchet — leaking
//!   `master_secret` forges every header. This mirrors the pool engine's KDF
//!   (REALITY.md §5.4); keep the secret rotatable.
//! * The timestamp bounds *replay window*, not replay entirely: within the skew
//!   window a captured header is still valid. That is acceptable for v1 (the
//!   payload is TLS-wrapped); a nonce cache on the server would close it fully.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// Current wire-format version. Bump on any breaking layout change.
pub const VERSION: u8 = 1;

/// Length of the trailing HMAC-SHA256 tag, in bytes.
pub const MAC_LEN: usize = 32;

/// Default freshness window: headers whose timestamp differs from server time by
/// more than this (in either direction) are rejected. Bounds replay while still
/// tolerating modest client/server clock drift.
pub const DEFAULT_MAX_SKEW_SECS: u64 = 120;

// SOCKS5-compatible address-type tags, reused so the client can map its parsed
// SOCKS request straight onto the wire with no translation table.
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// One-byte server reply, sent right after a header is accepted (or refused),
/// before the byte relay begins. Lets the client distinguish "auth rejected"
/// from "couldn't reach your destination" instead of guessing from a bare EOF.
pub mod reply {
    /// Header authenticated and destination dialed: relay follows.
    pub const OK: u8 = 0x00;
    /// The header failed authentication or freshness checks.
    pub const AUTH_FAIL: u8 = 0x01;
    /// Authenticated, but the exit node could not reach the destination.
    pub const DIAL_FAIL: u8 = 0x02;
}

/// The longest domain name we encode. DNS names cap at 253 characters; the
/// length prefix is a single byte, so 255 is the hard ceiling regardless.
pub const MAX_DOMAIN_LEN: usize = 253;

/// A destination host, tagged exactly like a SOCKS5 address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Host {
    /// A literal IPv4 address.
    V4([u8; 4]),
    /// A domain name, resolved by the *exit node* (so the client never leaks the
    /// lookup, and DNS happens where it can actually succeed).
    Domain(String),
    /// A literal IPv6 address.
    V6([u8; 16]),
}

/// A destination the client wants the exit node to reach: host plus port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// The destination host.
    pub host: Host,
    /// The destination port.
    pub port: u16,
}

impl Target {
    /// Construct a target from a host and port.
    pub fn new(host: Host, port: u16) -> Self {
        Self { host, port }
    }

    /// Render as `host:port` for logging. IPv6 hosts are bracketed.
    pub fn display(&self) -> String {
        match &self.host {
            Host::V4(a) => format!("{}.{}.{}.{}:{}", a[0], a[1], a[2], a[3], self.port),
            Host::Domain(d) => format!("{d}:{}", self.port),
            Host::V6(a) => {
                let s = a
                    .chunks(2)
                    .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                    .collect::<Vec<_>>()
                    .join(":");
                format!("[{s}]:{}", self.port)
            }
        }
    }

    /// Serialize just the `atyp || address || port` portion (no version, no MAC).
    /// Exposed so the server can recompute the MAC over the exact bytes it read.
    fn encode_addr(&self, out: &mut Vec<u8>) {
        match &self.host {
            Host::V4(a) => {
                out.push(ATYP_IPV4);
                out.extend_from_slice(a);
            }
            Host::Domain(d) => {
                out.push(ATYP_DOMAIN);
                out.push(d.len() as u8);
                out.extend_from_slice(d.as_bytes());
            }
            Host::V6(a) => {
                out.push(ATYP_IPV6);
                out.extend_from_slice(a);
            }
        }
        out.extend_from_slice(&self.port.to_be_bytes());
    }
}

/// Everything that can go wrong decoding or verifying a header.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtoError {
    /// The header ended before all required fields were present.
    #[error("truncated header: needed {needed} more byte(s)")]
    Truncated {
        /// How many additional bytes the parser still required.
        needed: usize,
    },

    /// The version byte did not match [`VERSION`].
    #[error("unsupported protocol version {found} (expected {VERSION})")]
    BadVersion {
        /// The version byte actually seen.
        found: u8,
    },

    /// The address-type tag was not one of the SOCKS5 values.
    #[error("unknown address type {atyp:#04x}")]
    BadAtyp {
        /// The unrecognized `atyp` byte.
        atyp: u8,
    },

    /// A domain name was not valid UTF-8.
    #[error("domain is not valid UTF-8")]
    BadDomain,

    /// A domain name exceeded [`MAX_DOMAIN_LEN`].
    #[error("domain too long ({len} > {MAX_DOMAIN_LEN})")]
    DomainTooLong {
        /// The offending length.
        len: usize,
    },

    /// The MAC did not verify: forged, corrupted, or wrong `master_secret`.
    #[error("authentication failed (bad MAC)")]
    BadMac,

    /// The timestamp was outside the freshness window.
    #[error("stale header: timestamp skew exceeds {max_skew}s")]
    Stale {
        /// The skew budget that was exceeded.
        max_skew: u64,
    },
}

/// Compute the header MAC over `preceding` bytes with `key`.
fn mac(key: &[u8], preceding: &[u8]) -> [u8; MAC_LEN] {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(preceding);
    let out = m.finalize().into_bytes();
    let mut tag = [0u8; MAC_LEN];
    tag.copy_from_slice(&out);
    tag
}

/// Build the full authenticated CONNECT header for `target`, stamped with
/// `timestamp` (UNIX seconds) and authenticated with `key` (the master secret).
///
/// The returned bytes are written verbatim as the first bytes of the TLS stream.
pub fn encode_request(key: &[u8], timestamp: u64, target: &Target) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 8 + 1 + 1 + MAX_DOMAIN_LEN + 2 + MAC_LEN);
    buf.push(VERSION);
    buf.extend_from_slice(&timestamp.to_le_bytes());
    target.encode_addr(&mut buf);
    let tag = mac(key, &buf);
    buf.extend_from_slice(&tag);
    buf
}

/// The result of parsing a header: the destination plus how many bytes it spanned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedRequest {
    /// The authenticated destination.
    pub target: Target,
    /// The client-supplied UNIX timestamp (already freshness-checked).
    pub timestamp: u64,
    /// Total header length in bytes (where the relayed payload begins).
    pub consumed: usize,
}

/// Parse and fully validate a header from `buf`: version, MAC, and freshness.
///
/// `now` is the server's current UNIX seconds and `max_skew` the tolerated drift
/// (use [`DEFAULT_MAX_SKEW_SECS`]). On success the destination is authenticated
/// and fresh, and `consumed` marks where the byte relay should begin.
///
/// Returns [`ProtoError::Truncated`] if `buf` does not yet hold a whole header —
/// callers reading from a socket should read more and retry.
pub fn parse_request(
    buf: &[u8],
    key: &[u8],
    now: u64,
    max_skew: u64,
) -> Result<ParsedRequest, ProtoError> {
    // version(1) + timestamp(8) + atyp(1) is the smallest possible prefix.
    let need = |have: usize, want: usize| -> Result<(), ProtoError> {
        if have < want {
            Err(ProtoError::Truncated { needed: want - have })
        } else {
            Ok(())
        }
    };

    need(buf.len(), 10)?;
    if buf[0] != VERSION {
        return Err(ProtoError::BadVersion { found: buf[0] });
    }
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&buf[1..9]);
    let timestamp = u64::from_le_bytes(ts_bytes);

    let atyp = buf[9];
    let mut cursor = 10;
    let host = match atyp {
        ATYP_IPV4 => {
            need(buf.len(), cursor + 4)?;
            let mut a = [0u8; 4];
            a.copy_from_slice(&buf[cursor..cursor + 4]);
            cursor += 4;
            Host::V4(a)
        }
        ATYP_DOMAIN => {
            need(buf.len(), cursor + 1)?;
            let len = buf[cursor] as usize;
            cursor += 1;
            if len > MAX_DOMAIN_LEN {
                return Err(ProtoError::DomainTooLong { len });
            }
            need(buf.len(), cursor + len)?;
            let d = std::str::from_utf8(&buf[cursor..cursor + len])
                .map_err(|_| ProtoError::BadDomain)?
                .to_string();
            cursor += len;
            Host::Domain(d)
        }
        ATYP_IPV6 => {
            need(buf.len(), cursor + 16)?;
            let mut a = [0u8; 16];
            a.copy_from_slice(&buf[cursor..cursor + 16]);
            cursor += 16;
            Host::V6(a)
        }
        other => return Err(ProtoError::BadAtyp { atyp: other }),
    };

    need(buf.len(), cursor + 2)?;
    let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
    cursor += 2;

    // The MAC covers every byte up to (but not including) itself.
    need(buf.len(), cursor + MAC_LEN)?;
    let signed = &buf[..cursor];
    let tag = &buf[cursor..cursor + MAC_LEN];
    verify_mac(key, signed, tag)?;
    cursor += MAC_LEN;

    // Freshness: constant work regardless of outcome; ordering after the MAC
    // means an unauthenticated peer never learns the server clock.
    if now.abs_diff(timestamp) > max_skew {
        return Err(ProtoError::Stale { max_skew });
    }

    Ok(ParsedRequest {
        target: Target { host, port },
        timestamp,
        consumed: cursor,
    })
}

/// Constant-time MAC check via `hmac`'s `verify_slice`.
fn verify_mac(key: &[u8], signed: &[u8], tag: &[u8]) -> Result<(), ProtoError> {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(signed);
    m.verify_slice(tag).map_err(|_| ProtoError::BadMac)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"a-shared-master-secret-32-bytes!!";

    fn roundtrip(target: Target) {
        let ts = 1_700_000_000;
        let bytes = encode_request(KEY, ts, &target);
        let parsed = parse_request(&bytes, KEY, ts, DEFAULT_MAX_SKEW_SECS).unwrap();
        assert_eq!(parsed.target, target);
        assert_eq!(parsed.timestamp, ts);
        assert_eq!(parsed.consumed, bytes.len());
    }

    #[test]
    fn roundtrip_ipv4() {
        roundtrip(Target::new(Host::V4([149, 154, 167, 51]), 443));
    }

    #[test]
    fn roundtrip_domain() {
        roundtrip(Target::new(Host::Domain("core.telegram.org".into()), 443));
    }

    #[test]
    fn roundtrip_ipv6() {
        roundtrip(Target::new(Host::V6([0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), 80));
    }

    #[test]
    fn wrong_key_fails_mac() {
        let target = Target::new(Host::V4([1, 2, 3, 4]), 80);
        let bytes = encode_request(KEY, 1_700_000_000, &target);
        let err = parse_request(&bytes, b"different-key", 1_700_000_000, DEFAULT_MAX_SKEW_SECS)
            .unwrap_err();
        assert_eq!(err, ProtoError::BadMac);
    }

    #[test]
    fn flipped_address_bit_fails_mac() {
        let target = Target::new(Host::V4([1, 2, 3, 4]), 80);
        let mut bytes = encode_request(KEY, 1_700_000_000, &target);
        bytes[11] ^= 0x01; // flip a bit in the address region
        let err = parse_request(&bytes, KEY, 1_700_000_000, DEFAULT_MAX_SKEW_SECS).unwrap_err();
        assert_eq!(err, ProtoError::BadMac);
    }

    #[test]
    fn stale_timestamp_rejected() {
        let target = Target::new(Host::V4([1, 2, 3, 4]), 80);
        let bytes = encode_request(KEY, 1_700_000_000, &target);
        // Server clock is 10 minutes ahead of the stamped time.
        let err = parse_request(&bytes, KEY, 1_700_000_600, DEFAULT_MAX_SKEW_SECS).unwrap_err();
        assert_eq!(err, ProtoError::Stale { max_skew: DEFAULT_MAX_SKEW_SECS });
    }

    #[test]
    fn future_timestamp_within_window_ok() {
        let target = Target::new(Host::V4([1, 2, 3, 4]), 80);
        let bytes = encode_request(KEY, 1_700_000_060, &target);
        // Client clock 60s ahead but inside the 120s window.
        assert!(parse_request(&bytes, KEY, 1_700_000_000, DEFAULT_MAX_SKEW_SECS).is_ok());
    }

    #[test]
    fn bad_version_rejected() {
        let target = Target::new(Host::V4([1, 2, 3, 4]), 80);
        let mut bytes = encode_request(KEY, 1_700_000_000, &target);
        bytes[0] = 0xFF;
        let err = parse_request(&bytes, KEY, 1_700_000_000, DEFAULT_MAX_SKEW_SECS).unwrap_err();
        assert_eq!(err, ProtoError::BadVersion { found: 0xFF });
    }

    #[test]
    fn truncated_header_reports_more_needed() {
        let target = Target::new(Host::Domain("example.com".into()), 443);
        let bytes = encode_request(KEY, 1_700_000_000, &target);
        // Feed every strict prefix; each should ask for more, never panic.
        for cut in 0..bytes.len() {
            let err = parse_request(&bytes[..cut], KEY, 1_700_000_000, DEFAULT_MAX_SKEW_SECS)
                .unwrap_err();
            assert!(matches!(err, ProtoError::Truncated { .. }), "cut={cut}: {err:?}");
        }
        // The full buffer parses.
        assert!(parse_request(&bytes, KEY, 1_700_000_000, DEFAULT_MAX_SKEW_SECS).is_ok());
    }
}
