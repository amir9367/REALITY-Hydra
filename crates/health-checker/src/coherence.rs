//! Coherence allowlist — axis (a) of the health check (REALITY.md Traps 2 & 3).
//!
//! A pool SNI is only camouflage if its *real* DNS answer lands in the same CDN
//! edge range your server is fronted by. If `SNI=foo.example` resolves to some
//! Apple range but you connect to a Cloudflare-fronted box, a tier-D correlator
//! (Trap 3) — or even a hosting-database lookup (Trap 2) — catches the mismatch.
//!
//! This module is pure: it parses the configured `coherence_cidrs` into a set of
//! networks and tests IP membership. No DNS, no network.

use std::net::IpAddr;

use ipnet::IpNet;

use crate::error::HealthError;

/// A parsed, non-empty set of CDN edge CIDRs an SNI's resolved IPs must fall in.
#[derive(Clone, Debug)]
pub struct CoherenceAllowlist {
    nets: Vec<IpNet>,
}

impl CoherenceAllowlist {
    /// Parse the configured `coherence_cidrs` strings (e.g. `"104.16.0.0/13"`).
    ///
    /// Rejects an empty list (it would fail every entry) and any unparseable
    /// CIDR. Both v4 and v6 networks are accepted and matched against the
    /// matching address family.
    pub fn parse<I, S>(cidrs: I) -> Result<Self, HealthError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut nets = Vec::new();
        for cidr in cidrs {
            let cidr = cidr.as_ref();
            let net: IpNet = cidr.parse().map_err(|e: ipnet::AddrParseError| {
                HealthError::BadCidr {
                    cidr: cidr.to_string(),
                    message: e.to_string(),
                }
            })?;
            nets.push(net);
        }
        if nets.is_empty() {
            return Err(HealthError::EmptyAllowlist);
        }
        Ok(Self { nets })
    }

    /// Whether `ip` falls within any allowed network.
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.nets.iter().any(|net| net.contains(&ip))
    }

    /// Whether *all* of `ips` are in range — and the slice is non-empty.
    ///
    /// The health check requires every resolved address to be coherent: a record
    /// set that mixes an in-range and an out-of-range IP is exactly the kind of
    /// incoherence Trap 3 looks for, so one stray address fails the entry.
    pub fn contains_all(&self, ips: &[IpAddr]) -> bool {
        !ips.is_empty() && ips.iter().all(|ip| self.contains(*ip))
    }
}
