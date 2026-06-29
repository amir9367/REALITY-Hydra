//! Live TLS inspector backed by `tokio-rustls` (the `live-tls` feature).
//!
//! Compiled only when `live-tls` is on. This is a plain validation client: it
//! opens a TLS 1.3 connection to `dest` with the given SNI, reads the negotiated
//! protocol version, the selected ALPN, and the leaf certificate's dNSName SANs,
//! then drops the connection. It is *only* a diagnostic of what a CDN edge
//! serves for a name — it is not the data-path client (REALITY.md §7 P7), which
//! is a separate crate.
//!
//! Roots come from `webpki-roots`; ALPN offers `h2` and `http/1.1` so we can
//! observe which the edge selects (axis c wants `h2`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use crate::error::HealthError;
use crate::prober::{TlsInspector, TlsObservation};

/// A [`TlsInspector`] that performs a real validation handshake.
#[derive(Clone)]
pub struct RustlsInspector {
    connector: TlsConnector,
    connect_timeout: Duration,
}

impl RustlsInspector {
    /// Build an inspector trusting the Mozilla webpki root set, offering ALPN
    /// `h2` then `http/1.1`, with the given per-connection timeout.
    pub fn new(connect_timeout: Duration) -> Self {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        // Observe which the edge picks; axis (c) requires h2.
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Self {
            connector: TlsConnector::from(Arc::new(config)),
            connect_timeout,
        }
    }

    fn probe_err(&self, dest: &str, sni: &str, message: impl ToString) -> HealthError {
        HealthError::Probe {
            dest: dest.to_string(),
            sni: sni.to_string(),
            message: message.to_string(),
        }
    }
}

impl Default for RustlsInspector {
    fn default() -> Self {
        Self::new(Duration::from_secs(10))
    }
}

impl TlsInspector for RustlsInspector {
    async fn inspect(&self, dest: &str, sni: &str) -> Result<TlsObservation, HealthError> {
        let server_name = ServerName::try_from(sni.to_string())
            .map_err(|e| self.probe_err(dest, sni, e))?;

        let start = Instant::now();

        let tcp = tokio::time::timeout(self.connect_timeout, TcpStream::connect(dest))
            .await
            .map_err(|_| self.probe_err(dest, sni, "TCP connect timed out"))?
            .map_err(|e| self.probe_err(dest, sni, e))?;

        let tls = tokio::time::timeout(
            self.connect_timeout,
            self.connector.connect(server_name, tcp),
        )
        .await
        .map_err(|_| self.probe_err(dest, sni, "TLS handshake timed out"))?
        .map_err(|e| self.probe_err(dest, sni, e))?;

        let rtt = start.elapsed();

        let (_, conn) = tls.get_ref();
        let is_tls13 = matches!(
            conn.protocol_version(),
            Some(tokio_rustls::rustls::ProtocolVersion::TLSv1_3)
        );
        let alpn = conn.alpn_protocol().map(|p| p.to_vec());

        let leaf_san_dns_names = match conn.peer_certificates().and_then(|certs| certs.first()) {
            Some(leaf) => leaf_dns_sans(leaf.as_ref()),
            None => Vec::new(),
        };

        Ok(TlsObservation {
            is_tls13,
            alpn,
            leaf_san_dns_names,
            rtt,
        })
    }
}

/// Parse the leaf certificate DER and pull its dNSName SAN entries.
///
/// A parse failure yields an empty list rather than an error — an unreadable or
/// SAN-less cert simply fails the SAN-match axis, which is the right verdict.
fn leaf_dns_sans(der: &[u8]) -> Vec<String> {
    use x509_parser::extensions::GeneralName;
    use x509_parser::prelude::FromDer;

    let Ok((_, cert)) = x509_parser::certificate::X509Certificate::from_der(der) else {
        return Vec::new();
    };

    let Ok(Some(san)) = cert.subject_alternative_name() else {
        return Vec::new();
    };

    san.value
        .general_names
        .iter()
        .filter_map(|gn| match gn {
            GeneralName::DNSName(name) => Some((*name).to_string()),
            _ => None,
        })
        .collect()
}
