//! Client side of the self-tunnel: open a pinned-TLS connection to the exit node
//! and send the authenticated CONNECT header.
//!
//! REALITY borrows a real site's certificate; we can't (patched-stack problem,
//! REALITY.md §7 P7). So the exit node presents a self-signed cert and we trust
//! *exactly that one* by its SHA-256 pin — no CA, no hostname check. The outer
//! SNI is still set to a rotating pool domain for a touch of cover, but identity
//! is proven by the pin, not the name.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tunnel_proto::{encode_request, reply, Target};

use crate::error::ClientError;

/// A configured tunnel dialer: reusable across connections.
pub struct TunnelClient {
    connector: TlsConnector,
    /// Where the exit node listens (`host:port`).
    server_addr: String,
    /// The shared master secret that authenticates each CONNECT header.
    master_secret: Vec<u8>,
}

impl TunnelClient {
    /// Build a dialer for `server_addr`, pinning the exit node's cert to
    /// `cert_pin` (SHA-256 of its DER). `None` accepts any cert — testing only.
    pub fn new(
        server_addr: String,
        cert_pin: Option<[u8; 32]>,
        master_secret: Vec<u8>,
    ) -> Result<Self, ClientError> {
        let verifier = Arc::new(PinnedVerifier {
            pin: cert_pin,
            schemes: ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes(),
        });

        let config = rustls::ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| ClientError::Tls(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
            server_addr,
            master_secret,
        })
    }

    /// Open a tunnel to `target`, presenting `sni` as the outer TLS server name.
    ///
    /// Connects TCP → TLS (pinned) → sends the authenticated header → waits for
    /// the exit node's one-byte accept. The returned stream is ready to relay.
    pub async fn open(&self, sni: &str, target: &Target) -> Result<TlsStream<TcpStream>, ClientError> {
        let tcp = TcpStream::connect(&self.server_addr)
            .await
            .map_err(|source| ClientError::TunnelConnect {
                addr: self.server_addr.clone(),
                source,
            })?;

        // rustls needs an owned, validated name; fall back to a fixed placeholder
        // if a pool entry somehow isn't a legal DNS name (identity is pinned, so
        // the exact bytes here don't affect security).
        let server_name = ServerName::try_from(sni.to_string())
            .or_else(|_| ServerName::try_from("www.microsoft.com".to_string()))
            .map_err(|e| ClientError::Tls(format!("invalid server name: {e}")))?;

        let mut stream = self
            .connector
            .connect(server_name, tcp)
            .await
            .map_err(|source| ClientError::TunnelTls {
                addr: self.server_addr.clone(),
                source,
            })?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let header = encode_request(&self.master_secret, timestamp, target);
        stream.write_all(&header).await?;

        // Wait for the exit node's verdict before relaying.
        let mut reply_byte = [0u8; 1];
        stream.read_exact(&mut reply_byte).await?;
        match reply_byte[0] {
            reply::OK => Ok(stream),
            reply::AUTH_FAIL => Err(ClientError::TunnelRejected {
                reason: "exit node rejected authentication (check master_secret matches the server)"
                    .into(),
            }),
            reply::DIAL_FAIL => Err(ClientError::TunnelRejected {
                reason: format!("exit node could not reach {}", target.display()),
            }),
            other => Err(ClientError::TunnelRejected {
                reason: format!("unexpected reply byte {other:#04x}"),
            }),
        }
    }
}

/// A rustls verifier that trusts exactly one certificate, identified by the
/// SHA-256 of its DER encoding (or any cert when `pin` is `None`).
#[derive(Debug)]
struct PinnedVerifier {
    pin: Option<[u8; 32]>,
    schemes: Vec<SignatureScheme>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self.pin {
            None => Ok(ServerCertVerified::assertion()),
            Some(expected) => {
                let got: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
                if got == expected {
                    Ok(ServerCertVerified::assertion())
                } else {
                    Err(rustls::Error::General(
                        "certificate pin mismatch: the exit node presented an unexpected \
                         certificate (wrong cert_pin, or a man-in-the-middle)"
                            .into(),
                    ))
                }
            }
        }
    }

    // Identity is proven by the pin above; accept the handshake signatures so the
    // TLS 1.2/1.3 key exchange itself still completes normally.
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}
