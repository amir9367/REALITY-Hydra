//! The exit node's TLS identity: a self-signed leaf the client pins by SHA-256.
//!
//! REALITY borrows a real site's certificate; we can't (that needs the patched
//! stack, REALITY.md §7 P7). So instead the server presents its *own* self-signed
//! cert and the client trusts exactly that one cert by its SHA-256 fingerprint —
//! standard certificate pinning. No CA, no hostname to match, no Let's Encrypt.
//!
//! On first run the server generates the cert, writes `cert.der` + `key.der` next
//! to the config, and prints the pin to fold into the client's `hydra://` bundle.
//! Later runs load those files so the pin stays stable across restarts.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};

use crate::error::ServerError;

/// A self-signed leaf certificate plus its private key and pin.
pub struct TlsMaterial {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    /// SHA-256 of the certificate DER — what the client pins.
    pub pin: [u8; 32],
}

impl TlsMaterial {
    /// Generate a fresh self-signed certificate for `sans` (the server's IP
    /// and/or domain; any value works since the client pins, not verifies).
    pub fn generate(sans: &[String]) -> Result<Self, ServerError> {
        let names = if sans.is_empty() {
            vec!["hydra.local".to_string()]
        } else {
            sans.to_vec()
        };
        let key = rcgen::generate_simple_self_signed(names)
            .map_err(|e| ServerError::CertGen(e.to_string()))?;
        let cert_der = key.cert.der().to_vec();
        let key_der = key.key_pair.serialize_der();
        let pin = pin_of(&cert_der);
        Ok(Self {
            cert_der,
            key_der,
            pin,
        })
    }

    /// Load a previously generated cert/key pair (raw DER files).
    pub fn load_der(cert_path: &Path, key_path: &Path) -> Result<Self, ServerError> {
        let read = |p: &Path| -> Result<Vec<u8>, ServerError> {
            std::fs::read(p).map_err(|source| ServerError::CertRead {
                path: p.display().to_string(),
                source,
            })
        };
        let cert_der = read(cert_path)?;
        let key_der = read(key_path)?;
        if cert_der.is_empty() {
            return Err(ServerError::CertParse {
                path: cert_path.display().to_string(),
                reason: "empty certificate file".into(),
            });
        }
        let pin = pin_of(&cert_der);
        Ok(Self {
            cert_der,
            key_der,
            pin,
        })
    }

    /// Load the pair from `dir` if both files exist, otherwise generate a new one
    /// and persist it. Returns the material and whether it was freshly generated.
    pub fn load_or_generate(dir: &Path, sans: &[String]) -> Result<(Self, bool), ServerError> {
        let (cert_path, key_path) = der_paths(dir);
        if cert_path.exists() && key_path.exists() {
            Ok((Self::load_der(&cert_path, &key_path)?, false))
        } else {
            let material = Self::generate(sans)?;
            material.persist(dir)?;
            Ok((material, true))
        }
    }

    /// Write `cert.der` and `key.der` into `dir`, creating it if needed.
    pub fn persist(&self, dir: &Path) -> Result<(), ServerError> {
        std::fs::create_dir_all(dir)?;
        let (cert_path, key_path) = der_paths(dir);
        std::fs::write(&cert_path, &self.cert_der)?;
        std::fs::write(&key_path, &self.key_der)?;
        Ok(())
    }

    /// The pin as base64 (what goes into the client `hydra.toml` as `cert_pin`).
    pub fn pin_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.pin)
    }

    /// Build a rustls `ServerConfig` presenting this certificate.
    ///
    /// Uses the `ring` provider explicitly so it never depends on a process-wide
    /// default being installed first.
    pub fn server_config(&self) -> Result<Arc<rustls::ServerConfig>, ServerError> {
        let certs = vec![CertificateDer::from(self.cert_der.clone())];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone()));

        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| ServerError::Tls(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| ServerError::Tls(e.to_string()))?;
        Ok(Arc::new(cfg))
    }
}

/// SHA-256 of the certificate DER.
fn pin_of(cert_der: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(cert_der);
    h.finalize().into()
}

/// The `cert.der` / `key.der` paths inside `dir`.
fn der_paths(dir: &Path) -> (PathBuf, PathBuf) {
    (dir.join("cert.der"), dir.join("key.der"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_is_pinnable_and_builds_a_config() {
        let m = TlsMaterial::generate(&["127.0.0.1".into()]).unwrap();
        assert_eq!(m.pin.len(), 32);
        assert_eq!(m.pin, pin_of(&m.cert_der));
        // The base64 pin decodes back to the same 32 bytes.
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(m.pin_base64())
            .unwrap();
        assert_eq!(decoded, m.pin);
        assert!(m.server_config().is_ok());
    }
}
