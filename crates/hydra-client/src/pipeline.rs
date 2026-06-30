//! The Hydra connection pipeline: PoolEngine → Selector → DnsWarmer → RealityTLS.
//!
//! This module wires the four existing crates into a single connection path.
//! For each inbound SOCKS5 CONNECT request, the pipeline:
//!
//! 1. Derives the current epoch pool from the shared secret + salt.
//! 2. Picks an SNI via weighted-random selection (sticky per destination).
//! 3. Warms DNS for the chosen SNI (defeats Trap 1).
//! 4. Opens a REALITY-authenticated TLS connection to the CDN edge.
//! 5. Relays bytes between the app and the TLS stream.
//!
//! The pipeline is generic over the DNS resolver — the same code works with a
//! [`dns_warmer::MockResolver`] in tests and a [`dns_warmer::HickoryResolver`]
//! in production (behind the `live-dns` feature).

use std::sync::Arc;

use dns_warmer::{DnsWarmer, MockResolver, Resolver, WarmerConfig};
use pool_engine::{
    ActivePool, Epoch, HydraConfig, Selector, accepted_pool_window, current_epoch,
};
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::watch;

use crate::error::ClientError;
use crate::socks5;

/// The Hydra outbound pipeline, parameterized over a DNS resolver.
///
/// Holds the shared configuration, the DNS warmer, and the current epoch pool.
/// The pool is refreshed whenever the epoch advances (driven by a background
/// task or checked lazily on each connection).
pub struct Pipeline<R: Resolver> {
    config: Arc<HydraConfig>,
    warmer: Arc<DnsWarmer<R>>,
    selector: Arc<tokio::sync::Mutex<Selector>>,
    pool: Arc<tokio::sync::RwLock<ActivePool>>,
    current_epoch: Arc<watch::Sender<Epoch>>,
}

impl Pipeline<MockResolver> {
    /// Build a pipeline with a mock resolver (for tests and offline builds).
    pub fn mock(config: HydraConfig) -> Self {
        let resolver = MockResolver::new();
        Self::with_resolver(config, resolver, WarmerConfig::default())
    }
}

impl<R: Resolver> Pipeline<R> {
    /// Build a pipeline with a custom resolver.
    pub fn with_resolver(
        config: HydraConfig,
        resolver: R,
        warmer_config: WarmerConfig,
    ) -> Self {
        let epoch = current_epoch(config.epoch_len);
        let pool = accepted_pool_window(
            config.master_secret(),
            &config.server_salt,
            &config.master_list,
            epoch,
            config.active_k,
        );

        let (epoch_tx, _) = watch::channel(epoch);

        let warmer_config_clone = warmer_config;

        Self {
            config: Arc::new(config),
            warmer: Arc::new(DnsWarmer::with_config(resolver, warmer_config_clone)),
            selector: Arc::new(tokio::sync::Mutex::new(Selector::new(30_000))),
            pool: Arc::new(tokio::sync::RwLock::new(pool)),
            current_epoch: Arc::new(epoch_tx),
        }
    }

    /// Refresh the epoch pool if the clock has advanced to a new epoch.
    ///
    /// Called lazily on each connection; a background task could also call it
    /// periodically. This is cheap (pure logic, no I/O).
    pub async fn maybe_refresh_epoch(&self) {
        let epoch = current_epoch(self.config.epoch_len);
        let mut rx = self.current_epoch.subscribe();
        // Check if the epoch changed (non-blocking).
        if *rx.borrow_and_update() != epoch {
            let new_pool = accepted_pool_window(
                self.config.master_secret(),
                &self.config.server_salt,
                &self.config.master_list,
                epoch,
                self.config.active_k,
            );
            *self.pool.write().await = new_pool;
            let _ = self.current_epoch.send(epoch);
        }
    }

    /// A snapshot copy of the current active epoch pool. For tests and
    /// introspection; the connection path reads the pool under a lock directly.
    pub async fn active_pool(&self) -> ActivePool {
        self.pool.read().await.clone()
    }

    /// Pick an SNI for `dest` using the live selector and pool, exactly as the
    /// connection path does. Exposed so integration tests can exercise selection
    /// without driving a full SOCKS5 connection.
    pub async fn select_sni(&self, dest: &str, now_ms: u64) -> Option<String> {
        let mut sel = self.selector.lock().await;
        let pool = self.pool.read().await;
        sel.pick(&pool, dest, now_ms)
    }

    /// Handle one inbound SOCKS5 connection: perform the handshake, select an
    /// SNI, warm DNS, open the REALITY TLS connection, and relay bytes.
    pub async fn handle_connection(&self, mut inbound: TcpStream) -> Result<(), ClientError> {
        // 1. SOCKS5 handshake — learn what the app wants to connect to.
        let target = socks5::handshake(&mut inbound)
            .await
            .map_err(ClientError::Socks5)?;

        let dest_str = target.display();

        // 2. Refresh epoch if needed.
        self.maybe_refresh_epoch().await;

        // 3. Pick an SNI from the active pool (sticky per destination).
        let sni = {
            let mut sel = self.selector.lock().await;
            let pool = self.pool.read().await;
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            sel.pick(&pool, &dest_str, now_ms)
                .ok_or_else(|| ClientError::Dns {
                    sni: String::new(),
                    message: "active pool is empty".into(),
                })?
        };

        // 4. Warm DNS for the chosen SNI (defeats Trap 1).
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.warmer
            .warm(&sni, now_ms)
            .await
            .map_err(|e| ClientError::Dns {
                sni: sni.clone(),
                message: e.to_string(),
            })?;

        // 5. Open a REALITY-authenticated TLS connection.
        //    The `dest` is the CDN edge the server is fronted by.
        let server_addr = self
            .config
            .dest
            .as_deref()
            .unwrap_or("127.0.0.1:443");

        // For now, without the `boring-impersonate` feature, we fall back to a
        // plain TCP connection to demonstrate the pipeline flow. The full
        // RealityTLS client requires BoringSSL.
        #[cfg(feature = "boring-impersonate")]
        let outbound = {
            let reality_cfg = reality_tls::RealityConfig::new(
                [0u8; 32], // TODO: load from hydra.toml
                vec![],
                reality_tls::Fingerprint::default(),
            )?;
            let client = reality_tls::RealityClient::new(reality_cfg)?;
            client.connect(server_addr, &sni).await?
        };

        #[cfg(not(feature = "boring-impersonate"))]
        let outbound = TcpStream::connect(server_addr).await?;

        // 6. Relay bytes bidirectionally.
        relay(inbound, outbound).await;

        Ok(())
    }
}

/// Bidirectional byte relay between two streams.
///
/// Copies data in both directions until one side closes or errors. Generic over
/// any `AsyncRead + AsyncWrite` so it relays a plain `TcpStream` (default build)
/// or a boring `SslStream<TcpStream>` (the `boring-impersonate` path) alike.
async fn relay<A, B>(mut a: A, mut b: B)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let _ = io::copy_bidirectional(&mut a, &mut b).await;
}

/// Clone the Arc internals for spawning into a new task.
impl<R: Resolver> Clone for Pipeline<R> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            warmer: self.warmer.clone(),
            selector: self.selector.clone(),
            pool: self.pool.clone(),
            current_epoch: self.current_epoch.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> HydraConfig {
        HydraConfig::from_toml_str(include_str!("../../pool-engine/fixtures/hydra.toml")).unwrap()
    }

    #[tokio::test]
    async fn pipeline_creates_with_mock_resolver() {
        let cfg = test_config();
        let pipeline = Pipeline::mock(cfg);
        let pool = pipeline.pool.read().await;
        assert!(!pool.is_empty());
    }

    #[tokio::test]
    async fn maybe_refresh_epoch_is_idempotent() {
        let cfg = test_config();
        let pipeline = Pipeline::mock(cfg);
        let before = pipeline.pool.read().await.len();
        pipeline.maybe_refresh_epoch().await;
        let after = pipeline.pool.read().await.len();
        assert_eq!(before, after);
    }
}
