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
use pool_engine::{ActivePool, Epoch, HydraConfig, Selector, accepted_pool_window, current_epoch};
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tunnel_proto::{Host, Target};

use crate::error::ClientError;
use crate::socks5::{self, Socks5Addr};
use crate::tunnel::TunnelClient;

/// Build the exit-node dialer from config, or `None` if it can't be built.
///
/// Prefers `server_addr`; falls back to `dest` so the existing manual-install
/// path (which writes the server into `dest`) keeps working. A TLS-build failure
/// is logged and yields `None` rather than aborting startup.
fn build_tunnel(config: &HydraConfig) -> Option<Arc<TunnelClient>> {
    let addr = config.server_addr.clone().or_else(|| config.dest.clone())?;
    match TunnelClient::new(addr, config.cert_pin, config.master_secret().to_vec()) {
        Ok(t) => Some(Arc::new(t)),
        Err(e) => {
            eprintln!("hydra-client: TLS setup failed, tunnel disabled: {e}");
            None
        }
    }
}

/// Map a parsed SOCKS5 address onto the tunnel wire target.
fn socks_to_target(addr: &Socks5Addr) -> Target {
    match addr {
        Socks5Addr::IPv4(a, p) => Target::new(Host::V4(*a), *p),
        Socks5Addr::Domain(d, p) => Target::new(Host::Domain(d.clone()), *p),
        Socks5Addr::IPv6(a, p) => Target::new(Host::V6(*a), *p),
    }
}

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
    /// The pinned-TLS dialer to the exit node. `None` when no `server_addr`/`dest`
    /// is configured (or the TLS stack failed to build) — connections then fail
    /// with a clear [`ClientError::NoServerAddr`].
    tunnel: Option<Arc<TunnelClient>>,
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
    pub fn with_resolver(config: HydraConfig, resolver: R, warmer_config: WarmerConfig) -> Self {
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

        // Build the exit-node dialer. The tunnel connects to `server_addr` if set,
        // otherwise falls back to `dest` (the manual-install path writes the
        // server there). Missing both, or a TLS-build failure, leaves it `None`.
        let tunnel = build_tunnel(&config);

        Self {
            config: Arc::new(config),
            warmer: Arc::new(DnsWarmer::with_config(resolver, warmer_config_clone)),
            selector: Arc::new(tokio::sync::Mutex::new(Selector::new(30_000))),
            pool: Arc::new(tokio::sync::RwLock::new(pool)),
            current_epoch: Arc::new(epoch_tx),
            tunnel,
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

    /// Handle one inbound SOCKS5 connection: perform the handshake, open the
    /// authenticated TLS tunnel to the exit node (which dials the real target),
    /// and relay bytes.
    ///
    /// SNI selection and DNS warming remain, but only as *camouflage* for the
    /// outer TLS ClientHello (rotating pool SNI, optional Trap-1 pre-warm). The
    /// destination itself is carried in the tunnel header and resolved by the
    /// exit node, so a failed warm no longer breaks the connection.
    pub async fn handle_connection(&self, mut inbound: TcpStream) -> Result<(), ClientError> {
        // 1. SOCKS5 handshake — learn what the app wants to connect to.
        let socks_addr = socks5::handshake(&mut inbound)
            .await
            .map_err(ClientError::Socks5)?;
        let target = socks_to_target(&socks_addr);
        let dest_str = target.display();

        // 2. Refresh epoch if needed.
        self.maybe_refresh_epoch().await;

        // 3. Pick a rotating pool SNI for the outer TLS ClientHello (camouflage).
        //    Falls back to a fixed name if the pool is somehow empty — identity is
        //    proven by the cert pin, so the exact SNI never affects correctness.
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let sni = {
            let mut sel = self.selector.lock().await;
            let pool = self.pool.read().await;
            sel.pick(&pool, &dest_str, now_ms)
                .unwrap_or_else(|| "www.microsoft.com".to_string())
        };

        // 4. Best-effort DNS warm for the decoy SNI (Trap 1). Never fatal: the
        //    exit node resolves the real destination, so a warm miss (e.g. the
        //    offline MockResolver) is just skipped with a note.
        if let Err(e) = self.warmer.warm(&sni, now_ms).await {
            eprintln!("hydra-client: dns warm for {sni} skipped: {e}");
        }

        // 5. Open the authenticated tunnel to the exit node and relay.
        let tunnel = self.tunnel.as_ref().ok_or(ClientError::NoServerAddr)?;
        let outbound = tunnel.open(&sni, &target).await?;

        eprintln!("hydra-client: {dest_str} via exit node (outer SNI {sni})");
        relay(inbound, outbound).await;

        Ok(())
    }
}

impl<R: Resolver + Send + Sync + 'static> Pipeline<R> {
    /// Accept SOCKS5 connections on `addr` and route each through the pipeline.
    ///
    /// Runs until the listener errors. Each connection is handled on its own
    /// task; per-connection errors are logged and do not stop the server. Both
    /// the `hydra-client` binary and `hydra serve` call this, so the accept loop
    /// lives in one place.
    pub async fn serve(self, addr: &str) -> Result<(), ClientError> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| ClientError::Bind {
                addr: addr.to_string(),
                message: e.to_string(),
            })?;

        eprintln!("hydra-client: listening on {addr}");

        loop {
            let (stream, peer) = listener.accept().await?;
            eprintln!("hydra-client: connection from {peer}");

            let pipeline = self.clone();
            tokio::spawn(async move {
                if let Err(e) = pipeline.handle_connection(stream).await {
                    eprintln!("hydra-client: connection error: {e}");
                }
            });
        }
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
            tunnel: self.tunnel.clone(),
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
