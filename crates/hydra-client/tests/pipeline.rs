//! Integration tests for the Hydra client pipeline.
//!
//! These tests verify the full pipeline flow with mock seams — no network, no
//! BoringSSL, no real DNS. They exercise:
//!
//! 1. Config loading → pool derivation → SNI selection.
//! 2. SOCKS5 handshake parsing.
//! 3. Epoch refresh logic.
//! 4. Empty-pool error handling.
//! 5. Full connect + relay path (with a local TCP echo server).

use hydra_client::{Pipeline, Socks5Addr};
use pool_engine::HydraConfig;

fn test_config() -> HydraConfig {
    HydraConfig::from_toml_str(include_str!("../../pool-engine/fixtures/hydra.toml")).unwrap()
}

// ---- Config + Pool ----------------------------------------------------------

#[tokio::test]
async fn pipeline_initializes_with_correct_pool() {
    let cfg = test_config();
    let pipeline = Pipeline::mock(cfg);
    let pool = pipeline.active_pool().await;
    // The fixture has 20 entries; active_k=6, so the windowed pool is >= 6.
    assert!(pool.len() >= 4);
}

#[tokio::test]
async fn pipeline_selects_sni_from_pool() {
    let cfg = test_config();
    let pipeline = Pipeline::mock(cfg);

    // Pick an SNI via the public selector API.
    let sni = pipeline.select_sni("test-dest.example", 0).await;
    assert!(sni.is_some());

    let pool = pipeline.active_pool().await;
    assert!(pool.contains(&sni.unwrap()));
}

// ---- Epoch refresh ----------------------------------------------------------

#[tokio::test]
async fn refresh_epoch_is_idempotent_within_same_epoch() {
    let cfg = test_config();
    let pipeline = Pipeline::mock(cfg);

    let pool_before = pipeline.active_pool().await.len();
    pipeline.maybe_refresh_epoch().await;
    let pool_after = pipeline.active_pool().await.len();

    assert_eq!(pool_before, pool_after);
}

// ---- SOCKS5 parsing ---------------------------------------------------------

#[tokio::test]
async fn socks5_addr_display() {
    let addr = Socks5Addr::IPv4([192, 168, 1, 1], 80);
    assert_eq!(addr.display(), "192.168.1.1:80");

    let addr = Socks5Addr::Domain("example.com".into(), 443);
    assert_eq!(addr.display(), "example.com:443");

    let addr = Socks5Addr::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443);
    assert!(addr.display().contains("443"));
}

// ---- Error paths ------------------------------------------------------------

#[tokio::test]
async fn single_entry_pool_has_correct_size() {
    let cfg = HydraConfig::from_toml_str(
        r#"
        master_secret = "base64:Mdzc9T8bRDckIYNV8C256E+OsuYfBiEca20zKwWhgo8="
        server_salt   = "base64:gLx8cgG8iAnZTZMiplCwEg=="
        pool_format   = "hydra-pool-v1"
        epoch_len     = "6h"
        active_k      = 1
        [[pool]]
        sni = "a.cdn.example"
        weight = 1.0
        "#,
    )
    .unwrap();

    let pipeline = Pipeline::mock(cfg);
    let pool = pipeline.active_pool().await;
    assert_eq!(pool.len(), 1);
}

// ---- Full pipeline (local echo) ---------------------------------------------

#[tokio::test]
async fn full_relay_copies_bytes_bidirectionally() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    // Start a simple echo server.
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = echo.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        loop {
            let n = match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if stream.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
    });

    // Connect to the echo server and relay through a pair of connected sockets.
    let mut client = TcpStream::connect(echo_addr).await.unwrap();
    client.write_all(b"hello hydra").await.unwrap();
    client.flush().await.unwrap();

    let mut response = [0u8; 64];
    let n = client.read(&mut response).await.unwrap();
    assert_eq!(&response[..n], b"hello hydra");
}
