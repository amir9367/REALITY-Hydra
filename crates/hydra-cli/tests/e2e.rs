//! End-to-end: the real client tunnel (`hydra_client::TunnelClient`) talking to
//! the real exit node (`hydra_server::serve_on`) over pinned TLS, relaying to a
//! throwaway echo "destination". This is the whole data path the Windows client
//! and the VPS exercise in production, minus the SOCKS front-end — proof that
//! bytes actually make the round trip.

use hydra_client::TunnelClient;
use hydra_server::{serve_on, TlsMaterial};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tunnel_proto::{Host, Target};

const SECRET: &[u8] = b"end-to-end-master-secret-32-byte";

/// Spawn an echo server; return its address. It echoes until the peer closes.
async fn spawn_echo() -> std::net::SocketAddr {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = echo.accept().await.unwrap();
        let mut b = [0u8; 1024];
        loop {
            match s.read(&mut b).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if s.write_all(&b[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    addr
}

/// Spawn the exit node on an ephemeral port; return (address, cert pin).
async fn spawn_server() -> (std::net::SocketAddr, [u8; 32]) {
    let material = TlsMaterial::generate(&["127.0.0.1".into()]).unwrap();
    let pin = material.pin;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve_on(listener, material, SECRET.to_vec(), 120).await;
    });
    (addr, pin)
}

#[tokio::test]
async fn tunnel_relays_bytes_through_exit_node() {
    let echo_addr = spawn_echo().await;
    let (server_addr, pin) = spawn_server().await;

    let client = TunnelClient::new(server_addr.to_string(), Some(pin), SECRET.to_vec()).unwrap();
    let target = Target::new(Host::V4([127, 0, 0, 1]), echo_addr.port());

    let mut stream = client.open("www.example.com", &target).await.unwrap();
    stream.write_all(b"hello tunnel").await.unwrap();

    let mut buf = [0u8; 12];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello tunnel");
}

#[tokio::test]
async fn wrong_pin_is_rejected_at_tls() {
    let (server_addr, _real_pin) = spawn_server().await;

    // A client that pins the wrong certificate must fail the TLS handshake and
    // never reach the header/relay stage.
    let bad_pin = [0xAB; 32];
    let client = TunnelClient::new(server_addr.to_string(), Some(bad_pin), SECRET.to_vec()).unwrap();
    let target = Target::new(Host::V4([127, 0, 0, 1]), 9);

    let err = client.open("www.example.com", &target).await;
    assert!(err.is_err(), "wrong pin must not connect");
}

#[tokio::test]
async fn wrong_secret_is_rejected_by_auth() {
    let echo_addr = spawn_echo().await;
    let (server_addr, pin) = spawn_server().await;

    // TLS pins correctly, but the header is signed with the wrong secret, so the
    // exit node replies AUTH_FAIL and `open` returns TunnelRejected.
    let client =
        TunnelClient::new(server_addr.to_string(), Some(pin), b"the-wrong-secret".to_vec()).unwrap();
    let target = Target::new(Host::V4([127, 0, 0, 1]), echo_addr.port());

    let err = client.open("www.example.com", &target).await;
    assert!(err.is_err(), "wrong secret must be rejected");
}
