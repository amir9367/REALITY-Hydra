//! The REALITY-Hydra self-tunnel **exit node**.
//!
//! Runs on a Linux VPS outside the censored network. It terminates TLS, reads the
//! one [`tunnel_proto`] CONNECT header the client sends, authenticates it with the
//! shared `master_secret`, dials the real destination itself, and relays bytes.
//! This is the half the repo was missing: previously the "server" was always
//! stock Xray. Here there is no Xray — client and server speak only our own
//! protocol.
//!
//! ```text
//!   TLS accept ─▶ read+verify header ─▶ TcpStream::connect(target) ─▶ relay
//! ```
//!
//! Security posture (be honest): the transport is pinned self-signed TLS, not
//! REALITY. It authenticates and encrypts, but a DPI system sees "some TLS to an
//! unknown cert," not "a browser visiting a real CDN." See REALITY.md §7 P7 for
//! why true REALITY needs a patched TLS stack we don't have here.

mod error;
mod tls;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tunnel_proto::{parse_request, reply, ProtoError};

pub use error::ServerError;
pub use tls::TlsMaterial;

/// The largest CONNECT header we will buffer: version(1) + ts(8) + atyp(1) +
/// max domain(1+253) + port(2) + mac(32) = 298; 512 leaves generous headroom
/// and caps how much an unauthenticated peer can make us hold.
const MAX_HEADER: usize = 512;

/// Run the exit node: accept TLS connections on `listen`, authenticate each with
/// `master_secret`, and relay to the destination each header names.
///
/// Runs until the listener errors. Per-connection failures (bad auth, unreachable
/// destination, TLS errors) are logged and never stop the accept loop.
pub async fn serve(
    listen: &str,
    material: TlsMaterial,
    master_secret: Vec<u8>,
    max_skew: u64,
) -> Result<(), ServerError> {
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|source| ServerError::Bind {
            addr: listen.to_string(),
            source,
        })?;
    eprintln!("hydra-server: listening on {listen} (TLS, pinned self-signed)");
    serve_on(listener, material, master_secret, max_skew).await
}

/// Like [`serve`], but runs on an already-bound [`TcpListener`]. Lets callers
/// (and tests) choose the socket — e.g. an ephemeral `127.0.0.1:0` port.
pub async fn serve_on(
    listener: TcpListener,
    material: TlsMaterial,
    master_secret: Vec<u8>,
    max_skew: u64,
) -> Result<(), ServerError> {
    let acceptor = TlsAcceptor::from(material.server_config()?);
    let key = Arc::new(master_secret);

    loop {
        let (tcp, peer) = listener.accept().await.map_err(ServerError::Accept)?;
        let acceptor = acceptor.clone();
        let key = key.clone();
        tokio::spawn(async move {
            let stream = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("hydra-server: TLS handshake from {peer} failed: {e}");
                    return;
                }
            };
            if let Err(e) = handle(stream, &key, max_skew).await {
                eprintln!("hydra-server: connection from {peer}: {e}");
            }
        });
    }
}

/// Handle one authenticated tunnel: read the header, dial the target, relay.
///
/// Generic over the stream so it can be driven by a plain TCP loopback in tests
/// as well as the real `TlsStream` in production.
async fn handle<S>(mut inbound: S, key: &[u8], max_skew: u64) -> Result<(), ServerError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Read until a full header parses. The client sends the header and then waits
    // for our reply before relaying, so bytes read here are header-only.
    let mut buf = Vec::with_capacity(MAX_HEADER);
    let parsed = loop {
        match parse_request(&buf, key, now(), max_skew) {
            Ok(p) => break p,
            Err(ProtoError::Truncated { .. }) => {
                if buf.len() >= MAX_HEADER {
                    return Err(io_err("header exceeded maximum length"));
                }
                let mut tmp = [0u8; MAX_HEADER];
                let n = inbound.read(&mut tmp).await?;
                if n == 0 {
                    return Err(io_err("connection closed before a full header arrived"));
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            Err(e) => {
                // Bad auth / version / address: tell the client, then drop.
                let _ = inbound.write_all(&[reply::AUTH_FAIL]).await;
                return Err(io_err(&format!("rejected header: {e}")));
            }
        }
    };

    let dest = parsed.target.display();

    // Dial the real destination (DNS happens here, on the exit side).
    let mut outbound = match TcpStream::connect(&dest).await {
        Ok(s) => s,
        Err(e) => {
            let _ = inbound.write_all(&[reply::DIAL_FAIL]).await;
            return Err(io_err(&format!("dial {dest} failed: {e}")));
        }
    };

    // Accepted: signal the client so it can begin relaying.
    inbound.write_all(&[reply::OK]).await?;

    // Any bytes read past the header are early payload — forward them first.
    let leftover = &buf[parsed.consumed..];
    if !leftover.is_empty() {
        outbound.write_all(leftover).await?;
    }

    // Full-duplex relay until either side closes.
    let _ = copy_bidirectional(&mut inbound, &mut outbound).await;
    Ok(())
}

/// Current UNIX time in seconds (saturating; only used for the freshness window).
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn io_err(msg: &str) -> ServerError {
    ServerError::Io(std::io::Error::other(msg.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tunnel_proto::{encode_request, Host, Target};

    const KEY: &[u8] = b"integration-test-master-secret!!!";

    /// Drive `handle` over an in-memory duplex against a real echo target, proving
    /// the full path: header verify → dial → relay, no TLS/socket flakiness.
    #[tokio::test]
    async fn relays_to_the_named_target() {
        // A throwaway echo server stands in for "the real destination".
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut b = [0u8; 64];
            let n = s.read(&mut b).await.unwrap();
            s.write_all(&b[..n]).await.unwrap();
        });

        let (client, server) = tokio::io::duplex(4096);

        let handle_task = tokio::spawn(async move { handle(server, KEY, 120).await });

        // Client side: send header for the echo target, read reply, exchange data.
        let target = Target::new(
            Host::V4(match echo_addr.ip() {
                std::net::IpAddr::V4(v4) => v4.octets(),
                _ => unreachable!(),
            }),
            echo_addr.port(),
        );
        let header = encode_request(KEY, now(), &target);
        let mut client = client;
        client.write_all(&header).await.unwrap();

        let mut reply_byte = [0u8; 1];
        client.read_exact(&mut reply_byte).await.unwrap();
        assert_eq!(reply_byte[0], reply::OK);

        client.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");

        drop(client);
        let _ = handle_task.await;
    }

    #[tokio::test]
    async fn bad_auth_is_rejected_with_reply() {
        let (client, server) = tokio::io::duplex(4096);
        let handle_task = tokio::spawn(async move { handle(server, KEY, 120).await });

        let target = Target::new(Host::V4([127, 0, 0, 1]), 9);
        // Sign with the wrong key → MAC fails on the server.
        let header = encode_request(b"WRONG-key-WRONG-key-WRONG-key!!!!", now(), &target);
        let mut client = client;
        client.write_all(&header).await.unwrap();

        let mut reply_byte = [0u8; 1];
        client.read_exact(&mut reply_byte).await.unwrap();
        assert_eq!(reply_byte[0], reply::AUTH_FAIL);

        assert!(handle_task.await.unwrap().is_err());
    }
}
