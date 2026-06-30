//! Minimal SOCKS5 server (RFC 1928) for the Hydra client inbound.
//!
//! Handles the SOCKS5 handshake and CONNECT command, then relays raw bytes
//! between the app and the Hydra pipeline. Supports:
//!
//! - No-auth (method `0x00`)
//! - CONNECT command (command `0x01`)
//! - IPv4, domain, and IPv6 address types
//!
//! This is intentionally minimal — a proof-of-concept inbound for Phase 5.
//! A production deployment would use a proper SOCKS5 library or a different
//! inbound (e.g. tun, HTTP proxy).

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The address the app wants to connect to, parsed from the SOCKS5 CONNECT
/// request.
#[derive(Clone, Debug)]
pub enum Socks5Addr {
    IPv4([u8; 4], u16),
    Domain(String, u16),
    IPv6([u8; 16], u16),
}

impl Socks5Addr {
    /// Display as `host:port` for logging.
    pub fn display(&self) -> String {
        match self {
            Socks5Addr::IPv4(a, p) => format!("{}.{}.{}.{}:{p}", a[0], a[1], a[2], a[3]),
            Socks5Addr::Domain(d, p) => format!("{d}:{p}"),
            Socks5Addr::IPv6(a, p) => {
                let s = a
                    .chunks(2)
                    .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                    .collect::<Vec<_>>()
                    .join(":");
                format!("[{s}]:{p}")
            }
        }
    }
}

/// Perform the SOCKS5 handshake on `stream`, returning the CONNECT target
/// address on success.
///
/// This consumes the greeting + request bytes from the stream and sends the
/// success reply. The caller then relays data between `stream` and the
/// outbound connection.
pub async fn handshake(stream: &mut TcpStream) -> Result<Socks5Addr, String> {
    // --- Greeting ---
    let ver = read_u8(stream).await?;
    if ver != 0x05 {
        return Err(format!("SOCKS5: unexpected version {ver}"));
    }
    let nmethods = read_u8(stream).await? as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await.map_err(|e| e.to_string())?;

    // Reply: no auth required.
    stream.write_all(&[0x05, 0x00]).await.map_err(|e| e.to_string())?;

    // --- CONNECT request ---
    let ver = read_u8(stream).await?;
    if ver != 0x05 {
        return Err(format!("SOCKS5: request version {ver}"));
    }
    let cmd = read_u8(stream).await?;
    if cmd != 0x01 {
        // Only CONNECT is supported.
        send_reply(stream, 0x07).await?;
        return Err(format!("SOCKS5: unsupported command {cmd}"));
    }
    let _rsv = read_u8(stream).await?;
    let atyp = read_u8(stream).await?;

    let addr = match atyp {
        0x01 => {
            // IPv4
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
            let port = read_u16(stream).await?;
            Socks5Addr::IPv4(buf, port)
        }
        0x03 => {
            // Domain
            let len = read_u8(stream).await? as usize;
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
            let domain = String::from_utf8(buf).map_err(|e| format!("SOCKS5: bad domain: {e}"))?;
            let port = read_u16(stream).await?;
            Socks5Addr::Domain(domain, port)
        }
        0x04 => {
            // IPv6
            let mut buf = [0u8; 16];
            stream.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
            let port = read_u16(stream).await?;
            Socks5Addr::IPv6(buf, port)
        }
        other => {
            send_reply(stream, 0x08).await?;
            return Err(format!("SOCKS5: unsupported address type {other}"));
        }
    };

    // Success reply.
    send_reply(stream, 0x00).await?;
    Ok(addr)
}

async fn send_reply(stream: &mut TcpStream, status: u8) -> Result<(), String> {
    // VER=5, REP=status, RSV=0, ATYP=1 (IPv4 0.0.0.0:0)
    stream
        .write_all(&[0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(|e| e.to_string())
}

async fn read_u8(stream: &mut TcpStream) -> Result<u8, String> {
    stream.read_u8().await.map_err(|e| e.to_string())
}

async fn read_u16(stream: &mut TcpStream) -> Result<u16, String> {
    stream.read_u16().await.map_err(|e| e.to_string())
}
