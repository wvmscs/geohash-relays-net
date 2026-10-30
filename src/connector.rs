// SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)
// SPDX-License-Identifier: GPL-3.0-or-later

//! How a client reaches a relay. The console: through Tor, never in clear
//! (its decision D1). The apps (features `bitchat`, `bitchat-android`): Tor
//! by default, but the user can turn it off, hence [`Direct`] in those
//! features only.
//!
//! A [`Connector`] opens a byte stream to `host:port` for an *isolation key*.
//! Streams with different keys go through different Tor circuits, so that a
//! relay cannot link the keys of two cells by their exit address (D20: one
//! key per cell). With a Tor daemon, the key is the SOCKS5 user name
//! (`IsolateSOCKSAuth`, on by default in Tor); with Arti (lot 11), an
//! isolation token.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{Error, Result};

/// A connected byte stream (TCP through Tor, or Arti's stream).
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

pub type BoxStream = Box<dyn Stream>;
pub type Connecting<'a> = Pin<Box<dyn Future<Output = io::Result<BoxStream>> + Send + 'a>>;
pub type Resolving<'a> = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>>;

/// Opens streams to relays.
pub trait Connector: Send + Sync {
    /// A stream to `host:port`. `isolation` names who the stream is for
    /// (a cell): streams with different keys must not share a circuit.
    fn connect<'a>(&'a self, host: &'a str, port: u16, isolation: &'a str) -> Connecting<'a>;

    /// For logs and the page: `"tor 127.0.0.1:9050"`, `"loopback (tests)"`.
    fn describe(&self) -> String;

    /// The addresses of `host`, resolved where this connector resolves
    /// names (through Tor: by the exit, never locally), on the circuit of
    /// `isolation`. For the census's geolocation (lot 13).
    fn resolve<'a>(&'a self, host: &'a str, isolation: &'a str) -> Resolving<'a> {
        let _ = (host, isolation);
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "this connector does not resolve names",
            ))
        })
    }
}

/// A literal address (`[v6]` too), without resolving anything.
fn literal(host: &str) -> Option<IpAddr> {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .ok()
}

/// Time allowed to reach the proxy and get its answer, Tor circuit included.
pub use geohash_relays::params::comm::CONNECT_TIMEOUT;
use geohash_relays::params::comm::{PROXY_CHECK_TIMEOUT, RESOLVE_TIMEOUT};

/// Tor (or any SOCKS5 proxy that isolates by user name) at `proxy`. Host
/// names are resolved by Tor, never locally.
#[derive(Debug, Clone)]
pub struct Socks5 {
    proxy: SocketAddr,
}

impl Socks5 {
    pub fn new(proxy: SocketAddr) -> Self {
        Socks5 { proxy }
    }

    /// Checks that a SOCKS5 proxy answers at the address, before anything
    /// else is tried: no Tor, no console (D1).
    pub async fn check(&self) -> Result<()> {
        let unavailable = || Error::TorUnavailable(self.proxy.to_string());
        let mut s = tokio::time::timeout(PROXY_CHECK_TIMEOUT, TcpStream::connect(self.proxy))
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?;
        s.write_all(&[5, 1, 2]).await.map_err(|_| unavailable())?;
        let mut answer = [0u8; 2];
        tokio::time::timeout(PROXY_CHECK_TIMEOUT, s.read_exact(&mut answer))
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?;
        if answer != [5, 2] {
            return Err(unavailable());
        }
        Ok(())
    }

    async fn open(&self, host: &str, port: u16, isolation: &str) -> io::Result<BoxStream> {
        let mut s = TcpStream::connect(self.proxy).await?;
        s.set_nodelay(true)?;
        handshake(&mut s, CONNECT, host, port, isolation).await?;
        Ok(Box::new(s))
    }

    /// Tor's `RESOLVE` extension of SOCKS5: the exit resolves the name.
    async fn ask(&self, host: &str, isolation: &str) -> io::Result<Vec<IpAddr>> {
        if let Some(ip) = literal(host) {
            return Ok(vec![ip]);
        }
        let mut s = TcpStream::connect(self.proxy).await?;
        match handshake(&mut s, TOR_RESOLVE, host, 0, isolation).await? {
            Some(ip) => Ok(vec![ip]),
            None => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SOCKS5: no address in the answer",
            )),
        }
    }
}

impl Connector for Socks5 {
    fn connect<'a>(&'a self, host: &'a str, port: u16, isolation: &'a str) -> Connecting<'a> {
        Box::pin(async move {
            tokio::time::timeout(CONNECT_TIMEOUT, self.open(host, port, isolation))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no answer through Tor"))?
        })
    }

    fn describe(&self) -> String {
        format!("tor {}", self.proxy)
    }

    fn resolve<'a>(&'a self, host: &'a str, isolation: &'a str) -> Resolving<'a> {
        Box::pin(async move {
            tokio::time::timeout(RESOLVE_TIMEOUT, self.ask(host, isolation))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no answer through Tor"))?
        })
    }
}

/// SOCKS5 `CONNECT`.
const CONNECT: u8 = 1;
/// Tor's SOCKS5 extension: resolve a name (the port is ignored).
const TOR_RESOLVE: u8 = 0xF0;

/// SOCKS5 user name and password for an isolation key: Tor isolates streams
/// whose credentials differ. Neither is a secret.
fn credentials(isolation: &str) -> (Vec<u8>, &'static [u8]) {
    let mut user = format!("bitchat-console/{isolation}").into_bytes();
    user.truncate(255);
    (user, b"x")
}

/// RFC 1928 (SOCKS5) with RFC 1929 user name and password, `command`
/// ([`CONNECT`], or Tor's [`TOR_RESOLVE`]) for a domain name (resolved by
/// the proxy). Returns the bound address of the answer: the address the
/// name resolved to, for [`TOR_RESOLVE`].
async fn handshake(
    s: &mut TcpStream,
    command: u8,
    host: &str,
    port: u16,
    isolation: &str,
) -> io::Result<Option<IpAddr>> {
    let bad = |what: &str| io::Error::new(io::ErrorKind::InvalidData, format!("SOCKS5: {what}"));
    s.write_all(&[5, 1, 2]).await?;
    let mut answer = [0u8; 2];
    s.read_exact(&mut answer).await?;
    if answer != [5, 2] {
        return Err(bad("the proxy refuses user name authentication"));
    }
    let (user, pass) = credentials(isolation);
    let mut auth = vec![1, user.len() as u8];
    auth.extend_from_slice(&user);
    auth.push(pass.len() as u8);
    auth.extend_from_slice(pass);
    s.write_all(&auth).await?;
    s.read_exact(&mut answer).await?;
    if answer[1] != 0 {
        return Err(bad("authentication refused"));
    }
    if host.is_empty() || host.len() > 255 {
        return Err(bad("host name length"));
    }
    let mut req = vec![5, command, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Err(bad("not a SOCKS5 answer"));
    }
    if head[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("SOCKS5: {}", reply_text(head[1])),
        ));
    }
    // The bound address (and port).
    let len = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await?;
            len[0] as usize
        }
        _ => return Err(bad("bound address type")),
    };
    let mut rest = vec![0u8; len + 2];
    s.read_exact(&mut rest).await?;
    Ok(match head[3] {
        1 => Some(IpAddr::from(
            <[u8; 4]>::try_from(&rest[..4]).expect("4 bytes"),
        )),
        4 => Some(IpAddr::from(
            <[u8; 16]>::try_from(&rest[..16]).expect("16 bytes"),
        )),
        _ => None,
    })
}

fn reply_text(code: u8) -> &'static str {
    match code {
        1 => "general failure",
        2 => "connection not allowed",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused",
        6 => "TTL expired",
        7 => "command not supported",
        8 => "address type not supported",
        _ => "unknown error",
    }
}

/// Direct connections to the loopback address only, for tests against a
/// local relay: any other host is refused, so this can never leak a
/// connection in clear to a real relay.
#[derive(Debug, Clone, Default)]
pub struct Loopback;

/// A loopback host: `localhost`, `127.x.x.x`, `::1`.
pub fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

impl Connector for Loopback {
    fn connect<'a>(&'a self, host: &'a str, port: u16, _isolation: &'a str) -> Connecting<'a> {
        Box::pin(async move {
            if !is_loopback(host) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("{host} is not a loopback address: real relays need Tor"),
                ));
            }
            let s = TcpStream::connect((host.trim_start_matches('[').trim_end_matches(']'), port))
                .await?;
            Ok(Box::new(s) as BoxStream)
        })
    }

    fn describe(&self) -> String {
        "loopback (tests)".into()
    }

    fn resolve<'a>(&'a self, host: &'a str, _isolation: &'a str) -> Resolving<'a> {
        Box::pin(async move {
            match literal(host) {
                Some(ip) if ip.is_loopback() => Ok(vec![ip]),
                _ if host.eq_ignore_ascii_case("localhost") => {
                    Ok(vec![IpAddr::from([127, 0, 0, 1])])
                }
                _ => Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("{host} is not a loopback address"),
                )),
            }
        })
    }
}

/// Direct TCP connections, without Tor, as the apps make when the user
/// turns Tor off (`userTorEnabled`, `TorMode`). Features `bitchat` and
/// `bitchat-android`, and `census` on request (`--direct`): the console
/// never connects in clear.
#[cfg(any(feature = "bitchat", feature = "bitchat-android", feature = "census"))]
#[derive(Debug, Clone, Default)]
pub struct Direct;

#[cfg(any(feature = "bitchat", feature = "bitchat-android", feature = "census"))]
impl Connector for Direct {
    fn connect<'a>(&'a self, host: &'a str, port: u16, _isolation: &'a str) -> Connecting<'a> {
        Box::pin(async move {
            let host = host.trim_start_matches('[').trim_end_matches(']');
            let s = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no answer"))??;
            Ok(Box::new(s) as BoxStream)
        })
    }

    fn describe(&self) -> String {
        "direct (no Tor)".into()
    }

    fn resolve<'a>(&'a self, host: &'a str, _isolation: &'a str) -> Resolving<'a> {
        Box::pin(async move {
            if let Some(ip) = literal(host) {
                return Ok(vec![ip]);
            }
            let found = tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((host, 0)))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no DNS answer"))??;
            Ok(found.map(|a| a.ip()).collect())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_hosts() {
        for h in ["localhost", "127.0.0.1", "127.8.9.10", "::1", "[::1]"] {
            assert!(is_loopback(h), "{h}");
        }
        for h in [
            "relay.damus.io",
            "10.0.0.1",
            "192.168.1.2",
            "example.com",
            "",
        ] {
            assert!(!is_loopback(h), "{h}");
        }
    }

    #[test]
    fn credentials_isolate_by_key() {
        assert_ne!(credentials("u09tv").0, credentials("u09tw").0);
        assert_eq!(credentials("u09tv").0, b"bitchat-console/u09tv");
        assert_eq!(credentials(&"x".repeat(400)).0.len(), 255);
    }
}
