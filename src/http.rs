// SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)
// SPDX-License-Identifier: GPL-3.0-or-later

//! A minimal HTTP client over the connector: relay lists, NIP-11 documents.

use geohash_relays::params::comm::{HTTP_USER_AGENT, MAX_NIP11_BYTES};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::connector::Connector;
use crate::error::{Error, Result};

/// The NIP-11 document of a relay (`ws[s]://` URL), on the circuit of
/// `isolation`: `None` when the relay has none (not `200`, not JSON).
pub async fn nip11(
    relay: &str,
    isolation: &str,
    connector: &dyn Connector,
) -> Result<Option<String>> {
    let url = if let Some(r) = relay.strip_prefix("wss://") {
        format!("https://{r}")
    } else if let Some(r) = relay.strip_prefix("ws://") {
        format!("http://{r}")
    } else {
        return Err(Error::Http(format!(
            "{relay}: not a ws:// or wss:// address"
        )));
    };
    match get(
        &url,
        "application/nostr+json",
        MAX_NIP11_BYTES,
        isolation,
        connector,
    )
    .await
    {
        Ok(body) => Ok(String::from_utf8(body)
            .ok()
            .filter(|t| serde_json::from_str::<serde_json::Value>(t).is_ok_and(|v| v.is_object()))),
        Err(Error::Http(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// `GET url` through the connector, HTTP/1.0 (no chunked body), TLS for
/// `https://`, with this `Accept` header, on the circuit of `isolation`:
/// the body of a `200` answer, at most `max_bytes`.
pub async fn get(
    url: &str,
    accept: &str,
    max_bytes: usize,
    isolation: &str,
    connector: &dyn Connector,
) -> Result<Vec<u8>> {
    let bad = |what: &str| Error::Http(format!("{url}: {what}"));
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(bad("not an http(s) URL"));
    };
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let path = if path.is_empty() { "/" } else { path };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().map_err(|_| bad("port"))?),
        None => (authority, if tls { 443 } else { 80 }),
    };
    let request = format!(
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: {HTTP_USER_AGENT}\r\nAccept: {accept}\r\nConnection: close\r\n\r\n"
    );
    let stream = connector.connect(host, port, isolation).await?;
    // Some servers keep the connection open whatever the request says: stop
    // at Content-Length when there is one, else at the end of the stream.
    let body = if tls {
        let name = rustls::pki_types::ServerName::try_from(host.to_owned())
            .map_err(|_| bad("host name"))?;
        let mut s = tokio_rustls::TlsConnector::from(crate::relay::tls_config())
            .connect(name, stream)
            .await?;
        s.write_all(request.as_bytes()).await?;
        // TLS buffers writes: without a flush the request never leaves.
        s.flush().await?;
        read_response(&mut s, max_bytes).await?
    } else {
        let mut s = stream;
        s.write_all(request.as_bytes()).await?;
        // TLS buffers writes: without a flush the request never leaves.
        s.flush().await?;
        read_response(&mut s, max_bytes).await?
    };
    let split = body
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| bad("no HTTP header"))?;
    let head = String::from_utf8_lossy(&body[..split]);
    let status = head.split_whitespace().nth(1).unwrap_or("");
    if status != "200" {
        return Err(bad(&format!("HTTP status {status}")));
    }
    let content = &body[split + 4..];
    if content.len() > max_bytes {
        return Err(bad("answer too large"));
    }
    Ok(content.to_vec())
}

/// Reads an HTTP response: the header, then `Content-Length` bytes or up to
/// the end of the stream, about `max_bytes` of body at most.
async fn read_response<S: tokio::io::AsyncRead + Unpin>(
    s: &mut S,
    max_bytes: usize,
) -> std::io::Result<Vec<u8>> {
    let limit = max_bytes + 64 * 1024;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        if let Some(split) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..split]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok());
            if let Some(len) = length
                && buf.len() >= split + 4 + len
            {
                buf.truncate(split + 4 + len);
                return Ok(buf);
            }
        }
        let n = s.read(&mut chunk).await?;
        if n == 0 || buf.len() > limit {
            return Ok(buf);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}
