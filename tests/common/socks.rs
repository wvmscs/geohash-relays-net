// SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)
// SPDX-License-Identifier: GPL-3.0-or-later

//! A SOCKS5 proxy for tests (RFC 1928 + 1929): records the user name, host
//! and port of each `CONNECT`, then connects to the host itself (tests only
//! use local targets) and copies bytes both ways.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// What one `CONNECT` asked for: (user name, host, port).
pub type Request = (String, String, u16);

pub struct TestSocks {
    pub addr: std::net::SocketAddr,
    pub requests: Arc<Mutex<Vec<Request>>>,
}

impl TestSocks {
    pub async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests: Arc<Mutex<Vec<Request>>> = Arc::default();
        let log = requests.clone();
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                let log = log.clone();
                tokio::spawn(async move {
                    let _ = serve(s, log).await;
                });
            }
        });
        TestSocks { addr, requests }
    }

    pub fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }
}

async fn serve(mut s: TcpStream, log: Arc<Mutex<Vec<Request>>>) -> std::io::Result<()> {
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await?;
    let mut methods = vec![0u8; head[1] as usize];
    s.read_exact(&mut methods).await?;
    if !methods.contains(&2) {
        s.write_all(&[5, 0xff]).await?;
        return Ok(());
    }
    s.write_all(&[5, 2]).await?;
    // A bare check (greeting only) ends here.
    let mut ver = [0u8; 2];
    if s.read_exact(&mut ver).await.is_err() {
        return Ok(());
    }
    let mut user = vec![0u8; ver[1] as usize];
    s.read_exact(&mut user).await?;
    let mut plen = [0u8; 1];
    s.read_exact(&mut plen).await?;
    let mut pass = vec![0u8; plen[0] as usize];
    s.read_exact(&mut pass).await?;
    s.write_all(&[1, 0]).await?;
    let mut req = [0u8; 5];
    s.read_exact(&mut req).await?;
    assert_eq!(&req[..4], &[5, 1, 0, 3], "CONNECT to a domain name");
    let mut host = vec![0u8; req[4] as usize];
    s.read_exact(&mut host).await?;
    let mut port = [0u8; 2];
    s.read_exact(&mut port).await?;
    let (host, port) = (String::from_utf8(host).unwrap(), u16::from_be_bytes(port));
    log.lock()
        .unwrap()
        .push((String::from_utf8(user).unwrap(), host.clone(), port));
    match TcpStream::connect((host.as_str(), port)).await {
        Ok(mut target) => {
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            let _ = tokio::io::copy_bidirectional(&mut s, &mut target).await;
        }
        Err(_) => s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?,
    }
    Ok(())
}

/// Echoes what it receives; returns its port.
pub async fn echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}
