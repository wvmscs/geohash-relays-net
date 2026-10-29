// SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)
// SPDX-License-Identifier: GPL-3.0-or-later

//! The Tor connector against a local SOCKS5 proxy: isolation by user name,
//! names resolved by the proxy, failures, and no clear connection.

mod common;

use common::socks::{TestSocks, echo};
use geohash_relays_net::Error;
use geohash_relays_net::connector::{Connector, Loopback, Socks5};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn round_trip(c: &dyn Connector, port: u16, key: &str) {
    let mut s = c.connect("localhost", port, key).await.unwrap();
    s.write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    s.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"ping");
}

#[tokio::test]
async fn streams_are_isolated_by_cell() {
    let proxy = TestSocks::spawn().await;
    let port = echo().await;
    let tor = Socks5::new(proxy.addr);
    tor.check().await.unwrap();
    round_trip(&tor, port, "u09tv").await;
    round_trip(&tor, port, "u09tw").await;
    round_trip(&tor, port, "u09tv").await;
    let users: Vec<String> = proxy.requests().into_iter().map(|r| r.0).collect();
    assert_eq!(
        users,
        [
            "bitchat-console/u09tv",
            "bitchat-console/u09tw",
            "bitchat-console/u09tv"
        ]
    );
    // The name goes to the proxy unresolved.
    assert!(
        proxy
            .requests()
            .iter()
            .all(|r| r.1 == "localhost" && r.2 == port)
    );
    assert_eq!(tor.describe(), format!("tor {}", proxy.addr));
}

#[tokio::test]
async fn no_tor_no_console() {
    // Nothing listens there.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = closed.local_addr().unwrap();
    drop(closed);
    match Socks5::new(addr).check().await {
        Err(Error::TorUnavailable(at)) => assert_eq!(at, addr.to_string()),
        other => panic!("{other:?}"),
    }
    // Something that is not a SOCKS5 proxy.
    let port = echo().await;
    let not_socks = format!("127.0.0.1:{port}").parse().unwrap();
    assert!(matches!(
        Socks5::new(not_socks).check().await,
        Err(Error::TorUnavailable(_))
    ));
}

#[tokio::test]
async fn refused_targets_say_why() {
    let proxy = TestSocks::spawn().await;
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let err = match Socks5::new(proxy.addr)
        .connect("127.0.0.1", port, "u09tv")
        .await
    {
        Err(e) => e,
        Ok(_) => panic!("connected to a closed port"),
    };
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
    assert!(err.to_string().contains("connection refused"), "{err}");
}

#[tokio::test]
async fn loopback_never_leaves_the_machine() {
    let port = echo().await;
    round_trip(&Loopback, port, "u09tv").await;
    let err = match Loopback.connect("relay.damus.io", 443, "u09tv").await {
        Err(e) => e,
        Ok(_) => panic!("clear connection to a real relay"),
    };
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
}
