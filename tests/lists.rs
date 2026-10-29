// SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)
// SPDX-License-Identifier: GPL-3.0-or-later

//! Relay lists: download through the connector, cache, fallback, refusals.

mod common;

use std::sync::{Arc, Mutex};

use geohash_relays::Platform;
use geohash_relays_net::Error;
use geohash_relays_net::connector::{Loopback, Socks5};
use geohash_relays_net::lists::{ListSource, load};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// An HTTP server whose answer the test changes: `Some(body)` is a 200,
/// `None` a 500.
async fn list_server(body: Option<String>) -> (String, Arc<Mutex<Option<String>>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/relays.csv", l.local_addr().unwrap());
    let body = Arc::new(Mutex::new(body));
    let shared = body.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf).await;
            let answer = match shared.lock().unwrap().clone() {
                Some(b) => format!("HTTP/1.0 200 OK\r\nContent-Type: text/csv\r\n\r\n{b}"),
                None => "HTTP/1.0 500 Oops\r\n\r\n".to_owned(),
            };
            let _ = s.write_all(answer.as_bytes()).await;
        }
    });
    (url, body)
}

fn temp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "bitchat-console-lists-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    d
}

const LIST: &str =
    "Relay URL,Latitude,Longitude\nrelay.one.example,48.85,2.35\nrelay.two.example,50.1,8.6\n";

#[tokio::test]
async fn downloaded_then_cached() {
    let cache = temp("cache");
    let (url, body) = list_server(Some(LIST.into())).await;
    let src = ListSource::parse(&url);
    let dir = load(&src, Platform::Ios, Arc::new(Loopback), &cache)
        .await
        .unwrap();
    assert_eq!(dir.len(), 2);
    assert!(cache.join("ios.csv").exists());

    // Download fails: the cached copy is used.
    *body.lock().unwrap() = None;
    assert_eq!(
        load(&src, Platform::Ios, Arc::new(Loopback), &cache)
            .await
            .unwrap()
            .len(),
        2
    );
    // A list iOS refuses (a host at two places): the cached copy too.
    *body.lock().unwrap() = Some(format!("{LIST}relay.one.example,10.0,10.0\n"));
    assert_eq!(
        load(&src, Platform::Ios, Arc::new(Loopback), &cache)
            .await
            .unwrap()
            .len(),
        2
    );
    // Android does not check that.
    let dir = load(&src, Platform::Android, Arc::new(Loopback), &cache)
        .await
        .unwrap();
    assert_eq!(dir.len(), 3);
    std::fs::remove_dir_all(&cache).unwrap();
}

#[tokio::test]
async fn no_list_no_cache_is_an_error() {
    let cache = temp("none");
    let (url, _) = list_server(None).await;
    match load(
        &ListSource::parse(&url),
        Platform::Ios,
        Arc::new(Loopback),
        &cache,
    )
    .await
    {
        Err(Error::NoRelayList { platform, reason }) => {
            assert_eq!(platform, "ios");
            assert!(reason.contains("500"), "{reason}");
        }
        other => panic!("{other:?}"),
    }
    // A local file is read as is, never cached.
    let file =
        std::env::temp_dir().join(format!("bitchat-console-list-{}.csv", std::process::id()));
    std::fs::write(&file, LIST).unwrap();
    let dir = load(
        &ListSource::Path(file.clone()),
        Platform::Ios,
        Arc::new(Loopback),
        &cache,
    )
    .await
    .unwrap();
    assert_eq!(dir.len(), 2);
    assert!(!cache.join("ios.csv").exists());
    std::fs::remove_file(file).unwrap();
}

#[tokio::test]
async fn lists_come_through_tor() {
    // Through the SOCKS proxy, under their own isolation key.
    let proxy = common::socks::TestSocks::spawn().await;
    let cache = temp("tor");
    let (url, _) = list_server(Some(LIST.into())).await;
    let dir = load(
        &ListSource::parse(&url),
        Platform::Ios,
        Arc::new(Socks5::new(proxy.addr)),
        &cache,
    )
    .await
    .unwrap();
    assert_eq!(dir.len(), 2);
    let r = proxy.requests();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].0, "bitchat-console/relay-lists");
    let _ = std::fs::remove_dir_all(&cache);
}

#[tokio::test]
async fn a_server_that_keeps_the_connection_open() {
    // Like the CDN of raw.githubusercontent.com: Content-Length, no close.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/relays.csv", l.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let answer = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{LIST}",
                    LIST.len()
                );
                let _ = s.write_all(answer.as_bytes()).await;
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            });
        }
    });
    let cache = temp("keepalive");
    let dir = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        load(
            &ListSource::parse(&url),
            Platform::Ios,
            Arc::new(Loopback),
            &cache,
        ),
    )
    .await
    .expect("hung on an open connection")
    .unwrap();
    assert_eq!(dir.len(), 2);
    let _ = std::fs::remove_dir_all(&cache);
}
