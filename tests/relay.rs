// SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)
// SPDX-License-Identifier: GPL-3.0-or-later

//! The relay client of the active feature, against a local relay.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use common::TestRelay;
use geohash_relays_net::connector::Loopback;
use geohash_relays_net::nostr::{Event, Filter, unix_now};
use geohash_relays_net::relay::{ConnState, Policy, RelayEvent, spawn};
use tokio::sync::mpsc;

async fn next(
    rx: &mut mpsc::UnboundedReceiver<RelayEvent>,
    f: impl Fn(&RelayEvent) -> bool,
) -> RelayEvent {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let e = rx.recv().await.expect("connection alive");
            if f(&e) {
                return e;
            }
        }
    })
    .await
    .expect("in time")
}

#[tokio::test]
async fn publishes_reads_and_waits_for_ok() {
    let relay = TestRelay::spawn("127.0.0.1:0").await.unwrap();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let filter = Filter {
        kinds: vec![20000],
        tags: BTreeMap::from([('g', vec!["u09tv".to_owned()])]),
        ..Default::default()
    };
    let conn = spawn(
        relay.url(),
        "u09tv".into(),
        vec![filter],
        Arc::new(Loopback),
        tx,
        None,
    );
    next(&mut rx, |e| {
        matches!(
            e,
            RelayEvent::State {
                state: ConnState::Connected,
                ..
            }
        )
    })
    .await;

    let key = k256::schnorr::SigningKey::from_bytes(&[7u8; 32]).unwrap();
    let e = Event::signed(
        &key,
        unix_now(),
        20000,
        vec![vec!["g".into(), "u09tv".into()]],
        "hi".into(),
    );
    conn.publish(e.clone());
    // The relay sends the event to its subscribers, then its OK: either
    // order is fine.
    let (mut ok, mut seen) = (false, false);
    while !(ok && seen) {
        match next(&mut rx, |e| {
            matches!(e, RelayEvent::Ok { .. } | RelayEvent::Event { .. })
        })
        .await
        {
            RelayEvent::Ok { accepted, id, .. } => {
                assert!(accepted && id == e.id);
                ok = true;
            }
            RelayEvent::Event { event, .. } => {
                assert_eq!(event.id, e.id);
                assert_eq!(event.meta().tag("g"), Some("u09tv"));
                seen = true;
            }
            _ => unreachable!(),
        }
    }
}

#[tokio::test]
async fn retries_with_the_feature_policy() {
    // Nothing listens there: the connection waits, then tries again.
    let (tx, mut rx) = mpsc::unbounded_channel();
    let _conn = spawn(
        "ws://127.0.0.1:9".into(),
        "u0".into(),
        vec![],
        Arc::new(Loopback),
        tx,
        None,
    );
    let w = next(&mut rx, |e| {
        matches!(
            e,
            RelayEvent::State {
                state: ConnState::Waiting { .. },
                ..
            }
        )
    })
    .await;
    let RelayEvent::State {
        state: ConnState::Waiting { retry_in_secs },
        ..
    } = w
    else {
        unreachable!()
    };
    assert!(retry_in_secs <= 1, "{retry_in_secs}");
    assert_eq!(
        geohash_relays_net::IMPLEMENTATION,
        if cfg!(feature = "bitchat") {
            "bitchat"
        } else if cfg!(feature = "bitchat-android") {
            "bitchat-android"
        } else {
            "console"
        }
    );
    let p = Policy::current();
    if cfg!(feature = "bitchat") {
        assert_eq!(p, Policy::IOS);
    } else {
        assert_eq!(p, Policy::CONSOLE);
    }
}
