// SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)
// SPDX-License-Identifier: GPL-3.0-or-later

//! A4 through the runner: an "iOS" relay and an "Android" relay with no
//! common reader; the republisher connects them, once, without loops.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use common::TestRelay;
use geohash_relays::a4::{Plan, Republisher};
use geohash_relays_net::connector::Loopback;
use geohash_relays_net::nostr::{Event, unix_now};
use geohash_relays_net::ports::SystemClock;
use geohash_relays_net::runner::Runner;
use tokio::sync::watch;

fn runner() -> Runner {
    Runner {
        connector: Arc::new(Loopback),
        clock: Arc::new(SystemClock),
        fetch: None,
        isolation: "a4".into(),
        tick: Duration::from_millis(200),
    }
}

#[tokio::test]
async fn connects_two_relay_sets_once() {
    let (ios, android) = (
        TestRelay::spawn("127.0.0.1:0").await.unwrap(),
        TestRelay::spawn("127.0.0.1:0").await.unwrap(),
    );
    let plan = Plan {
        cells: BTreeMap::from([(
            "u09tv".to_owned(),
            BTreeSet::from([ios.url(), android.url()]),
        )]),
    };
    // Two republishers on the same sets: no loop between them.
    let (stop, stop_rx) = watch::channel(false);
    let r1 = tokio::spawn({
        let (plan, stop_rx) = (plan.clone(), stop_rx.clone());
        async move { runner().run(Republisher::new(plan), stop_rx, |_| {}).await }
    });
    let r2 =
        tokio::spawn(async move { runner().run(Republisher::new(plan), stop_rx, |_| {}).await });
    tokio::time::sleep(Duration::from_millis(500)).await;

    let key = k256::schnorr::SigningKey::from_bytes(&[3u8; 32]).unwrap();
    let e = Event::signed(
        &key,
        unix_now(),
        20000,
        vec![vec!["g".into(), "u09tv".into()]],
        "from iOS".into(),
    );
    ios.publish(e.clone());
    // Settle (3 s) plus a tick.
    let mut got = 0;
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        got = android.received(&e.id);
        if got > 0 {
            break;
        }
    }
    assert!(got >= 1, "never republished");
    tokio::time::sleep(Duration::from_secs(4)).await;
    // At most one publication per republisher, and none back to iOS.
    assert!(android.received(&e.id) <= 2, "{}", android.received(&e.id));
    assert_eq!(ios.received(&e.id), 0);
    stop.send(true).unwrap();
    let (m1, m2) = (r1.await.unwrap(), r2.await.unwrap());
    let total = m1.counters().republished + m2.counters().republished;
    assert!((1..=2).contains(&total), "{total}");
}
