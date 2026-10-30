// SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)
// SPDX-License-Identifier: GPL-3.0-or-later

//! The census against a local relay: its relay lists are read, the newest
//! of each author kept, the relays they name added and read in a next round
//! (here they cannot be reached: the loopback connector refuses them), the
//! relay that answered qualified.

#![cfg(feature = "census")]

mod common;

use std::sync::Arc;

use common::TestRelay;
use geohash_relays::params::KIND_RELAY_LIST;
use geohash_relays_net::census::{self, Refresh, Store};
use geohash_relays_net::connector::Loopback;
use geohash_relays_net::nostr::{Event, unix_now};

fn relay_list(seed: u8, created_at: i64, relays: &[&str]) -> Event {
    let key = k256::schnorr::SigningKey::from_bytes(&[seed; 32]).unwrap();
    Event::signed(
        &key,
        created_at,
        KIND_RELAY_LIST,
        relays
            .iter()
            .map(|r| vec!["r".into(), (*r).into()])
            .collect(),
        String::new(),
    )
}

#[tokio::test]
async fn a_refresh_reads_lists_and_follows_them() {
    let relay = TestRelay::spawn("127.0.0.1:0").await.unwrap();
    let now = unix_now();
    // Alice changed her list: only the newest counts. Bob names a local
    // address, which is not a public relay.
    relay.publish(relay_list(1, now - 100, &["wss://old.example.org"]));
    relay.publish(relay_list(
        1,
        now - 10,
        &["wss://new.example.org", "wss://other.example.org/"],
    ));
    relay.publish(relay_list(
        2,
        now - 50,
        &["wss://new.example.org", "ws://127.0.0.1:1"],
    ));

    let mut store = Store::open_in_memory().unwrap();
    store.give(&[relay.url()], now).unwrap();
    let how = Refresh {
        rounds: 3,
        probe: false,
    };
    let report = census::refresh(&mut store, Arc::new(Loopback), None, &how)
        .await
        .unwrap();

    // Round 1: the local relay, 3 valid lists read (2 of them Alice's),
    // 2 relays named; round 2: those, unreachable; nothing new after.
    assert_eq!(report.rounds.len(), 2, "{report:?}");
    let first = &report.rounds[0];
    assert_eq!((first.read, first.answered, first.new), (1, 1, 2));
    assert_eq!(first.lists, 2, "one list per author");
    let second = &report.rounds[1];
    assert_eq!((second.read, second.answered, second.new), (2, 0, 0));

    assert_eq!(
        store.relays().unwrap(),
        [
            relay.url(),
            "wss://new.example.org".to_owned(),
            "wss://other.example.org".to_owned()
        ]
    );
    assert_eq!(store.mentions("wss://new.example.org").unwrap(), 2);
    assert_eq!(store.mentions("wss://old.example.org").unwrap(), 0);
    let s = store.summary().unwrap();
    assert_eq!((s.relays, s.given, s.answered, s.lists), (3, 1, 1, 2));
    // The relay that answered is qualified (no NIP-11 document here: no
    // refusal); a `ws://` relay is not for the apps' lists.
    assert_eq!((report.qualified, s.usable), (1, 1));
    let mut csv = Vec::new();
    assert_eq!(census::bitchat_csv(&store, &mut csv).unwrap(), 0);
    relay.shutdown().await;
}
