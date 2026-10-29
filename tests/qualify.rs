// SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)
// SPDX-License-Identifier: GPL-3.0-or-later

//! A6 through the runner: a probe writes its test event and reads it back.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use common::TestRelay;
use geohash_relays::a6::Prober;
use geohash_relays::params::A6_PROBE_CELL;
use geohash_relays_net::connector::Loopback;
use geohash_relays_net::nostr::{Event, unix_now};
use geohash_relays_net::ports::{ConnectorFetch, SystemClock};
use geohash_relays_net::runner::Runner;
use tokio::sync::watch;

#[tokio::test]
async fn a_probe_writes_and_reads_back() {
    let relay = TestRelay::spawn("127.0.0.1:0").await.unwrap();
    let key = k256::schnorr::SigningKey::from_bytes(&[9u8; 32]).unwrap();
    let test = Event::signed(
        &key,
        unix_now(),
        20000,
        vec![vec!["g".into(), A6_PROBE_CELL.into()]],
        "probe".into(),
    );
    let prober = Prober::new(
        vec![relay.url()],
        BTreeMap::from([(relay.url(), test.meta())]),
        &[],
    );
    let runner = Runner {
        connector: Arc::new(Loopback),
        clock: Arc::new(SystemClock),
        fetch: Some(Arc::new(ConnectorFetch(Arc::new(Loopback)))),
        isolation: "qualify".into(),
        tick: Duration::from_millis(200),
    };
    let (stop, stop_rx) = watch::channel(false);
    let p = tokio::time::timeout(
        Duration::from_secs(20),
        runner.run(prober, stop_rx, |p: &Prober| {
            if p.done() {
                let _ = stop.send(true);
            }
        }),
    )
    .await
    .expect("probe finished");
    let q = p.qualification();
    let v = &q.verdicts[&relay.url()];
    assert!(v.usable() && v.probed, "{v:?}");
    // Delivered live, not kept (the test relay keeps no ephemeral event):
    // R11 warns.
    assert_eq!(
        v.warnings
            .iter()
            .map(|w| w.requirement())
            .collect::<Vec<_>>(),
        ["R11"]
    );
    // The test relay has no NIP-11 document.
    assert!(p.nip11_of(&relay.url()).is_none());
}
