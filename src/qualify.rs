// SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)
// SPDX-License-Identifier: GPL-3.0-or-later

//! A6 of geohash-relays, run (§7 questions 1 to 3): relays against the
//! requirements, through the connector. Used by bitchat-console
//! (`--qualify`, `--qualify-probe`) and by the census (`relay-census
//! --refresh`, `--probe`).
//!
//! Without `probe`, only the NIP-11 documents are read. With it, one kind
//! 20000 test event per relay, in the probe cell (open sea), signed with a
//! throwaway key, is written and read back: a real publication, so only on
//! the user's request.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use geohash_relays::a6::Prober;
use geohash_relays::params::{A6_PROBE_CELL, KIND_CHANNEL};
use tokio::sync::watch;

use crate::connector::Connector;
use crate::nostr::{Event, unix_now};
use crate::ports::{ConnectorFetch, SystemClock};
use crate::runner::Runner;

/// Qualifies `relays` (normalised): NIP-11 documents, and test events when
/// `probe`. Gives up after `limit`. Returns the prober, and whether it
/// finished.
pub async fn run(
    relays: Vec<String>,
    connector: Arc<dyn Connector>,
    probe: bool,
    limit: Duration,
) -> (Prober, bool) {
    let mut tests = BTreeMap::new();
    if probe {
        let key = throwaway_key();
        let now = unix_now();
        for (i, r) in relays.iter().enumerate() {
            let e = Event::signed(
                &key,
                now,
                KIND_CHANNEL,
                vec![vec!["g".into(), A6_PROBE_CELL.into()]],
                format!("geohash-relays probe {i}"),
            );
            tests.insert(r.clone(), e.meta());
        }
    }
    let runner = Runner {
        connector: connector.clone(),
        clock: Arc::new(SystemClock),
        fetch: Some(Arc::new(ConnectorFetch(connector))),
        isolation: "qualify".into(),
        tick: Duration::from_secs(1),
    };
    let (stop, stop_rx) = watch::channel(false);
    let timeout = stop.clone();
    let timer = tokio::spawn(async move {
        tokio::time::sleep(limit).await;
        let _ = timeout.send(true);
    });
    let prober = Prober::new(relays, tests, &[]);
    let p = runner
        .run(prober, stop_rx, move |p: &Prober| {
            if p.done() {
                let _ = stop.send(true);
            }
        })
        .await;
    timer.abort();
    let complete = p.done();
    if !complete {
        tracing::warn!("qualification stopped after {} s", limit.as_secs());
    }
    (p, complete)
}

/// A key used for the test events of one run only.
fn throwaway_key() -> k256::schnorr::SigningKey {
    let mut seed = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut seed);
    loop {
        if let Ok(k) = k256::schnorr::SigningKey::from_bytes(&seed) {
            return k;
        }
        seed[0] = seed[0].wrapping_add(1);
    }
}
