// SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)
// SPDX-License-Identifier: GPL-3.0-or-later

//! What a client of its own does with the two crates (`docs/integration.md`):
//! read a relay list, choose a cell's relays with a strategy, and listen to
//! them. Read only: nothing is published.
//!
//!   cargo run --features client --example client -- <list.csv> <cell> [--listen] [--tor 127.0.0.1:9050]
//!
//! Without `--listen`, it only prints each strategy's relays for the cell.
//! With it, it subscribes to kinds 20000 and 20001 of the cell on the
//! relays of the apps' choice for 30 s and counts what comes; it never shows
//! a content, a key or a nickname.

use std::sync::Arc;
use std::time::Duration;

use geohash_relays::a0::SharedStrategy;
use geohash_relays::a1::{HrwStrategy, Salts};
use geohash_relays::params::{KIND_CHANNEL, KIND_PRESENCE};
use geohash_relays::{AirhopStrategy, AppStrategy, Apps, Platform, RelayDirectory, Strategy};
use geohash_relays_net::connector::{Connector, Direct, Socks5};
use geohash_relays_net::nostr::{Filter, unix_now};
use geohash_relays_net::relay::{self, RelayEvent};
use tokio::sync::mpsc;

fn usage() -> ! {
    eprintln!("usage: client <list.csv> <cell> [--listen] [--tor 127.0.0.1:9050]");
    std::process::exit(2)
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [list, cell, rest @ ..] = args.as_slice() else {
        usage()
    };
    let listen = rest.iter().any(|a| a == "--listen");
    let tor = rest.iter().position(|a| a == "--tor").map(|i| {
        rest.get(i + 1)
            .unwrap_or_else(|| usage())
            .parse()
            .unwrap_or_else(|_| usage())
    });

    // 1. A list: georelays' format, `Relay URL,Latitude,Longitude`. In an
    //    app, `lists::load` fetches it and keeps a cached copy.
    let csv = std::fs::read_to_string(list).unwrap_or_else(|e| {
        eprintln!("{list}: {e}");
        std::process::exit(1)
    });
    let ios_rule = RelayDirectory::parse(&csv, Platform::Ios);
    let android_rule = RelayDirectory::parse(&csv, Platform::Android);

    // 2. Strategies: the same `Strategy` trait for all of them.
    let strategies: Vec<(&str, Box<dyn Strategy>)> = vec![
        (
            "apps (iOS + Android rules)",
            Box::new(AppStrategy::new(
                Some(ios_rule.clone()),
                Some(android_rule.clone()),
                Apps::Both,
            )),
        ),
        (
            "AirHop",
            Box::new(AirhopStrategy::from_directory(&android_rule)),
        ),
        (
            "A0",
            Box::new(SharedStrategy::from_directory(ios_rule.clone())),
        ),
        (
            "A1 (one salt)",
            Box::new(
                HrwStrategy::new(&ios_rule)
                    .with_salts(Salts::Fixed(b"example".to_vec()), unix_now()),
            ),
        ),
    ];
    for (name, s) in &strategies {
        let read = s.read(cell).unwrap_or_else(|e| {
            eprintln!("{cell}: {e}");
            std::process::exit(2)
        });
        let write = s.write(cell).expect("the cell was valid for read");
        println!("{name}: read {}, write {}", read.len(), write.len());
        for r in &read {
            println!("  #{:<2} {:>8.0} km  {}", r.rank, r.relay.km, r.relay.url);
        }
    }
    if !listen {
        return;
    }

    // 3. Listening: one connection per relay, for this cell. Through Tor
    //    with `--tor` (one circuit per cell: the isolation key is the cell),
    //    else directly.
    let connector: Arc<dyn Connector> = match tor {
        Some(proxy) => Arc::new(Socks5::new(proxy)),
        None => Arc::new(Direct),
    };
    let filter = Filter {
        kinds: vec![KIND_CHANNEL, KIND_PRESENCE],
        since: Some(unix_now() - 3600),
        tags: [('g', vec![cell.clone()])].into(),
        ..Filter::default()
    };
    let (tx, mut rx) = mpsc::unbounded_channel();
    let apps = &strategies[0].1;
    let handles: Vec<_> = apps
        .read(cell)
        .expect("checked above")
        .into_iter()
        .map(|s| {
            relay::spawn(
                s.relay.url,
                cell.clone(),
                vec![filter.clone()],
                connector.clone(),
                tx.clone(),
                None,
            )
        })
        .collect();
    let (mut events, mut connected) = (0usize, 0usize);
    let until = tokio::time::Instant::now() + Duration::from_secs(30);
    while let Ok(Some(e)) = tokio::time::timeout_at(until, rx.recv()).await {
        match e {
            RelayEvent::Event { .. } => events += 1,
            RelayEvent::State { relay, state, .. } => {
                if state == relay::ConnState::Connected {
                    connected += 1;
                }
                println!("{relay}: {state:?}");
            }
            RelayEvent::Closed { relay, reason, .. } => println!("{relay}: closed: {reason}"),
            _ => {}
        }
    }
    println!(
        "{} relays, {connected} connections made, {events} events of #{cell} in 30 s",
        handles.len()
    );
}
