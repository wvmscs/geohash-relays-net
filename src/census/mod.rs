// SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)
// SPDX-License-Identifier: GPL-3.0-or-later

//! Census of relays (feature `census`, lot 13 of geohash-relays, G15), run
//! by `relay-census`:
//!
//! * relays given by hand ([`Store::give`]);
//! * [`refresh`]: rounds of [`geohash_relays::census::Crawler`] over the
//!   relays known, then over the new ones the relay lists (NIP-65) named,
//!   until none is new; then, for every relay that answered, at the same
//!   time, its place ([`geo`]) and its A6 qualification ([`crate::qualify`]:
//!   NIP-11, and a write test on request);
//! * [`bitchat_csv`]: the relays the apps can use, as their lists give them;
//! * [`legacy`]: the census against the apps' own lists;
//! * [`eligibility`]: for each strategy, the relays it can use and the ones
//!   it leaves out, by reason (a comparison criterion of the strategies).

pub mod geo;
pub mod legacy;
pub mod store;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use geohash_relays::census::{Crawler, Exclusion, STRATEGIES};
use geohash_relays::params::{CENSUS_CONCURRENCY, CENSUS_TIMEOUT_SECS};
use geohash_relays::strategy::Needs;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

pub use geo::{GeoIp, Place};
pub use store::{Listed, Relay, Store, Summary, by_server};

use crate::connector::Connector;
use crate::error::Result;
use crate::nostr::unix_now;
use crate::ports::SystemClock;
use crate::relay::host_port;
use crate::runner::Runner;

/// How a refresh goes.
#[derive(Debug, Clone)]
pub struct Refresh {
    /// Rounds at most.
    pub rounds: usize,
    /// Write and read back a test event on each relay that answered (a real
    /// publication: only on the user's request).
    pub probe: bool,
}

/// What a refresh did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Per round: relays read, answered, valid lists, new relays named.
    pub rounds: Vec<Round>,
    pub located: usize,
    pub qualified: usize,
    /// The qualification ended within its time limit.
    pub qualification_complete: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Round {
    pub read: usize,
    pub answered: usize,
    pub lists: usize,
    pub new: usize,
}

/// Rounds over the relays known, then over the new ones, until none is new
/// or `rounds` is reached; then places and qualifications of the relays
/// read. `geoip`: none, no places.
pub async fn refresh(
    store: &mut Store,
    connector: Arc<dyn Connector>,
    geoip: Option<&GeoIp>,
    how: &Refresh,
) -> Result<Report> {
    let mut report = Report::default();
    let mut to_read = store.relays()?;
    let mut read = BTreeSet::new();
    for n in 1..=how.rounds {
        if to_read.is_empty() {
            break;
        }
        let crawler = round(to_read.clone(), connector.clone()).await;
        let now = unix_now();
        let mut answered = 0;
        for (url, outcome) in crawler.outcomes() {
            store.crawled(url, outcome, now)?;
            answered += usize::from(matches!(
                outcome,
                geohash_relays::census::Outcome::Answered { .. }
            ));
        }
        for list in crawler.lists() {
            store.list(list, now)?;
        }
        read.extend(to_read.iter().cloned());
        let new = store.found(crawler.named(), now)?;
        let r = Round {
            read: to_read.len(),
            answered,
            lists: crawler.lists().count(),
            new: new.len(),
        };
        tracing::info!(
            round = n,
            read = r.read,
            answered = r.answered,
            lists = r.lists,
            new = r.new,
            "census round"
        );
        report.rounds.push(r);
        to_read = new;
    }
    // The relays that answered this time: their place and their verdict.
    let answered: Vec<String> = store
        .answered()?
        .into_iter()
        .filter(|u| read.contains(u))
        .collect();
    // Places and qualifications at the same time: independent, each
    // CENSUS_CONCURRENCY (or A6_CONCURRENCY) at a time.
    let limit = Duration::from_secs(
        (CENSUS_TIMEOUT_SECS as u64) * (answered.len() as u64 / CENSUS_CONCURRENCY as u64 + 2) * 2,
    );
    let placing = async {
        match geoip {
            Some(geoip) => locate(connector.clone(), geoip, &answered).await,
            None => Vec::new(),
        }
    };
    let qualifying = crate::qualify::run(answered.clone(), connector.clone(), how.probe, limit);
    let (places, (prober, complete)) = tokio::join!(placing, qualifying);
    let now = unix_now();
    for (url, place) in places {
        match place {
            Ok(Some(place)) => {
                store.located(&url, &place, now)?;
                report.located += 1;
            }
            Ok(None) => store.not_located(&url, "address not in the geolocation file", now)?,
            Err(why) => store.not_located(&url, &why, now)?,
        }
    }
    let q = prober.qualification();
    for url in &answered {
        if let Some(v) = q.verdicts.get(url) {
            store.qualified(url, prober.nip11_of(url).is_some(), v, now)?;
            report.qualified += 1;
        }
    }
    report.qualification_complete = complete;
    Ok(report)
}

/// One round: the relay lists of `relays`, until every relay has answered,
/// failed or been left.
async fn round(relays: Vec<String>, connector: Arc<dyn Connector>) -> Crawler {
    let runner = Runner {
        connector,
        clock: Arc::new(SystemClock),
        fetch: None,
        isolation: "census".into(),
        tick: Duration::from_secs(1),
    };
    // Each relay has CENSUS_TIMEOUT_SECS, CENSUS_CONCURRENCY at a time.
    let limit = Duration::from_secs(
        (CENSUS_TIMEOUT_SECS as u64) * (relays.len() as u64 / CENSUS_CONCURRENCY as u64 + 2),
    );
    let (stop, stop_rx) = watch::channel(false);
    let timeout = stop.clone();
    let timer = tokio::spawn(async move {
        tokio::time::sleep(limit).await;
        let _ = timeout.send(true);
    });
    let crawler = runner
        .run(Crawler::new(relays), stop_rx, move |c: &Crawler| {
            if c.done() {
                let _ = stop.send(true);
            }
        })
        .await;
    timer.abort();
    crawler
}

/// A relay's place: `None` when its address is not in the file; why it has
/// none otherwise.
type Placed = (String, std::result::Result<Option<Place>, String>);

/// Resolves each relay's host through the connector (Tor: by the exit) and
/// places it.
async fn locate(connector: Arc<dyn Connector>, geoip: &GeoIp, relays: &[String]) -> Vec<Placed> {
    let gate = Arc::new(Semaphore::new(CENSUS_CONCURRENCY));
    let mut tasks = JoinSet::new();
    for url in relays {
        let (url, connector, gate) = (url.clone(), connector.clone(), gate.clone());
        tasks.spawn(async move {
            let _turn = gate.acquire_owned().await;
            let addresses = match host_port(&url) {
                Some((host, _)) if host.ends_with(".onion") => Err("onion: no place".to_owned()),
                Some((host, _)) => connector
                    .resolve(&host, &host)
                    .await
                    .map_err(|e| e.to_string()),
                None => Err("not a relay address".to_owned()),
            };
            (url, addresses)
        });
    }
    let mut placed = Vec::new();
    while let Some(done) = tasks.join_next().await {
        let Ok((url, addresses)) = done else { continue };
        placed.push((url, addresses.map(|a| geoip.locate(&a))));
    }
    placed
}

/// The relays a strategy can use, and the ones it leaves out by reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eligibility {
    pub strategy: &'static str,
    pub needs: Needs,
    /// Usable addresses…
    pub usable: usize,
    /// … and the servers they are ([`by_server`]).
    pub servers: usize,
    pub excluded: BTreeMap<Exclusion, usize>,
}

/// For each strategy that chooses relays ([`STRATEGIES`]).
pub fn eligibility(relays: &[Relay]) -> Vec<Eligibility> {
    STRATEGIES
        .iter()
        .map(|(strategy, needs)| {
            let mut e = Eligibility {
                strategy,
                needs: *needs,
                usable: 0,
                servers: by_server(relays, *needs)
                    .values()
                    .filter(|r| r.excluded(*needs).is_none())
                    .count(),
                excluded: BTreeMap::new(),
            };
            for r in relays {
                match r.excluded(*needs) {
                    None => e.usable += 1,
                    Some((why, _)) => *e.excluded.entry(why).or_default() += 1,
                }
            }
            e
        })
        .collect()
}

/// The eligibility as a Markdown table, one line per strategy.
pub fn render_eligibility(rows: &[Eligibility], total: usize) -> String {
    let reasons = [
        Exclusion::NeverRead,
        Exclusion::NoAnswer,
        Exclusion::NotQualified,
        Exclusion::Refused,
        Exclusion::Clear,
        Exclusion::NoPlace,
    ];
    let mut out =
        format!("{total} relays in the census.\n\n| Strategy | Needs a place | Usable | Servers |");
    for r in reasons {
        let _ = write!(out, " {} |", r.describe());
    }
    out.push_str("\n|---|---|---|---|");
    out.push_str(&"---|".repeat(reasons.len()));
    out.push('\n');
    for e in rows {
        let _ = write!(
            out,
            "| {} | {} | {} | {} |",
            e.strategy,
            if e.needs.place { "yes" } else { "no" },
            e.usable,
            e.servers
        );
        for r in reasons {
            let _ = write!(out, " {} |", e.excluded.get(&r).copied().unwrap_or(0));
        }
        out.push('\n');
    }
    out
}

/// The relays the BitChat apps can use, in their lists' CSV form
/// (`Relay URL,Latitude,Longitude`, an address without `wss://` per line),
/// for the harmonised apps: [`Relay::bitchat`]. Returns how many.
pub fn bitchat_csv(store: &Store, out: &mut impl Write) -> Result<usize> {
    let relays = store.bitchat()?;
    writeln!(out, "Relay URL,Latitude,Longitude")?;
    for r in &relays {
        writeln!(out, "{},{:.4},{:.4}", r.host, r.lat, r.lon)?;
    }
    Ok(relays.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use geohash_relays::a6::Verdict;
    use geohash_relays::census::Outcome;

    #[test]
    fn what_each_strategy_can_use() {
        let relay = |url: &str, placed: bool| Relay {
            url: url.into(),
            answered: Some(true),
            failure: None,
            place: placed.then_some((1.0, 2.0)),
            city: None,
            country: None,
            locate_error: None,
            qualified: true,
            refusals: Some(String::new()),
            mentions: 0,
        };
        let relays = [
            relay("wss://placed.example.org", true),
            relay("wss://placed.example.org/inbox", true),
            relay("wss://abcdefghijklmnop.onion", false),
            Relay {
                answered: Some(false),
                ..relay("wss://dead.example.org", true)
            },
        ];
        let rows = eligibility(&relays);
        let of = |name: &str| rows.iter().find(|e| e.strategy == name).unwrap();
        assert_eq!((of("AS").usable, of("AS").servers), (2, 1));
        assert_eq!(of("AS").excluded[&Exclusion::NoPlace], 1);
        assert_eq!((of("A1").usable, of("A1").servers), (3, 2));
        assert!(!of("A1").excluded.contains_key(&Exclusion::NoPlace));
        assert_eq!(of("A1").excluded[&Exclusion::NoAnswer], 1);
        let table = render_eligibility(&rows, relays.len());
        assert!(
            table.contains("| AS | yes | 2 | 1 | 0 | 1 | 0 | 0 | 0 | 1 |"),
            "{table}"
        );
        assert!(
            table.contains("| A1 | no | 3 | 2 | 0 | 1 | 0 | 0 | 0 | 0 |"),
            "{table}"
        );
    }

    #[test]
    fn csv_as_the_apps_read_it() {
        let s = Store::open_in_memory().unwrap();
        s.give(&["wss://relay.example.org".into()], 1).unwrap();
        s.crawled(
            "wss://relay.example.org",
            &Outcome::Answered { lists: 1 },
            2,
        )
        .unwrap();
        s.located(
            "wss://relay.example.org",
            &Place {
                ip: "203.0.113.7".parse().unwrap(),
                lat: 40.705_71,
                lon: -74.013_62,
                country: Some("US".into()),
                city: None,
                geohash: "dr5reg".into(),
            },
            3,
        )
        .unwrap();
        s.qualified("wss://relay.example.org", true, &Verdict::default(), 4)
            .unwrap();
        let mut out = Vec::new();
        assert_eq!(bitchat_csv(&s, &mut out).unwrap(), 1);
        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            text,
            "Relay URL,Latitude,Longitude\nrelay.example.org,40.7057,-74.0136\n"
        );
        // The apps' own parser reads it.
        let ios = geohash_relays::RelayDirectory::parse(&text, geohash_relays::Platform::Ios);
        assert_eq!(ios.relays()[0].url, "wss://relay.example.org");
    }
}
