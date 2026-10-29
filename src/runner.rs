// SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)
// SPDX-License-Identifier: GPL-3.0-or-later

//! Runs a strategy machine ([`geohash_relays::sansio::Machine`]) with the
//! communication of the active feature: one connection per relay
//! ([`crate::relay`]), NIP-11 documents through [`HttpFetch`], the time from
//! [`Clock`]. Events become inputs only once their id and signature are
//! verified and their tags are within the apps' limits.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use geohash_relays::sansio::{Action, Input, Machine};
use geohash_relays::strategy::Health;
use tokio::sync::{mpsc, watch};

use crate::connector::Connector;
use crate::nostr::Event;
use crate::ports::{Clock, HttpFetch};
use crate::relay::{self, ConnState, RelayEvent, RelayHandle};

/// What a run needs.
pub struct Runner {
    pub connector: Arc<dyn Connector>,
    pub clock: Arc<dyn Clock>,
    /// NIP-11 documents; `None`: [`Action::FetchNip11`] gets `None` back.
    pub fetch: Option<Arc<dyn HttpFetch>>,
    /// Isolation key of the connections (one Tor circuit per key).
    pub isolation: String,
    /// How often the machine gets [`Input::Tick`].
    pub tick: Duration,
}

struct Links {
    conns: HashMap<String, RelayHandle>,
    events: mpsc::UnboundedSender<RelayEvent>,
}

impl Runner {
    /// Runs `machine` until `stop` turns true (or its sender is dropped);
    /// `observe` sees the machine after each tick. Returns the machine.
    pub async fn run<M: Machine>(
        &self,
        mut machine: M,
        mut stop: watch::Receiver<bool>,
        mut observe: impl FnMut(&M),
    ) -> M {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (nip11_tx, mut nip11_rx) = mpsc::unbounded_channel::<(String, Option<String>)>();
        let mut links = Links {
            conns: HashMap::new(),
            events: tx,
        };
        let first = machine.start(self.clock.now());
        self.apply(first, &mut links, &nip11_tx);
        let mut tick = tokio::time::interval(self.tick);
        let mut dead: HashMap<String, bool> = HashMap::new();
        loop {
            let input = tokio::select! {
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        return machine;
                    }
                    continue;
                }
                _ = tick.tick() => Input::Tick { now: self.clock.now() },
                Some((relay, json)) = nip11_rx.recv() => Input::Nip11 { relay, json },
                Some(e) = rx.recv() => match to_input(e, &mut dead) {
                    Some(i) => i,
                    None => continue,
                },
            };
            let is_tick = matches!(input, Input::Tick { .. });
            let actions = machine.handle(input);
            self.apply(actions, &mut links, &nip11_tx);
            if is_tick {
                observe(&machine);
            }
        }
    }

    fn connection<'a>(&self, links: &'a mut Links, relay: &str) -> &'a RelayHandle {
        links.conns.entry(relay.to_owned()).or_insert_with(|| {
            relay::spawn(
                relay.to_owned(),
                self.isolation.clone(),
                Vec::new(),
                self.connector.clone(),
                links.events.clone(),
                None,
            )
        })
    }

    fn apply(
        &self,
        actions: Vec<Action>,
        links: &mut Links,
        nip11: &mpsc::UnboundedSender<(String, Option<String>)>,
    ) {
        for a in actions {
            match a {
                Action::Subscribe { relay, filter } => {
                    self.connection(links, &relay)
                        .set_filters(vec![(&filter).into()]);
                }
                Action::Unsubscribe { relay } => {
                    links.conns.remove(&relay);
                }
                Action::Publish { relay, raw, id } => match serde_json::from_str::<Event>(&raw) {
                    Ok(e) => self.connection(links, &relay).publish(e),
                    Err(e) => tracing::warn!(%id, error = %e, "not an event, not published"),
                },
                Action::FetchNip11 { relay } => {
                    let (fetch, tx) = (self.fetch.clone(), nip11.clone());
                    tokio::spawn(async move {
                        let json = match fetch {
                            Some(f) => f.nip11(&relay).await.ok().flatten(),
                            None => None,
                        };
                        let _ = tx.send((relay, json));
                    });
                }
            }
        }
    }
}

/// A relay report as a machine input. A relay is reported failed once per
/// loss, until it connects again.
fn to_input(e: RelayEvent, dead: &mut HashMap<String, bool>) -> Option<Input> {
    match e {
        RelayEvent::Event { relay, event, .. } => {
            if event.verify().is_err() || !event.within_tag_limits() {
                return None;
            }
            Some(Input::Event {
                relay,
                event: event.meta(),
            })
        }
        RelayEvent::Ok {
            relay,
            id,
            accepted,
            message,
            ..
        } => Some(Input::Ok {
            relay,
            id,
            accepted,
            message,
        }),
        RelayEvent::Eose { relay, .. } => Some(Input::Eose { relay }),
        RelayEvent::State { relay, state, .. } => {
            let health = match &state {
                ConnState::Connected => {
                    dead.insert(relay, false);
                    return None;
                }
                ConnState::Connecting => return None,
                ConnState::Waiting { .. } => Health::Dead,
                ConnState::Abandoned { reason } if reason.starts_with("redirected") => {
                    Health::Redirect
                }
                ConnState::Abandoned { reason } if reason.starts_with("certificate") => {
                    Health::BadCertificate
                }
                ConnState::Abandoned { reason } if reason.contains("auth") => Health::AuthRequired,
                ConnState::Abandoned { .. } => Health::Dead,
            };
            if dead.insert(relay.clone(), true) == Some(true) {
                return None;
            }
            Some(Input::Failed { relay, health })
        }
        _ => None,
    }
}
