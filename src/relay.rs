// SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)
// SPDX-License-Identifier: GPL-3.0-or-later

//! One connection to one relay for one cell (D20), through the connector
//! (Tor): subscription, events, publications, reconnection.
//!
//! Each connection is a task. It reports everything to the console on one
//! channel ([`RelayEvent`]) and takes [`RelayHandle`] commands.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use k256::schnorr::SigningKey;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use geohash_relays::params::comm;

use crate::connector::Connector;
use crate::nostr::{Event, Filter};

/// State of a connection, for the page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnState {
    Connecting,
    Connected,
    /// Lost; next try in this many seconds.
    Waiting {
        retry_in_secs: u64,
    },
    /// Given up: the relay requires authentication (NIP-42) and refused
    /// it, or there is no key to give it.
    Abandoned {
        reason: String,
    },
}

/// What a connection reports. `relay` is the relay URL, `cell` the cell the
/// connection is for.
#[derive(Debug, Clone, PartialEq)]
pub enum RelayEvent {
    State {
        relay: String,
        cell: String,
        state: ConnState,
    },
    Event {
        relay: String,
        cell: String,
        event: Event,
    },
    /// End of stored events for the subscription.
    Eose { relay: String, cell: String },
    /// The relay's answer to a publication.
    Ok {
        relay: String,
        cell: String,
        id: String,
        accepted: bool,
        message: String,
    },
    Notice {
        relay: String,
        cell: String,
        text: String,
    },
    /// The relay closed the subscription.
    Closed {
        relay: String,
        cell: String,
        reason: String,
    },
    /// The relay accepted the NIP-42 authentication (D28).
    Authenticated { relay: String, cell: String },
}

/// NIP-42 authentication event.
pub use geohash_relays::params::KIND_AUTH;

/// Publications kept to be sent again after authentication.
use geohash_relays::params::comm::RECENT_PUBLICATIONS as RECENT;

/// The NIP-42 answer to `challenge` from `relay`, signed with `key`.
pub fn auth_event(key: &SigningKey, relay: &str, challenge: &str, created_at: i64) -> Event {
    Event::signed(
        key,
        created_at,
        KIND_AUTH,
        vec![
            vec!["relay".into(), relay.into()],
            vec!["challenge".into(), challenge.into()],
        ],
        String::new(),
    )
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

enum Cmd {
    Publish(Event),
    Filters(Vec<Filter>),
}

/// A running connection. Dropping it closes the connection.
pub struct RelayHandle {
    tx: mpsc::UnboundedSender<Cmd>,
    task: JoinHandle<()>,
}

impl RelayHandle {
    /// Sends an event now, or as soon as the connection is up.
    pub fn publish(&self, event: Event) {
        let _ = self.tx.send(Cmd::Publish(event));
    }

    /// Replaces the subscription filters (sent again under the same id).
    pub fn set_filters(&self, filters: Vec<Filter>) {
        let _ = self.tx.send(Cmd::Filters(filters));
    }
}

impl Drop for RelayHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub use geohash_relays::params::comm::{BACKOFF_MAX, BACKOFF_MIN};

/// How a connection retries and ends a history, per implementation (the
/// active feature).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Policy {
    /// Consecutive failed attempts before a pause; `None`: never pause.
    pub max_attempts: Option<u32>,
    /// The pause after `max_attempts` failures.
    pub pause: Duration,
    /// Each delay is randomised by this fraction, either way.
    pub jitter: f64,
    /// A history without `EOSE` ends after this long.
    pub eose_timeout: Option<Duration>,
}

impl Policy {
    /// The console: backoff from 1 s to 5 min, without limit.
    pub const CONSOLE: Policy = Policy {
        max_attempts: None,
        pause: Duration::ZERO,
        jitter: 0.0,
        eose_timeout: None,
    };
    /// iOS (`NostrRelayManager.swift`): ±20 %, 10 attempts then 10 min,
    /// history ended after 10 s without `EOSE`.
    pub const IOS: Policy = Policy {
        max_attempts: Some(comm::IOS_MAX_ATTEMPTS),
        pause: comm::IOS_RETRY_AFTER_GIVING_UP,
        jitter: comm::IOS_BACKOFF_JITTER,
        eose_timeout: Some(comm::IOS_EOSE_TIMEOUT),
    };
    /// Android (`NostrRelayManager.kt`): backoff without limit.
    pub const ANDROID: Policy = Policy::CONSOLE;

    /// The policy of the active feature.
    pub const fn current() -> Policy {
        #[cfg(feature = "bitchat")]
        return Policy::IOS;
        #[cfg(feature = "bitchat-android")]
        return Policy::ANDROID;
        #[cfg(not(any(feature = "bitchat", feature = "bitchat-android")))]
        Policy::CONSOLE
    }

    /// The wait after `failures` consecutive failed attempts, `backoff`
    /// being the current backoff; `noise` in [0, 1) draws the jitter.
    pub fn delay(&self, failures: u32, backoff: Duration, noise: f64) -> Duration {
        if self.max_attempts.is_some_and(|max| failures >= max) {
            return self.pause;
        }
        backoff.mul_f64(1.0 + self.jitter * (2.0 * noise - 1.0))
    }
}

/// A number in [0, 1) that differs from call to call (jitter only).
fn noise() -> f64 {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    f64::from(n % 1_000_000) / 1_000_000.0
}

/// Starts a connection to `url` for `cell`. With `auth`, the key of the
/// connection (the cell's, or a group's), it answers NIP-42 challenges (D28).
pub fn spawn(
    url: String,
    cell: String,
    filters: Vec<Filter>,
    connector: Arc<dyn Connector>,
    events: mpsc::UnboundedSender<RelayEvent>,
    auth: Option<SigningKey>,
) -> RelayHandle {
    let (tx, rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(run(url, cell, filters, connector, events, rx, auth));
    RelayHandle { tx, task }
}

/// `ws[s]://host[:port][/path]` -> (host, port).
pub fn host_port(url: &str) -> Option<(String, u16)> {
    let (scheme, rest) = url.split_once("://")?;
    let default = match scheme {
        "wss" => 443,
        "ws" => 80,
        _ => return None,
    };
    let authority = rest.split('/').next()?;
    if let Some(v6) = authority.strip_prefix('[') {
        let (host, after) = v6.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => default,
        };
        return Some((host.to_owned(), port));
    }
    match authority.rsplit_once(':') {
        Some((h, p)) => Some((h.to_owned(), p.parse().ok()?)),
        None if !authority.is_empty() => Some((authority.to_owned(), default)),
        None => None,
    }
}

/// TLS client configuration: ring, the web's root certificates.
pub fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            Arc::new(
                rustls::ClientConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()
                    .expect("ring supports the default versions")
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        })
        .clone()
}

/// Subscription id of the cell's channel.
fn sub_id(cell: &str) -> String {
    format!("geo-{cell}")
}

async fn run(
    url: String,
    cell: String,
    mut filters: Vec<Filter>,
    connector: Arc<dyn Connector>,
    events: mpsc::UnboundedSender<RelayEvent>,
    mut rx: mpsc::UnboundedReceiver<Cmd>,
    auth: Option<SigningKey>,
) {
    let state = |s: ConnState| {
        let _ = events.send(RelayEvent::State {
            relay: url.clone(),
            cell: cell.clone(),
            state: s,
        });
    };
    let Some((host, port)) = host_port(&url) else {
        state(ConnState::Abandoned {
            reason: "not a ws:// or wss:// address".into(),
        });
        return;
    };
    let mut queue: Vec<Event> = Vec::new();
    let policy = Policy::current();
    let mut backoff = BACKOFF_MIN;
    let mut failures: u32 = 0;
    loop {
        state(ConnState::Connecting);
        let attempt = async {
            let stream = connector.connect(&host, port, &cell).await?;
            let (ws, _) = tokio_tungstenite::client_async_tls_with_config(
                url.as_str(),
                stream,
                None,
                Some(tokio_tungstenite::Connector::Rustls(tls_config())),
            )
            .await
            .map_err(std::io::Error::other)?;
            Ok::<_, std::io::Error>(ws)
        };
        match attempt.await {
            Ok(ws) => {
                backoff = BACKOFF_MIN;
                failures = 0;
                state(ConnState::Connected);
                let (mut sink, mut source) = ws.split();
                let req = |filters: &[Filter]| {
                    let mut msg = vec![json!("REQ"), json!(sub_id(&cell))];
                    msg.extend(filters.iter().map(Filter::to_json));
                    WsMessage::text(Value::Array(msg).to_string())
                };
                let event_msg = |e: &Event| WsMessage::text(json!(["EVENT", e]).to_string());
                // NIP-42, for this session: the AUTH sent, its outcome, what
                // waits for it.
                let mut auth_id: Option<String> = None;
                let mut authed = false;
                let mut resubscribe = false;
                let mut recent: VecDeque<Event> = VecDeque::new();
                let mut waiting: Vec<Event> = Vec::new();
                let mut retried: HashSet<String> = HashSet::new();
                let remember = |e: &Event, recent: &mut VecDeque<Event>| {
                    if auth.is_some() {
                        recent.push_back(e.clone());
                        if recent.len() > RECENT {
                            recent.pop_front();
                        }
                    }
                };
                // A connection for writing only (presence) subscribes to nothing.
                let mut alive = filters.is_empty() || sink.send(req(&filters)).await.is_ok();
                for e in queue.drain(..) {
                    if alive {
                        remember(&e, &mut recent);
                        alive = sink.send(event_msg(&e)).await.is_ok();
                    }
                }
                // iOS ends a history without EOSE after a while.
                let mut eose_deadline = policy
                    .eose_timeout
                    .filter(|_| !filters.is_empty())
                    .map(|t| tokio::time::Instant::now() + t);
                while alive {
                    let eose_wait = async {
                        match eose_deadline {
                            Some(at) => tokio::time::sleep_until(at).await,
                            None => std::future::pending().await,
                        }
                    };
                    tokio::select! {
                        _ = eose_wait => {
                            eose_deadline = None;
                            let _ = events.send(RelayEvent::Eose { relay: url.clone(), cell: cell.clone() });
                        }
                        cmd = rx.recv() => match cmd {
                            None => return,
                            Some(Cmd::Publish(e)) => {
                                remember(&e, &mut recent);
                                if sink.send(event_msg(&e)).await.is_err() {
                                    queue.push(e);
                                    alive = false;
                                }
                            }
                            Some(Cmd::Filters(f)) => {
                                filters = f;
                                eose_deadline = policy
                                    .eose_timeout
                                    .filter(|_| !filters.is_empty())
                                    .map(|t| tokio::time::Instant::now() + t);
                                alive = sink.send(req(&filters)).await.is_ok();
                            }
                        },
                        msg = source.next() => match msg {
                            Some(Ok(WsMessage::Text(text))) => {
                                let report = |e: RelayEvent| { let _ = events.send(e); };
                                let (relay, c) = (url.clone(), cell.clone());
                                match parse(&text, &url, &cell) {
                                    None => {}
                                    Some(Incoming::Report(e)) => {
                                        if matches!(e, RelayEvent::Eose { .. }) {
                                            eose_deadline = None;
                                        }
                                        report(e)
                                    }
                                    Some(Incoming::Challenge(challenge)) => {
                                        let Some(key) = &auth else { continue };
                                        let e = auth_event(key, &url, &challenge, now());
                                        auth_id = Some(e.id.clone());
                                        let msg = WsMessage::text(json!(["AUTH", e]).to_string());
                                        alive = sink.send(msg).await.is_ok();
                                    }
                                    Some(Incoming::Closed(reason)) => {
                                        let needs_auth = reason.starts_with("auth-required:");
                                        report(RelayEvent::Closed { relay, cell: c, reason: reason.clone() });
                                        if needs_auth {
                                            if auth.is_none() || authed {
                                                state(ConnState::Abandoned { reason });
                                                return;
                                            }
                                            resubscribe = true;
                                        }
                                    }
                                    Some(Incoming::Ok { id, accepted, message }) => {
                                        if auth_id.as_deref() == Some(id.as_str()) {
                                            if !accepted {
                                                state(ConnState::Abandoned {
                                                    reason: format!("authentication refused: {message}"),
                                                });
                                                return;
                                            }
                                            authed = true;
                                            report(RelayEvent::Authenticated { relay, cell: c });
                                            if resubscribe && !filters.is_empty() {
                                                alive = sink.send(req(&filters)).await.is_ok();
                                            }
                                            for e in waiting.drain(..) {
                                                if alive {
                                                    alive = sink.send(event_msg(&e)).await.is_ok();
                                                }
                                            }
                                            continue;
                                        }
                                        // Refused for want of authentication: sent
                                        // again once, after it.
                                        if !accepted
                                            && message.starts_with("auth-required:")
                                            && auth.is_some()
                                            && !authed
                                            && retried.insert(id.clone())
                                            && let Some(e) = recent.iter().find(|e| e.id == id)
                                        {
                                            waiting.push(e.clone());
                                            continue;
                                        }
                                        report(RelayEvent::Ok { relay, cell: c, id, accepted, message });
                                    }
                                }
                            }
                            Some(Ok(WsMessage::Ping(p))) => {
                                alive = sink.send(WsMessage::Pong(p)).await.is_ok();
                            }
                            Some(Ok(WsMessage::Close(_))) | None | Some(Err(_)) => alive = false,
                            Some(Ok(_)) => {}
                        },
                    }
                }
            }
            Err(e) => {
                // A redirection or a refused certificate does not heal by
                // trying again (iOS: a permanent failure, §1.5).
                if let Some(reason) = permanent(&e.to_string()) {
                    state(ConnState::Abandoned { reason });
                    return;
                }
                tracing::debug!(relay = %url, cell = %cell, error = %e, "relay unreachable");
            }
        }
        failures += 1;
        let wait = policy.delay(failures, backoff, noise());
        if policy.max_attempts.is_some_and(|max| failures >= max) {
            failures = 0;
            // Doubled below: the first try after the pause waits BACKOFF_MIN.
            backoff = BACKOFF_MIN / 2;
        }
        state(ConnState::Waiting {
            retry_in_secs: wait.as_secs(),
        });
        // Commands keep coming while waiting: queue the publications.
        let wake = tokio::time::sleep(wait);
        tokio::pin!(wake);
        loop {
            tokio::select! {
                _ = &mut wake => break,
                cmd = rx.recv() => match cmd {
                    None => return,
                    Some(Cmd::Publish(e)) => queue.push(e),
                    Some(Cmd::Filters(f)) => filters = f,
                },
            }
        }
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}

/// The reason to give up for good, from a connection error: a redirection
/// of the WebSocket upgrade (R2), a refused TLS certificate (R1).
pub fn permanent(error: &str) -> Option<String> {
    if error.contains("HTTP error: 30") {
        Some(format!("redirected (R2): {error}"))
    } else if error.contains("invalid peer certificate") {
        Some(format!("certificate refused (R1): {error}"))
    } else {
        None
    }
}

/// A relay message, sorted: what only goes up, and what the connection
/// itself acts on.
enum Incoming {
    Report(RelayEvent),
    /// NIP-42 challenge.
    Challenge(String),
    /// The subscription was closed, with this reason.
    Closed(String),
    Ok {
        id: String,
        accepted: bool,
        message: String,
    },
}

fn parse(text: &str, relay: &str, cell: &str) -> Option<Incoming> {
    let Ok(Value::Array(msg)) = serde_json::from_str::<Value>(text) else {
        return None;
    };
    let s = |i: usize| {
        msg.get(i)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let (relay, cell) = (relay.to_owned(), cell.to_owned());
    Some(match s(0).as_str() {
        "EVENT" => match msg.get(2).cloned().map(serde_json::from_value::<Event>) {
            Some(Ok(event)) => Incoming::Report(RelayEvent::Event { relay, cell, event }),
            _ => return None,
        },
        "EOSE" => Incoming::Report(RelayEvent::Eose { relay, cell }),
        "OK" => Incoming::Ok {
            id: s(1),
            accepted: msg.get(2).and_then(Value::as_bool).unwrap_or(false),
            message: s(3),
        },
        "NOTICE" => Incoming::Report(RelayEvent::Notice {
            relay,
            cell,
            text: s(1),
        }),
        "CLOSED" => Incoming::Closed(s(2)),
        "AUTH" => Incoming::Challenge(s(1)),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        assert_eq!(
            host_port("wss://relay.damus.io"),
            Some(("relay.damus.io".into(), 443))
        );
        assert_eq!(host_port("wss://nos.lol/"), Some(("nos.lol".into(), 443)));
        assert_eq!(
            host_port("wss://r.example:7447/x"),
            Some(("r.example".into(), 7447))
        );
        assert_eq!(
            host_port("ws://127.0.0.1:9000"),
            Some(("127.0.0.1".into(), 9000))
        );
        assert_eq!(host_port("ws://[::1]:9000"), Some(("::1".into(), 9000)));
        assert_eq!(host_port("https://x"), None);
        assert_eq!(host_port("wss://"), None);
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    #[test]
    fn ios_pauses_after_ten_failures_and_jitters() {
        let p = Policy::IOS;
        let b = Duration::from_secs(8);
        assert_eq!(p.delay(10, b, 0.5), comm::IOS_RETRY_AFTER_GIVING_UP);
        assert_eq!(p.delay(3, b, 0.5), b);
        assert!(p.delay(3, b, 0.0) < b && p.delay(3, b, 0.0) >= b.mul_f64(0.8));
        assert!(p.delay(3, b, 0.999) > b && p.delay(3, b, 0.999) <= b.mul_f64(1.2));
        assert_eq!(Policy::ANDROID.delay(1000, b, 0.0), b);
    }
}
