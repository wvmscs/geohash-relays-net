// SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)
// SPDX-License-Identifier: GPL-3.0-or-later

//! A local NIP-01 relay for the network tests, and signing keys.
//!
//! The relay supports `EVENT` (signature checked, answered with `OK`), `REQ`
//! (stored events, `EOSE`, then live events; a REQ with an existing id
//! replaces it) and `CLOSE`. Like real relays, it forwards the ephemeral
//! kinds (20000–29999, so BitChat's 20000/20001) live without storing them.
//! No limits. NIP-42 on request ([`TestRelay::spawn_auth`]): a challenge
//! at connection, REQ and EVENT refused with `auth-required:` until an AUTH
//! answers it, and optionally a list of the authors allowed to write.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use geohash_relays_net::nostr::{Event, Filter};
use k256::schnorr::SigningKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

struct Sub {
    conn: usize,
    id: String,
    filters: Vec<Filter>,
    out: mpsc::UnboundedSender<String>,
}

/// NIP-42 behaviour of the test relay.
#[derive(Clone, Default, PartialEq)]
pub enum AuthMode {
    #[default]
    Open,
    /// Like relay.damus.io for private messages: authenticate first.
    Required,
    /// Authentication for writing only, the challenge sent with the first
    /// refusal (some relays wait until it is needed).
    WriteLater,
    /// Like relay.mmwaves.de: authenticate, and only these authors write.
    Whitelist(Vec<String>),
}

#[derive(Default)]
struct Shared {
    stored: Mutex<Vec<Event>>,
    subs: Mutex<Vec<Sub>>,
    auth: AuthMode,
    /// Accepted AUTH events, and EVENT frames received, by event id.
    auths: AtomicUsize,
    received: Mutex<Vec<String>>,
}

impl Shared {
    fn publish(&self, e: Event) -> Result<(), &'static str> {
        if e.verify().is_err() {
            return Err("invalid: bad signature");
        }
        if !(20000..30000).contains(&e.kind) {
            self.stored.lock().unwrap().push(e.clone());
        }
        for s in self.subs.lock().unwrap().iter() {
            if s.filters.iter().any(|f| f.matches(&e)) {
                let _ = s.out.send(json!(["EVENT", s.id, e]).to_string());
            }
        }
        Ok(())
    }
}

pub struct TestRelay {
    shared: Arc<Shared>,
    addr: SocketAddr,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl TestRelay {
    /// Binds (`"127.0.0.1:0"` picks a free port) and serves in the background.
    pub async fn spawn(bind: &str) -> std::io::Result<Self> {
        Self::spawn_auth(bind, AuthMode::Open).await
    }

    /// The same, with NIP-42.
    pub async fn spawn_auth(bind: &str, auth: AuthMode) -> std::io::Result<Self> {
        let listener = TcpListener::bind(bind).await?;
        let addr = listener.local_addr()?;
        let shared = Arc::new(Shared {
            auth,
            ..Shared::default()
        });
        let (stop, stop_rx) = watch::channel(false);
        let s = shared.clone();
        let task = tokio::spawn(async move {
            let mut stop_rx = stop_rx;
            let next_conn = AtomicUsize::new(0);
            loop {
                tokio::select! {
                    _ = stop_rx.changed() => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { continue };
                        let conn = next_conn.fetch_add(1, Ordering::SeqCst);
                        tokio::spawn(serve(stream, conn, s.clone(), stop_rx.clone()));
                    }
                }
            }
        });
        Ok(TestRelay {
            shared,
            addr,
            stop,
            task,
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn url(&self) -> String {
        format!("ws://{}", self.addr)
    }

    /// Publishes as if a client had sent it.
    pub fn publish(&self, e: Event) {
        self.shared.publish(e).expect("test event must verify");
    }

    /// AUTH events accepted so far.
    pub fn auths(&self) -> usize {
        self.shared.auths.load(Ordering::SeqCst)
    }

    /// How many times a client sent the event `id`.
    pub fn received(&self, id: &str) -> usize {
        self.shared
            .received
            .lock()
            .unwrap()
            .iter()
            .filter(|i| *i == id)
            .count()
    }

    /// Stops accepting and closes every connection.
    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}

async fn serve(
    stream: TcpStream,
    conn: usize,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
) {
    let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
        return;
    };
    let (mut sink, mut source) = ws.split();
    let (out, mut out_rx) = mpsc::unbounded_channel::<String>();
    let challenge = format!("challenge-{conn}");
    let mut authed: Option<String> = None;
    let mut challenged = false;
    if !matches!(shared.auth, AuthMode::Open | AuthMode::WriteLater) {
        let _ = out.send(json!(["AUTH", challenge]).to_string());
        challenged = true;
    }
    // The challenge after a refusal, when not sent yet.
    let challenge_now = |challenged: &mut bool| {
        if !*challenged {
            let _ = out.send(json!(["AUTH", challenge]).to_string());
            *challenged = true;
        }
    };
    let writer = tokio::spawn(async move {
        while let Some(text) = out_rx.recv().await {
            if sink.send(Message::text(text)).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            msg = source.next() => {
                let Some(Ok(Message::Text(text))) = msg else {
                    match msg {
                        Some(Ok(_)) => continue,
                        _ => break,
                    }
                };
                let Ok(Value::Array(frame)) = serde_json::from_str::<Value>(text.as_str()) else { continue };
                match frame.first().and_then(Value::as_str) {
                    Some("EVENT") => {
                        let reply = match frame.get(1).map(|v| serde_json::from_value::<Event>(v.clone())) {
                            Some(Ok(e)) => {
                                let id = e.id.clone();
                                shared.received.lock().unwrap().push(id.clone());
                                let refusal = match (&shared.auth, &authed) {
                                    (AuthMode::Open, _) => None,
                                    (_, None) => Some("auth-required: please authenticate"),
                                    (AuthMode::Whitelist(ok), Some(_)) if !ok.contains(&e.pubkey) => {
                                        Some("auth-required: event author pubkey not in whitelist")
                                    }
                                    _ => None,
                                };
                                match refusal.map_or_else(|| shared.publish(e), Err) {
                                    Ok(()) => json!(["OK", id, true, ""]),
                                    Err(why) => {
                                        if why.starts_with("auth-required") {
                                            let _ = out.send(json!(["OK", id, false, why]).to_string());
                                            challenge_now(&mut challenged);
                                            continue;
                                        }
                                        json!(["OK", id, false, why])
                                    }
                                }
                            }
                            _ => json!(["NOTICE", "invalid: malformed EVENT"]),
                        };
                        let _ = out.send(reply.to_string());
                    }
                    Some("AUTH") => {
                        let Some(Ok(e)) = frame.get(1).map(|v| serde_json::from_value::<Event>(v.clone())) else { continue };
                        let ok = e.kind == 22242
                            && e.verify().is_ok()
                            && e.tag_value("challenge") == Some(challenge.as_str())
                            && e.tag_value("relay").is_some();
                        if ok {
                            shared.auths.fetch_add(1, Ordering::SeqCst);
                            authed = Some(e.pubkey.clone());
                        }
                        let _ = out.send(json!(["OK", e.id, ok, if ok { "" } else { "invalid: bad AUTH" }]).to_string());
                    }
                    Some("REQ") => {
                        let Some(id) = frame.get(1).and_then(Value::as_str).map(str::to_owned) else { continue };
                        if !matches!(shared.auth, AuthMode::Open | AuthMode::WriteLater) && authed.is_none() {
                            let _ = out.send(json!(["CLOSED", id, "auth-required: requested filter requires authentication"]).to_string());
                            challenge_now(&mut challenged);
                            continue;
                        }
                        let filters: Vec<Filter> = frame[2..].iter().filter_map(Filter::from_json).collect();
                        let mut subs = shared.subs.lock().unwrap();
                        subs.retain(|s| !(s.conn == conn && s.id == id));
                        for e in shared.stored.lock().unwrap().iter() {
                            if filters.iter().any(|f| f.matches(e)) {
                                let _ = out.send(json!(["EVENT", id, e]).to_string());
                            }
                        }
                        let _ = out.send(json!(["EOSE", id]).to_string());
                        subs.push(Sub { conn, id, filters, out: out.clone() });
                    }
                    Some("CLOSE") => {
                        if let Some(id) = frame.get(1).and_then(Value::as_str) {
                            shared.subs.lock().unwrap().retain(|s| !(s.conn == conn && s.id == id));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    shared.subs.lock().unwrap().retain(|s| s.conn != conn);
    drop(out);
    let _ = writer.await;
}

/// A signing key for test events. Keys are derived from a counter, so they
/// are distinct within a test binary and need no random source.
pub struct Identity {
    key: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let n = NEXT.fetch_add(1, Ordering::SeqCst);
            let seed = Sha256::digest(format!("bitchat-geohash test key {n}").as_bytes());
            if let Ok(key) = SigningKey::from_bytes(&seed) {
                return Identity { key };
            }
        }
    }

    pub fn public_key_hex(&self) -> String {
        hex(&self.key.verifying_key().to_bytes())
    }
}

/// Signs test events (the library itself never signs).
pub trait Sign: Sized {
    fn sign(self, who: &Identity) -> Result<Event, String>;
}

impl Sign for Event {
    fn sign(mut self, who: &Identity) -> Result<Event, String> {
        if self.pubkey != who.public_key_hex() {
            return Err("signing key does not match pubkey".into());
        }
        self.id = self.compute_id();
        let id: Vec<u8> = (0..self.id.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&self.id[i..i + 2], 16).unwrap())
            .collect();
        let sig = who
            .key
            .sign_raw(&id, &[0u8; 32])
            .map_err(|e| e.to_string())?;
        self.sig = Some(hex(&sig.to_bytes()));
        Ok(self)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
