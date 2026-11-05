# Integrating geohash-relays and geohash-relays-net in a client

For a Nostr client of its own (not a copy of one of the bitchat apps) that wants to choose its
relays per geohash cell with the strategies of
[geohash-relays](https://github.com/wvmscs/geohash-relays) and to reach them with this crate.
The first such client integrates `v0.2.0`; what it learns comes back here, then as pull
requests to the other clients of the location channels.

A working example, read only: [`examples/client.rs`](../examples/client.rs).

```sh
cargo run --features client --example client -- nostr_relays.csv u09tv            # the relays of each strategy
cargo run --features client --example client -- nostr_relays.csv u09tv --listen \
    --tor 127.0.0.1:9050                                                          # and listen 30 s, through Tor
```

## 1. The two crates

| Crate | Licence | What | Network |
|---|---|---|---|
| `geohash-relays` | Unlicense OR 0BSD | relay lists, the apps' rules, the strategies (`AS`, AirHop, A0 to A6), the machines of those that talk to relays (`sansio`), every constant (`params`) | none |
| `geohash-relays-net` | GPL-3.0-or-later | connections (Tor, direct), one relay connection per cell, lists and NIP-11 over the connector, the runner of the machines, A6 qualification | all of it |

A client under another licence can use `geohash-relays` alone (pure functions) and bring its
own network code; `geohash-relays-net` makes the whole client GPL-3.0-or-later.

## 2. Dependencies

```toml
[dependencies]
# Both at the versions that go together: geohash-relays-net v0.2.0 is built on
# this tag, and Cargo must see one geohash-relays only.
geohash-relays = { git = "https://github.com/wvmscs/geohash-relays.git", tag = "strategies-2026.11.05" }
geohash-relays-net = { git = "https://github.com/wvmscs/geohash-relays-net.git", tag = "v0.2.0", features = ["client"] }
# Optional: Tor inside the process instead of a Tor daemon.
# geohash-relays-net = { ..., features = ["client", "arti"] }
```

- **One feature** of `bitchat`, `bitchat-android`, `console`, `client` (a `compile_error!`
  otherwise). A client of its own takes `client`: reconnection with a backoff from 1 s to
  5 min without limit (`relay::Policy::CLIENT`), Tor optional (`connector::Direct` exists).
  `console` forbids direct connections; `bitchat` and `bitchat-android` copy the apps' quirks.
- **TLS:** rustls with the `ring` provider. If another dependency brings `aws-lc-rs` too,
  install `ring` as the process default before the first connection
  (`rustls::crypto::ring::default_provider().install_default()`), or rustls panics when it must
  pick one.
- **`cargo deny`:** allow the two git sources (`allow-git`).
- **Never** depend on the branch `strategies` itself from a released version: it may be
  rebased; its tags `strategies-YYYY.MM.DD` never move.

## 3. The relay list

```rust
use geohash_relays::{Platform, RelayDirectory};
use geohash_relays_net::lists::{self, ListSource};

// From a URL through the connector (cached copy in `cache_dir` when it fails), or a path.
let list = lists::load(&ListSource::official(Platform::Android), Platform::Android, connector.clone(), &cache_dir).await?;
// Or a list you already have:
let list = RelayDirectory::parse(&csv, Platform::Ios);
```

- `Platform` says **how a list is read**, not where it comes from: `Ios` keeps one entry per
  normalised server (`host`, `host:443` and `wss://host/` are one), `Android` keeps every line.
  A client of its own reads with `Ios` (one server, one place).
- Which list: the apps read two lists of different ages (see geohash-relays'
  [docs/clients.md](https://github.com/wvmscs/geohash-relays/blob/strategies/docs/clients.md)):
  half of the iOS list no longer answers. Prefer georelays' daily `nostr_relays.csv`
  (`Platform::Android.list_url()`), or better a **qualified** list published by a few trusted
  machines with `relay-census --compat bitchat` (README): one list, read by every client, is
  what makes them meet. Do not run the census on phones.

## 4. Choosing a cell's relays

Every strategy implements `geohash_relays::Strategy`:

```rust
let read: Vec<Selected> = strategy.read("u09tv")?;    // where to subscribe
let write: Vec<Selected> = strategy.write("u09tv")?;  // where to publish (wider for A0, A1 near an epoch change)
```

`Selected.relay.url` is normalised (`wss://host[:port][/path]`); `rank` is 1-based; `role` is
`ReadWrite` or `WriteOnly`. Compare servers with `geohash_relays::server(url)`, never raw strings.

| Goal | Strategy | Notes |
|---|---|---|
| Meet the bitchat users of a cell | `AppStrategy::new(Some(ios), Some(android), Apps::Both)` | the union of what iOS and Android pick, each with its own list and rule: write and read there. Add `AirhopStrategy::from_directory(&android)` to meet AirHop users too |
| Meet the other users of **your** client | `a0::SharedStrategy::from_directory(list)` | one list, iOS rule, write 8 and read 5; `.with_health(health)` replaces the relays found dead, `.qualified(&q)` drops those A6 refuses |
| The same, hard to capture | `a1::HrwStrategy::new(&list).with_salts(Salts::ByEpoch(..), now)` | rendezvous hashing: no distance, so no place needed and an attacker cannot buy the nearest servers; the salt must be shared by your peers and unknown in advance; rebuild it when the epoch changes (`params::A1_EPOCH_SECS`) |
| Discover relays from the cell's own users | `a3` | the relays announced in presences (tags), with proof of work; for later |

`AS` and AirHop exist to reach the apps as they are; A0 and A1 are what the study proposes for
new clients (`docs/evaluation.md`, `docs/clients.md`). A relay of your own (a private relay)
is not a strategy's business: connect to it beside the cell's relays.

## 5. Connecting

```rust
use geohash_relays_net::connector::{Connector, Direct, Socks5};
use geohash_relays_net::nostr::Filter;
use geohash_relays_net::relay::{self, RelayEvent};

let connector: Arc<dyn Connector> = Arc::new(Socks5::new("127.0.0.1:9050".parse()?)); // or Direct, or arti::Arti
let filter = Filter { kinds: vec![20000, 20001], since: Some(now - 3600), tags: [('g', vec![cell.clone()])].into(), ..Filter::default() };
let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
let handle = relay::spawn(url, cell.clone(), vec![filter], connector.clone(), tx, Some(cell_key));
handle.publish(event);            // sent now, or once connected; again after NIP-42
handle.set_filters(new_filters);  // replaces the subscription
// drop(handle) closes the connection.
```

- **One connection per (relay, cell)**: the cell is the Tor isolation key, so two cells never
  share a circuit and a relay cannot link them by exit. Keep one key per cell too (the apps
  derive it from the geohash).
- **What comes back** (`RelayEvent`): `State` (`Connecting`, `Connected`, `Waiting`,
  `Abandoned`), `Event` (signature checked, tag limits), `Eose`, `Ok` (accepted or not, with
  the relay's message), `Closed`, `Notice`, `Authenticated`. Wait for `Ok` before counting a
  publication as sent; read `Closed`; give `auth` the cell's key to answer NIP-42.
- **Health for the strategy**: turn `Abandoned`, repeated `Waiting`, and `Ok { accepted: false }`
  into `geohash_relays::RelayHealth` (`Health::Dead`, `AuthRequired`, `WriteRefused`…) and
  build A0 again with `.with_health(..)`: it then picks the next relay instead.
- **Events**: `nostr::Event::signed(&key, created_at, kind, tags, content)`; `Event::verify()`
  for what you receive from elsewhere.

## 6. Qualifying relays (A6)

```rust
let (prober, finished) = geohash_relays_net::qualify::run(relays, connector, false, Duration::from_secs(60)).await;
let q = prober.qualification();
let list = q.filter(list)?;          // without the refused relays
let a0 = SharedStrategy::from_directory(list).qualified(&q);
```

With `probe = false`, only NIP-11 documents are read. `probe = true` publishes one test event
per relay in a cell of the open sea: a real publication, do it on purpose only, never in tests.

## 7. Rules to keep

- No content, nickname, key or seed in logs.
- Tests never publish on public relays: use `connector::Loopback` and a local relay, or your
  own test relay.
- Every constant comes from `geohash_relays::params`, with its source: if you need another
  value, propose it there.
- Report what you change or need (a feature's policy, a strategy parameter) as an issue or a
  pull request on these two repositories: the next clients get it from there.
