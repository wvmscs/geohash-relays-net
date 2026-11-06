# Using geohash-relays in your Nostr client

For developers of a Nostr client (in Rust) that wants to talk in **BitChat's location channels**,
or to give its own users channels by place, and needs to know **which relays to use for a
place**.

## The problem, in one paragraph

A location channel is a place on the map, written as a **geohash** (`u09tv` is a few
kilometres of Paris). Its messages are Nostr events tagged with that geohash. There is no
central server: every phone must **guess the same few relays** for the place, publish there and
listen there. If two phones guess differently, they never see each other's messages. BitChat
iOS and BitChat Android already guess differently from each other a third of the time.
**geohash-relays** answers the question "which relays for this place?" the way each app does
it, and in better ways; **geohash-relays-net** connects to those relays.

## Words used here

| Word | Meaning |
|---|---|
| cell | a geohash: a place, from a country (2 characters) to a street (7) |
| relay list | a CSV file of relays with their position (`Relay URL,Latitude,Longitude`), published by georelays; the apps pick relays from it |
| strategy | a rule that turns (list, cell) into the relays to use. `AS` is what the BitChat apps do today; `A0`, `A1`… are the improvements studied in geohash-relays |
| read / write | the relays to listen to / to publish to; usually the same |
| Tor isolation | each cell gets its own Tor circuit, so a relay cannot link two cells to one user |

## Step 0: which crate do you need?

| You want | Take | Licence |
|---|---|---|
| only the answer "which relays for this cell" (you have your own Nostr networking) | `geohash-relays` | Unlicense or 0BSD: anything goes |
| the answer **and** the connections (Tor or direct, reconnection, NIP-42) | `geohash-relays` + `geohash-relays-net` | GPL-3.0-or-later for your client |

## Step 1: dependencies

```toml
[dependencies]
geohash-relays = { git = "https://github.com/wvmscs/geohash-relays.git", tag = "strategies-2026.11.05" }
# Only if you want the connections too:
geohash-relays-net = { git = "https://github.com/wvmscs/geohash-relays-net.git", tag = "v0.2.0", features = ["client"] }
```

- Keep exactly these two versions together: `geohash-relays-net` v0.2.0 is built on that tag
  of `geohash-relays`.
- `geohash-relays-net` needs **one** feature. Take `client` (yours is a client of its own).
  Add `arti` if you want Tor inside your process instead of a Tor daemon.
- It uses rustls with `ring`. If another of your dependencies brings `aws-lc-rs`, call
  `rustls::crypto::ring::default_provider().install_default()` once at start-up.

## Step 2: get a relay list

```rust
use geohash_relays::{Platform, RelayDirectory};

let csv: String = /* download it, or ship one */;
let list = RelayDirectory::parse(&csv, Platform::Android);
```

- Where from: georelays' list, updated daily:
  `https://raw.githubusercontent.com/permissionlesstech/georelays/main/nostr_relays.csv`.
  Refresh it regularly: a list a few months old makes your users miss the others (see
  geohash-relays' [docs/current-state.md](https://github.com/wvmscs/geohash-relays/blob/strategies/docs/current-state.md)).
- `Platform` only says how the file is read: `Android` keeps every line as it is, `Ios` keeps
  one line per server. Use the one of the strategy you pick below.
- With `geohash-relays-net`, `lists::load(source, platform, connector, cache_dir)` downloads it
  through Tor and keeps a copy for when the download fails.

## Step 3: the relays of a cell

```rust
use geohash_relays::{AppStrategy, Apps, Strategy};

// Talk with BitChat users: write and read where both apps do.
let ios_list = RelayDirectory::parse(&ios_csv, Platform::Ios);
let android_list = RelayDirectory::parse(&android_csv, Platform::Android);
let strategy = AppStrategy::new(Some(ios_list), Some(android_list), Apps::Both);

let to_listen = strategy.read("u09tv")?;   // Vec<Selected>
let to_publish = strategy.write("u09tv")?;
for s in &to_listen {
    println!("{}", s.relay.url);           // wss://…, already normalised
}
```

Which strategy to take:

| Your goal | Strategy | In short |
|---|---|---|
| Be seen by BitChat users, as the apps are today | `AppStrategy` (`AS`) with both lists | the union of what iOS and Android pick (5 + 5) |
| Also reach AirHop users | add `AirhopStrategy::from_directory(&android_list)` | the 10 relays AirHop picks |
| Your own users among themselves, simply | `a0::SharedStrategy::from_directory(list)` | one list, the 5 nearest relays to read, 8 to write, dead relays replaced |
| Your own users, hard for an attacker to take over | `a1::HrwStrategy::new(&list).with_salts(..)` | relays drawn by a hash instead of by distance; your users must share the salt |

A private relay of yours is not a strategy's business: connect to it beside the cell's relays.

## Step 4: connect, listen, publish (geohash-relays-net)

```rust
use std::sync::Arc;
use geohash_relays_net::connector::{Connector, Socks5};
use geohash_relays_net::nostr::{Event, Filter};
use geohash_relays_net::relay::{self, RelayEvent};

// Through a Tor daemon (or `connector::Direct`, or `arti::Arti`).
let connector: Arc<dyn Connector> = Arc::new(Socks5::new("127.0.0.1:9050".parse()?));

// What to listen to: the cell's messages (20000) and presences (20001).
let filter = Filter {
    kinds: vec![20000, 20001],
    tags: [('g', vec!["u09tv".to_string()])].into(),
    ..Filter::default()
};

// One connection per relay of the cell; everything comes back on `rx`.
let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
let handles: Vec<_> = to_listen
    .iter()
    .map(|s| relay::spawn(s.relay.url.clone(), "u09tv".into(), vec![filter.clone()],
                          connector.clone(), tx.clone(), Some(cell_key.clone())))
    .collect();

// Publish: on each relay of `to_publish` (a handle per relay).
handles[0].publish(Event::signed(&cell_key, now, 20000, tags, text));

// Read what comes.
while let Some(e) = rx.recv().await {
    match e {
        RelayEvent::Event { event, .. } => { /* a message or a presence of the cell */ }
        RelayEvent::Ok { accepted, .. } => { /* the relay took your event, or not */ }
        RelayEvent::State { relay, state, .. } => { /* connecting, connected, waiting, given up */ }
        _ => {}
    }
}
```

- `cell_key` is the key you sign with in that cell. BitChat derives one key per cell from the
  user's identity, so that two cells cannot be linked; do the same.
- The cell is also the Tor isolation key: each cell gets its own circuit.
- Reconnection, NIP-42 authentication and the wait for `OK` are done for you.
- Dropping a handle closes its connection.

## Step 5 (optional): set dead relays aside

Relays die. Two tools:

- **What your connections see**: when a relay gives up (`ConnState::Abandoned`) or refuses
  your events (`Ok { accepted: false }`), record it in a `RelayHealth` map and rebuild A0 with
  `.with_health(health)`: it takes the next relay instead.
- **Checking relays in advance**: `geohash_relays_net::qualify::run(relays, connector, false,
  limit)` reads each relay's NIP-11 document and says which ones refuse what BitChat needs
  (payment, writes restricted, authentication…). Remove them from the list
  (`prober.qualification().filter(list)?`).

## A complete example

[`examples/client.rs`](../examples/client.rs) loads a list, prints the relays each strategy
picks for a cell, and with `--listen` counts for 30 seconds the events of that cell, without
publishing anything:

```sh
curl -sO https://raw.githubusercontent.com/permissionlesstech/georelays/main/nostr_relays.csv
cargo run --features client --example client -- nostr_relays.csv u09tv
cargo run --features client --example client -- nostr_relays.csv u09tv --listen --tor 127.0.0.1:9050
```

## Rules

- Never log message contents, nicknames or keys.
- In tests, never publish on public relays: use a local relay (`connector::Loopback`).
- Something missing or wrong? Open an issue or a pull request on
  [geohash-relays](https://github.com/wvmscs/geohash-relays) (strategies, constants) or
  [geohash-relays-net](https://github.com/wvmscs/geohash-relays-net) (connections). The next
  clients will benefit.
