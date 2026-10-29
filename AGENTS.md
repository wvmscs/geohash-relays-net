# AGENTS.md

Guidance for coding agents (and humans) working in this crate.

## What this is

`geohash-relays-net`: the communication of the `geohash-relays` strategies (decision G12 of
`../geohash-relays/PLAN_ET1.md`): connections to relays, relay lists, NIP-11 documents, and
the runner of the strategy machines (`geohash_relays::sansio`). `geohash-relays` stays pure
(no network) and proposable to the apps; everything that talks to the network is here, under
GPL-3.0-or-later. bitchat-console uses it; `geohash-relays` never depends on it.

## Features

Exactly one of three (a `compile_error!` otherwise), whose communication functions are used:

- `bitchat`: the iOS/macOS app (`NostrRelayManager.swift`): 10 attempts then 10 min, ±20 %,
  history ended after 10 s without `EOSE`. Tor optional (`connector::Direct`), as in the app.
- `bitchat-android`: the Android app (`NostrRelayManager.kt`): backoff without limit. Tor
  optional.
- `console`: bitchat-console and bitchat-geohash. **Tor mandatory** (no direct connector, only
  `Loopback` for tests), one circuit per cell.

All three wait for `OK`, answer `AUTH` (NIP-42) and read `CLOSED`, which the apps ignore today
(decision G13): the apps' side comes as pull requests (lot 12).

`arti` adds Tor inside the process, with any of them.

## Constraints

- Every constant lives in `geohash_relays::params` (decision G14), with its source: none here.
- Every behaviour of a feature cites the app source it mirrors (file and function).
- Never publish on public relays or real channels from tests or by agents. Tests are offline
  (local relay, local SOCKS proxy); the ones on the real network are `#[ignore]`d and need the
  relay given in `BITCHAT_TEST_RELAY`.
- Never log keys, seeds, message contents or pubkeys.
- Code, comments and rustdoc in English.
- Own git repository (`origin` = `git@github.com:wvmscs/geohash-relays-net.git`, branch
  `main`), own `[workspace]`. Tagged versions never change; no new tags.

## Commands

```sh
cargo fmt --check
for f in bitchat bitchat-android console; do
  cargo clippy --all-targets --features $f -- -D warnings && cargo test --features $f
done
cargo deny --features console,arti check advisories licenses sources
reuse lint
```

While `geohash-relays` changes on its `strategies` branch, test against the local copy:

```sh
cargo test --features console \
  --config 'patch."https://github.com/wvmscs/geohash-relays.git".geohash-relays.path="../geohash-relays"'
```

<!-- REUSE-IgnoreStart -->
A new file starts with
`SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)` and
`SPDX-License-Identifier: GPL-3.0-or-later` in a comment, or is covered by `REUSE.toml`.
<!-- REUSE-IgnoreEnd -->
