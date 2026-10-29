# geohash-relays-net

Communication for the [geohash-relays](https://github.com/wvmscs/geohash-relays) strategies:
how a BitChat client reaches relays, with the behaviour of one implementation, chosen by a
feature.

| Feature | Implementation | Behaviour |
|---|---|---|
| `bitchat` | iOS/macOS app | backoff 1 s to 5 min ±20 %, 10 attempts then 10 min, history ended after 10 s without `EOSE`; Tor optional |
| `bitchat-android` | Android app | backoff 1 s to 5 min without limit; Tor optional |
| `console` | bitchat-console, bitchat-geohash | backoff 1 s to 5 min without limit; **Tor mandatory**, one circuit per cell |

All three wait for `OK`, answer NIP-42 `AUTH` and read `CLOSED` (the apps ignore them today).

## What it does

- `connector`: streams to relays: `Socks5` (a Tor daemon, isolation by user name), `Arti`
  (feature `arti`), `Direct` (app features only), `Loopback` (tests).
- `relay`: one connection to one relay for one cell: subscription, events, publications,
  NIP-42, reconnection with the feature's `Policy`.
- `nostr`: events (id, BIP-340 signature, verification, tag limits) and filters.
- `http`, `lists`: the apps' relay lists and NIP-11 documents, over the connector.
- `ports`: what a strategy machine needs (`Clock`, `HttpFetch`), and the runner that drives
  `geohash_relays::sansio` machines.

## Licence

GPL-3.0-or-later. Every file says so with its SPDX tags ([REUSE](https://reuse.software)): a
header, or `REUSE.toml`; the licence text is in `LICENSES/`.
