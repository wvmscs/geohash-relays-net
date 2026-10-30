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

- `connector`: streams to relays, and names resolved the same way: `Socks5` (a Tor daemon,
  isolation by user name, names resolved by the exit), `Arti` (feature `arti`), `Direct`
  (app features, and `census` on request), `Loopback` (tests).
- `relay`: one connection to one relay for one cell: subscription, events, publications,
  NIP-42, reconnection with the feature's `Policy`.
- `nostr`: events (id, BIP-340 signature, verification, tag limits) and filters.
- `http`, `lists`: the apps' relay lists and NIP-11 documents, over the connector.
- `ports`: what a strategy machine needs (`Clock`, `HttpFetch`), and the runner that drives
  `geohash_relays::sansio` machines.
- `qualify`: A6 run (NIP-11 documents, and a write test on request), for bitchat-console and
  the census.
- `census` (feature `census`): the census of relays below.

## Census of relays: `relay-census`

A SQLite base of the relays users name in their relay lists (NIP-65, kind 10002), with their
place and whether the BitChat apps can use them.

```sh
cargo install --git https://github.com/wvmscs/geohash-relays-net --features console,census,arti relay-census
relay-census --set wss://relay.primal.net wss://nos.lol      # the relays to start from
relay-census --refresh --geoip dbip-city-lite.mmdb            # through Tor, read-only
relay-census --compat bitchat --out relays.csv                # for the apps' lists
relay-census --legacy                                         # against the apps' own lists
```

- `--set`: records relays (normalised as the apps key servers; local and private addresses
  refused).
- `--refresh`: reads the relay lists of every known relay (the newest list of each author),
  adds the relays they name, and reads those, round after round until none is new
  (`--rounds`, 8 by default). Then, for the relays that answered, both at the same time: their address (resolved
  through Tor), its place in the geolocation file (latitude, longitude, country, city,
  geohash), and the BitChat requirements (A6 of geohash-relays: NIP-11 declarations; R1, R2
  and R5 to R9 refuse, R8, R11, R13 warn). `--probe` adds a write test: one kind 20000 event
  per relay, with a throwaway key, in the cell `7zzzzzzz` (open sea), read back; it is a real
  publication on every relay, so only on purpose.
- `--compat bitchat`: the usable relays in the apps' list format (`Relay URL,Latitude,Longitude`,
  a host per line): `wss://` on port 443 without a path, answered, placed, no refusal.
- `--legacy`: the census against the apps' own lists, iOS then Android, as a diff by server:
  `-` in the list but not usable for the census (and why: unknown, never read, did not
  answer, refused, not placed), `+` usable for the census but not in the list (its place),
  ` ` in both (how far apart the two places are). The lists are read from local copies
  (`--lists-dir`, default the base's directory), downloaded through the connector when
  missing or older than 24 h, as the apps do.
- Through a Tor daemon by default (`--tor-socks`, `$BITCHAT_TOR_SOCKS`, else 127.0.0.1:9050),
  or Arti in the binary (`--arti`), or `--direct` (every relay then sees this machine).
- The geolocation file is not included: DB-IP's free
  [IP to City Lite](https://db-ip.com/db/download/ip-to-city-lite) (MMDB format, monthly,
  [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/): credit "IP Geolocation by DB-IP"
  where you publish places from it), or MaxMind GeoLite2 City (an account is needed).
  `$RELAY_CENSUS_GEOIP` instead of `--geoip`.

The base (`relay-census.sqlite` by default, `--db`): `relay` (one line per relay: given or
found, last reading and why it failed, place, NIP-11, refusals and warnings), `relay_list`
(the newest list of each author: its id, date, where it was read) and `list_relay` (the
relays each list names).

## Licence

GPL-3.0-or-later. Every file says so with its SPDX tags ([REUSE](https://reuse.software)): a
header, or `REUSE.toml`; the licence text is in `LICENSES/`.
