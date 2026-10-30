# Changelog

## [Unreleased]

### Added
- Census of relays (feature `census`, lot 13 of geohash-relays, G15): the binary
  `relay-census` (`--set`, `--refresh`, `--compat bitchat`) and its SQLite base; rounds of
  `geohash_relays::census::Crawler` (NIP-65 relay lists) until no relay is new; places from an
  offline IP geolocation file (DB-IP Lite, GeoLite2; `maxminddb`); A6 qualification, with a
  write test on request (`--probe`); the apps' CSV list of usable relays. Places and
  qualifications run at the same time (`tokio::join!`), each 16 at a time.
- `relay-census --eligibility`: for each strategy, the relays it can use and the ones it
  leaves out, by reason (`geohash_relays::census::exclusion`, the `NEEDS` of each strategy).
  `--compat bitchat` follows the common rule of the harmonised apps: ports and paths kept,
  one CSV (`Relay::bitchat`, `Relay::excluded`), one address per server (`by_server`: the one
  without a path, else the most named); `--legacy` compares by server; `--eligibility` counts
  servers too.
- `relay-census --legacy` (`census::legacy`): the census against the apps' own lists (iOS,
  Android), a diff by server with the reasons; the lists from local copies younger than 24 h,
  else downloaded through the connector (`--lists-dir`). `Store::all`, `Relay::bitchat` (one
  rule for `--compat` and `--legacy`).
- `Connector::resolve`: host names resolved where the connector resolves them (Tor's SOCKS5
  `RESOLVE`, Arti, the system for `Direct`, loopback for tests).
- `qualify::run`: the A6 run, moved from bitchat-console, for it and the census.
- `Direct` also with the feature `census` (`relay-census --direct`).

### Fixed
- NIP-11 fetches give up after `NIP11_TIMEOUT` (20 s): some servers never answer and held a
  place of the A6 prober (found by the real measurement of lot 9).

### Added
- Lot 4 (A6): a redirection (R2) or a refused certificate (R1) ends a connection for good
  (`relay::permanent`), reported as `Health::Redirect` and `Health::BadCertificate`; the A6
  prober through the runner (live delivery, then read-back).
- `runner` (lot 2): runs a `geohash_relays::sansio` machine over the feature's relay
  connections; events verified (id, signature, tag limits) before they become inputs;
  publications on the relays the machine names; NIP-11 through `HttpFetch`. Tested with the A4
  republisher: two relay sets connected once, no loop between two republishers.
- Crate skeleton (lot 0 of geohash-relays' `PLAN_ET1.md`): GPL-3.0-or-later, REUSE, CI for
  each feature, `cargo deny`, `SECURITY.md`, `CONTRIBUTING.md`.
- Features `bitchat`, `bitchat-android`, `console`, exclusive; `arti`.
- From bitchat-console: `connector` (`Socks5`, `Loopback`, `Arti`), `relay`, `nostr`, `lists`,
  with their tests; constants from `geohash_relays::params`.
- `connector::Direct` (app features), `relay::Policy` per feature (iOS: 10 attempts then
  10 min, ±20 %, `EOSE` after 10 s), `http::get` and `http::nip11`, `Filter::authors`,
  conversions to the `sansio` types, `ports` (`Clock`, `HttpFetch`).
