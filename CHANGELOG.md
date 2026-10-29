# Changelog

## [Unreleased]

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
