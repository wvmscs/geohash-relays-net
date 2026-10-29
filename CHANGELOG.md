# Changelog

## [Unreleased]

### Added
- Crate skeleton (lot 0 of geohash-relays' `PLAN_ET1.md`): GPL-3.0-or-later, REUSE, CI for
  each feature, `cargo deny`, `SECURITY.md`, `CONTRIBUTING.md`.
- Features `bitchat`, `bitchat-android`, `console`, exclusive; `arti`.
- From bitchat-console: `connector` (`Socks5`, `Loopback`, `Arti`), `relay`, `nostr`, `lists`,
  with their tests; constants from `geohash_relays::params`.
- `connector::Direct` (app features), `relay::Policy` per feature (iOS: 10 attempts then
  10 min, ±20 %, `EOSE` after 10 s), `http::get` and `http::nip11`, `Filter::authors`,
  conversions to the `sansio` types, `ports` (`Clock`, `HttpFetch`).
