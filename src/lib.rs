// SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)
// SPDX-License-Identifier: GPL-3.0-or-later

//! Communication for the `geohash-relays` strategies: connections to relays,
//! relay lists, NIP-11 documents, and the runner of the strategy machines.
//!
//! One feature, and one only, says whose communication functions are used:
//!
//! * `bitchat`: the iOS/macOS app (`NostrRelayManager.swift`): 10 attempts
//!   then 10 min, ±20 % jitter, history ended after 10 s without `EOSE`;
//!   Tor optional ([`connector::Direct`]);
//! * `bitchat-android`: the Android app (`NostrRelayManager.kt`): backoff
//!   without limit; Tor optional;
//! * `console`: bitchat-console and bitchat-geohash: **Tor mandatory**, one
//!   circuit per cell;
//! * `client`: a client of its own that integrates the strategies
//!   (`docs/integration.md`): backoff without limit, Tor optional.
//!
//! All of them wait for `OK`, answer `AUTH` (NIP-42) and read `CLOSED`,
//! which the apps ignore today: the apps' side comes as pull requests (lot 12
//! of the plan). Every constant is in [`geohash_relays::params`].

#[cfg(any(
    all(feature = "bitchat", feature = "bitchat-android"),
    all(feature = "bitchat", feature = "console"),
    all(feature = "bitchat", feature = "client"),
    all(feature = "bitchat-android", feature = "console"),
    all(feature = "bitchat-android", feature = "client"),
    all(feature = "console", feature = "client"),
))]
compile_error!(
    "features `bitchat`, `bitchat-android`, `console` and `client` are exclusive: enable one"
);

#[cfg(not(any(
    feature = "bitchat",
    feature = "bitchat-android",
    feature = "console",
    feature = "client"
)))]
compile_error!("enable one of the features `bitchat`, `bitchat-android`, `console`, `client`");

#[cfg(feature = "arti")]
pub mod arti;
#[cfg(feature = "census")]
pub mod census;
pub mod connector;
mod error;
pub mod http;
pub mod lists;
pub mod nostr;
pub mod ports;
pub mod qualify;
pub mod relay;
pub mod runner;

pub use error::{Error, Result};

/// The active feature: `"bitchat"`, `"bitchat-android"`, `"console"` or
/// `"client"`.
pub const IMPLEMENTATION: &str = if cfg!(feature = "bitchat") {
    "bitchat"
} else if cfg!(feature = "bitchat-android") {
    "bitchat-android"
} else if cfg!(feature = "client") {
    "client"
} else {
    "console"
};
