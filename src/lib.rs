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
//!   circuit per cell.
//!
//! All three wait for `OK`, answer `AUTH` (NIP-42) and read `CLOSED`, which
//! the apps ignore today: the apps' side comes as pull requests (lot 12 of
//! the plan). Every constant is in [`geohash_relays::params`].

#[cfg(any(
    all(feature = "bitchat", feature = "bitchat-android"),
    all(feature = "bitchat", feature = "console"),
    all(feature = "bitchat-android", feature = "console"),
))]
compile_error!("features `bitchat`, `bitchat-android` and `console` are exclusive: enable one");

#[cfg(not(any(feature = "bitchat", feature = "bitchat-android", feature = "console")))]
compile_error!("enable one of the features `bitchat`, `bitchat-android`, `console`");

#[cfg(feature = "arti")]
pub mod arti;
pub mod connector;
mod error;
pub mod http;
pub mod lists;
pub mod nostr;
pub mod ports;
pub mod relay;
pub mod runner;

pub use error::{Error, Result};

/// The active feature: `"bitchat"`, `"bitchat-android"` or `"console"`.
pub const IMPLEMENTATION: &str = if cfg!(feature = "bitchat") {
    "bitchat"
} else if cfg!(feature = "bitchat-android") {
    "bitchat-android"
} else {
    "console"
};
