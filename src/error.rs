// SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)
// SPDX-License-Identifier: GPL-3.0-or-later

//! Error type of the crate.

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// No Tor where Tor is needed.
    #[error("Tor is not reachable at {0}: start tor, or give its SOCKS address with --tor-socks")]
    TorUnavailable(String),
    /// Arti could not start or bootstrap.
    #[error("Tor (Arti): {0}")]
    Tor(String),
    #[error("no {platform} relay list: {reason}, and no cached copy")]
    NoRelayList { platform: String, reason: String },
    #[error("HTTP: {0}")]
    Http(String),
    /// The census base (feature `census`).
    #[error("census base: {0}")]
    Db(String),
    /// The IP geolocation file (feature `census`).
    #[error("IP geolocation: {0}")]
    GeoIp(String),
    #[error(transparent)]
    Strategy(#[from] geohash_relays::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
