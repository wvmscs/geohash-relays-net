// SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)
// SPDX-License-Identifier: GPL-3.0-or-later

//! The ports (decision G2 of geohash-relays' `PLAN_ET1.md`): what a strategy
//! machine ([`geohash_relays::sansio::Machine`]) needs from the outside, one
//! trait per need, with the behaviour of the active feature's
//! implementation. The runner drives a machine through
//! them; a test drives it through fakes.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use geohash_relays::params::comm::NIP11_TIMEOUT;

use crate::connector::Connector;
use crate::error::Result;

/// The time, in Unix seconds.
pub trait Clock: Send + Sync {
    fn now(&self) -> i64;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        crate::nostr::unix_now()
    }
}

pub type Fetching<'a> = Pin<Box<dyn Future<Output = Result<Option<String>>> + Send + 'a>>;

/// NIP-11 documents (A6).
pub trait HttpFetch: Send + Sync {
    /// The NIP-11 document of `relay`, `None` when it has none.
    fn nip11<'a>(&'a self, relay: &'a str) -> Fetching<'a>;
}

/// NIP-11 through a connector (Tor for the console), one circuit per relay.
pub struct ConnectorFetch(pub Arc<dyn Connector>);

impl HttpFetch for ConnectorFetch {
    fn nip11<'a>(&'a self, relay: &'a str) -> Fetching<'a> {
        Box::pin(async move {
            // A server that never answers must not hold a place.
            tokio::time::timeout(
                NIP11_TIMEOUT,
                crate::http::nip11(relay, relay, self.0.as_ref()),
            )
            .await
            .unwrap_or(Ok(None))
        })
    }
}
