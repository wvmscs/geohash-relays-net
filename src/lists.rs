// SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)
// SPDX-License-Identifier: GPL-3.0-or-later

//! The apps' relay lists: downloaded through the connector (Tor, D21), the
//! last valid copy kept in the data directory as a fallback, or read from a
//! local file.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use geohash_relays::{Platform, RelayDirectory};

use crate::connector::Connector;
use crate::error::{Error, Result};

/// Largest list accepted (the real ones are about 20 KB).
pub use geohash_relays::params::comm::MAX_LIST_BYTES;

/// Where a list comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListSource {
    /// `https://…` (or `http://` on the loopback, for tests).
    Url(String),
    Path(PathBuf),
}

impl ListSource {
    pub fn official(platform: Platform) -> Self {
        ListSource::Url(platform.list_url().to_owned())
    }

    /// `http://` or `https://` is a URL, anything else a path.
    pub fn parse(s: &str) -> Self {
        if s.starts_with("https://") || s.starts_with("http://") {
            ListSource::Url(s.to_owned())
        } else {
            ListSource::Path(s.into())
        }
    }
}

/// Reads a list, falling back on the cached copy. A list without relays,
/// or an iOS list with a host at two places (the app refuses it), is not
/// used: the cached copy is, if any.
pub async fn load(
    source: &ListSource,
    platform: Platform,
    connector: Arc<dyn Connector>,
    cache_dir: &Path,
) -> Result<RelayDirectory> {
    let cache = cache_dir.join(format!("{}.csv", platform.as_str()));
    let fresh = match source {
        ListSource::Path(p) => std::fs::read_to_string(p).map_err(Error::from),
        ListSource::Url(url) => fetch(url, connector.as_ref()).await,
    };
    let refused = match fresh {
        Ok(csv) => {
            let dir = RelayDirectory::parse(&csv, platform);
            match (dir.is_empty(), dir.conflict()) {
                (false, None) => {
                    if matches!(source, ListSource::Url(_)) {
                        std::fs::create_dir_all(cache_dir)?;
                        std::fs::write(&cache, &csv)?;
                    }
                    tracing::info!(
                        platform = platform.as_str(),
                        relays = dir.len(),
                        "relay list loaded"
                    );
                    return Ok(dir);
                }
                (true, _) => "no usable relay".to_owned(),
                (false, Some(host)) => format!("host {host} at two places (the app refuses it)"),
            }
        }
        Err(e) => e.to_string(),
    };
    match std::fs::read_to_string(&cache) {
        Ok(csv) => {
            tracing::warn!(platform = platform.as_str(), reason = %refused, "relay list not usable, using the cached copy");
            Ok(RelayDirectory::parse(&csv, platform))
        }
        Err(_) => Err(Error::NoRelayList {
            platform: platform.as_str().to_owned(),
            reason: refused,
        }),
    }
}

/// `GET url` through the connector (isolation `relay-lists`): a relay list.
pub async fn fetch(url: &str, connector: &dyn Connector) -> Result<String> {
    let body = crate::http::get(
        url,
        "text/csv, text/plain",
        MAX_LIST_BYTES,
        "relay-lists",
        connector,
    )
    .await?;
    String::from_utf8(body).map_err(|_| Error::Http(format!("{url}: not UTF-8 text")))
}
