// SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tor in the binary, with Arti (lot 11, feature `arti`), as the iOS app
//! does (`localPackages/Arti`, `arti-client`). No daemon to install.
//!
//! Each isolation key (a cell, D20) gets its own [`IsolationToken`]: streams
//! of two cells never share a circuit.

use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::Mutex;

use arti_client::config::TorClientConfigBuilder;
use arti_client::{IsolationToken, StreamPrefs, TorClient};
use tor_rtcompat::PreferredRuntime;

use crate::connector::{BoxStream, Connecting, Connector};
use crate::error::{Error, Result};

pub struct Arti {
    client: std::sync::Arc<TorClient<PreferredRuntime>>,
    tokens: Mutex<HashMap<String, IsolationToken>>,
}

impl Arti {
    /// Starts Tor and waits until it can build circuits. State and
    /// directory cache live under `dir` (`tor-state`, `tor-cache`), so later
    /// starts are faster.
    pub async fn bootstrap(dir: &Path) -> Result<Arti> {
        let config =
            TorClientConfigBuilder::from_directories(dir.join("tor-state"), dir.join("tor-cache"))
                .build()
                .map_err(|e| Error::Tor(e.to_string()))?;
        let client = TorClient::create_bootstrapped(config)
            .await
            .map_err(|e| Error::Tor(e.to_string()))?;
        Ok(Arti {
            client,
            tokens: Mutex::new(HashMap::new()),
        })
    }

    fn prefs(&self, isolation: &str) -> StreamPrefs {
        let token = *self
            .tokens
            .lock()
            .expect("not poisoned")
            .entry(isolation.to_owned())
            .or_insert_with(IsolationToken::new);
        let mut prefs = StreamPrefs::new();
        prefs.set_isolation(token);
        prefs
    }
}

impl Connector for Arti {
    fn connect<'a>(&'a self, host: &'a str, port: u16, isolation: &'a str) -> Connecting<'a> {
        Box::pin(async move {
            let prefs = self.prefs(isolation);
            let stream = tokio::time::timeout(
                crate::connector::CONNECT_TIMEOUT,
                self.client.connect_with_prefs((host, port), &prefs),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no answer through Tor"))?
            .map_err(|e| io::Error::other(e.to_string()))?;
            Ok(Box::new(stream) as BoxStream)
        })
    }

    fn describe(&self) -> String {
        "tor (arti, in the binary)".into()
    }
}
