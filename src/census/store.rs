// SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)
// SPDX-License-Identifier: GPL-3.0-or-later

//! The census base (SQLite): the relays, the newest relay list of each
//! author, and what each list names. Migrations are numbered by
//! `PRAGMA user_version`, applied in order, never edited.

use std::path::Path;

use geohash_relays::a6::{Finding, Verdict};
use geohash_relays::census::{Candidate, Exclusion, Outcome, RelayList, exclusion};
use geohash_relays::strategy::Health;
use geohash_relays::strategy::Needs;
use rusqlite::{Connection, OptionalExtension, params};

use super::geo::Place;
use crate::error::{Error, Result};

const MIGRATIONS: &[&str] = &[
    // 1: relays, relay lists and what they name.
    "CREATE TABLE relay (
        url TEXT PRIMARY KEY,
        -- given with --set (1), or found in a relay list only (0)
        given INTEGER NOT NULL DEFAULT 0,
        first_seen INTEGER NOT NULL,
        -- last reading of its relay lists
        crawled_at INTEGER,
        answered INTEGER,
        lists INTEGER,
        failure TEXT,
        -- IP geolocation
        ip TEXT,
        country TEXT,
        city TEXT,
        lat REAL,
        lon REAL,
        geohash TEXT,
        located_at INTEGER,
        locate_error TEXT,
        -- A6: whether it has a NIP-11 document, and the verdict
        has_nip11 INTEGER,
        refusals TEXT,
        warnings TEXT,
        probed INTEGER,
        qualified_at INTEGER
    );
    CREATE TABLE relay_list (
        pubkey TEXT PRIMARY KEY,
        event_id TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        read_from TEXT NOT NULL,
        seen_at INTEGER NOT NULL
    );
    CREATE TABLE list_relay (
        pubkey TEXT NOT NULL REFERENCES relay_list (pubkey) ON DELETE CASCADE,
        url TEXT NOT NULL,
        PRIMARY KEY (pubkey, url)
    );
    CREATE INDEX list_relay_url ON list_relay (url);",
];

fn db(e: rusqlite::Error) -> Error {
    Error::Db(e.to_string())
}

/// What the base holds, in numbers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    pub relays: usize,
    pub given: usize,
    pub answered: usize,
    pub located: usize,
    pub qualified: usize,
    pub usable: usize,
    pub lists: usize,
}

/// A relay for the apps' lists: host, latitude, longitude.
#[derive(Debug, Clone, PartialEq)]
pub struct Listed {
    pub host: String,
    pub lat: f64,
    pub lon: f64,
}

/// A relay as the base knows it.
#[derive(Debug, Clone, PartialEq)]
pub struct Relay {
    pub url: String,
    /// Its last reading: answered or not; never read.
    pub answered: Option<bool>,
    pub failure: Option<String>,
    /// Latitude, longitude.
    pub place: Option<(f64, f64)>,
    pub city: Option<String>,
    pub country: Option<String>,
    pub locate_error: Option<String>,
    pub qualified: bool,
    /// Requirements refused (`R5 AuthRequired; …`), empty when none.
    pub refusals: Option<String>,
}

impl Relay {
    /// What a strategy cares about.
    pub fn candidate(&self) -> Candidate<'_> {
        Candidate {
            url: &self.url,
            answered: self.answered,
            qualified: self.qualified,
            refused: self.refusals.as_deref().is_some_and(|r| !r.is_empty()),
            placed: self.place.is_some(),
        }
    }

    /// Why a strategy with these `needs` cannot use it, with the details
    /// the base has; `None`: it can.
    pub fn excluded(&self, needs: Needs) -> Option<(Exclusion, String)> {
        let e = exclusion(&self.candidate(), needs)?;
        let detail = match e {
            Exclusion::NoAnswer => self.failure.clone(),
            Exclusion::Refused => self.refusals.clone(),
            Exclusion::NoPlace => Some(
                self.locate_error
                    .clone()
                    .unwrap_or_else(|| "no geolocation file".into()),
            ),
            _ => None,
        };
        let text = match detail {
            Some(d) => format!("{}: {d}", e.describe()),
            None => e.describe().to_owned(),
        };
        Some((e, text))
    }

    /// Its line in the relay list of the harmonised apps (the common rule,
    /// a strategy by distance: [`geohash_relays::as_::NEEDS`]), or why it
    /// has none. The address without `wss://` (port and path kept, as
    /// [`geohash_relays::normalize_url`] keeps them).
    pub fn bitchat(&self) -> std::result::Result<Listed, String> {
        if let Some((_, why)) = self.excluded(geohash_relays::as_::NEEDS) {
            return Err(why);
        }
        let (lat, lon) = self.place.ok_or("no place")?;
        Ok(Listed {
            host: self.url.trim_start_matches("wss://").to_owned(),
            lat,
            lon,
        })
    }

    /// `City CC`, as far as known.
    pub fn where_(&self) -> String {
        [self.city.as_deref(), self.country.as_deref()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" ")
    }
}

pub struct Store {
    conn: Connection,
}

impl Store {
    /// Opens the base at `path`, created and migrated if needed.
    pub fn open(path: &Path) -> Result<Store> {
        let conn = Connection::open(path).map_err(db)?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(db)?;
        Store::migrated(conn)
    }

    pub fn open_in_memory() -> Result<Store> {
        Store::migrated(Connection::open_in_memory().map_err(db)?)
    }

    fn migrated(mut conn: Connection) -> Result<Store> {
        conn.pragma_update(None, "foreign_keys", true).map_err(db)?;
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(db)?;
        let version = version as usize;
        if version > MIGRATIONS.len() {
            return Err(Error::Db(format!(
                "census base version {version} is newer than this program ({})",
                MIGRATIONS.len()
            )));
        }
        for (i, sql) in MIGRATIONS.iter().enumerate().skip(version) {
            let tx = conn.transaction().map_err(db)?;
            tx.execute_batch(sql).map_err(db)?;
            tx.pragma_update(None, "user_version", (i + 1) as i64)
                .map_err(db)?;
            tx.commit().map_err(db)?;
        }
        Ok(Store { conn })
    }

    /// Records relays given by hand (normalised URLs). Returns how many were
    /// not known.
    pub fn give(&self, urls: &[String], now: i64) -> Result<usize> {
        let mut new = 0;
        for url in urls {
            let known = self
                .conn
                .execute("UPDATE relay SET given = 1 WHERE url = ?1", [url])
                .map_err(db)?
                == 1;
            if !known {
                self.conn
                    .execute(
                        "INSERT INTO relay (url, given, first_seen) VALUES (?1, 1, ?2)",
                        params![url, now],
                    )
                    .map_err(db)?;
                new += 1;
            }
        }
        Ok(new)
    }

    /// Records relays found in relay lists; returns the ones not known.
    pub fn found(&self, urls: impl IntoIterator<Item = String>, now: i64) -> Result<Vec<String>> {
        let mut new = Vec::new();
        for url in urls {
            if self
                .conn
                .execute(
                    "INSERT INTO relay (url, first_seen) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
                    params![url, now],
                )
                .map_err(db)?
                == 1
            {
                new.push(url);
            }
        }
        Ok(new)
    }

    /// Every relay known.
    pub fn relays(&self) -> Result<Vec<String>> {
        let mut st = self
            .conn
            .prepare("SELECT url FROM relay ORDER BY url")
            .map_err(db)?;
        let rows = st.query_map([], |r| r.get(0)).map_err(db)?;
        rows.collect::<rusqlite::Result<_>>().map_err(db)
    }

    /// The relays that answered their last reading.
    pub fn answered(&self) -> Result<Vec<String>> {
        let mut st = self
            .conn
            .prepare("SELECT url FROM relay WHERE answered = 1 ORDER BY url")
            .map_err(db)?;
        let rows = st.query_map([], |r| r.get(0)).map_err(db)?;
        rows.collect::<rusqlite::Result<_>>().map_err(db)
    }

    /// How reading a relay's lists ended.
    pub fn crawled(&self, url: &str, outcome: &Outcome, now: i64) -> Result<()> {
        let (answered, lists, failure) = match outcome {
            Outcome::Answered { lists } => (true, Some(*lists as i64), None),
            Outcome::Failed(h) => (false, None, Some(health(h))),
            Outcome::Silent => (false, None, Some("silent")),
        };
        self.conn
            .execute(
                "UPDATE relay SET crawled_at = ?2, answered = ?3, lists = ?4, failure = ?5
                 WHERE url = ?1",
                params![url, now, answered, lists, failure],
            )
            .map_err(db)?;
        Ok(())
    }

    /// A relay list: kept when it is the newest of its author.
    pub fn list(&mut self, list: &RelayList, now: i64) -> Result<()> {
        let older: Option<(i64, String)> = self
            .conn
            .query_row(
                "SELECT created_at, event_id FROM relay_list WHERE pubkey = ?1",
                [&list.pubkey],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db)?;
        if older.is_some_and(|(at, id)| (at, id) >= (list.created_at, list.id.clone())) {
            return Ok(());
        }
        let tx = self.conn.transaction().map_err(db)?;
        tx.execute("DELETE FROM relay_list WHERE pubkey = ?1", [&list.pubkey])
            .map_err(db)?;
        tx.execute(
            "INSERT INTO relay_list (pubkey, event_id, created_at, read_from, seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![list.pubkey, list.id, list.created_at, list.read_from, now],
        )
        .map_err(db)?;
        for url in &list.relays {
            tx.execute(
                "INSERT OR IGNORE INTO list_relay (pubkey, url) VALUES (?1, ?2)",
                params![list.pubkey, url],
            )
            .map_err(db)?;
        }
        tx.commit().map_err(db)
    }

    /// Where a relay is, from its address.
    pub fn located(&self, url: &str, place: &Place, now: i64) -> Result<()> {
        self.conn
            .execute(
                "UPDATE relay SET ip = ?2, country = ?3, city = ?4, lat = ?5, lon = ?6,
                 geohash = ?7, located_at = ?8, locate_error = NULL WHERE url = ?1",
                params![
                    url,
                    place.ip.to_string(),
                    place.country,
                    place.city,
                    place.lat,
                    place.lon,
                    place.geohash,
                    now
                ],
            )
            .map_err(db)?;
        Ok(())
    }

    /// Why a relay could not be located (its last place is kept).
    pub fn not_located(&self, url: &str, why: &str, now: i64) -> Result<()> {
        self.conn
            .execute(
                "UPDATE relay SET locate_error = ?2, located_at = ?3 WHERE url = ?1",
                params![url, why, now],
            )
            .map_err(db)?;
        Ok(())
    }

    /// The NIP-11 document and the A6 verdict of a relay.
    pub fn qualified(&self, url: &str, has_nip11: bool, verdict: &Verdict, now: i64) -> Result<()> {
        let names = |f: &[Finding]| {
            f.iter()
                .map(|x| format!("{} {x:?}", x.requirement()))
                .collect::<Vec<_>>()
                .join("; ")
        };
        self.conn
            .execute(
                "UPDATE relay SET has_nip11 = ?2, refusals = ?3, warnings = ?4, probed = ?5,
                 qualified_at = ?6 WHERE url = ?1",
                params![
                    url,
                    has_nip11,
                    names(&verdict.refusals),
                    names(&verdict.warnings),
                    verdict.probed,
                    now
                ],
            )
            .map_err(db)?;
        Ok(())
    }

    /// The relays the BitChat apps can use, as their lists give them
    /// (`host,latitude,longitude`): see [`Relay::bitchat`].
    pub fn bitchat(&self) -> Result<Vec<Listed>> {
        Ok(self
            .all()?
            .iter()
            .filter_map(|r| r.bitchat().ok())
            .collect())
    }

    /// Every relay of the base, by URL.
    pub fn all(&self) -> Result<Vec<Relay>> {
        let mut st = self
            .conn
            .prepare(
                "SELECT url, answered, failure, lat, lon, city, country, locate_error,
                 qualified_at IS NOT NULL, refusals FROM relay ORDER BY url",
            )
            .map_err(db)?;
        let rows = st
            .query_map([], |r| {
                Ok(Relay {
                    url: r.get(0)?,
                    answered: r.get(1)?,
                    failure: r.get(2)?,
                    place: match (r.get::<_, Option<f64>>(3)?, r.get::<_, Option<f64>>(4)?) {
                        (Some(lat), Some(lon)) => Some((lat, lon)),
                        _ => None,
                    },
                    city: r.get(5)?,
                    country: r.get(6)?,
                    locate_error: r.get(7)?,
                    qualified: r.get(8)?,
                    refusals: r.get(9)?,
                })
            })
            .map_err(db)?;
        rows.collect::<rusqlite::Result<_>>().map_err(db)
    }

    pub fn summary(&self) -> Result<Summary> {
        let count = |sql: &str| -> Result<usize> {
            self.conn
                .query_row(sql, [], |r| r.get::<_, i64>(0))
                .map(|n| n as usize)
                .map_err(db)
        };
        Ok(Summary {
            relays: count("SELECT count(*) FROM relay")?,
            given: count("SELECT count(*) FROM relay WHERE given = 1")?,
            answered: count("SELECT count(*) FROM relay WHERE answered = 1")?,
            located: count("SELECT count(*) FROM relay WHERE lat IS NOT NULL")?,
            qualified: count("SELECT count(*) FROM relay WHERE qualified_at IS NOT NULL")?,
            usable: count(
                "SELECT count(*) FROM relay WHERE qualified_at IS NOT NULL AND refusals = ''",
            )?,
            lists: count("SELECT count(*) FROM relay_list")?,
        })
    }

    /// How many relay lists name `url`.
    pub fn mentions(&self, url: &str) -> Result<usize> {
        self.conn
            .query_row(
                "SELECT count(*) FROM list_relay WHERE url = ?1",
                [url],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n as usize)
            .map_err(db)
    }
}

fn health(h: &Health) -> &'static str {
    match h {
        Health::Dead => "dead",
        Health::AuthRequired => "auth required (R5)",
        Health::Redirect => "redirected (R2)",
        Health::BadCertificate => "certificate refused (R1)",
        Health::WriteRefused => "write refused",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(pubkey: &str, id: &str, at: i64, relays: &[&str]) -> RelayList {
        RelayList {
            id: id.into(),
            pubkey: pubkey.into(),
            created_at: at,
            relays: relays.iter().map(|r| (*r).into()).collect(),
            read_from: "wss://seed.example.org".into(),
        }
    }

    #[test]
    fn relays_given_and_found() {
        let s = Store::open_in_memory().unwrap();
        let given = [
            "wss://a.example.org".to_owned(),
            "wss://b.example.org".to_owned(),
        ];
        assert_eq!(s.give(&given, 10).unwrap(), 2);
        assert_eq!(s.give(&given[..1], 20).unwrap(), 0);
        let new = s
            .found(
                ["wss://a.example.org".into(), "wss://c.example.org".into()],
                30,
            )
            .unwrap();
        assert_eq!(new, ["wss://c.example.org"]);
        assert_eq!(s.relays().unwrap().len(), 3);
        let sum = s.summary().unwrap();
        assert_eq!((sum.relays, sum.given), (3, 2));
    }

    #[test]
    fn newest_list_of_an_author() {
        let mut s = Store::open_in_memory().unwrap();
        s.list(
            &list(
                "p",
                "2",
                20,
                &["wss://a.example.org", "wss://b.example.org"],
            ),
            1,
        )
        .unwrap();
        s.list(&list("p", "1", 10, &["wss://old.example.org"]), 2)
            .unwrap();
        assert_eq!(s.mentions("wss://old.example.org").unwrap(), 0);
        assert_eq!(s.mentions("wss://a.example.org").unwrap(), 1);
        s.list(&list("p", "3", 30, &["wss://b.example.org"]), 3)
            .unwrap();
        assert_eq!(s.mentions("wss://a.example.org").unwrap(), 0);
        s.list(&list("q", "4", 30, &["wss://b.example.org"]), 3)
            .unwrap();
        assert_eq!(s.mentions("wss://b.example.org").unwrap(), 2);
        assert_eq!(s.summary().unwrap().lists, 2);
    }

    #[test]
    fn the_bitchat_list() {
        let s = Store::open_in_memory().unwrap();
        let urls: Vec<String> = [
            "wss://good.example.org",
            "wss://refused.example.org",
            "wss://silent.example.org",
            "wss://unplaced.example.org",
            "wss://port.example.org:7777",
            "wss://path.example.org/nostr",
            "ws://clear.example.org",
            "wss://abcdefghijklmnop.onion",
        ]
        .map(String::from)
        .into();
        s.give(&urls, 1).unwrap();
        let place = Place {
            ip: "203.0.113.7".parse().unwrap(),
            lat: 48.8566,
            lon: 2.3522,
            country: Some("FR".into()),
            city: Some("Paris".into()),
            geohash: "u09tvw".into(),
        };
        let ok = Verdict::default();
        let refused = Verdict {
            refusals: vec![Finding::AuthRequired],
            ..Verdict::default()
        };
        for u in &urls {
            let silent = u.contains("silent");
            let outcome = if silent {
                Outcome::Silent
            } else {
                Outcome::Answered { lists: 0 }
            };
            s.crawled(u, &outcome, 2).unwrap();
            // An onion has no address to locate.
            if !u.contains("unplaced") && !u.ends_with(".onion") {
                s.located(u, &place, 3).unwrap();
            }
            let v = if u.contains("refused") { &refused } else { &ok };
            s.qualified(u, false, v, 4).unwrap();
        }
        // The common rule keeps ports and paths; no ws://, no place, no
        // answer or a refusal leave a relay out of a list ranked by distance.
        let hosts: Vec<String> = s.bitchat().unwrap().into_iter().map(|l| l.host).collect();
        assert_eq!(
            hosts,
            [
                "good.example.org",
                "path.example.org/nostr",
                "port.example.org:7777"
            ]
        );
        let relays = s.all().unwrap();
        let why = |url: &str| {
            relays
                .iter()
                .find(|r| r.url == url)
                .unwrap()
                .excluded(geohash_relays::as_::NEEDS)
                .map(|(e, _)| e)
        };
        assert_eq!(
            why("wss://abcdefghijklmnop.onion"),
            Some(Exclusion::NoPlace)
        );
        assert_eq!(why("ws://clear.example.org"), Some(Exclusion::Clear));
        assert_eq!(why("wss://silent.example.org"), Some(Exclusion::NoAnswer));
        // A strategy that does not rank by distance keeps the onion.
        let onion = relays.iter().find(|r| r.url.ends_with(".onion")).unwrap();
        assert!(onion.excluded(geohash_relays::a1::NEEDS).is_none());
        let sum = s.summary().unwrap();
        assert_eq!((sum.answered, sum.located, sum.usable), (7, 6, 7));
    }

    #[test]
    fn a_newer_base_is_refused() {
        let dir = std::env::temp_dir().join(format!("census-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("census.sqlite");
        Store::open(&path).unwrap();
        Connection::open(&path)
            .unwrap()
            .pragma_update(None, "user_version", 99)
            .unwrap();
        assert!(matches!(Store::open(&path), Err(Error::Db(_))));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
