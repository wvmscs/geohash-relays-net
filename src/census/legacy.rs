// SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)
// SPDX-License-Identifier: GPL-3.0-or-later

//! The census against the apps' relay lists (`relay-census --legacy`): what
//! each list has that the census finds unusable, what the census finds
//! usable that the list lacks, and how far apart the two places of a relay
//! in both are.
//!
//! The lists are read from a local copy younger than
//! [`LIST_MAX_AGE_SECS`] (the apps download theirs every 24 h), else
//! downloaded through the connector and kept ([`crate::lists::load`]).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use geohash_relays::census::server;
use geohash_relays::params::LIST_MAX_AGE_SECS;
use geohash_relays::select::haversine_km;
use geohash_relays::{Platform, RelayDirectory, normalize_url};

use super::store::{Relay, by_server};
use crate::connector::Connector;
use crate::error::Result;
use crate::lists::{ListSource, load};

/// An app's list, and where it came from.
#[derive(Debug, Clone)]
pub struct AppList {
    pub platform: Platform,
    pub list: RelayDirectory,
    /// The local copy read.
    pub path: PathBuf,
    /// Its age, in seconds.
    pub age: i64,
}

/// The local copy of a platform's list.
pub fn copy_path(dir: &Path, platform: Platform) -> PathBuf {
    dir.join(format!("{}.csv", platform.as_str()))
}

/// The local copy, if younger than [`LIST_MAX_AGE_SECS`].
pub fn recent(dir: &Path, platform: Platform) -> Option<AppList> {
    let path = copy_path(dir, platform);
    let age = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())?
        .as_secs() as i64;
    if age >= LIST_MAX_AGE_SECS {
        return None;
    }
    let csv = std::fs::read_to_string(&path).ok()?;
    Some(AppList {
        platform,
        list: RelayDirectory::parse(&csv, platform),
        path,
        age,
    })
}

/// The official list, downloaded through `connector` into `dir` (the last
/// valid copy is used when the download fails or is refused).
pub async fn download(
    dir: &Path,
    platform: Platform,
    connector: Arc<dyn Connector>,
) -> Result<AppList> {
    let list = load(&ListSource::official(platform), platform, connector, dir).await?;
    let path = copy_path(dir, platform);
    let age = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .map_or(0, |d| d.as_secs() as i64);
    Ok(AppList {
        platform,
        list,
        path,
        age,
    })
}

/// One line of the diff, by server.
#[derive(Debug, Clone, PartialEq)]
pub enum Line {
    /// In the list, not usable for the census: why.
    OnlyList { host: String, why: String },
    /// Usable for the census, not in the list: where.
    OnlyCensus { host: String, place: String },
    /// In both: the distance between the two places, in km.
    Both { host: String, km: f64 },
}

impl Line {
    fn host(&self) -> &str {
        match self {
            Line::OnlyList { host, .. }
            | Line::OnlyCensus { host, .. }
            | Line::Both { host, .. } => host,
        }
    }
}

/// The diff of an app's list with the census, by server ([`server`]): an
/// app's list names a server once, the census may know it under several
/// paths ([`by_server`] picks one).
pub fn diff(relays: &[Relay], app: &AppList) -> Vec<Line> {
    let census = by_server(relays, geohash_relays::as_::NEEDS);
    // The list by server: Android may have one twice (`host`, `host:443`),
    // the first coordinates count.
    let mut listed: BTreeMap<String, (f64, f64)> = BTreeMap::new();
    for e in app.list.relays() {
        if let Some(url) = normalize_url(&e.url) {
            listed
                .entry(server(&url).to_owned())
                .or_insert((e.lat, e.lon));
        }
    }
    let mut lines = Vec::new();
    for (srv, (lat, lon)) in &listed {
        let host = srv.trim_start_matches("wss://").to_owned();
        let line = match census.get(srv.as_str()).map(|r| r.bitchat()) {
            None => Line::OnlyList {
                host,
                why: "unknown to the census".into(),
            },
            Some(Err(why)) => Line::OnlyList { host, why },
            Some(Ok(c)) => Line::Both {
                host,
                km: haversine_km(*lat, *lon, c.lat, c.lon),
            },
        };
        lines.push(line);
    }
    for (srv, r) in &census {
        if listed.contains_key(*srv) {
            continue;
        }
        if let Ok(c) = r.bitchat() {
            lines.push(Line::OnlyCensus {
                host: c.host,
                place: r.where_(),
            });
        }
    }
    lines.sort_by(|a, b| a.host().cmp(b.host()));
    lines
}

/// The diff as text: `-` in the list only (not usable for the census), `+`
/// usable for the census only, ` ` in both, then the counts.
pub fn render(app: &AppList, census: &str, lines: &[Line]) -> String {
    let mut out = String::new();
    let width = lines.iter().map(|l| l.host().len()).max().unwrap_or(0);
    let _ = writeln!(
        out,
        "--- {} list ({}, {} h old, {} relays)",
        app.platform.as_str(),
        app.path.display(),
        app.age / 3600,
        app.list.len()
    );
    let _ = writeln!(out, "+++ {census}");
    let (mut only_list, mut unknown, mut only_census, mut both) = (0, 0, 0, 0);
    for l in lines {
        match l {
            Line::OnlyList { host, why } => {
                only_list += 1;
                unknown += usize::from(why == "unknown to the census");
                let _ = writeln!(out, "-{host:<width$}  {why}");
            }
            Line::OnlyCensus { host, place } => {
                only_census += 1;
                let _ = writeln!(out, "+{host:<width$}  {place}");
            }
            Line::Both { host, km } => {
                both += 1;
                let _ = writeln!(out, " {host:<width$}  both, {km:.0} km apart");
            }
        }
    }
    let _ = writeln!(
        out,
        "@@ {only_list} in the list only ({unknown} unknown to the census), {only_census} usable \
         for the census only, {both} in both"
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(url: &str, answered: bool, refusals: &str, place: Option<(f64, f64)>) -> Relay {
        Relay {
            url: url.into(),
            answered: Some(answered),
            failure: (!answered).then(|| "dead".into()),
            place,
            city: Some("Paris".into()),
            country: Some("FR".into()),
            locate_error: None,
            qualified: true,
            refusals: Some(refusals.into()),
            mentions: 0,
        }
    }

    #[test]
    fn the_diff_by_server() {
        let csv = "Relay URL,Latitude,Longitude\n\
                   both.example.org,48.85,2.35\n\
                   dead.example.org,0,0\n\
                   refused.example.org,0,0\n\
                   unknown.example.org,0,0\n\
                   both.example.org:443,1,1\n";
        let app = AppList {
            platform: Platform::Android,
            list: RelayDirectory::parse(csv, Platform::Android),
            path: "android.csv".into(),
            age: 7200,
        };
        let relays = [
            relay("wss://both.example.org", true, "", Some((48.86, 2.35))),
            relay("wss://dead.example.org", false, "", None),
            relay(
                "wss://refused.example.org",
                true,
                "R5 AuthRequired",
                Some((0.0, 0.0)),
            ),
            relay("wss://new.example.org", true, "", Some((48.8, 2.3))),
            relay("wss://path.example.org/x", true, "", Some((48.8, 2.3))),
        ];
        let lines = diff(&relays, &app);
        assert_eq!(lines.len(), 6);
        assert!(
            matches!(&lines[0], Line::Both { host, km } if host == "both.example.org" && *km < 2.0)
        );
        assert_eq!(
            lines[1],
            Line::OnlyList {
                host: "dead.example.org".into(),
                why: "did not answer: dead".into()
            }
        );
        assert_eq!(
            lines[2],
            Line::OnlyCensus {
                host: "new.example.org".into(),
                place: "Paris FR".into()
            }
        );
        // A path is kept by the common rule.
        assert_eq!(
            lines[3],
            Line::OnlyCensus {
                host: "path.example.org/x".into(),
                place: "Paris FR".into()
            }
        );
        assert_eq!(
            lines[4],
            Line::OnlyList {
                host: "refused.example.org".into(),
                why: "refused (A6): R5 AuthRequired".into()
            }
        );
        assert_eq!(
            lines[5],
            Line::OnlyList {
                host: "unknown.example.org".into(),
                why: "unknown to the census".into()
            }
        );
        let text = render(&app, "relay-census (test)", &lines);
        assert!(text.starts_with(
            "--- android list (android.csv, 2 h old, 5 relays)\n+++ relay-census (test)\n"
        ));
        assert!(
            text.contains("\n-dead.example.org     did not answer: dead\n"),
            "{text}"
        );
        assert!(
            text.contains("\n+new.example.org      Paris FR\n"),
            "{text}"
        );
        assert!(text.ends_with(
            "@@ 3 in the list only (1 unknown to the census), 2 usable for the census only, 1 in both\n"
        ));
    }

    #[test]
    fn a_recent_copy_is_used() {
        let dir = std::env::temp_dir().join(format!("legacy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(recent(&dir, Platform::Ios).is_none());
        std::fs::write(
            copy_path(&dir, Platform::Ios),
            "Relay URL,Latitude,Longitude\nrelay.example.org,1,2\n",
        )
        .unwrap();
        let app = recent(&dir, Platform::Ios).unwrap();
        assert_eq!((app.list.len(), app.age < 60), (1, true));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
