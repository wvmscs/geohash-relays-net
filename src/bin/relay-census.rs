// SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)
// SPDX-License-Identifier: GPL-3.0-or-later

//! `relay-census`: a census of Nostr relays in a SQLite base (lot 13 of
//! geohash-relays, G15), and the ones the BitChat apps can use.
//!
//!   relay-census [--db relay-census.sqlite] [--tor-socks 127.0.0.1:9050 | --arti | --direct]
//!       (--set <relay>... | --refresh [--geoip <file.mmdb>] [--rounds 8] [--probe]
//!        | --compat bitchat [--out <file.csv>] | --legacy [--lists-dir <dir>] [--out <file>]
//!        | --eligibility [--out <file.md>])
//!
//! Exit code 2 for a wrong command line, 1 when the work cannot be done.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use geohash_relays::Platform;
use geohash_relays::census::relay_url;
use geohash_relays::params::{A6_PROBE_CELL, CENSUS_MAX_ROUNDS};
use geohash_relays_net::census::{self, GeoIp, Refresh, Store, legacy};
use geohash_relays_net::connector::{Connector, Direct, Socks5};

const USAGE: &str =
    "usage: relay-census [--db <file>] [--tor-socks <addr:port> | --arti | --direct]
       (--set <relay>... | --refresh [--geoip <file.mmdb>] [--rounds <n>] [--probe]
        | --compat bitchat [--out <file.csv>]
        | --legacy [--lists-dir <dir>] [--out <file>] | --eligibility [--out <file>]) [--verbose]

  --set <relay>...     records relays (wss://… URLs, spaces or commas between them)
  --refresh            reads the relay lists (NIP-65, kind 10002) of the relays known, adds
                       the relays they name, again with the new ones until none is new
                       (--rounds, default 8); then places the relays that answered
                       (--geoip) and checks them against the BitChat requirements (A6)
  --geoip <file.mmdb>  IP geolocation file (DB-IP \"IP to City Lite\", or GeoLite2 City);
                       default $RELAY_CENSUS_GEOIP; without one, no places
  --probe              also writes, then reads back, one kind 20000 test event per relay
                       (throwaway key, cell 7zzzzzzz at sea): a real publication
  --compat bitchat     the relays the harmonised apps can use (common rule: ports and paths
                       kept), in their lists' CSV form
  --eligibility        for each strategy, the relays it can use and the ones it leaves out,
                       by reason (Markdown table)
  --legacy             the census against the apps' own lists (iOS, Android): - in a list
                       but not usable (why), + usable but not in it, both (km apart)
  --lists-dir <dir>    copies of the apps' lists, downloaded (through Tor) when missing or
                       older than 24 h (default: the base's directory)
  --out <file>         where to write --compat, --legacy or --eligibility (default: standard
                       output)
  --db <file>          the census base (default relay-census.sqlite)
  --tor-socks <addr>   Tor daemon (default $BITCHAT_TOR_SOCKS, else 127.0.0.1:9050)
  --arti               Tor inside the program (built with --features arti)
  --direct             no Tor: every relay sees this machine's address";

#[derive(Debug, PartialEq)]
enum Command {
    Set(Vec<String>),
    Refresh,
    Compat,
    Legacy,
    Eligibility,
}

#[derive(Debug, PartialEq)]
enum Tor {
    Socks(SocketAddr),
    Arti,
    Direct,
}

#[derive(Debug)]
struct Args {
    db: PathBuf,
    tor: Tor,
    geoip: Option<PathBuf>,
    rounds: usize,
    probe: bool,
    out: Option<PathBuf>,
    lists_dir: Option<PathBuf>,
    verbose: bool,
    command: Command,
}

fn parse(args: impl IntoIterator<Item = String>) -> Result<Args, String> {
    let mut it = args.into_iter().peekable();
    let default_socks = std::env::var("BITCHAT_TOR_SOCKS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 9050)));
    let mut a = Args {
        db: "relay-census.sqlite".into(),
        tor: Tor::Socks(default_socks),
        geoip: std::env::var_os("RELAY_CENSUS_GEOIP").map(PathBuf::from),
        rounds: CENSUS_MAX_ROUNDS,
        probe: false,
        out: None,
        lists_dir: None,
        verbose: false,
        command: Command::Refresh,
    };
    let mut command = None;
    let set = |c: Command, command: &mut Option<Command>| match command {
        Some(_) => Err("one of --set, --refresh, --compat, --legacy, --eligibility".to_owned()),
        None => {
            *command = Some(c);
            Ok(())
        }
    };
    while let Some(arg) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "--db" => a.db = value()?.into(),
            "--tor-socks" => {
                let v = value()?;
                a.tor = Tor::Socks(
                    v.parse()
                        .map_err(|_| format!("--tor-socks: address:port expected, got {v:?}"))?,
                )
            }
            "--arti" => a.tor = Tor::Arti,
            "--direct" => a.tor = Tor::Direct,
            "--geoip" => a.geoip = Some(value()?.into()),
            "--rounds" => {
                let v = value()?;
                a.rounds = v
                    .parse()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or(format!("--rounds: a number from 1, got {v:?}"))?
            }
            "--probe" => a.probe = true,
            "--out" => a.out = Some(value()?.into()),
            "--verbose" => a.verbose = true,
            "--refresh" => set(Command::Refresh, &mut command)?,
            "--legacy" => set(Command::Legacy, &mut command)?,
            "--eligibility" => set(Command::Eligibility, &mut command)?,
            "--lists-dir" => a.lists_dir = Some(value()?.into()),
            "--compat" => {
                let v = value()?;
                if v != "bitchat" {
                    return Err(format!("--compat: only bitchat, got {v:?}"));
                }
                set(Command::Compat, &mut command)?
            }
            "--set" => {
                let mut relays = Vec::new();
                while let Some(v) = it.next_if(|v| !v.starts_with("--")) {
                    relays.extend(
                        v.split(',')
                            .map(str::trim)
                            .filter(|r| !r.is_empty())
                            .map(str::to_owned),
                    );
                }
                if relays.is_empty() {
                    return Err("--set needs at least one relay".into());
                }
                set(Command::Set(relays), &mut command)?
            }
            other => return Err(format!("unknown option {other}")),
        }
    }
    a.command = command.ok_or("one of --set, --refresh, --compat, --legacy, --eligibility")?;
    if a.probe && a.command != Command::Refresh {
        return Err("--probe goes with --refresh".into());
    }
    Ok(a)
}

fn fail(what: &str, e: impl std::fmt::Display) -> ! {
    eprintln!("relay-census: {what}: {e}");
    std::process::exit(1)
}

async fn connector(tor: &Tor, db: &std::path::Path) -> Arc<dyn Connector> {
    match tor {
        Tor::Socks(addr) => {
            let s = Socks5::new(*addr);
            if let Err(e) = s.check().await {
                fail("no Tor", e)
            }
            Arc::new(s)
        }
        Tor::Direct => {
            eprintln!("relay-census: --direct: every relay sees this machine's address");
            Arc::new(Direct)
        }
        #[cfg(feature = "arti")]
        Tor::Arti => {
            let dir = db
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(std::path::Path::new("."))
                .join("relay-census-arti");
            eprintln!("starting Tor (Arti)…");
            match geohash_relays_net::arti::Arti::bootstrap(&dir).await {
                Ok(a) => Arc::new(a),
                Err(e) => fail("no Tor", e),
            }
        }
        #[cfg(not(feature = "arti"))]
        Tor::Arti => {
            let _ = db;
            fail(
                "--arti",
                "this build has no Arti: rebuild with --features arti, or use --tor-socks",
            )
        }
    }
}

#[tokio::main]
async fn main() {
    let args = parse(std::env::args().skip(1)).unwrap_or_else(|e| {
        eprintln!("relay-census: {e}\n{USAGE}");
        std::process::exit(2)
    });
    tracing_subscriber::fmt()
        .with_max_level(if args.verbose {
            tracing::Level::DEBUG
        } else {
            tracing::Level::INFO
        })
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut store = Store::open(&args.db)
        .unwrap_or_else(|e| fail(&format!("cannot open {}", args.db.display()), e));
    match &args.command {
        Command::Set(given) => {
            let (good, bad): (Vec<_>, Vec<_>) = given.iter().partition(|r| relay_url(r).is_some());
            for r in &bad {
                eprintln!("relay-census: not a public relay address, skipped: {r}");
            }
            if good.is_empty() {
                std::process::exit(2)
            }
            let urls: Vec<String> = good.iter().filter_map(|r| relay_url(r)).collect();
            let new = store
                .give(&urls, geohash_relays_net::nostr::unix_now())
                .unwrap_or_else(|e| fail("cannot record", e));
            eprintln!(
                "{} relays recorded ({new} new) in {}",
                urls.len(),
                args.db.display()
            );
        }
        Command::Refresh => {
            if store.relays().unwrap_or_default().is_empty() {
                fail(
                    "nothing to read",
                    "no relay known yet: give some with --set",
                )
            }
            let geoip = args.geoip.as_ref().map(|p| {
                GeoIp::open(p).unwrap_or_else(|e| fail("cannot read the geolocation file", e))
            });
            match &geoip {
                Some(g) => eprintln!("places from {}", g.describe()),
                None => eprintln!("no --geoip: relays are not placed"),
            }
            if args.probe {
                eprintln!(
                    "--probe: one kind 20000 test event per relay that answers, in cell \
                     {A6_PROBE_CELL}, with a throwaway key"
                );
            }
            let connector = connector(&args.tor, &args.db).await;
            eprintln!("through {}", connector.describe());
            let how = Refresh {
                rounds: args.rounds,
                probe: args.probe,
            };
            let report = census::refresh(&mut store, connector, geoip.as_ref(), &how)
                .await
                .unwrap_or_else(|e| fail("refresh", e));
            for (i, r) in report.rounds.iter().enumerate() {
                eprintln!(
                    "round {}: {} relays read, {} answered, {} relay lists, {} new relays",
                    i + 1,
                    r.read,
                    r.answered,
                    r.lists,
                    r.new
                );
            }
            eprintln!(
                "{} placed, {} qualified{}",
                report.located,
                report.qualified,
                if report.qualification_complete {
                    ""
                } else {
                    " (qualification stopped at its time limit)"
                }
            );
        }
        Command::Legacy => {
            let dir = args.lists_dir.clone().unwrap_or_else(|| {
                args.db
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(std::path::Path::new("."))
                    .to_path_buf()
            });
            // Tor only when a list must be downloaded.
            let mut tor: Option<Arc<dyn Connector>> = None;
            let mut text = String::new();
            for platform in [Platform::Ios, Platform::Android] {
                let app = match legacy::recent(&dir, platform) {
                    Some(app) => app,
                    None => {
                        if tor.is_none() {
                            tor = Some(connector(&args.tor, &args.db).await);
                        }
                        let c = tor.clone().expect("just set");
                        eprintln!(
                            "downloading the {} list through {}",
                            platform.as_str(),
                            c.describe()
                        );
                        legacy::download(&dir, platform, c)
                            .await
                            .unwrap_or_else(|e| fail("no list", e))
                    }
                };
                let relays = store
                    .all()
                    .unwrap_or_else(|e| fail("cannot read the base", e));
                let usable = relays.iter().filter(|r| r.bitchat().is_ok()).count();
                let lines = legacy::diff(&relays, &app);
                text.push_str(&legacy::render(
                    &app,
                    &format!("relay-census ({}, {usable} usable)", args.db.display()),
                    &lines,
                ));
                text.push('\n');
            }
            match &args.out {
                Some(path) => std::fs::write(path, text)
                    .unwrap_or_else(|e| fail(&format!("cannot write {}", path.display()), e)),
                None => print!("{text}"),
            }
        }
        Command::Eligibility => {
            let relays = store
                .all()
                .unwrap_or_else(|e| fail("cannot read the base", e));
            let table = census::render_eligibility(&census::eligibility(&relays), relays.len());
            match &args.out {
                Some(path) => std::fs::write(path, table)
                    .unwrap_or_else(|e| fail(&format!("cannot write {}", path.display()), e)),
                None => print!("{table}"),
            }
        }
        Command::Compat => {
            let n = match &args.out {
                Some(path) => {
                    let mut f = std::fs::File::create(path)
                        .unwrap_or_else(|e| fail(&format!("cannot write {}", path.display()), e));
                    census::bitchat_csv(&store, &mut f)
                }
                None => census::bitchat_csv(&store, &mut std::io::stdout().lock()),
            }
            .unwrap_or_else(|e| fail("cannot write the list", e));
            eprintln!("{n} relays usable by the BitChat apps");
        }
    }
    if let Ok(s) = store.summary() {
        eprintln!(
            "base: {} relays ({} given), {} answered, {} placed, {} qualified, {} usable, {} relay lists",
            s.relays, s.given, s.answered, s.located, s.qualified, s.usable, s.lists
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<Args, String> {
        parse(s.split_whitespace().map(String::from))
    }

    #[test]
    fn command_lines() {
        let a =
            p("--set wss://a.example.org,wss://b.example.org wss://c.example.org --db x.sqlite")
                .unwrap();
        assert_eq!(
            a.command,
            Command::Set(vec![
                "wss://a.example.org".into(),
                "wss://b.example.org".into(),
                "wss://c.example.org".into()
            ])
        );
        assert_eq!(a.db, PathBuf::from("x.sqlite"));
        let a = p("--refresh --direct --rounds 3 --probe --geoip city.mmdb").unwrap();
        assert_eq!(
            (a.command, a.tor, a.rounds, a.probe),
            (Command::Refresh, Tor::Direct, 3, true)
        );
        assert_eq!(a.geoip, Some(PathBuf::from("city.mmdb")));
        let a = p("--compat bitchat --out list.csv --tor-socks 127.0.0.1:9150").unwrap();
        assert_eq!(a.command, Command::Compat);
        assert_eq!(a.tor, Tor::Socks("127.0.0.1:9150".parse().unwrap()));

        let err = |s: &str| p(s).unwrap_err();
        assert!(err("").contains("one of"));
        assert!(err("--set").contains("at least one relay"));
        assert!(err("--refresh --compat bitchat").contains("one of"));
        assert!(err("--compat android").contains("only bitchat"));
        assert!(err("--compat bitchat --probe").contains("goes with --refresh"));
        assert!(err("--refresh --rounds 0").contains("--rounds"));
        assert!(err("--refresh --nope").contains("unknown option"));
        let a = p("--legacy --lists-dir lists --out diff.txt").unwrap();
        assert_eq!(a.command, Command::Legacy);
        assert_eq!(a.lists_dir, Some(PathBuf::from("lists")));
        assert!(err("--legacy --compat bitchat").contains("one of"));
        assert_eq!(p("--eligibility").unwrap().command, Command::Eligibility);
    }
}
