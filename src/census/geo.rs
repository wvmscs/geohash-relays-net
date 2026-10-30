// SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)
// SPDX-License-Identifier: GPL-3.0-or-later

//! Where a relay is: its address, then an offline IP geolocation file in
//! the MaxMind DB format (DB-IP "IP to City Lite", free under CC BY 4.0, or
//! MaxMind GeoLite2 City), as the relay lists of the apps are made (IP
//! geolocation: a city, often its centre). Nothing is asked of an online
//! service.

use std::net::IpAddr;
use std::path::Path;

use geohash_relays::params::CENSUS_GEOHASH_PRECISION;
use maxminddb::{Reader, geoip2};

use crate::error::{Error, Result};

/// A relay's place.
#[derive(Debug, Clone, PartialEq)]
pub struct Place {
    /// The address located.
    pub ip: IpAddr,
    pub lat: f64,
    pub lon: f64,
    /// ISO 3166-1 code.
    pub country: Option<String>,
    /// City, in English.
    pub city: Option<String>,
    pub geohash: String,
}

/// An IP geolocation file.
pub struct GeoIp {
    reader: Reader<Vec<u8>>,
}

impl GeoIp {
    pub fn open(path: &Path) -> Result<GeoIp> {
        let reader = Reader::open_readfile(path)
            .map_err(|e| Error::GeoIp(format!("{}: {e}", path.display())))?;
        Ok(GeoIp { reader })
    }

    /// What the file is (`DBIP-City-Lite`, `GeoLite2-City`…), and its date.
    pub fn describe(&self) -> String {
        let m = self.reader.metadata();
        format!("{} ({} UTC)", m.database_type, m.build_epoch)
    }

    /// The place of the first address that has one: IPv4 first (the apps'
    /// lists are made from IPv4 addresses).
    pub fn locate(&self, ips: &[IpAddr]) -> Option<Place> {
        let mut ips = ips.to_vec();
        ips.sort_by_key(|ip| ip.is_ipv6());
        ips.into_iter().find_map(|ip| self.place(ip))
    }

    fn place(&self, ip: IpAddr) -> Option<Place> {
        let city: geoip2::City = self.reader.lookup(ip).ok()?.decode().ok()??;
        let (lat, lon) = (city.location.latitude?, city.location.longitude?);
        let geohash = geohash_relays::geohash::encode(lat, lon, CENSUS_GEOHASH_PRECISION)?;
        Some(Place {
            ip,
            lat,
            lon,
            country: city.country.iso_code.map(str::to_owned),
            city: city.city.names.english.map(str::to_owned),
            geohash,
        })
    }
}
