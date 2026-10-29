// SPDX-FileCopyrightText: 2026 William VITAL, FR (wvmscs)
// SPDX-License-Identifier: GPL-3.0-or-later

//! The NIP-01 subset the console needs: events (id, BIP-340 signature and
//! its check), REQ filters, the current time. From bitchat-geohash
//! (`src/nostr.rs`), with signing added: the console publishes.

use std::collections::BTreeMap;

use k256::schnorr::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

/// Limits on what a relay may hand us, checked before anything else.
pub use geohash_relays::params::comm::{
    MAX_EVENT_TAG_VALUE_BYTES, MAX_EVENT_TAG_VALUES, MAX_EVENT_TAGS,
};

/// Unix time, in seconds.
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Why an event does not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidEvent {
    IdMismatch,
    MissingSignature,
    BadEncoding,
    BadPublicKey,
    BadSignature,
}

/// A NIP-01 event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Empty in a rumor (the unsigned inner event of a private message).
    #[serde(default)]
    pub id: String,
    pub pubkey: String,
    pub created_at: i64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

impl Event {
    /// An unsigned event with its id computed.
    pub fn new_unsigned(
        pubkey: &str,
        created_at: i64,
        kind: u32,
        tags: Vec<Vec<String>>,
        content: String,
    ) -> Self {
        let mut e = Event {
            id: String::new(),
            pubkey: pubkey.to_owned(),
            created_at,
            kind,
            tags,
            content,
            sig: None,
        };
        e.id = e.compute_id();
        e
    }

    /// NIP-01 id: SHA-256 of `[0,pubkey,created_at,kind,tags,content]`, hex.
    pub fn compute_id(&self) -> String {
        let canonical = json!([
            0,
            self.pubkey,
            self.created_at,
            self.kind,
            self.tags,
            self.content
        ]);
        hex_encode(&Sha256::digest(canonical.to_string().as_bytes()))
    }

    /// Checks that `id` matches the content and that `sig` is a valid
    /// BIP-340 signature of it by `pubkey`.
    pub fn verify(&self) -> Result<(), InvalidEvent> {
        if self.id != self.compute_id() {
            return Err(InvalidEvent::IdMismatch);
        }
        let sig = self.sig.as_deref().ok_or(InvalidEvent::MissingSignature)?;
        let (Some(id), Some(sig), Some(pk)) = (
            hex_decode(&self.id),
            hex_decode(sig),
            hex_decode(&self.pubkey),
        ) else {
            return Err(InvalidEvent::BadEncoding);
        };
        let key = VerifyingKey::from_bytes(&pk).map_err(|_| InvalidEvent::BadPublicKey)?;
        let sig = Signature::try_from(sig.as_slice()).map_err(|_| InvalidEvent::BadSignature)?;
        key.verify_raw(&id, &sig)
            .map_err(|_| InvalidEvent::BadSignature)
    }

    pub fn within_tag_limits(&self) -> bool {
        self.tags.len() <= MAX_EVENT_TAGS
            && self.tags.iter().all(|t| {
                t.len() <= MAX_EVENT_TAG_VALUES
                    && t.iter().all(|v| v.len() <= MAX_EVENT_TAG_VALUE_BYTES)
            })
    }

    /// First value of the first tag named `name`.
    pub fn tag_value(&self, name: &str) -> Option<&str> {
        self.tags
            .iter()
            .find(|t| t.first().map(String::as_str) == Some(name))
            .and_then(|t| t.get(1))
            .map(String::as_str)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("an event always serializes")
    }

    /// A signed event: `pubkey` from the key, id computed, BIP-340
    /// signature with fresh auxiliary randomness.
    pub fn signed(
        key: &k256::schnorr::SigningKey,
        created_at: i64,
        kind: u32,
        tags: Vec<Vec<String>>,
        content: String,
    ) -> Self {
        let pubkey = hex_encode(&key.verifying_key().to_bytes());
        let mut e = Event::new_unsigned(&pubkey, created_at, kind, tags, content);
        let id = hex_decode(&e.id).expect("our own id is hex");
        let mut aux = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut aux);
        let sig = key
            .sign_raw(&id, &aux)
            .expect("signing a 32-byte digest cannot fail");
        e.sig = Some(hex_encode(&sig.to_bytes()));
        e
    }
}

/// A REQ filter, limited to the fields location channels use.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    pub kinds: Vec<u32>,
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub limit: Option<usize>,
    /// Authors (public keys, hex); empty: any.
    pub authors: Vec<String>,
    /// Single-letter tag filters (`'g'` -> geohashes, serialised as `#g`).
    pub tags: BTreeMap<char, Vec<String>>,
}

impl Filter {
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        if !self.kinds.is_empty() {
            m.insert("kinds".into(), json!(self.kinds));
        }
        if !self.authors.is_empty() {
            m.insert("authors".into(), json!(self.authors));
        }
        if let Some(s) = self.since {
            m.insert("since".into(), json!(s));
        }
        if let Some(u) = self.until {
            m.insert("until".into(), json!(u));
        }
        if let Some(l) = self.limit {
            m.insert("limit".into(), json!(l));
        }
        for (k, v) in &self.tags {
            m.insert(format!("#{k}"), json!(v));
        }
        Value::Object(m)
    }

    /// Reads a filter; unknown fields are ignored.
    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let mut f = Filter {
            kinds: o
                .get("kinds")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|k| k.as_u64().map(|k| k as u32))
                        .collect()
                })
                .unwrap_or_default(),
            since: o.get("since").and_then(Value::as_i64),
            until: o.get("until").and_then(Value::as_i64),
            limit: o.get("limit").and_then(Value::as_u64).map(|l| l as usize),
            authors: o
                .get("authors")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
            tags: BTreeMap::new(),
        };
        for (k, val) in o {
            let mut name = k.strip_prefix('#').unwrap_or_default().chars();
            if let (Some(c), None, Some(values)) = (name.next(), name.next(), val.as_array()) {
                let values = values
                    .iter()
                    .filter_map(|x| x.as_str().map(str::to_owned))
                    .collect();
                f.tags.insert(c, values);
            }
        }
        Some(f)
    }

    pub fn matches(&self, e: &Event) -> bool {
        (self.kinds.is_empty() || self.kinds.contains(&e.kind))
            && (self.authors.is_empty() || self.authors.contains(&e.pubkey))
            && self.since.is_none_or(|s| e.created_at >= s)
            && self.until.is_none_or(|u| e.created_at <= u)
            && self.tags.iter().all(|(name, wanted)| {
                let name = name.to_string();
                e.tags.iter().any(|t| {
                    t.first() == Some(&name) && t.get(1).is_some_and(|v| wanted.contains(v))
                })
            })
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

impl From<&geohash_relays::sansio::FilterSpec> for Filter {
    fn from(f: &geohash_relays::sansio::FilterSpec) -> Self {
        Filter {
            kinds: f.kinds.clone(),
            since: f.since,
            until: None,
            limit: f.limit.map(|l| l as usize),
            authors: f.authors.clone(),
            tags: f.tags.iter().cloned().collect(),
        }
    }
}

impl Event {
    /// The event as the strategy machines see it (it must be verified).
    pub fn meta(&self) -> geohash_relays::sansio::EventMeta {
        geohash_relays::sansio::EventMeta {
            id: self.id.clone(),
            pubkey: self.pubkey.clone(),
            kind: self.kind,
            created_at: self.created_at,
            tags: self.tags.clone(),
            raw: self.to_json(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let bytes = [0u8, 1, 0xab, 0xff];
        assert_eq!(hex_encode(&bytes), "0001abff");
        assert_eq!(hex_decode("0001abff").unwrap(), bytes);
        assert_eq!(hex_decode("0001ABFF").unwrap(), bytes);
        assert!(hex_decode("abc").is_none());
        assert!(hex_decode("zz").is_none());
    }

    /// The id hashes NIP-01's canonical serialisation, without spaces.
    #[test]
    fn id_is_the_nip01_hash() {
        let e = Event::new_unsigned("a", 1, 1, vec![vec!["g".into(), "u0".into()]], "x".into());
        let canonical = r#"[0,"a",1,1,[["g","u0"]],"x"]"#;
        assert_eq!(e.id, hex_encode(&Sha256::digest(canonical.as_bytes())));
    }

    #[test]
    fn unsigned_or_tampered_events_do_not_verify() {
        let mut e = Event::new_unsigned(&"0".repeat(64), 1, 20000, vec![], "x".into());
        assert_eq!(e.verify(), Err(InvalidEvent::MissingSignature));
        e.content = "y".into();
        assert_eq!(e.verify(), Err(InvalidEvent::IdMismatch));
    }

    #[test]
    fn filter_json_round_trip_and_matching() {
        let f = Filter {
            kinds: vec![20000, 20001],
            since: Some(10),
            tags: BTreeMap::from([('g', vec!["u09tv".to_owned()])]),
            ..Default::default()
        };
        let v = f.to_json();
        assert_eq!(
            v,
            json!({"kinds": [20000, 20001], "since": 10, "#g": ["u09tv"]})
        );
        assert_eq!(Filter::from_json(&v), Some(f.clone()));
        let tagged = |g: &str, t: i64| {
            Event::new_unsigned(
                "a",
                t,
                20000,
                vec![vec!["g".into(), g.into()]],
                String::new(),
            )
        };
        assert!(f.matches(&tagged("u09tv", 10)));
        assert!(!f.matches(&tagged("u09tv", 9)));
        assert!(!f.matches(&tagged("u09tu", 10)));
    }
}
