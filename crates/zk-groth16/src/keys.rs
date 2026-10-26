//! Key packs, key and setup identities, and the verifier's trust list.
//!
//! A *key pack* carries the proving keys of any set of approved circuits as one file, identical for
//! the native CLI and the browser: `ZKG16KEY`, a little-endian `u32` count, then per key a `u16`
//! name length, the circuit name, a `u64` length and the zkey bytes.
//!
//! A [`KeyId`] names one verifying key: SHA-256 over a domain tag, the circuit name, its approved
//! r1cs hash, the zkey header (alpha, beta, gamma, delta and sizes) and the IC points. A setup id
//! is SHA-256 over a domain tag and every `(name, key id)` in name order. A verifier accepts proofs
//! only under keys its [`Trust`] list names, by setup id or key id: any valid setup can be
//! imported and used to prove, but which setup a verifier relies on is the verifier's decision.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use crate::digest::{hex, sha256};
use crate::setup::approved;
use crate::zkey::{self, HEADER, IC};
use crate::{Groth16Error, Result};

const PACK_MAGIC: &[u8; 8] = b"ZKG16KEY";
const KEY_TAG: &[u8] = b"zk-groth16/key/v1";
const SETUP_TAG: &[u8] = b"zk-groth16/setup/v1";

/// The identity of one verifying key, or of a whole setup.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId([u8; 32]);

impl KeyId {
    /// The identity of `zkey` as the key of circuit `name`.
    pub fn of(name: &str, zkey: &[u8]) -> Result<Self> {
        let sections = zkey::sections(zkey)?;
        let section = |id: u32| {
            sections
                .get(&id)
                .copied()
                .ok_or_else(|| Groth16Error::Format(format!("zkey: missing section {id}")))
        };
        let r1cs = approved(name)?.r1cs_sha256.as_bytes();
        let parts = [
            KEY_TAG,
            name.as_bytes(),
            &[0],
            r1cs,
            section(HEADER)?,
            section(IC)?,
        ];
        Ok(Self(sha256(&parts.concat())))
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex(&self.0))
    }
}

impl FromStr for KeyId {
    type Err = Groth16Error;

    fn from_str(text: &str) -> Result<Self> {
        let bad = || Groth16Error::Format(format!("`{text}` is not a 64-digit hex id"));
        if text.len() != 64 || !text.is_ascii() {
            return Err(bad());
        }
        let mut id = [0u8; 32];
        for (byte, pair) in id.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
            let digits = std::str::from_utf8(pair).map_err(|_| bad())?;
            *byte = u8::from_str_radix(digits, 16).map_err(|_| bad())?;
        }
        Ok(Self(id))
    }
}

/// Proving keys by circuit name.
#[derive(Clone, Default)]
pub struct KeyPack {
    keys: BTreeMap<String, Arc<[u8]>>,
}

fn malformed(what: &str) -> Groth16Error {
    Groth16Error::Format(format!("key pack: {what}"))
}

fn take<'a>(bytes: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if bytes.len() < n {
        return Err(malformed("unexpected end"));
    }
    let (head, tail) = bytes.split_at(n);
    *bytes = tail;
    Ok(head)
}

fn number(bytes: &mut &[u8], width: usize) -> Result<usize> {
    let mut le = [0u8; 8];
    le[..width].copy_from_slice(take(bytes, width)?);
    usize::try_from(u64::from_le_bytes(le)).map_err(|_| malformed("entry too large"))
}

impl KeyPack {
    /// Add (or replace) circuit `name`'s key; `name` must be an approved circuit.
    pub fn insert(&mut self, name: &str, zkey: Vec<u8>) -> Result<()> {
        approved(name)?;
        self.keys.insert(name.to_owned(), Arc::from(zkey));
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&Arc<[u8]>> {
        self.keys.get(name)
    }

    /// `(circuit, zkey)` in name order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.keys
            .iter()
            .map(|(name, zkey)| (name.as_str(), &**zkey))
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.keys.keys().map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The setup id: every key's [`KeyId`] in name order.
    pub fn setup_id(&self) -> Result<KeyId> {
        let mut bytes = SETUP_TAG.to_vec();
        for (name, zkey) in self.iter() {
            bytes.extend(name.as_bytes());
            bytes.push(0);
            bytes.extend(KeyId::of(name, zkey)?.0);
        }
        Ok(KeyId(sha256(&bytes)))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = PACK_MAGIC.to_vec();
        out.extend((self.keys.len() as u32).to_le_bytes());
        for (name, zkey) in self.iter() {
            out.extend((name.len() as u16).to_le_bytes());
            out.extend(name.as_bytes());
            out.extend((zkey.len() as u64).to_le_bytes());
            out.extend(zkey);
        }
        out
    }

    /// A pack of approved circuits with no name twice; the keys themselves are checked on use.
    pub fn from_bytes(pack: &[u8]) -> Result<Self> {
        let mut bytes = pack;
        if take(&mut bytes, PACK_MAGIC.len())? != PACK_MAGIC {
            return Err(Groth16Error::Format("not a groth16 key pack".into()));
        }
        let mut keys = Self::default();
        for _ in 0..number(&mut bytes, 4)? {
            let length = number(&mut bytes, 2)?;
            let name = std::str::from_utf8(take(&mut bytes, length)?)
                .map_err(|_| malformed("name is not UTF-8"))?;
            let length = number(&mut bytes, 8)?;
            if keys.get(name).is_some() {
                return Err(malformed(&format!("`{name}` appears twice")));
            }
            keys.insert(name, take(&mut bytes, length)?.to_vec())?;
        }
        if !bytes.is_empty() {
            return Err(malformed("trailing bytes"));
        }
        Ok(keys)
    }
}

/// The setups (or single keys) a verifier accepts proofs under.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Trust(BTreeSet<KeyId>);

impl Trust {
    /// Ids separated by whitespace or commas; `#` starts a comment.
    pub fn parse(text: &str) -> Result<Self> {
        let ids = text
            .lines()
            .map(|line| line.split('#').next().unwrap_or_default())
            .flat_map(|line| line.split(|c: char| c == ',' || c.is_whitespace()))
            .filter(|id| !id.is_empty())
            .map(KeyId::from_str)
            .collect::<Result<_>>()?;
        Ok(Self(ids))
    }

    pub fn insert(&mut self, id: KeyId) {
        self.0.insert(id);
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn ids(&self) -> impl Iterator<Item = &KeyId> {
        self.0.iter()
    }

    /// Whether a key of setup `setup` with identity `key` may verify proofs.
    pub fn allows(&self, setup: &KeyId, key: &KeyId) -> bool {
        self.0.contains(setup) || self.0.contains(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packs_round_trip_and_reject_damage() {
        let mut pack = KeyPack::default();
        pack.insert("open_32", vec![1, 2, 3]).unwrap();
        pack.insert("compare_32", vec![]).unwrap();
        assert!(pack.insert("not_a_circuit", vec![]).is_err());
        let bytes = pack.to_bytes();
        let back = KeyPack::from_bytes(&bytes).unwrap();
        assert_eq!(back.names().collect::<Vec<_>>(), ["compare_32", "open_32"]);
        assert_eq!(&**back.get("open_32").unwrap(), &[1, 2, 3]);
        assert!(KeyPack::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        assert!(KeyPack::from_bytes(&[bytes.as_slice(), &[0]].concat()).is_err());
        assert!(KeyPack::from_bytes(b"ZKG16XXX\0\0\0\0").is_err());
    }

    #[test]
    fn trust_lists_parse_ids_and_comments() {
        let id = "ab".repeat(32);
        let trust = Trust::parse(&format!("# mine\n{id}, {id}\n")).unwrap();
        let key: KeyId = id.parse().unwrap();
        assert_eq!(key.to_string(), id);
        assert!(trust.allows(&key, &KeyId([0; 32])));
        assert!(trust.allows(&KeyId([0; 32]), &key));
        assert!(!trust.allows(&KeyId([0; 32]), &KeyId([1; 32])));
        assert!(Trust::parse("xyz").is_err());
        assert!(Trust::parse("").unwrap().is_empty());
    }
}
