//! The contribution record of a zkey (section 10), in snarkjs's format: the circuit hash, then per
//! contribution its public key, transcript and parameters. Each transcript hashes the circuit hash,
//! every earlier contribution and the new public key, so the records form a chain anyone can
//! re-check.

use ark_bn254::{G1Affine, G2Affine};

use super::rng::{MAX_BEACON_EXPONENT, MIN_BEACON_EXPONENT};
use crate::digest::blake2b;
use crate::points::{encode_g1, encode_g2, uncompressed_g1, uncompressed_g2, G1_BYTES, G2_BYTES};
use crate::{Groth16Error, Result};

/// A contribution made from fresh entropy.
pub(crate) const RANDOM: u32 = 0;
/// A contribution expanded from a public beacon value.
pub(crate) const BEACON: u32 = 1;
const NAME: u8 = 1;
const ITERATIONS: u8 = 2;
const BEACON_VALUE: u8 = 3;
/// Longest contributor name snarkjs stores.
pub const MAX_NAME_BYTES: usize = 64;

/// A public beacon: its value and `log2` of the SHA-256 iterations applied to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Beacon {
    pub value: Vec<u8>,
    pub exponent: u8,
}

impl Beacon {
    /// A beacon a verifier can recompute: 1 to 255 bytes, and 2^10 to 2^28 iterations.
    pub fn new(value: Vec<u8>, exponent: u8) -> Result<Self> {
        let beacon = Self { value, exponent };
        beacon.check()?;
        Ok(beacon)
    }

    pub(crate) fn check(&self) -> Result<()> {
        if self.value.is_empty() || self.value.len() > 255 {
            return Err(Groth16Error::Setup(
                "a beacon value is 1 to 255 bytes".into(),
            ));
        }
        if !(MIN_BEACON_EXPONENT..=MAX_BEACON_EXPONENT).contains(&self.exponent) {
            return Err(Groth16Error::Setup(format!(
                "beacons use 2^{MIN_BEACON_EXPONENT} to 2^{MAX_BEACON_EXPONENT} hash iterations"
            )));
        }
        Ok(())
    }
}

/// One contribution's public record.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Record {
    pub delta_after: G1Affine,
    pub g1_s: G1Affine,
    pub g1_sx: G1Affine,
    pub g2_spx: G2Affine,
    pub transcript: [u8; 64],
    pub name: Option<String>,
    pub beacon: Option<Beacon>,
}

/// Section 10: the circuit hash and the contributions in order.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Mpc {
    pub cs_hash: [u8; 64],
    pub records: Vec<Record>,
}

fn malformed(what: &str) -> Groth16Error {
    Groth16Error::Format(format!("zkey contributions: {what}"))
}

impl Record {
    /// The bytes every later transcript (and the contribution hash) covers.
    fn public_key(&self) -> Vec<u8> {
        [
            uncompressed_g1(&self.delta_after),
            uncompressed_g1(&self.g1_s),
            uncompressed_g1(&self.g1_sx),
            uncompressed_g2(&self.g2_spx),
            self.transcript.to_vec(),
        ]
        .concat()
    }

    /// The contribution hash snarkjs prints.
    pub(crate) fn hash(&self) -> [u8; 64] {
        blake2b(&[&self.public_key()])
    }

    fn params(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(name) = &self.name {
            out.extend([NAME, name.len() as u8]);
            out.extend(name.as_bytes());
        }
        if let Some(beacon) = &self.beacon {
            out.extend([
                ITERATIONS,
                beacon.exponent,
                BEACON_VALUE,
                beacon.value.len() as u8,
            ]);
            out.extend(&beacon.value);
        }
        out
    }

    fn write(&self, out: &mut Vec<u8>) {
        for point in [&self.delta_after, &self.g1_s, &self.g1_sx] {
            out.extend(encode_g1(point));
        }
        out.extend(encode_g2(&self.g2_spx));
        out.extend(self.transcript);
        let kind = if self.beacon.is_some() {
            BEACON
        } else {
            RANDOM
        };
        out.extend(kind.to_le_bytes());
        let params = self.params();
        out.extend((params.len() as u32).to_le_bytes());
        out.extend(params);
    }
}

impl Mpc {
    /// The transcript the next contribution must carry, given its `g1_s` and `g1_sx`.
    pub(crate) fn next_transcript(&self, g1_s: &G1Affine, g1_sx: &G1Affine) -> [u8; 64] {
        let earlier: Vec<Vec<u8>> = self.records.iter().map(Record::public_key).collect();
        let mut parts: Vec<&[u8]> = vec![&self.cs_hash];
        parts.extend(earlier.iter().map(Vec::as_slice));
        let (s, sx) = (uncompressed_g1(g1_s), uncompressed_g1(g1_sx));
        parts.extend([s.as_slice(), sx.as_slice()]);
        blake2b(&parts)
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.cs_hash.to_vec();
        out.extend((self.records.len() as u32).to_le_bytes());
        for record in &self.records {
            record.write(&mut out);
        }
        out
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let mut r = Cursor(bytes);
        let cs_hash = r.array()?;
        let records = (0..r.u32()?).map(|_| r.record()).collect::<Result<_>>()?;
        if !r.0.is_empty() {
            return Err(malformed("trailing bytes"));
        }
        Ok(Self { cs_hash, records })
    }
}

/// Validates a contributor name for storage.
pub(crate) fn check_name(name: &str) -> Result<()> {
    if name.len() > MAX_NAME_BYTES {
        return Err(Groth16Error::Setup(format!(
            "contributor names are at most {MAX_NAME_BYTES} bytes"
        )));
    }
    Ok(())
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(malformed("unexpected end"));
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    /// A point, checked to be on the curve and in the prime-order subgroup.
    fn g1(&mut self) -> Result<G1Affine> {
        crate::zkey::checked_g1(self.take(G1_BYTES)?)
    }

    fn g2(&mut self) -> Result<G2Affine> {
        crate::zkey::checked_g2(self.take(G2_BYTES)?)
    }

    fn record(&mut self) -> Result<Record> {
        let (delta_after, g1_s, g1_sx) = (self.g1()?, self.g1()?, self.g1()?);
        let g2_spx = self.g2()?;
        let transcript = self.array()?;
        let kind = self.u32()?;
        let length = self.u32()? as usize;
        let mut params = Cursor(self.take(length)?);
        let mut record = Record {
            delta_after,
            g1_s,
            g1_sx,
            g2_spx,
            transcript,
            name: None,
            beacon: None,
        };
        params.params(&mut record)?;
        if (kind == BEACON) != record.beacon.is_some() || kind > BEACON {
            return Err(malformed("contribution type and parameters disagree"));
        }
        Ok(record)
    }

    /// Tagged parameters in increasing tag order: name, beacon exponent, beacon value.
    fn params(&mut self, record: &mut Record) -> Result<()> {
        let mut last = 0;
        let mut exponent = None;
        while !self.0.is_empty() {
            let tag = self.u8()?;
            if tag <= last {
                return Err(malformed("parameters out of order"));
            }
            last = tag;
            match tag {
                NAME => record.name = Some(self.name()?),
                ITERATIONS => exponent = Some(self.u8()?),
                BEACON_VALUE => {
                    let length = self.u8()? as usize;
                    let value = self.take(length)?.to_vec();
                    let exponent =
                        exponent.ok_or_else(|| malformed("beacon without iterations"))?;
                    record.beacon = Some(Beacon { value, exponent });
                }
                _ => return Err(malformed("unknown parameter")),
            }
        }
        Ok(())
    }

    fn name(&mut self) -> Result<String> {
        let length = self.u8()? as usize;
        String::from_utf8(self.take(length)?.to_vec()).map_err(|_| malformed("name is not UTF-8"))
    }
}
