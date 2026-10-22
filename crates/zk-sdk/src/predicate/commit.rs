//! Value commitments: the public handle a predicate is about, and the private opening that proves it.
//!
//! `digest = Poseidon2-sponge([signed, limb count, limbs.., blinding..])` over KoalaBear with
//! Plonky3's width-16 permutation, rate 8, capacity `[DOMAIN, message length, 0..]`. The circuits in
//! `circuits/lib/commit.circom` compute exactly this; `tests/commitment_circuit.rs` proves the two
//! agree. Commitments are binding up to the sponge's collision resistance (about 2^124 over eight
//! 31-bit elements) and hiding while the blinding stays secret and uniformly random.

use std::sync::OnceLock;

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::{default_koalabear_poseidon2_16, KoalaBear, Poseidon2KoalaBear};
use p3_symmetric::Permutation;
use serde::{Deserialize, Serialize};

use super::int::{IntType, Number, Width};
use crate::{Result, ZkError};

pub(super) const FIELD_MODULUS: u32 = 0x7f00_0001;
const COMMIT_DOMAIN: u32 = 1_514_344_449;
const RATE: usize = 8;
const WIDTH: usize = 16;
pub const BLINDING_ELEMENTS: usize = 8;
pub const DIGEST_ELEMENTS: usize = 8;

type Blinding = [u32; BLINDING_ELEMENTS];
type Digest = [u32; DIGEST_ELEMENTS];

fn permutation() -> &'static Poseidon2KoalaBear<WIDTH> {
    static PERMUTATION: OnceLock<Poseidon2KoalaBear<WIDTH>> = OnceLock::new();
    PERMUTATION.get_or_init(default_koalabear_poseidon2_16)
}

fn message(ty: IntType, encoded: u128, blinding: &Blinding) -> Vec<u32> {
    let limbs = ty.limbs(encoded);
    let mut message = vec![u32::from(ty.signed), limbs.len() as u32];
    message.extend(limbs.iter().map(|l| *l as u32));
    message.extend_from_slice(blinding);
    message
}

fn digest(ty: IntType, encoded: u128, blinding: &Blinding) -> Digest {
    let message = message(ty, encoded, blinding);
    let mut state = [KoalaBear::ZERO; WIDTH];
    state[RATE] = KoalaBear::new(COMMIT_DOMAIN);
    state[RATE + 1] = KoalaBear::new(message.len() as u32);
    for block in message.chunks(RATE) {
        for (slot, value) in state.iter_mut().zip(block) {
            *slot += KoalaBear::new(*value);
        }
        permutation().permute_mut(&mut state);
    }
    std::array::from_fn(|i| state[i].as_canonical_u32())
}

/// Uniform field elements by rejection sampling over the OS (or browser) CSPRNG.
fn random_blinding() -> Result<Blinding> {
    let mut out = [0u32; BLINDING_ELEMENTS];
    let mut filled = 0;
    while filled < out.len() {
        let mut bytes = [0u8; 4];
        getrandom::fill(&mut bytes)
            .map_err(|e| ZkError::Unavailable(format!("randomness: {e}")))?;
        let candidate = u32::from_le_bytes(bytes) & 0x7fff_ffff;
        if candidate < FIELD_MODULUS {
            out[filled] = candidate;
            filled += 1;
        }
    }
    Ok(out)
}

/// The public commitment to a typed integer. Safe to publish; it carries its type, which the
/// digest binds, so a commitment cannot be reinterpreted under another width or signedness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Commitment {
    ty: IntType,
    digest: Digest,
}

/// The secret behind a [`Commitment`]: the value and its blinding. Never log or transmit it; the
/// `Debug` output is redacted. Browser and process memory are not zeroized.
#[derive(Clone, PartialEq, Eq)]
pub struct Opening {
    ty: IntType,
    value: Number,
    blinding: Blinding,
}

impl std::fmt::Debug for Opening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Opening({}, <redacted>)", self.ty)
    }
}

impl Commitment {
    /// Commit to `value` under a fresh random blinding. Returns the public commitment and the
    /// private opening the prover needs.
    pub fn commit(ty: IntType, value: impl Into<Number>) -> Result<(Self, Opening)> {
        Self::commit_with_blinding(ty, value, random_blinding()?)
    }

    /// Deterministic variant for reproducible tests and vectors. A reused or guessable blinding
    /// breaks hiding; real callers use [`Commitment::commit`].
    pub fn commit_with_blinding(
        ty: IntType,
        value: impl Into<Number>,
        blinding: Blinding,
    ) -> Result<(Self, Opening)> {
        let value = value.into();
        if blinding.iter().any(|b| *b >= FIELD_MODULUS) {
            return Err(ZkError::Predicate(
                "blinding element is not a field element".into(),
            ));
        }
        let commitment = Self {
            ty,
            digest: digest(ty, ty.encode(value)?, &blinding),
        };
        Ok((
            commitment,
            Opening {
                ty,
                value,
                blinding,
            },
        ))
    }

    pub fn ty(&self) -> IntType {
        self.ty
    }

    pub fn digest(&self) -> Digest {
        self.digest
    }

    /// Canonical text form `<type>:<64 hex digits>`, e.g. `u64:00ab..`.
    pub fn to_text(&self) -> String {
        let hex: String = self.digest.iter().map(|d| format!("{d:08x}")).collect();
        format!("{}:{hex}", self.ty)
    }

    pub fn from_text(text: &str) -> Result<Self> {
        let invalid =
            || ZkError::Format(format!("`{text}` is not a commitment (type:64 hex digits)"));
        let (name, hex) = text.split_once(':').ok_or_else(invalid)?;
        let ty = parse_type(name).ok_or_else(invalid)?;
        if hex.len() != DIGEST_ELEMENTS * 8 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(invalid());
        }
        let mut digest = [0u32; DIGEST_ELEMENTS];
        for (slot, chunk) in digest.iter_mut().zip(hex.as_bytes().chunks(8)) {
            let element =
                u32::from_str_radix(std::str::from_utf8(chunk).map_err(|_| invalid())?, 16)
                    .map_err(|_| invalid())?;
            if element >= FIELD_MODULUS {
                return Err(invalid());
            }
            *slot = element;
        }
        Ok(Self { ty, digest })
    }
}

fn parse_type(name: &str) -> Option<IntType> {
    let signed = match name.as_bytes().first()? {
        b'u' => false,
        b'i' => true,
        _ => return None,
    };
    let width = match &name[1..] {
        "32" => Width::W32,
        "64" => Width::W64,
        "128" => Width::W128,
        _ => return None,
    };
    Some(IntType::new(width, signed))
}

impl Serialize for Commitment {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_text())
    }
}

impl<'de> Deserialize<'de> for Commitment {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_text(&text).map_err(serde::de::Error::custom)
    }
}

impl Opening {
    pub fn ty(&self) -> IntType {
        self.ty
    }

    /// Whether this opening really opens `commitment`. The circuits enforce this independently;
    /// checking first just turns a wrong opening into a clear error instead of an unsatisfied
    /// constraint.
    pub fn opens(&self, commitment: &Commitment) -> bool {
        self.ty == commitment.ty
            && self
                .encoded()
                .is_ok_and(|encoded| digest(self.ty, encoded, &self.blinding) == commitment.digest)
    }

    pub(super) fn encoded(&self) -> Result<u128> {
        self.ty.encode(self.value)
    }

    pub(super) fn blinding(&self) -> &Blinding {
        &self.blinding
    }

    /// The secret as JSON, for storage or transfer to the prover. Treat it as a private key.
    pub fn to_secret_json(&self) -> String {
        serde_json::json!({
            "type": self.ty.to_string(),
            "value": self.value.to_string(),
            "blinding": self.blinding,
        })
        .to_string()
    }

    pub fn from_secret_json(text: &str) -> Result<Self> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Secret {
            r#type: String,
            value: String,
            blinding: Blinding,
        }
        let secret: Secret =
            serde_json::from_str(text).map_err(|e| ZkError::Format(e.to_string()))?;
        let ty = parse_type(&secret.r#type)
            .ok_or_else(|| ZkError::Format(format!("unknown integer type `{}`", secret.r#type)))?;
        let value: Number = secret.value.parse()?;
        ty.encode(value)?;
        if secret.blinding.iter().any(|b| *b >= FIELD_MODULUS) {
            return Err(ZkError::Format(
                "blinding element is not a field element".into(),
            ));
        }
        Ok(Self {
            ty,
            value,
            blinding: secret.blinding,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLIND: Blinding = [1, 2, 3, 4, 5, 6, 7, 8];

    #[test]
    fn deterministic_and_binding_to_every_input() {
        let (a, _) = Commitment::commit_with_blinding(IntType::U64, 18u64, BLIND).unwrap();
        let (same, _) = Commitment::commit_with_blinding(IntType::U64, 18u64, BLIND).unwrap();
        assert_eq!(a, same);
        let (other_value, _) =
            Commitment::commit_with_blinding(IntType::U64, 19u64, BLIND).unwrap();
        let mut other_blind = BLIND;
        other_blind[7] = 9;
        let (other_blinding, _) =
            Commitment::commit_with_blinding(IntType::U64, 18u64, other_blind).unwrap();
        let (other_width, _) =
            Commitment::commit_with_blinding(IntType::U32, 18u32, BLIND).unwrap();
        let (other_sign, _) = Commitment::commit_with_blinding(IntType::I64, 18i64, BLIND).unwrap();
        let digests = [a, other_value, other_blinding, other_width, other_sign].map(|c| c.digest);
        for i in 0..digests.len() {
            for j in i + 1..digests.len() {
                assert_ne!(digests[i], digests[j], "{i} vs {j}");
            }
        }
    }

    #[test]
    fn fresh_commitments_hide_equal_values() {
        let (a, _) = Commitment::commit(IntType::U32, 7u32).unwrap();
        let (b, _) = Commitment::commit(IntType::U32, 7u32).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn opening_checks_value_blinding_and_type() {
        let (c, opening) = Commitment::commit_with_blinding(IntType::U64, 18u64, BLIND).unwrap();
        assert!(opening.opens(&c));
        let (_, wrong_value) =
            Commitment::commit_with_blinding(IntType::U64, 19u64, BLIND).unwrap();
        assert!(!wrong_value.opens(&c));
        let (_, wrong_type) = Commitment::commit_with_blinding(IntType::I64, 18i64, BLIND).unwrap();
        assert!(!wrong_type.opens(&c));
    }

    #[test]
    fn text_and_secret_forms_round_trip_and_reject_garbage() {
        let (c, opening) = Commitment::commit(IntType::I128, -5i32).unwrap();
        assert_eq!(Commitment::from_text(&c.to_text()).unwrap(), c);
        assert_eq!(
            Opening::from_secret_json(&opening.to_secret_json()).unwrap(),
            opening
        );
        for bad in [
            "",
            "u64",
            "u7:00",
            "x64:00",
            &c.to_text()[..20],
            &c.to_text().replacen("128", "127", 1),
        ] {
            assert!(Commitment::from_text(bad).is_err(), "{bad}");
        }
        let all_ones = format!("u32:{}", "f".repeat(64));
        assert!(
            Commitment::from_text(&all_ones).is_err(),
            "non-canonical field element"
        );
        assert!(Opening::from_secret_json(
            r#"{"type":"u32","value":"-1","blinding":[0,0,0,0,0,0,0,0]}"#
        )
        .is_err());
        assert_eq!(format!("{opening:?}"), "Opening(i128, <redacted>)");
    }

    #[test]
    fn rejects_non_canonical_blinding() {
        assert!(Commitment::commit_with_blinding(IntType::U32, 1u32, [FIELD_MODULUS; 8]).is_err());
    }
}
