//! Value commitments: the public handle a predicate is about, and the private opening that proves it.
//!
//! Each commitment belongs to one [`Scheme`]:
//!
//! - Spartan-WHIR: `digest = Poseidon2-sponge([signed, limb count, limbs.., blinding..])` over
//!   KoalaBear with Plonky3's width-16 permutation, rate 8, capacity `[DOMAIN, message length, 0..]`
//!   (`circuits/lib/koalabear/commit.circom`; `tests/commitment_circuit.rs` proves the two agree).
//!   Binding up to the sponge's collision resistance (about 2^124 over eight 31-bit elements).
//! - Groth16: `digest = Poseidon5(DOMAIN, signed, limb count, packed value, blinding)` over BN254
//!   (`circuits/lib/bn254/commit.circom`, computed by `zk_groth16::commit`). Binding up to Poseidon's
//!   collision resistance over BN254 (about 2^127).
//!
//! Both hide the value while the blinding stays secret and uniformly random.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
use zk_groth16::{Bn254, Fr};
use zk_witness::Field as _;

pub use super::hash::DIGEST_ELEMENTS;
pub(super) use super::hash::FIELD_MODULUS;
use super::hash::{sponge, COMMIT_DOMAIN};
use super::int::{IntType, Number};
use super::scheme::Scheme;
use crate::{Result, ZkError};

pub const BLINDING_ELEMENTS: usize = 8;

type KoalaBlinding = [u32; BLINDING_ELEMENTS];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Digest {
    KoalaBear(super::hash::Digest),
    Bn254(Fr),
}

#[derive(Clone, PartialEq, Eq)]
enum Blinding {
    KoalaBear(KoalaBlinding),
    Bn254(Fr),
}

impl Zeroize for Blinding {
    fn zeroize(&mut self) {
        match self {
            Self::KoalaBear(elements) => elements.zeroize(),
            Self::Bn254(scalar) => scalar.zeroize(),
        }
    }
}

fn digest(ty: IntType, encoded: u128, blinding: &Blinding) -> Digest {
    let limbs = ty.limbs(encoded);
    match blinding {
        Blinding::KoalaBear(blinding) => {
            let mut message = vec![u32::from(ty.signed), limbs.len() as u32];
            message.extend(limbs.iter().map(|l| *l as u32));
            message.extend_from_slice(blinding);
            Digest::KoalaBear(sponge(COMMIT_DOMAIN, &message))
        }
        Blinding::Bn254(blinding) => {
            let limbs: Vec<u16> = limbs.iter().map(|l| *l as u16).collect();
            Digest::Bn254(zk_groth16::commit(ty.signed, &limbs, *blinding))
        }
    }
}

/// Uniform KoalaBear elements by rejection sampling over the OS (or browser) CSPRNG.
fn random_koalabear() -> Result<KoalaBlinding> {
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

fn random_blinding(scheme: Scheme) -> Result<Blinding> {
    match scheme {
        Scheme::SpartanWhir => random_koalabear().map(Blinding::KoalaBear),
        Scheme::Groth16 => zk_groth16::random_scalar()
            .map(Blinding::Bn254)
            .map_err(|e| ZkError::Unavailable(e.to_string())),
    }
}

/// A BN254 scalar as 64 big-endian hex digits.
fn scalar_hex(scalar: Fr) -> String {
    Bn254::to_le(scalar)
        .iter()
        .rev()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The canonical scalar spelled by 64 hex digits, if any.
fn scalar_from_hex(hex: &str) -> Option<Fr> {
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = (0..32)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    bytes.reverse();
    Bn254::from_le(&bytes)
}

fn koalabear_digest(hex: &str) -> Option<super::hash::Digest> {
    if hex.len() != DIGEST_ELEMENTS * 8 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut digest = [0u32; DIGEST_ELEMENTS];
    for (slot, chunk) in digest.iter_mut().zip(hex.as_bytes().chunks(8)) {
        let element = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
        if element >= FIELD_MODULUS {
            return None;
        }
        *slot = element;
    }
    Some(digest)
}

/// The public commitment to a typed integer. Safe to publish; it carries its type and scheme, which
/// the digest binds, so a commitment cannot be reinterpreted under another width, signedness or
/// proof system.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Commitment {
    ty: IntType,
    digest: Digest,
}

/// The secret behind a [`Commitment`]: the value and its blinding. Never log or transmit it; the
/// `Debug` output is redacted. The value and blinding are overwritten when the opening is dropped
/// (best effort: copies the compiler or allocator made earlier, and the browser's JavaScript
/// strings, are outside Rust's reach; see docs/SECURITY.md).
#[derive(Clone, PartialEq, Eq)]
pub struct Opening {
    ty: IntType,
    value: Number,
    blinding: Blinding,
}

impl Zeroize for Opening {
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.blinding.zeroize();
    }
}

impl Drop for Opening {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for Opening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Opening({}, <redacted>)", self.ty)
    }
}

impl Commitment {
    /// Commit to `value` for Spartan-WHIR under a fresh random blinding. Returns the public
    /// commitment and the private opening the prover needs.
    pub fn commit(ty: IntType, value: impl Into<Number>) -> Result<(Self, Opening)> {
        Self::commit_in(Scheme::SpartanWhir, ty, value)
    }

    /// Commit to `value` for `scheme` under a fresh random blinding.
    pub fn commit_in(
        scheme: Scheme,
        ty: IntType,
        value: impl Into<Number>,
    ) -> Result<(Self, Opening)> {
        Self::with_blinding(ty, value.into(), random_blinding(scheme)?)
    }

    /// Deterministic Spartan-WHIR variant for reproducible tests and vectors. A reused or
    /// guessable blinding breaks hiding; real callers use [`Commitment::commit`].
    pub fn commit_with_blinding(
        ty: IntType,
        value: impl Into<Number>,
        blinding: KoalaBlinding,
    ) -> Result<(Self, Opening)> {
        if blinding.iter().any(|b| *b >= FIELD_MODULUS) {
            return Err(ZkError::Predicate(
                "blinding element is not a field element".into(),
            ));
        }
        Self::with_blinding(ty, value.into(), Blinding::KoalaBear(blinding))
    }

    fn with_blinding(ty: IntType, value: Number, blinding: Blinding) -> Result<(Self, Opening)> {
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

    pub fn scheme(&self) -> Scheme {
        match self.digest {
            Digest::KoalaBear(_) => Scheme::SpartanWhir,
            Digest::Bn254(_) => Scheme::Groth16,
        }
    }

    /// The digest as circuit signals: eight KoalaBear elements, or one BN254 scalar.
    pub(super) fn signals(&self) -> Vec<Fr> {
        match self.digest {
            Digest::KoalaBear(words) => words.iter().map(|w| Fr::from(*w)).collect(),
            Digest::Bn254(scalar) => vec![scalar],
        }
    }

    /// Canonical text form: `<type>:<64 hex digits>` for Spartan-WHIR (e.g. `u64:00ab..`), and
    /// `groth16:<type>:<64 hex digits>` for Groth16.
    pub fn to_text(&self) -> String {
        match self.digest {
            Digest::KoalaBear(words) => {
                let hex: String = words.iter().map(|d| format!("{d:08x}")).collect();
                format!("{}:{hex}", self.ty)
            }
            Digest::Bn254(scalar) => format!("groth16:{}:{}", self.ty, scalar_hex(scalar)),
        }
    }

    pub fn from_text(text: &str) -> Result<Self> {
        let invalid = || {
            ZkError::Format(format!(
                "`{text}` is not a commitment ([groth16:]type:64 hex digits)"
            ))
        };
        let (bn254, rest) = match text.strip_prefix("groth16:") {
            Some(rest) => (true, rest),
            None => (false, text),
        };
        let (name, hex) = rest.split_once(':').ok_or_else(invalid)?;
        let ty: IntType = name.parse().map_err(|_| invalid())?;
        let digest = if bn254 {
            Digest::Bn254(scalar_from_hex(hex).ok_or_else(invalid)?)
        } else {
            Digest::KoalaBear(koalabear_digest(hex).ok_or_else(invalid)?)
        };
        Ok(Self { ty, digest })
    }
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

/// A secret's blinding as stored: eight KoalaBear elements, or one BN254 scalar in hex.
#[derive(Deserialize)]
#[serde(untagged)]
enum BlindingText {
    Elements(KoalaBlinding),
    Scalar(String),
}

impl Zeroize for BlindingText {
    fn zeroize(&mut self) {
        match self {
            Self::Elements(elements) => elements.zeroize(),
            Self::Scalar(hex) => hex.zeroize(),
        }
    }
}

impl BlindingText {
    fn parse(&self, scheme: Scheme) -> Result<Blinding> {
        let invalid = || ZkError::Format(format!("not a {scheme} blinding"));
        match (scheme, self) {
            (Scheme::SpartanWhir, Self::Elements(elements)) => {
                if elements.iter().any(|b| *b >= FIELD_MODULUS) {
                    return Err(ZkError::Format(
                        "blinding element is not a field element".into(),
                    ));
                }
                Ok(Blinding::KoalaBear(*elements))
            }
            (Scheme::Groth16, Self::Scalar(hex)) => scalar_from_hex(hex)
                .map(Blinding::Bn254)
                .ok_or_else(invalid),
            _ => Err(invalid()),
        }
    }
}

impl Opening {
    pub fn ty(&self) -> IntType {
        self.ty
    }

    pub fn scheme(&self) -> Scheme {
        match self.blinding {
            Blinding::KoalaBear(_) => Scheme::SpartanWhir,
            Blinding::Bn254(_) => Scheme::Groth16,
        }
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

    pub(super) fn value(&self) -> Number {
        self.value
    }

    pub(super) fn encoded(&self) -> Result<u128> {
        self.ty.encode(self.value)
    }

    /// The blinding as circuit signals: eight KoalaBear elements, or one BN254 scalar.
    pub(super) fn blinding_signals(&self) -> Vec<Fr> {
        match &self.blinding {
            Blinding::KoalaBear(words) => words.iter().map(|w| Fr::from(*w)).collect(),
            Blinding::Bn254(scalar) => vec![*scalar],
        }
    }

    /// The secret as JSON, for storage or transfer to the prover. Treat it as a private key.
    /// Spartan-WHIR secrets keep their original shape; Groth16 secrets add `"scheme"`.
    pub fn to_secret_json(&self) -> String {
        let (ty, value) = (self.ty.to_string(), self.value.to_string());
        match &self.blinding {
            Blinding::KoalaBear(words) => {
                serde_json::json!({ "type": ty, "value": value, "blinding": words })
            }
            Blinding::Bn254(scalar) => serde_json::json!({
                "scheme": Scheme::Groth16.name(),
                "type": ty,
                "value": value,
                "blinding": scalar_hex(*scalar),
            }),
        }
        .to_string()
    }

    pub fn from_secret_json(text: &str) -> Result<Self> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Secret {
            scheme: Option<String>,
            r#type: String,
            value: String,
            blinding: BlindingText,
        }
        impl Drop for Secret {
            fn drop(&mut self) {
                self.value.zeroize();
                self.blinding.zeroize();
            }
        }
        let secret: Secret =
            serde_json::from_str(text).map_err(|e| ZkError::Format(e.to_string()))?;
        let scheme = match &secret.scheme {
            Some(name) => name.parse()?,
            None => Scheme::SpartanWhir,
        };
        let ty: IntType = secret.r#type.parse()?;
        let value: Number = secret.value.parse()?;
        ty.encode(value)?;
        Ok(Self {
            ty,
            value,
            blinding: secret.blinding.parse(scheme)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLIND: KoalaBlinding = [1, 2, 3, 4, 5, 6, 7, 8];

    #[test]
    fn zeroizing_an_opening_destroys_the_secret() {
        let (commitment, mut opening) =
            Commitment::commit_with_blinding(IntType::U64, 18u64, BLIND).unwrap();
        assert!(opening.opens(&commitment));
        opening.zeroize();
        assert_eq!(opening.value(), Number::default());
        assert_eq!(
            opening.blinding_signals(),
            vec![Fr::from(0u8); BLINDING_ELEMENTS]
        );
        assert!(!opening.opens(&commitment));
        assert!(!opening.to_secret_json().contains("18"));
    }

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
        for scheme in [Scheme::SpartanWhir, Scheme::Groth16] {
            let (a, _) = Commitment::commit_in(scheme, IntType::U32, 7u32).unwrap();
            let (b, _) = Commitment::commit_in(scheme, IntType::U32, 7u32).unwrap();
            assert_ne!(a, b);
        }
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

    #[test]
    fn groth16_commitments_round_trip_and_never_open_across_schemes() {
        let (c, opening) = Commitment::commit_in(Scheme::Groth16, IntType::I64, -9i32).unwrap();
        assert_eq!(
            (c.scheme(), opening.scheme()),
            (Scheme::Groth16, Scheme::Groth16)
        );
        assert!(c.to_text().starts_with("groth16:i64:"));
        assert_eq!(Commitment::from_text(&c.to_text()).unwrap(), c);
        let secret = opening.to_secret_json();
        let parsed = Opening::from_secret_json(&secret).unwrap();
        assert_eq!(parsed, opening);
        assert!(parsed.opens(&c));
        let (koala, koala_opening) = Commitment::commit(IntType::I64, -9i32).unwrap();
        assert!(!opening.opens(&koala) && !koala_opening.opens(&c));
        assert!(Opening::from_secret_json(&secret.replace("groth16", "spartan-whir")).is_err());
        let modulus = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";
        assert!(
            Commitment::from_text(&format!("groth16:u32:{modulus}")).is_err(),
            "non-canonical scalar"
        );
        assert!(Commitment::from_text(&format!("groth16:u32:{}", &modulus[..62])).is_err());
    }
}
