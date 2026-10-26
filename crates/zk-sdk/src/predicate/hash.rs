//! The hashes of the predicate library. Spartan-WHIR uses the Poseidon2 capacity-tagged sponge
//! behind commitments and Merkle leaves and the two-to-one node compression over KoalaBear
//! (`circuits/lib/koalabear/sponge.circom` computes exactly these; `tests/commitment_circuit.rs` and
//! `tests/sets.rs` prove the two agree). Groth16 uses the BN254 Poseidon sponge and compression of
//! `zk_groth16` (`circuits/lib/bn254/merkle.circom`). A [`Node`] is a commitment digest or Merkle
//! hash of either kind.

use std::sync::OnceLock;

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::{default_koalabear_poseidon2_16, KoalaBear, Poseidon2KoalaBear};
use p3_symmetric::Permutation;
use zeroize::Zeroize;
use zk_groth16::{Bn254, Fr};
use zk_witness::Field as _;

use super::scheme::Scheme;

pub(super) const FIELD_MODULUS: u32 = 0x7f00_0001;
pub const DIGEST_ELEMENTS: usize = 8;
const RATE: usize = 8;
const WIDTH: usize = 16;

pub(super) const COMMIT_DOMAIN: u32 = 1_514_344_449;
pub(super) const LEAF_DOMAIN: u32 = 1_514_344_450;
pub(super) const GAP_DOMAIN: u32 = 1_514_344_451;
pub(super) const CREDENTIAL_DOMAIN: u32 = 1_514_344_452;

pub type Digest = [u32; DIGEST_ELEMENTS];

fn permutation() -> &'static Poseidon2KoalaBear<WIDTH> {
    static PERMUTATION: OnceLock<Poseidon2KoalaBear<WIDTH>> = OnceLock::new();
    PERMUTATION.get_or_init(default_koalabear_poseidon2_16)
}

fn digest_of(state: &[KoalaBear; WIDTH]) -> Digest {
    std::array::from_fn(|i| state[i].as_canonical_u32())
}

/// Sponge over `message` with capacity `[domain, message length, 0...]`, rate 8.
pub(super) fn sponge(domain: u32, message: &[u32]) -> Digest {
    let mut state = [KoalaBear::ZERO; WIDTH];
    state[RATE] = KoalaBear::new(domain);
    state[RATE + 1] = KoalaBear::new(message.len() as u32);
    for block in message.chunks(RATE) {
        for (slot, value) in state.iter_mut().zip(block) {
            *slot += KoalaBear::new(*value);
        }
        permutation().permute_mut(&mut state);
    }
    digest_of(&state)
}

/// Merkle node: permute `(left, right)` and add `left` back to the first eight elements.
pub(super) fn compress(left: &Digest, right: &Digest) -> Digest {
    let mut state = [KoalaBear::ZERO; WIDTH];
    for i in 0..DIGEST_ELEMENTS {
        state[i] = KoalaBear::new(left[i]);
        state[DIGEST_ELEMENTS + i] = KoalaBear::new(right[i]);
    }
    permutation().permute_mut(&mut state);
    for (slot, l) in state.iter_mut().zip(left) {
        *slot += KoalaBear::new(*l);
    }
    digest_of(&state)
}

/// A BN254 scalar as 64 big-endian hex digits.
pub(super) fn scalar_hex(scalar: Fr) -> String {
    Bn254::to_le(scalar)
        .iter()
        .rev()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The canonical scalar spelled by 64 hex digits, if any.
pub(super) fn scalar_from_hex(hex: &str) -> Option<Fr> {
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = (0..32)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    bytes.reverse();
    Bn254::from_le(&bytes)
}

/// Eight canonical KoalaBear elements from 64 hex digits, if they spell one.
fn digest_from_hex(hex: &str) -> Option<Digest> {
    if hex.len() != DIGEST_ELEMENTS * 8 || !hex.is_ascii() {
        return None;
    }
    let mut digest = [0u32; DIGEST_ELEMENTS];
    for (slot, chunk) in digest.iter_mut().zip(hex.as_bytes().chunks(8)) {
        let text = std::str::from_utf8(chunk).ok()?;
        if !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let element = u32::from_str_radix(text, 16).ok()?;
        if element >= FIELD_MODULUS {
            return None;
        }
        *slot = element;
    }
    Some(digest)
}

fn digest_hex(digest: &Digest) -> String {
    digest.iter().map(|d| format!("{d:08x}")).collect()
}

/// One digest: eight KoalaBear elements (Spartan-WHIR) or one BN254 scalar (Groth16). Every node
/// of a tree, and every path into it, belongs to the tree's scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum Node {
    KoalaBear(Digest),
    Bn254(Fr),
}

impl Zeroize for Node {
    fn zeroize(&mut self) {
        match self {
            Self::KoalaBear(digest) => digest.zeroize(),
            Self::Bn254(scalar) => scalar.zeroize(),
        }
    }
}

impl Node {
    /// The padding leaf of empty positions.
    pub(super) fn zero(scheme: Scheme) -> Self {
        match scheme {
            Scheme::SpartanWhir => Self::KoalaBear([0; DIGEST_ELEMENTS]),
            Scheme::Groth16 => Self::Bn254(Fr::from(0u8)),
        }
    }

    pub(super) fn scheme(&self) -> Scheme {
        match self {
            Self::KoalaBear(_) => Scheme::SpartanWhir,
            Self::Bn254(_) => Scheme::Groth16,
        }
    }

    /// The node as circuit signals.
    pub(super) fn signals(&self) -> Vec<Fr> {
        match self {
            Self::KoalaBear(digest) => digest.iter().map(|w| Fr::from(*w)).collect(),
            Self::Bn254(scalar) => vec![*scalar],
        }
    }

    /// 64 hex digits in either scheme.
    pub(super) fn to_hex(self) -> String {
        match self {
            Self::KoalaBear(digest) => digest_hex(&digest),
            Self::Bn254(scalar) => scalar_hex(scalar),
        }
    }

    pub(super) fn from_hex(scheme: Scheme, hex: &str) -> Option<Self> {
        match scheme {
            Scheme::SpartanWhir => digest_from_hex(hex).map(Self::KoalaBear),
            Scheme::Groth16 => scalar_from_hex(hex).map(Self::Bn254),
        }
    }

    /// The leaf hash of `message` (limb-sized words) under `domain` in `scheme`.
    pub(super) fn leaf(scheme: Scheme, domain: u32, message: &[u32]) -> Self {
        match scheme {
            Scheme::SpartanWhir => Self::KoalaBear(sponge(domain, message)),
            Scheme::Groth16 => {
                let message: Vec<Fr> = message.iter().map(|w| Fr::from(*w)).collect();
                Self::Bn254(zk_groth16::sponge(u64::from(domain), &message))
            }
        }
    }

    /// The parent of `self` (left) and `right`. Callers check that a tree's nodes share one scheme
    /// before hashing ([`super::set::SetPath`] holds paths to that).
    pub(super) fn parent(&self, right: &Self) -> Self {
        match (self, right) {
            (Self::KoalaBear(left), Self::KoalaBear(right)) => {
                Self::KoalaBear(compress(left, right))
            }
            (Self::Bn254(left), Self::Bn254(right)) => {
                Self::Bn254(zk_groth16::compress(*left, *right))
            }
            _ => unreachable!("the nodes of one tree share its scheme"),
        }
    }
}
