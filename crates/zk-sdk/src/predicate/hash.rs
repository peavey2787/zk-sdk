//! The Poseidon2 hashes of the predicate library: the capacity-tagged sponge behind commitments and
//! Merkle leaves, and the two-to-one node compression. `circuits/lib/sponge.circom` computes
//! exactly these; `tests/commitment_circuit.rs` and `tests/sets.rs` prove the two agree.

use std::sync::OnceLock;

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::{default_koalabear_poseidon2_16, KoalaBear, Poseidon2KoalaBear};
use p3_symmetric::Permutation;

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
