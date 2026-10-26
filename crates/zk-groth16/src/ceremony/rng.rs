//! The deterministic generator snarkjs (ffjavascript) uses to hash a transcript to a G2 point and to
//! expand a beacon into a contribution, reproduced bit for bit so keys verify both here and with
//! `snarkjs zkey verify`.
//!
//! It is ChaCha20 (10 double rounds) keyed by eight words, emitting each block's sixteen words in
//! order. A field element is four 64-bit draws (the first draw the high half of each), masked to the
//! modulus' bit length and redrawn until below the modulus; the value is taken as the element's
//! Montgomery representation, as ffjavascript does. A point draws `x` and a sign bit until
//! `x^3 + b` is a square, picks the root whose sign matches, and clears the cofactor.

use ark_bn254::{g1, g2, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::{
    short_weierstrass::{Affine, SWCurveConfig},
    AffineRepr, CurveGroup,
};
use ark_ff::{BigInt, BigInteger, Field, Fp, MontBackend, MontConfig, PrimeField, Zero};

use crate::digest::{be_words, sha256};

const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646E, 0x7962_2D32, 0x6B20_6574];
/// ffjavascript's cofactor for BN254 G2 (`2p - r`), applied by plain double-and-add.
const G2_COFACTOR: [u64; 4] = [
    0x345f_2299_c0f9_fa8d,
    0x06ce_ecda_572a_2489,
    0xb850_45b6_8181_585e,
    0x3064_4e72_e131_a029,
];

pub(crate) struct ChaCha {
    state: [u32; 16],
    block: [u32; 16],
    used: usize,
}

fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

impl ChaCha {
    pub(crate) fn new(seed: [u32; 8]) -> Self {
        let mut state = [0u32; 16];
        state[..4].copy_from_slice(&CONSTANTS);
        state[4..12].copy_from_slice(&seed);
        Self {
            state,
            block: [0; 16],
            used: 16,
        }
    }

    /// Seeded with the first 32 bytes of `hash` as big-endian words.
    pub(crate) fn from_hash(hash: &[u8]) -> Self {
        Self::new(be_words(&hash[..32]))
    }

    fn refill(&mut self) {
        let mut s = self.state;
        for _ in 0..10 {
            for [a, b, c, d] in [
                [0, 4, 8, 12],
                [1, 5, 9, 13],
                [2, 6, 10, 14],
                [3, 7, 11, 15],
                [0, 5, 10, 15],
                [1, 6, 11, 12],
                [2, 7, 8, 13],
                [3, 4, 9, 14],
            ] {
                quarter_round(&mut s, a, b, c, d);
            }
        }
        for (out, (mixed, initial)) in self.block.iter_mut().zip(s.iter().zip(&self.state)) {
            *out = mixed.wrapping_add(*initial);
        }
        self.used = 0;
        for word in &mut self.state[12..] {
            *word = word.wrapping_add(1);
            if *word != 0 {
                break;
            }
        }
    }

    fn next_u32(&mut self) -> u32 {
        if self.used == 16 {
            self.refill();
        }
        self.used += 1;
        self.block[self.used - 1]
    }

    fn next_u64(&mut self) -> u64 {
        let high = u64::from(self.next_u32());
        (high << 32) | u64::from(self.next_u32())
    }

    fn next_bool(&mut self) -> bool {
        self.next_u32() & 1 == 1
    }

    /// ffjavascript's `F.fromRng` for a 254-bit prime field.
    fn element<P: MontConfig<4>>(&mut self) -> Fp<MontBackend<P, 4>, 4> {
        let top_bits = P::MODULUS.num_bits() - 192;
        loop {
            let mut limbs: [u64; 4] = std::array::from_fn(|_| self.next_u64());
            limbs[3] &= (1u64 << top_bits) - 1;
            if BigInt(limbs) < P::MODULUS {
                return Fp::new_unchecked(BigInt(limbs));
            }
        }
    }

    pub(crate) fn scalar(&mut self) -> Fr {
        self.element()
    }

    fn fq2(&mut self) -> Fq2 {
        let c0 = self.element();
        Fq2::new(c0, self.element())
    }

    /// ffjavascript's `G.fromRng`.
    fn point<C: SWCurveConfig>(
        &mut self,
        coordinate: fn(&mut Self) -> C::BaseField,
        negative: fn(&C::BaseField) -> bool,
        cofactor: &[u64],
    ) -> Affine<C> {
        loop {
            let x = coordinate(self);
            let greatest = self.next_bool();
            let Some(mut y) = (x.square() * x + C::COEFF_B).sqrt() else {
                continue;
            };
            if greatest ^ negative(&y) {
                y = -y;
            }
            return Affine::<C>::new_unchecked(x, y)
                .mul_bigint(cofactor)
                .into_affine();
        }
    }

    pub(crate) fn g1(&mut self) -> G1Affine {
        self.point::<g1::Config>(|r| r.element(), fq_negative, &[1])
    }

    pub(crate) fn g2(&mut self) -> G2Affine {
        self.point::<g2::Config>(Self::fq2, fq2_negative, &G2_COFACTOR)
    }
}

fn fq_negative(x: &Fq) -> bool {
    x.into_bigint() > Fq::MODULUS_MINUS_ONE_DIV_TWO
}

fn fq2_negative(x: &Fq2) -> bool {
    if x.c1.is_zero() {
        fq_negative(&x.c0)
    } else {
        fq_negative(&x.c1)
    }
}

/// snarkjs's `hashToG2`: the G2 point a contribution's transcript commits to.
pub(crate) fn hash_to_g2(transcript: &[u8]) -> G2Affine {
    ChaCha::from_hash(transcript).g2()
}

/// The most hash iterations a beacon may ask a verifier to recompute (2^28 SHA-256).
pub const MAX_BEACON_EXPONENT: u8 = 28;
/// snarkjs refuses beacons with fewer than 2^10 iterations.
pub const MIN_BEACON_EXPONENT: u8 = 10;

/// snarkjs's `rngFromBeaconParams`: SHA-256 iterated `2^exponent` times over the beacon value.
pub(crate) fn beacon(value: &[u8], exponent: u8) -> ChaCha {
    let mut hash = sha256(value);
    for _ in 1..(1u64 << exponent) {
        hash = sha256(&hash);
    }
    ChaCha::from_hash(&hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first block of the all-zero key matches the reference ChaCha20 keystream
    /// (RFC 7539 test vector, read as little-endian words), as ffjavascript's generator does.
    #[test]
    fn zero_seed_matches_the_chacha20_keystream() {
        let mut rng = ChaCha::new([0; 8]);
        assert_eq!(rng.next_u32(), 0xade0_b876);
        assert_eq!(rng.next_u32(), 0x903d_f1a0);
    }

    #[test]
    fn sampled_points_are_in_the_prime_order_groups() {
        let mut rng = ChaCha::new([7; 8]);
        let (p, q) = (rng.g1(), rng.g2());
        assert!(p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve());
        assert!(q.is_on_curve() && q.is_in_correct_subgroup_assuming_on_curve());
        assert!(!q.is_zero());
        assert_eq!(hash_to_g2(&[1; 64]), hash_to_g2(&[1; 64]));
        assert_ne!(hash_to_g2(&[1; 64]), hash_to_g2(&[2; 64]));
    }
}
