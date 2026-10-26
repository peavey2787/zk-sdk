//! The BN254 scalar field for the shared witness solver.

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, Field as _, PrimeField};
use zk_witness::Field;

/// BN254's scalar field (circom's `bn128` prime). Elements are always canonical.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bn254;

impl Field for Bn254 {
    type Element = Fr;
    const ZERO: Fr = Fr::ZERO;
    const ONE: Fr = Fr::ONE;

    fn modulus_le() -> Vec<u8> {
        Fr::MODULUS.to_bytes_le()
    }

    fn add(a: Fr, b: Fr) -> Fr {
        a + b
    }

    fn neg(a: Fr) -> Fr {
        -a
    }

    fn mul(a: Fr, b: Fr) -> Fr {
        a * b
    }

    fn inv(a: Fr) -> Fr {
        a.inverse()
            .expect("the solver only inverts non-zero coefficients")
    }

    fn is_canonical(_: Fr) -> bool {
        true
    }

    fn from_le(bytes: &[u8]) -> Option<Fr> {
        let bytes: [u8; 32] = bytes.try_into().ok()?;
        let mut limbs = [0u64; 4];
        for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
            *limb = u64::from_le_bytes(chunk.try_into().expect("8 bytes"));
        }
        Fr::from_bigint(ark_ff::BigInt(limbs))
    }

    fn to_le(a: Fr) -> Vec<u8> {
        a.into_bigint().to_bytes_le()
    }

    fn to_u128(a: Fr) -> Option<u128> {
        let [low, high, rest @ ..] = a.into_bigint().0;
        (rest == [0, 0]).then(|| u128::from(high) << 64 | u128::from(low))
    }

    fn from_u64(v: u64) -> Fr {
        Fr::from(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_round_trips_and_rejects_the_modulus() {
        let x = Fr::from(123_456_789u64) - Fr::from(2u64).pow([200]);
        assert_eq!(Bn254::from_le(&Bn254::to_le(x)), Some(x));
        assert_eq!(Bn254::from_le(&Bn254::modulus_le()), None);
        assert_eq!(Bn254::from_le(&[0; 31]), None);
    }

    #[test]
    fn small_values_are_visible_to_bit_decoding() {
        let big = Fr::from(u64::MAX) * Fr::from(4u64);
        assert_eq!(Bn254::to_u128(big), Some(u128::from(u64::MAX) * 4));
        assert_eq!(Bn254::to_u128(-Fr::ONE), None);
    }
}
