//! BN254 point encodings used by snarkjs files.
//!
//! * *LEM* (zkey and ptau sections): each coordinate little-endian in Montgomery form, G2
//!   coordinates as `c0, c1`; the point at infinity is all zeros.
//! * *Uncompressed* (what snarkjs hashes): each coordinate big-endian in normal form, G2 coordinates
//!   as `c1, c0`; the point at infinity is all zeros.

use ark_bn254::{Fq, Fq2, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInt, BigInteger, PrimeField, Zero};

pub(crate) const ELEMENT: usize = 32;
pub(crate) const G1_BYTES: usize = 2 * ELEMENT;
pub(crate) const G2_BYTES: usize = 4 * ELEMENT;

fn put_lem(out: &mut Vec<u8>, x: &Fq) {
    out.extend(x.0 .0.iter().flat_map(|limb| limb.to_le_bytes()));
}

fn put_be(out: &mut Vec<u8>, x: &Fq) {
    out.extend(x.into_bigint().to_bytes_be());
}

pub(crate) fn encode_g1(p: &G1Affine) -> Vec<u8> {
    let mut out = Vec::with_capacity(G1_BYTES);
    let (x, y) = p.xy().unwrap_or_default();
    put_lem(&mut out, &x);
    put_lem(&mut out, &y);
    out
}

pub(crate) fn encode_g2(p: &G2Affine) -> Vec<u8> {
    let mut out = Vec::with_capacity(G2_BYTES);
    let (x, y) = p.xy().unwrap_or_default();
    for c in [x.c0, x.c1, y.c0, y.c1] {
        put_lem(&mut out, &c);
    }
    out
}

pub(crate) fn uncompressed_g1(p: &G1Affine) -> Vec<u8> {
    let mut out = Vec::with_capacity(G1_BYTES);
    let (x, y) = p.xy().unwrap_or_default();
    put_be(&mut out, &x);
    put_be(&mut out, &y);
    out
}

pub(crate) fn uncompressed_g2(p: &G2Affine) -> Vec<u8> {
    let mut out = Vec::with_capacity(G2_BYTES);
    let (x, y) = p.xy().unwrap_or_default();
    for c in [x.c1, x.c0, y.c1, y.c0] {
        put_be(&mut out, &c);
    }
    out
}

/// A base-field element from its LEM bytes, without a range check: only for bytes pinned by hash.
fn lem_unchecked(bytes: &[u8]) -> Fq {
    let mut limbs = [0u64; 4];
    for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
        *limb = u64::from_le_bytes(chunk.try_into().expect("8 bytes"));
    }
    Fq::new_unchecked(BigInt(limbs))
}

/// A G1 point from LEM bytes without curve or subgroup checks: only for bytes pinned by hash.
pub(crate) fn g1_unchecked(bytes: &[u8]) -> G1Affine {
    let (x, y) = (
        lem_unchecked(&bytes[..ELEMENT]),
        lem_unchecked(&bytes[ELEMENT..]),
    );
    if x.is_zero() && y.is_zero() {
        G1Affine::zero()
    } else {
        G1Affine::new_unchecked(x, y)
    }
}

/// A G2 point from LEM bytes without curve or subgroup checks: only for bytes pinned by hash.
pub(crate) fn g2_unchecked(bytes: &[u8]) -> G2Affine {
    let c = |i: usize| lem_unchecked(&bytes[i * ELEMENT..(i + 1) * ELEMENT]);
    let (x, y) = (Fq2::new(c(0), c(1)), Fq2::new(c(2), c(3)));
    if x.is_zero() && y.is_zero() {
        G2Affine::zero()
    } else {
        G2Affine::new_unchecked(x, y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodings_round_trip_and_follow_snarkjs_byte_order() {
        let (g1, g2) = (G1Affine::generator(), G2Affine::generator());
        assert_eq!(g1_unchecked(&encode_g1(&g1)), g1);
        assert_eq!(g2_unchecked(&encode_g2(&g2)), g2);
        assert!(g1_unchecked(&encode_g1(&G1Affine::zero())).is_zero());
        // The G1 generator is (1, 2): big-endian in the uncompressed form.
        let u = uncompressed_g1(&g1);
        assert_eq!((u[31], u[63]), (1, 2));
        assert_eq!(uncompressed_g2(&G2Affine::zero()), vec![0; G2_BYTES]);
        let u2 = uncompressed_g2(&g2);
        assert_eq!(
            &u2[..ELEMENT],
            g2.x.c1.into_bigint().to_bytes_be().as_slice()
        );
    }
}
