//! The Groth16 prover (Groth 2016, as in snarkjs and ark-groth16) over a parsed zkey.

use ark_bn254::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::VariableBaseMSM;

use crate::zkey::ProvingKey;

/// Proof points A, B, C.
pub struct Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
}

/// `assignment` is the full witness (constant wire first); `h` the QAP quotient evaluations;
/// `r` and `s` the fresh blinding scalars.
pub fn prove(pk: &ProvingKey, assignment: &[Fr], n_inputs: usize, h: &[Fr], r: Fr, s: Fr) -> Proof {
    let g1 = |bases: &[G1Affine], scalars: &[Fr]| G1Projective::msm_unchecked(bases, scalars);
    let a = g1(&pk.a_query, assignment) + pk.vk.alpha_g1 + pk.delta_g1 * r;
    let b_g1 = g1(&pk.b_g1_query, assignment) + pk.beta_g1 + pk.delta_g1 * s;
    let b = G2Projective::msm_unchecked(&pk.b_g2_query, assignment)
        + pk.vk.beta_g2
        + pk.vk.delta_g2 * s;
    let c = g1(&pk.l_query, &assignment[n_inputs..]) + g1(&pk.h_query, h) + a * s + b_g1 * r
        - pk.delta_g1 * (r * s);
    Proof {
        a: a.into(),
        b: b.into(),
        c: c.into(),
    }
}
