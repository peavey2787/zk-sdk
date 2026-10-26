//! The Groth16 verifier: `e(A, B) = e(alpha, beta) e(sum x_i IC_i, gamma) e(C, delta)`.

use ark_bn254::{Bn254 as Curve, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{
    bn::G2Prepared,
    pairing::{Pairing, PairingOutput},
    VariableBaseMSM,
};
use ark_serialize::{CanonicalDeserialize, Compress, Validate};

use crate::{zkey::VerifyingKeyPoints, Groth16Error, Result};

/// Compressed Groth16 proof: A and C in G1, B in G2.
pub const PROOF_BYTES: usize = 128;

/// A circuit's verifying key, prepared for pairing checks.
pub struct VerifyingKey {
    ic: Vec<G1Affine>,
    alpha_beta: PairingOutput<Curve>,
    neg_gamma: G2Prepared<ark_bn254::Config>,
    neg_delta: G2Prepared<ark_bn254::Config>,
}

fn point<P: CanonicalDeserialize>(bytes: &mut &[u8]) -> Result<P> {
    P::deserialize_with_mode(bytes, Compress::Yes, Validate::Yes)
        .map_err(|_| Groth16Error::Rejected)
}

impl VerifyingKey {
    pub(crate) fn new(vk: &VerifyingKeyPoints) -> Self {
        Self {
            ic: vk.ic.clone(),
            alpha_beta: Curve::pairing(vk.alpha_g1, vk.beta_g2),
            neg_gamma: (-vk.gamma_g2).into(),
            neg_delta: (-vk.delta_g2).into(),
        }
    }

    /// Accept only a canonical, in-group proof of exactly these public signals.
    pub fn verify(&self, public_signals: &[Fr], proof: &[u8]) -> Result<()> {
        if proof.len() != PROOF_BYTES || public_signals.len() + 1 != self.ic.len() {
            return Err(Groth16Error::Rejected);
        }
        let mut bytes = proof;
        let a: G1Affine = point(&mut bytes)?;
        let b: G2Affine = point(&mut bytes)?;
        let c: G1Affine = point(&mut bytes)?;
        let inputs = G1Projective::msm_unchecked(&self.ic[1..], public_signals) + self.ic[0];
        let lhs = Curve::multi_pairing(
            [a, inputs.into(), c],
            [b.into(), self.neg_gamma.clone(), self.neg_delta.clone()],
        );
        if lhs == self.alpha_beta {
            Ok(())
        } else {
            Err(Groth16Error::Rejected)
        }
    }
}
